// MIT License
//
// Copyright (c) 2021 Lennart Braun
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <algorithm>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <regex>
#include <stdexcept>

#include <boost/algorithm/string.hpp>
#include <boost/json/serialize.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/log/trivial.hpp>
#include <boost/program_options.hpp>

#include "algorithm/circuit_loader.h"
#include "base/gate_factory.h"
#include "base/mpclan_tensor_backend.h"
#include "communication/communication_layer.h"
#include "communication/tcp_transport.h"
#include "statistics/analysis.h"
#include "utility/logger.h"
#include "tensor/tensor.h"
#include "tensor/tensor_op.h"
#include "tensor/tensor_op_factory.h"
#include "protocols/beavy/tensor.h"

namespace po = boost::program_options;

struct Options {
  std::size_t threads;
  bool json;
  std::size_t num_parties;
  std::size_t num_repetitions;
  std::size_t num_simd;
  bool sync_between_setup_and_online;
  MOTION::MPCProtocol arithmetic_protocol;
  MOTION::MPCProtocol boolean_protocol;
  std::size_t my_id;
  MOTION::Communication::tcp_parties_config tcp_config;
  bool no_run = false;
};

std::optional<Options> parse_program_options(int argc, char* argv[]) {
  Options options;
  boost::program_options::options_description desc("Allowed options");
  // clang-format off
  desc.add_options()
    ("help,h", po::bool_switch()->default_value(false),"produce help message")
    ("config-file", po::value<std::string>(), "config file containing options")
    ("my-id", po::value<std::size_t>()->required(), "my party id")
    ("num_parties", po::value<std::size_t>()->required(), "number of parties")
    ("party", po::value<std::vector<std::string>>()->multitoken(),
     "(party id, IP, port), e.g., --party 1,127.0.0.1,7777")
    ("threads", po::value<std::size_t>()->default_value(0), "number of threads to use for gate evaluation")
    ("json", po::bool_switch()->default_value(false), "output data in JSON format")
    ("arithmetic-protocol", po::value<std::string>()->required(), "2PC protocol (GMW or BEAVY)")
    ("boolean-protocol", po::value<std::string>()->required(), "2PC protocol (Yao, GMW or BEAVY)")
    ("repetitions", po::value<std::size_t>()->default_value(1), "number of repetitions")
    ("num-simd", po::value<std::size_t>()->default_value(1), "number of SIMD values")
    ("sync-between-setup-and-online", po::bool_switch()->default_value(false),
     "run a synchronization protocol before the online phase starts")
    ("no-run", po::bool_switch()->default_value(false), "just build the circuit, but not execute it")
    ;
  // clang-format on

  po::variables_map vm;
  po::store(po::parse_command_line(argc, argv, desc), vm);
  bool help = vm["help"].as<bool>();
  if (help) {
    std::cerr << desc << "\n";
    return std::nullopt;
  }
  if (vm.count("config-file")) {
    std::ifstream ifs(vm["config-file"].as<std::string>().c_str());
    po::store(po::parse_config_file(ifs, desc), vm);
  }
  try {
    po::notify(vm);
  } catch (std::exception& e) {
    std::cerr << "error:" << e.what() << "\n\n";
    std::cerr << desc << "\n";
    return std::nullopt;
  }

  options.num_parties = vm["num_parties"].as<std::size_t>();
  options.my_id = vm["my-id"].as<std::size_t>();
  options.threads = vm["threads"].as<std::size_t>();
  options.json = vm["json"].as<bool>();
  options.num_repetitions = vm["repetitions"].as<std::size_t>();
  options.num_simd = vm["num-simd"].as<std::size_t>();
  options.sync_between_setup_and_online = vm["sync-between-setup-and-online"].as<bool>();
  options.no_run = vm["no-run"].as<bool>();

  auto arithmetic_protocol = vm["arithmetic-protocol"].as<std::string>();
  boost::algorithm::to_lower(arithmetic_protocol);
  if (arithmetic_protocol == "gmw") {
    options.arithmetic_protocol = MOTION::MPCProtocol::ArithmeticGMW;
  } else if (arithmetic_protocol == "beavy") {
    options.arithmetic_protocol = MOTION::MPCProtocol::ArithmeticBEAVY;
  } else {
    std::cerr << "invalid protocol: " << arithmetic_protocol << "\n";
    return std::nullopt;
  }
  auto boolean_protocol = vm["boolean-protocol"].as<std::string>();
  boost::algorithm::to_lower(boolean_protocol);
  if (boolean_protocol == "yao") {
    options.boolean_protocol = MOTION::MPCProtocol::Yao;
  } else if (boolean_protocol == "gmw") {
    options.boolean_protocol = MOTION::MPCProtocol::BooleanGMW;
  } else if (boolean_protocol == "beavy") {
    options.boolean_protocol = MOTION::MPCProtocol::BooleanBEAVY;
  } else {
    std::cerr << "invalid protocol: " << boolean_protocol << "\n";
    return std::nullopt;
  }

  const auto parse_party_argument =
      [](const std::string& s) -> std::pair<std::size_t, MOTION::Communication::tcp_connection_config> {
    const static std::regex party_argument_re("([0-9]),([^,]+),(\\d{1,5})");
    std::smatch match;
    if (!std::regex_match(s, match, party_argument_re)) {
      throw std::invalid_argument("invalid party argument");
    }
    auto id = boost::lexical_cast<std::size_t>(match[1]);
    auto host = match[2];
    auto port = boost::lexical_cast<std::uint16_t>(match[3]);
    return {id, {host, port}};
  };

  const std::vector<std::string> party_infos = vm["party"].as<std::vector<std::string>>();
  if (party_infos.size() != options.num_parties) {
    std::cerr << "There must be `num_parties` party infos.\n";
    return std::nullopt;
  }

  options.tcp_config.resize(options.num_parties);

  for (const auto& party_info : party_infos) {
    const auto [id, conn_info] = parse_party_argument(party_info);
    options.tcp_config[id] = conn_info;
  }

  return options;
}

std::unique_ptr<MOTION::Communication::CommunicationLayer> setup_communication(
    const Options& options) {
  MOTION::Communication::TCPSetupHelper helper(options.my_id, options.tcp_config);
  return std::make_unique<MOTION::Communication::CommunicationLayer>(options.my_id,
                                                                     helper.setup_connections());
}

std::size_t choose(std::size_t n, std::size_t t) {
    std::vector<std::size_t> fac(n + 1, 1);
    for (std::size_t i = 2 ; i <= n; ++i) {
        fac[i] = fac[i-1] * i;
    }
    return (fac[n] / (fac[t] * fac[n-t]));
}

auto make_input_share(MOTION::tensor::TensorDimensions dims, std::size_t num_parties, bool random) {

    auto t = std::make_shared<MOTION::proto::beavy::ArithmeticBEAVYTensor<std::uint64_t>>(dims, num_parties);
    auto& tensor_secret_share = t->get_common_secret_share();
    auto total_shares = choose(num_parties, num_parties/2);
    tensor_secret_share.resize((1LL << num_parties), 0);
    std::size_t sum = 0;
    for (std::size_t i = 0; i < total_shares; ++i) {
        tensor_secret_share[i] = i + 10;
    }
    auto& pub_share = t->get_public_share();
    if (random) {
        pub_share = MOTION::Helpers::RandomVector<std::uint64_t>(dims.get_data_size());
    } else {
#pragma omp parallel for
        for (std::size_t i = 0; i < dims.get_data_size(); ++i) {
            pub_share[i] = i + 65;
        }
   }
    t->set_setup_ready();
    t->set_online_ready();
    return std::dynamic_pointer_cast<const MOTION::tensor::Tensor>(t);
}

void run_circuit(const Options& options, MOTION::MPCLanTensorBackend& backend) {

  if (options.no_run) {
    return;
  }

  MOTION::MPCProtocol arithmetic_protocol = options.arithmetic_protocol;
  MOTION::MPCProtocol boolean_protocol = options.boolean_protocol;

  auto& arithmetic_tof = backend.get_tensor_op_factory(arithmetic_protocol);
  auto& boolean_tof = backend.get_tensor_op_factory(boolean_protocol);

  MOTION::tensor::TensorDimensions dims{
      .batch_size_ = 1, .num_channels_ = 1, .height_ = 28, .width_ = 28};
  MOTION::tensor::TensorDimensions conv1_dims{
    .batch_size_ = 6, .num_channels_ = 1, .height_ = 5, .width_ = 5};
  MOTION::tensor::TensorDimensions conv2_dims{
  .batch_size_ = 6, .num_channels_ = 1, .height_ = 5, .width_ = 5};
  MOTION::tensor::TensorDimensions gemm_dims1{
      .batch_size_ = 1, .num_channels_ = 1, .height_ = 1200, .width_ = 120};
  MOTION::tensor::TensorDimensions gemm_dims2{
  .batch_size_ = 1, .num_channels_ = 1, .height_ = 120, .width_ = 84};
  MOTION::tensor::TensorDimensions gemm_dims3{
  .batch_size_ = 1, .num_channels_ = 1, .height_ = 84, .width_ = 10};
  const MOTION::tensor::Conv2DOp conv_op1 = {.kernel_shape_ = {6, 1, 5, 5},
                                            .input_shape_ = {1, 28, 28},
                                            .output_shape_ = {6, 28, 28},
                                            .dilations_ = {1, 1},
                                            .pads_ = {4, 4, 0, 0},
                                            .strides_ = {1, 1}};
  const MOTION::tensor::Conv2DOp conv_op2 = {.kernel_shape_ = {6, 1, 5, 5},
                                            .input_shape_ = {1, 6*14, 14},
                                            .output_shape_ = {6, 6*14 - 4, 10},
                                            .dilations_ = {1, 1},
                                            .pads_ = {0, 0, 0, 0},
                                            .strides_ = {1, 1}};
  const MOTION::tensor::MaxPoolOp maxpool_op1 = {
                                            .input_shape_ = {6, 28, 28},
                                            .output_shape_ = {6, 14, 14},
                                            .kernel_shape_ = {2, 2},
                                            .strides_ = {2, 2}};
  const MOTION::tensor::MaxPoolOp maxpool_op2 = {
                                            .input_shape_ = {6, 6*14 - 4, 10},
                                            .output_shape_ = {6, 3*14 - 2, 5},
                                            .kernel_shape_ = {2, 2},
                                            .strides_ = {2, 2}};
  
  const MOTION::tensor::GemmOp gemm_op_1 = {
      .input_A_shape_ = {1, 1200}, .input_B_shape_ = {1200, 120}, .output_shape_ = {1, 120}};
  const MOTION::tensor::GemmOp gemm_op_2 = {
      .input_A_shape_ = {1, 120}, .input_B_shape_ = {120, 84}, .output_shape_ = {1, 84}};
  const MOTION::tensor::GemmOp gemm_op_3 = {
      .input_A_shape_ = {1, 84}, .input_B_shape_ = {84, 10}, .output_shape_ = {1, 10}};
  auto input_tensor = make_input_share(dims, options.num_parties, /*random=*/false);

  std::function<MOTION::tensor::TensorCP(const MOTION::tensor::TensorCP&)> make_activation = 
  [&](const auto& input) {
    const auto boolean_tensor = boolean_tof.make_tensor_conversion(boolean_protocol, input);
    const auto relu_tensor = boolean_tof.make_tensor_relu_op(boolean_tensor);
    return boolean_tof.make_tensor_conversion(arithmetic_protocol, relu_tensor);
  };

  std::function<MOTION::tensor::TensorCP(const MOTION::tensor::TensorCP&, const MOTION::tensor::MaxPoolOp&)> make_maxpool_layer = 
  [&](const auto& input, const MOTION::tensor::MaxPoolOp& maxpool_op) {
    const auto boolean_tensor = boolean_tof.make_tensor_conversion(boolean_protocol, input);
    const auto relu_tensor = boolean_tof.make_tensor_maxpool_op(maxpool_op, boolean_tensor);
    return boolean_tof.make_tensor_conversion(arithmetic_protocol, relu_tensor);
  };

  // First convolution layer + activation :
  auto conv1_kernel = make_input_share(conv1_dims, options.num_parties, /*random=*/true);
  auto conv1 = arithmetic_tof.make_tensor_conv2d_op(conv_op1, input_tensor,
   conv1_kernel, /*fractional_bits=*/0);
  auto activated = make_activation(conv1);
  auto max1 = make_maxpool_layer(activated, maxpool_op1);
  // 6 x 14 x 14
  auto flatten1 = arithmetic_tof.make_tensor_flatten_op(max1, /*axis=*/3);

  auto conv2_kernel = make_input_share(conv2_dims, options.num_parties, /*random=*/true);
  auto conv2 = arithmetic_tof.make_tensor_conv2d_op(conv_op2, flatten1, conv2_kernel, /*fractional_bits=*/0);
  auto activated2 = make_activation(conv2);
  auto max2 = make_maxpool_layer(activated2, maxpool_op2);
  // 6 x 5 x 5
  // Flatten the output to 1 x 150
  auto flat_tensor = arithmetic_tof.make_tensor_flatten_op(max2, /*axis=*/0);
  auto random_weights1 = make_input_share(gemm_dims1, options.num_parties, true);
  auto gemm1 = arithmetic_tof.make_tensor_gemm_op(gemm_op_1, flat_tensor, random_weights1, /*fractional_bits=*/0);

  auto random_weights2 = make_input_share(gemm_dims2, options.num_parties, true);
  auto gemm2 = arithmetic_tof.make_tensor_gemm_op(gemm_op_2, gemm1, random_weights2, /*fractional_bits=*/0);

  auto random_weights3 = make_input_share(gemm_dims3, options.num_parties, true);
  auto gemm3 = arithmetic_tof.make_tensor_gemm_op(gemm_op_3, gemm2, random_weights3, /*fractional_bits=*/0);


  // execute the protocol
  backend.run();

  // gemm3->wait_online();
  gemm3->wait_online();

  std::cout << "LeNet-5 execution complete!\n";
}

void print_stats(const Options& options,
                 const MOTION::Statistics::AccumulatedRunTimeStats& run_time_stats,
                 const MOTION::Statistics::AccumulatedCommunicationStats& comm_stats) {
  if (options.json) {
    auto obj = MOTION::Statistics::to_json("millionaires_problem", run_time_stats, comm_stats);
    obj.emplace("party_id", options.my_id);
    obj.emplace("arithmetic_protocol", MOTION::ToString(options.arithmetic_protocol));
    obj.emplace("boolean_protocol", MOTION::ToString(options.boolean_protocol));
    obj.emplace("simd", options.num_simd);
    obj.emplace("threads", options.threads);
    obj.emplace("sync_between_setup_and_online", options.sync_between_setup_and_online);
    std::cout << obj << "\n";
  } else {
    std::cout << MOTION::Statistics::print_stats("millionaires_problem", run_time_stats,
                                                 comm_stats);
  }
}

int main(int argc, char* argv[]) {
  auto options = parse_program_options(argc, argv);
  if (!options.has_value()) {
    return EXIT_FAILURE;
  }

  try {
    auto comm_layer = setup_communication(*options);
    auto logger = std::make_shared<MOTION::Logger>(options->my_id,
                                                   boost::log::trivial::severity_level::trace);
    comm_layer->set_logger(logger);
    MOTION::Statistics::AccumulatedRunTimeStats run_time_stats;
    MOTION::Statistics::AccumulatedCommunicationStats comm_stats;
    for (std::size_t i = 0; i < options->num_repetitions; ++i) {
      MOTION::MPCLanTensorBackend backend(*comm_layer, options->threads,
                                      options->sync_between_setup_and_online, logger);
      run_circuit(*options, backend);
      comm_layer->sync();
      comm_stats.add(comm_layer->get_transport_statistics());
      comm_layer->reset_transport_statistics();
      run_time_stats.add(backend.get_run_time_stats());
    }
    comm_layer->shutdown();
    print_stats(*options, run_time_stats, comm_stats);
  } catch (std::runtime_error& e) {
    std::cerr << "ERROR OCCURRED: " << e.what() << "\n";
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
