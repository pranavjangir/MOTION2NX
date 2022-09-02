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
#include "base/swift_backend.h"
#include "communication/communication_layer.h"
#include "communication/tcp_transport.h"
#include "statistics/analysis.h"
#include "utility/logger.h"
#include "protocols/swift/wire.h"
#include "protocols/swift/gate.h"
#include "protocols/swift/swift_provider.h"
#include "utility/bit_vector.h"
#include "protocols/swift/swift_provider.cpp"

namespace po = boost::program_options;
using namespace MOTION::proto::swift;

struct Options {
  std::size_t threads;
  bool json;
  std::size_t num_repetitions;
  std::size_t num_simd;
  bool sync_between_setup_and_online;
  MOTION::MPCProtocol arithmetic_protocol;
  MOTION::MPCProtocol boolean_protocol;
  std::uint64_t input_value;
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
    ("party", po::value<std::vector<std::string>>()->multitoken(),
     "(party id, IP, port), e.g., --party 1,127.0.0.1,7777")
    ("threads", po::value<std::size_t>()->default_value(0), "number of threads to use for gate evaluation")
    ("json", po::bool_switch()->default_value(false), "output data in JSON format")
    ("arithmetic-protocol", po::value<std::string>()->required(), "2PC protocol (GMW or BEAVY)")
    ("boolean-protocol", po::value<std::string>()->required(), "2PC protocol (Yao, GMW or BEAVY)")
    ("input-value", po::value<std::uint64_t>()->required(), "input value for Yao's Millionaires' Problem")
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

  options.my_id = vm["my-id"].as<std::size_t>();
  options.threads = vm["threads"].as<std::size_t>();
  options.json = vm["json"].as<bool>();
  options.num_repetitions = vm["repetitions"].as<std::size_t>();
  options.num_simd = vm["num-simd"].as<std::size_t>();
  options.sync_between_setup_and_online = vm["sync-between-setup-and-online"].as<bool>();
  options.no_run = vm["no-run"].as<bool>();

  auto arithmetic_protocol = vm["arithmetic-protocol"].as<std::string>();
  options.arithmetic_protocol = MOTION::MPCProtocol::ArithmeticSWIFT;
  auto boolean_protocol = vm["boolean-protocol"].as<std::string>();
  options.boolean_protocol = MOTION::MPCProtocol::BooleanSWIFT;

  options.input_value = vm["input-value"].as<std::uint64_t>();

  const auto parse_party_argument =
      [](const auto& s) -> std::pair<std::size_t, MOTION::Communication::tcp_connection_config> {
    const static std::regex party_argument_re("([012]),([^,]+),(\\d{1,5})");
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
  if (party_infos.size() != 3) {
    std::cerr << "expecting 3 --party options\n";
    return std::nullopt;
  }

  options.tcp_config.resize(3);
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

auto make_input_share(const std::size_t val) {
    auto wire = std::make_shared<ArithmeticSWIFTWire<std::uint64_t>>(1);
    wire->get_public_share() = {val + 380};
    wire->get_secret_share()[0] = {3};
    wire->get_secret_share()[1] = {0};
    wire->get_secret_share()[2] = {377};
    wire->set_setup_ready();
    wire->set_online_ready();

    return wire;
}

auto make_boolean_share(bool value) {
  auto wire = std::make_shared<BooleanSWIFTWire>(1);
  wire->get_public_share().Set((value ^ 1), 0);
  wire->get_secret_share()[0].Set(1, 0);
  wire->get_secret_share()[1].Set(1, 0);
  wire->get_secret_share()[2].Set(1, 0);
  wire->set_setup_ready();
  wire->set_online_ready();
  return wire;
}

void run_circuit(const Options& options, MOTION::SwiftBackend& backend) {

  if (options.no_run) {
    return;
  }
  // MULT and AND verification.

  MOTION::MPCProtocol arithmetic_protocol = options.arithmetic_protocol;
  MOTION::MPCProtocol boolean_protocol = options.boolean_protocol;

  auto& arithmetic_tof = backend.get_gate_factory(arithmetic_protocol);
  auto& boolean_tof = backend.get_gate_factory(boolean_protocol);

  auto arith_shares1 = make_input_share(3);
  auto arith_shares2 = make_input_share(7);

  auto arith_output = arithmetic_tof.make_binary_gate(ENCRYPTO::PrimitiveOperationType::MUL, {arith_shares1}, {arith_shares2});
  assert(arith_output.size() == 1);
  std::vector<MOTION::WireVector> bo;
  std::vector<ENCRYPTO::ReusableFiberFuture<MOTION::BitValues>> futures;
  for (int i = 0 ; i < 2; ++i) {
    for (int j = 0; j < 2; ++j) {
      auto bool_share1 = make_boolean_share(i);
      auto bool_share2 = make_boolean_share(j);
      auto op = boolean_tof.make_binary_gate(ENCRYPTO::PrimitiveOperationType::AND, {bool_share1}, {bool_share2});
      auto fut = boolean_tof.make_boolean_output_gate_my(MOTION::ALL_PARTIES, op);
      bo.push_back(std::move(op));
      futures.push_back(std::move(fut));
    }
  }
  
  backend.run();

  arith_output[0]->wait_online();

  auto swift_wire = std::dynamic_pointer_cast<ArithmeticSWIFTWire<std::uint64_t>>(arith_output[0]);

  std::cout << swift_wire->get_public_share()[0] << std::endl;
  std::cout << swift_wire->get_secret_share()[0][0] << std::endl;
  std::cout << swift_wire->get_secret_share()[1][0] << std::endl;
  std::cout << swift_wire->get_secret_share()[2][0] << std::endl;

  // Check for the output correct.
  std::cout << " -------------------------------------------- " << std::endl;
  for (std::size_t i = 0 ; i < bo.size(); ++i) {
    bo[i][0]->wait_online();
    auto wiree = std::dynamic_pointer_cast<BooleanSWIFTWire>(bo[i][0]);
    std::cout << wiree->get_public_share().Get(0) << std::endl;
    std::cout << wiree->get_secret_share()[0].Get(0) << std::endl;
    std::cout << wiree->get_secret_share()[1].Get(0) << std::endl;
    std::cout << wiree->get_secret_share()[2].Get(0) << std::endl;
    std::cout << " -------------------------------------------- " << std::endl;
  }

  for (auto &ff : futures) {
    auto ans = ff.get()[0];
    std::cout << ans.Get(0) << std::endl;
  }
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
      MOTION::SwiftBackend backend(*comm_layer, options->threads,
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
