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
  std::size_t num_clients;
  std::size_t topk;
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
    ("num_clients", po::value<std::uint64_t>()->required(), "number of clients to run for")
    ("topk", po::value<std::uint64_t>()->required(), "the top k elements to return")
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
  options.num_clients = vm["num_clients"].as<std::size_t>();
  options.topk = vm["topk"].as<std::size_t>();
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

static std::vector<std::shared_ptr<MOTION::NewWire>> cast_wires(BooleanSWIFTWireVector&& wires) {
  return std::vector<std::shared_ptr<MOTION::NewWire>>(std::begin(wires), std::end(wires));
}

int BIT_SIZE = 0;

std::vector<uint64_t> convert_to_binary(uint64_t x) {
    std::vector<uint64_t> res;
    for (uint64_t i = 0; i < BIT_SIZE; ++i) {
        if (x%2 == 1) res.push_back(1);
        else res.push_back(0);
        x /= 2;
    }
    return res;
}

auto make_boolean_share(std::vector<uint64_t> inputs, const int bit_size) {
  BooleanSWIFTWireVector wires;
  for (uint64_t j = 0; j < bit_size; ++j) {
      auto wire = std::make_shared<BooleanSWIFTWire>(inputs.size());
      wires.push_back(std::move(wire));
  }
  for (uint64_t i = 0 ; i < inputs.size(); ++i) {
      auto conv = convert_to_binary(inputs[i]);
      for (uint64_t j = 0; j < bit_size; ++j) {
          wires[j]->get_public_share().Set(conv[j], i);
      }
  }
  for (uint64_t j = 0; j < bit_size; ++j) {
      wires[j]->set_setup_ready();
      wires[j]->set_online_ready();
  }
  return wires;
}

auto make_arithmetic_share(std::size_t num_clients) {
    ArithmeticSWIFTWireP<uint64_t> wire = 
    std::make_shared<ArithmeticSWIFTWire<uint64_t>>(num_clients);
    return wire;
}

auto make_boolean_conversion(MOTION::proto::swift::ArithmeticSWIFTWireP<std::uint64_t> wire, 
MOTION::GateFactory& bool_factory) {
    auto& swift_bool_factory = dynamic_cast<SWIFTProvider&>(bool_factory);
    MOTION::WireVector wv;
    auto casted_wire = std::dynamic_pointer_cast<MOTION::NewWire>(wire);
    wv.push_back(std::move(casted_wire));
    auto boolean_wires = swift_bool_factory.convert(MOTION::MPCProtocol::BooleanSWIFT, wv);
    return boolean_wires;
}

auto expands(MOTION::WireVector& inp, const int final_size) {
  MOTION::WireVector op;
  assert(inp.size() == 1);
  for (int i = 0; i < final_size; ++i) {
    op.push_back(inp[0]);
  }
  return std::move(op);
}

auto condswap(MOTION::WireVector& A, MOTION::WireVector& B, MOTION::WireVector& cond,
MOTION::GateFactory& bool_factory) {
  // if cond is true, chose A, otherwise chose B.
  
  // cond AND with A.
  auto condA = bool_factory.make_binary_gate(
      ENCRYPTO::PrimitiveOperationType::AND, A, cond);
  
  // cond negation AND with B.
  auto cond_neg = bool_factory.make_unary_gate(ENCRYPTO::PrimitiveOperationType::INV, cond);
  auto condNegB = bool_factory.make_binary_gate(
      ENCRYPTO::PrimitiveOperationType::AND, B, cond_neg);
  auto selection = bool_factory.make_binary_gate(
      ENCRYPTO::PrimitiveOperationType::XOR, condA, condNegB);
  return std::move(selection);
}

void run_circuit(const Options& options, MOTION::SwiftBackend& backend) {

  if (options.no_run) {
    return;
  }

  const int num_clients = options.num_clients;
  const int K = options.topk;

  MOTION::MPCProtocol arithmetic_protocol = options.arithmetic_protocol;
  MOTION::MPCProtocol boolean_protocol = options.boolean_protocol;

  auto& arithmetic_tof = backend.get_gate_factory(arithmetic_protocol);
  auto& boolean_tof = backend.get_gate_factory(boolean_protocol);

  std::vector<std::size_t> hh(K, 0);
  std::mt19937_64 rng(/*fixed_seed = */2);

  auto C = make_boolean_share(hh, 64);
  auto V = make_boolean_share(hh, BIT_SIZE);
  auto V_casted = cast_wires(V);
  auto C_casted = cast_wires(C);

  std::vector<std::size_t> allones(K, 1);
  std::vector<std::size_t> allK(K, K);
  std::vector<std::size_t> idx(K, 0);
  for (int i = 0; i < K; ++i) {
    idx[i] = i;
  }
  auto allones_wire = make_boolean_share(allones, BIT_SIZE); // Used for eq check.
  auto allzeroes_wire = make_boolean_share(hh, 64); // Used for addition / multiplication.
  auto allk_wire = make_boolean_share(allK, 64);
  auto index_wire = make_boolean_share(idx, 64);
  auto allones_casted = cast_wires(allones_wire);
  auto allzeroes_casted = cast_wires(allzeroes_wire);
  auto allk_casted = cast_wires(allk_wire);
  auto index_casted = cast_wires(index_wire);
  std::vector<std::size_t> vv = {3, 4, 3, 3, 4};
  for (int iter = 0; iter < 5; ++iter) {
    auto randm = vv[iter];
    std::vector<std::size_t> client(K, randm);
    auto d = make_boolean_share(client, BIT_SIZE);
    auto d_casted = cast_wires(d);
    MOTION::CircuitLoader circuit_loader;
    auto& eq_circuit =
      circuit_loader.load_eq_circuit(BIT_SIZE);
    auto xorr = boolean_tof.make_binary_gate(ENCRYPTO::PrimitiveOperationType::XOR,
   V_casted, d_casted);
   auto xor_inv = boolean_tof.make_unary_gate(
    ENCRYPTO::PrimitiveOperationType::INV, xorr);
    auto boolean_match = backend.make_circuit(eq_circuit, xor_inv, allones_casted);
    assert(boolean_match.size() == 1);
    auto boolean_match_expanded = allzeroes_casted;
    // TODO(pranav): Just check the MSB and LSB correctness?
    boolean_match_expanded[0] = boolean_match[0];
    
    auto& gt_circuit = circuit_loader.load_gt_circuit(BIT_SIZE, true);
    auto& addition_circuit = circuit_loader.load_circuit(fmt::format("int_add64_depth.bristol"),
          MOTION::CircuitFormat::Bristol);
    auto gt = backend.make_circuit(gt_circuit, C_casted, allzeroes_casted);
    auto boolean_empty = boolean_tof.make_unary_gate(
        ENCRYPTO::PrimitiveOperationType::INV, gt);
  //   auto arithmetic_match = boolean_tof.make_unary_gate(ENCRYPTO::PrimitiveOperationType::BIT2A,
  //  boolean_match);
    auto updated_C = backend.make_circuit(addition_circuit, C_casted, boolean_match_expanded);
    // auto updated_C = boolean_tof.make_binary_gate(ENCRYPTO::PrimitiveOperationType::ADD,
    //  arithmetic_match, C_casted);
    assert(updated_C.size() == 64);
    // TODO(pranav): Check if this is valid or not.
   C_casted = updated_C;
   auto arithmetic_empty = boolean_tof.make_unary_gate(ENCRYPTO::PrimitiveOperationType::BIT2A,
   boolean_empty);
   auto compacted_empty = boolean_tof.make_unary_gate(ENCRYPTO::PrimitiveOperationType::COMPACT,
   arithmetic_empty);
   // Get boolean transformation.
   auto boolean_tags = make_boolean_conversion(
    std::dynamic_pointer_cast<ArithmeticSWIFTWire<std::uint64_t>>(compacted_empty[0]), boolean_tof);
    auto xorr_k_eq = boolean_tof.make_binary_gate(ENCRYPTO::PrimitiveOperationType::XOR,
    boolean_tags, allk_casted);
    auto xor_k_eq_inv = boolean_tof.make_unary_gate(
      ENCRYPTO::PrimitiveOperationType::INV, xorr_k_eq);
    auto boolean_k_eq = backend.make_circuit(eq_circuit, xor_k_eq_inv, allones_casted);
    auto last_index_one_hot = boolean_tof.make_binary_gate(
      ENCRYPTO::PrimitiveOperationType::AND, boolean_k_eq, boolean_empty);
    // Take cascade of last_index_one_hot to get the b_not_empty single bit.
    assert(last_index_one_hot.size() == 1);
    // Duplicate wires.
    MOTION::WireVector one_hot_expanded;
    for (int bit_pos = 0; bit_pos < 64; ++bit_pos) {
      one_hot_expanded.push_back(last_index_one_hot[0]);
    }
    // Gives you boolean integer wires of size 64.. all but one of which are 0.
    // The non zero one contains the index of the last index.
    auto last_index = boolean_tof.make_binary_gate(
      ENCRYPTO::PrimitiveOperationType::AND, one_hot_expanded, index_casted);
    

    // Second part of the computation : Actual updation of C and V.
    auto b_not_empty = boolean_tof.make_unary_gate(ENCRYPTO::PrimitiveOperationType::COMPRESS,
    last_index_one_hot);
    auto b_found = boolean_tof.make_unary_gate(ENCRYPTO::PrimitiveOperationType::COMPRESS,
    boolean_match);
    auto b_not_found = boolean_tof.make_unary_gate(ENCRYPTO::PrimitiveOperationType::INV,
    b_found);
    auto b_decrement = boolean_tof.make_binary_gate(
      ENCRYPTO::PrimitiveOperationType::AND, b_not_empty, b_not_found);
    assert(b_decrement.size() == 1);
    assert(b_decrement[0]->get_num_simd() == K);
    auto boolean_no_match = boolean_tof.make_unary_gate(ENCRYPTO::PrimitiveOperationType::INV,
    boolean_match);

    auto b_to_fill = boolean_tof.make_binary_gate(
      ENCRYPTO::PrimitiveOperationType::AND, boolean_no_match, last_index_one_hot);

    auto b_to_fill64 = expands(b_to_fill, 64);
    auto b_to_fillBITS = expands(b_to_fill, BIT_SIZE);

    auto b_decrement_expanded = allzeroes_casted;
    b_decrement_expanded[0] = b_decrement[0];

    auto negative_b_dec = boolean_tof.make_unary_gate(ENCRYPTO::PrimitiveOperationType::BNEG,
    b_decrement_expanded);

    assert(negative_b_dec.size() == 64);

    auto new_C = backend.make_circuit(addition_circuit, C_casted, negative_b_dec);
    auto binary_one = allzeroes_casted;
    binary_one[0] = allones_casted[0];
    C_casted = condswap(binary_one, new_C, b_to_fill64, boolean_tof);
    V_casted = condswap(d_casted, V_casted, b_to_fillBITS, boolean_tof);
  }

  // Next we want to check the list of heavy hitters.
  std::vector<std::uint64_t> all_tau(K, 2);
  auto tau_wire = make_boolean_share(all_tau, 64);
  auto casted_tau = cast_wires(tau_wire);
  MOTION::CircuitLoader circuit_loader;
  auto& gt_circuit = circuit_loader.load_gt_circuit(64, true);
  auto comp_op = backend.make_circuit(gt_circuit, C_casted, casted_tau);
  assert(comp_op.size() == 1);
  auto comp_op_expanded = expands(comp_op, BIT_SIZE);
  auto final_hh_list = boolean_tof.make_binary_gate(ENCRYPTO::PrimitiveOperationType::AND, comp_op_expanded,
  V_casted);
  auto heavy_hitters_fut = boolean_tof.make_boolean_output_gate_my(MOTION::ALL_PARTIES, final_hh_list);
     //auto heavy_hitters_fut = boolean_tof.make_boolean_output_gate_my(MOTION::ALL_PARTIES, C_casted);
  
  // execute the protocol
  backend.run();

  auto hhlist = heavy_hitters_fut.get();

  for (auto& hh : hhlist) {
    std::cout << hh.AsString() << std::endl;
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
  // TODO(pranav): Make this changeable from the command line.
  BIT_SIZE = 64;
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
