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

auto make_input_share(const std::size_t num_clients) {
    ArithmeticSWIFTWireVector<std::uint64_t> wires;
    for (std::size_t i = 0; i < num_clients; ++i) {
        auto wire_i = std::make_shared<ArithmeticSWIFTWire<std::uint64_t>>(/*num_simd = */1);
        wire_i->get_public_share() = MOTION::Helpers::RandomVector<std::uint64_t>(1);
        wire_i->get_secret_share() = {MOTION::Helpers::RandomVector<std::uint64_t>(1),
        MOTION::Helpers::RandomVector<std::uint64_t>(1),
        MOTION::Helpers::RandomVector<std::uint64_t>(1)};
        wires.push_back(std::move(wire_i));
    }
    return wires;
}

MOTION::WireVector make_dummy_round(ArithmeticSWIFTWireVector<std::uint64_t>& wires,
 MOTION::GateFactory& arith_factory) {
    // Return these wires as the output.
    // This is just dummy output though and will not be used.
    MOTION::WireVector output_wires;
    auto& swift_arith_factory = dynamic_cast<SWIFTProvider&>(arith_factory);
    for (auto& wire : wires) {
      MOTION::WireVector wv;
      auto casted_wire = std::dynamic_pointer_cast<MOTION::NewWire>(wire);
      wv.push_back(std::move(casted_wire));
      auto output = swift_arith_factory.make_dummy_gate<ArithmeticSWIFTDummyGate, std::uint64_t>(wv);
      output_wires.push_back(std::move(output[0]));
    }
    return output_wires;
}

std::vector<MOTION::WireVector> make_boolean_conversion(ArithmeticSWIFTWireVector<std::uint64_t>& wires, 
MOTION::GateFactory& bool_factory, const int num_clients) {
    std::vector<MOTION::WireVector> boolean_wires(num_clients);
    auto& swift_bool_factory = dynamic_cast<SWIFTProvider&>(bool_factory);
    for (int i = 0 ; i < num_clients; ++i) {
        MOTION::WireVector wv;
        auto casted_wire = std::dynamic_pointer_cast<MOTION::NewWire>(wires[i]);
        wv.push_back(std::move(casted_wire));
        boolean_wires[i] = swift_bool_factory.convert(MOTION::MPCProtocol::BooleanSWIFT, wv);
    }
    return boolean_wires;
}

std::vector<MOTION::WireVector> N_comparisions(MOTION::SwiftBackend& backend,
 std::vector<MOTION::WireVector>& boolean_shares) {
      // load a boolean circuit for to compute 'greater-than'
    std::vector<MOTION::WireVector> dummy_output;
    MOTION::CircuitLoader circuit_loader;
    auto& gt_circuit =
        circuit_loader.load_gt_circuit(64, /*depth_optimized=*/true);
    // apply the circuit to adjacent boolean shares beacause why not.
    for (int i = 1; i < boolean_shares.size(); ++i) {
        auto output = backend.make_circuit(gt_circuit, boolean_shares[i-1], boolean_shares[i]);
        dummy_output.push_back(output);
    }
    return dummy_output;
}

void run_circuit(const Options& options, MOTION::SwiftBackend& backend) {

  if (options.no_run) {
    return;
  }

  const int num_clients = 400000;

  MOTION::MPCProtocol arithmetic_protocol = options.arithmetic_protocol;
  MOTION::MPCProtocol boolean_protocol = options.boolean_protocol;

  auto& arithmetic_tof = backend.get_gate_factory(arithmetic_protocol);
  auto& boolean_tof = backend.get_gate_factory(boolean_protocol);

  auto arith_shares = make_input_share(num_clients);
  auto dummy_output = make_dummy_round(arith_shares, arithmetic_tof);
  
  // auto boolean_shares = make_boolean_conversion(arith_shares, boolean_tof, num_clients);
  // int comparision_rounds = (int)(log2(num_clients)) + 2;
  
  // for (std::size_t reps = 0; reps < comparision_rounds; ++reps) {
  //     auto X = N_comparisions(backend, boolean_shares);
  // }

  // auto dummy_output2 = make_dummy_round(arith_shares, arithmetic_tof);

  // // Should there be a conversion gate here?
  // auto Y = N_comparisions(backend, boolean_shares);


  // execute the protocol
  backend.run();
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
