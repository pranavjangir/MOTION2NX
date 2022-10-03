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
  std::size_t num_simd;
  bool sync_between_setup_and_online;
  MOTION::MPCProtocol arithmetic_protocol;
  MOTION::MPCProtocol boolean_protocol;
  std::uint64_t input_value;
  std::size_t my_id;
  MOTION::Communication::tcp_parties_config tcp_config;
  MOTION::Communication::tcp_parties_config tcp_config2;
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
    ("num_clients", po::value<std::uint64_t>()->required(), "number of clients to run for")
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

  const auto parse_party_argument2 =
      [](const auto& s) -> std::pair<std::size_t, MOTION::Communication::tcp_connection_config> {
    const static std::regex party_argument_re("([012]),([^,]+),(\\d{1,5})");
    std::smatch match;
    if (!std::regex_match(s, match, party_argument_re)) {
      throw std::invalid_argument("invalid party argument");
    }
    auto id = boost::lexical_cast<std::size_t>(match[1]);
    auto host = match[2];
    auto port = boost::lexical_cast<std::uint16_t>(match[3]) + 100;
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
  options.tcp_config2.resize(3);
  for (const auto& party_info : party_infos) {
    const auto [id, conn_info] = parse_party_argument2(party_info);
    options.tcp_config2[id] = conn_info;
  }

  return options;
}

static std::vector<std::shared_ptr<MOTION::NewWire>> cast_wires(BooleanSWIFTWireVector&& wires) {
  return std::vector<std::shared_ptr<MOTION::NewWire>>(std::begin(wires), std::end(wires));
}

std::unique_ptr<MOTION::Communication::CommunicationLayer> setup_communication(
    const Options& options, bool use_second_port = false) {
  MOTION::Communication::TCPSetupHelper helper(options.my_id, (use_second_port ? options.tcp_config2 : options.tcp_config));
  return std::make_unique<MOTION::Communication::CommunicationLayer>(options.my_id,
                                                                     helper.setup_connections());
}

const int BIT_SIZE = 64;

std::vector<uint64_t> convert_to_binary(uint64_t x) {
    std::vector<uint64_t> res;
    for (uint64_t i = 0; i < BIT_SIZE; ++i) {
        if (x%2 == 1) res.push_back(1);
        else res.push_back(0);
        x /= 2;
    }
    return res;
}

auto make_boolean_share(std::vector<uint64_t> inputs) {
  BooleanSWIFTWireVector wires;
  for (uint64_t j = 0; j < BIT_SIZE; ++j) {
      auto wire = std::make_shared<BooleanSWIFTWire>(inputs.size());
      wires.push_back(std::move(wire));
  }
  for (uint64_t i = 0 ; i < inputs.size(); ++i) {
      auto conv = convert_to_binary(inputs[i]);
      for (uint64_t j = 0; j < BIT_SIZE; ++j) {
          wires[j]->get_public_share().Set(conv[j], i);
      }
  }
  for (uint64_t j = 0; j < BIT_SIZE; ++j) {
      wires[j]->set_setup_ready();
      wires[j]->set_online_ready();
  }
  return wires;
}

std::vector<std::size_t> approx_power_law_sampling(int num_clients) {
  std::vector<std::size_t> output;
  std::mt19937_64 rng(/*fixed_seed = */0);
  for (int i = 1; i <= 1000; ++i) {
    std::uint64_t element = rng();
    for (int j = 1 ; j <= i; ++j) {
      output.push_back(element);
    }
  }
  std::shuffle(output.begin(), output.end(), rng);
  assert(num_clients <= output.size());
  std::vector<std::size_t> trimmed_output(output.begin(), output.begin() + num_clients);
  return trimmed_output;
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

void run_circuit(const Options& options, MOTION::SwiftBackend& backend,
 MOTION::SwiftBackend& backend_post_compaction,
  std::unique_ptr<MOTION::Communication::CommunicationLayer>& comm_layer1,
  std::unique_ptr<MOTION::Communication::CommunicationLayer>& comm_layer2,
  MOTION::Statistics::AccumulatedCommunicationStats& comm_stats1,
  MOTION::Statistics::AccumulatedCommunicationStats& comm_stats2,
  MOTION::Statistics::AccumulatedRunTimeStats& runtime_stats1,
  MOTION::Statistics::AccumulatedRunTimeStats& runtime_stats2) {

  if (options.no_run) {
    return;
  }

  const int num_clients = options.num_clients;

  MOTION::MPCProtocol arithmetic_protocol = options.arithmetic_protocol;
  MOTION::MPCProtocol boolean_protocol = options.boolean_protocol;

  auto& arithmetic_tof = backend.get_gate_factory(arithmetic_protocol);
  auto& boolean_tof = backend.get_gate_factory(boolean_protocol);


  std::vector<std::size_t> inps = approx_power_law_sampling(num_clients);
  // for (int i = 0; i < num_clients; ++i) {
  //   inps[i] = (i%4);
  // }
  for (int i = 0; i < num_clients && i < 10; ++i) std::cout << inps[i] << "\n";
  auto bshares = make_boolean_share(inps);
  auto casted_bshares = cast_wires(bshares);
  auto shuffle_op = boolean_tof.make_unary_gate(ENCRYPTO::PrimitiveOperationType::SHUFFLE, casted_bshares);
  auto sorted_op = boolean_tof.make_unary_gate(ENCRYPTO::PrimitiveOperationType::SORT, shuffle_op);
      // auto sorted_fut = boolean_tof.make_boolean_output_gate_my(MOTION::ALL_PARTIES, sorted_op);
  auto zero_one_non_compact = boolean_tof.make_unary_gate(ENCRYPTO::PrimitiveOperationType::ADJCOMP, sorted_op);
      // auto zofut = boolean_tof.make_boolean_output_gate_my(MOTION::ALL_PARTIES, zero_one_non_compact);
  assert(zero_one_non_compact.size() == 1);

  auto zero_one_arith = boolean_tof.make_unary_gate(ENCRYPTO::PrimitiveOperationType::BIT2A,
   zero_one_non_compact);

  auto tagz = boolean_tof.make_unary_gate(ENCRYPTO::PrimitiveOperationType::COMPACT, zero_one_arith);
  assert(tagz.size() == 1);
  auto tagz_arith = std::dynamic_pointer_cast<ArithmeticSWIFTWire<std::uint64_t>>(tagz[0]);
  auto tagz_boolean = make_boolean_conversion(tagz_arith, boolean_tof);

  int extra_wires = (int)(log2(num_clients)) + 1;
  // TODO(pranav): Maybe keep this less?
  extra_wires = 64;
  auto tagz_boolean_expanded = tagz_boolean;
  for (int w = 0; w < extra_wires; ++w) {
    auto wire = std::make_shared<BooleanSWIFTWire>(num_clients);
    auto &ps = wire->get_public_share();
    for (int i = 0; i < num_clients; ++i) {
      ps.Set(((i&(1LL << w)) > 0), i);
    }
    wire->set_setup_ready();
    wire->set_online_ready();
    tagz_boolean_expanded.push_back(std::move(wire));
  }

  assert(tagz_boolean_expanded.size() == BIT_SIZE + extra_wires);

  auto shuffle_after_compaction = boolean_tof.make_unary_gate(
    ENCRYPTO::PrimitiveOperationType::SHUFFLE, tagz_boolean_expanded);

  MOTION::WireVector just_tags(tagz_boolean_expanded.begin(),
   tagz_boolean_expanded.begin() + 64);

  // MOTION::WireVector just_idx(tagz_boolean_expanded.begin() + 64,
  //  tagz_boolean_expanded.end());
  
  auto tag_fut = boolean_tof.make_boolean_output_gate_my(MOTION::ALL_PARTIES, just_tags);

  // auto idx_fut = boolean_tof.make_boolean_output_gate_my(MOTION::ALL_PARTIES, just_idx);

  backend.run();

  assert(shuffle_after_compaction.size() == BIT_SIZE + extra_wires);

  for (auto& wire : shuffle_after_compaction) wire->wait_online();

  auto ordering = tag_fut.get();

  std::vector<uint64_t> ordering_arith(num_clients, 0);
  assert(ordering[0].GetSize() == num_clients);
  for (int i = 0 ; i < num_clients; ++i) {
      ordering_arith[i] = -1; // Reduce one index beforehand to account for zero based indexing.
      for (uint64_t j = 0 ; j < ordering.size() ; ++j) {
          ordering_arith[i] += (1LL << j)*ordering[j].Get(i);
      }
      //  << "******* " << ordering_arith[i] << std::endl;
  }

  comm_layer1->sync();
  comm_stats1.add(comm_layer1->get_transport_statistics());
  comm_layer1->reset_transport_statistics();
  runtime_stats1.add(backend.get_run_time_stats());

  // auto idxxs = idx_fut.get();

  // std::vector<uint64_t> idxx(num_clients, 0);
  // assert(idxxs[0].GetSize() == num_clients);
  // assert(idxxs.size() == extra_wires);
  // for (int i = 0 ; i < num_clients; ++i) {
  //     idxx[i] = 0;
  //     for (uint64_t j = 0 ; j < idxxs.size() ; ++j) {
  //         idxx[i] += (1LL << j)*idxxs[j].Get(i);
  //     }
  //     std::cout << "bbbbbbbbbbbbb " << idxx[i] << std::endl;
  // }

  auto& bool_factory = backend_post_compaction.get_gate_factory(boolean_protocol);

  // construct new wire with online and setup ready that are reordered.
  auto reordered_zero_one = std::make_shared<BooleanSWIFTWire>(num_clients);
  BooleanSWIFTWireVector reordered_idx;

  auto zofut = bool_factory.make_boolean_output_gate_my(MOTION::ALL_PARTIES, zero_one_non_compact);
  auto swiftcasted_zo = std::dynamic_pointer_cast<BooleanSWIFTWire>(zero_one_non_compact[0]);
  for (int i = 0; i < extra_wires; ++i) {
    auto w = std::make_shared<BooleanSWIFTWire>(num_clients);
    reordered_idx.push_back(std::move(w));
  }

  MOTION::WireVector just_idx(tagz_boolean_expanded.begin() + 64,
   tagz_boolean_expanded.end());

   MOTION::WireVector just_tgz(tagz_boolean_expanded.begin(),
   tagz_boolean_expanded.begin() + 64);

  // auto idx_fut = bool_factory.make_boolean_output_gate_my(MOTION::ALL_PARTIES, just_idx);
  // auto tgz_fut2 = bool_factory.make_boolean_output_gate_my(MOTION::ALL_PARTIES, just_tgz);
  for (int i = 0; i < num_clients; ++i) {
    int new_idx = ordering_arith[i];
    reordered_zero_one->get_public_share().Set(swiftcasted_zo->get_public_share().
    Get(i), new_idx);
    for (int j = 0; j < 3; ++j) {
      reordered_zero_one->get_secret_share()[j].Set(swiftcasted_zo->get_secret_share()[j].
      Get(i), new_idx);
    }
    for (int wi = 0; wi < extra_wires; ++wi) {
      // tagz_boolean_expanded[64 + wi]->wait_online();
      auto wold = std::dynamic_pointer_cast<BooleanSWIFTWire>(tagz_boolean_expanded[64 + wi]);
      wold->wait_setup();
      wold->wait_online();
      auto& wnew = reordered_idx[wi];
      wnew->get_public_share().Set(wold->get_public_share().
      Get(i), new_idx);
      // std::cout << "wwwww " << wold->get_public_share().Get(i) << " " << new_idx << "\n";

      for (int j = 0; j < 3; ++j) {
        wnew->get_secret_share()[j].Set(wold->get_secret_share()[j].
        Get(i), new_idx);
        // std::cout << "sssss " << wold->get_secret_share()[j].Get(i) << " -- " << new_idx << "\n";
      }
    }
  }
  reordered_zero_one->set_setup_ready();
  reordered_zero_one->set_online_ready();

  for (int i = 0; i < extra_wires; ++i) {
    reordered_idx[i]->set_setup_ready();
    reordered_idx[i]->set_online_ready();
  }
      // auto futzo = bool_factory.make_boolean_output_gate_my(MOTION::ALL_PARTIES, {reordered_zero_one});
      
  MOTION::WireVector zero_one;
  for (int i = 0 ; i < BIT_SIZE; ++i) {
    zero_one.push_back(reordered_zero_one);
  }
  auto inverse_zo = bool_factory.make_unary_gate(ENCRYPTO::PrimitiveOperationType::INV,
   zero_one);
  
  std::vector<std::uint64_t> Nplus1(num_clients, num_clients);

  auto nplus1_wire = make_boolean_share(Nplus1);
  auto casted_reordered_idx = cast_wires(reordered_idx);
          // auto futidx = bool_factory.make_boolean_output_gate_my(MOTION::ALL_PARTIES, casted_reordered_idx);
  auto casted_nplus1 = cast_wires(nplus1_wire);
  auto and1 = bool_factory.make_binary_gate(ENCRYPTO::PrimitiveOperationType::AND,
   inverse_zo, casted_reordered_idx);

  auto and2 = bool_factory.make_binary_gate(ENCRYPTO::PrimitiveOperationType::AND,
   zero_one, casted_nplus1);
  
  auto final_selected_idx = bool_factory.make_binary_gate(ENCRYPTO::PrimitiveOperationType::XOR,
   and1, and2);
  assert(final_selected_idx.size() == BIT_SIZE);

  // auto idx_sel = bool_factory.make_boolean_output_gate_my(MOTION::ALL_PARTIES, final_selected_idx);

  auto subtraction_result = bool_factory.make_unary_gate(ENCRYPTO::PrimitiveOperationType::ADJSUB,
   final_selected_idx);
  
  // Find elements that occur more than 100 times ( >= 101).
  std::vector<std::uint64_t> tau(num_clients, 100-1);

  auto boolean_tau = make_boolean_share(tau);
  auto casted_tau = cast_wires(boolean_tau);

  // load a boolean circuit for to compute 'greater-than'
  MOTION::CircuitLoader circuit_loader;
  auto& gt_circuit =
      circuit_loader.load_gt_circuit(64, options.boolean_protocol != MOTION::MPCProtocol::Yao);
  // apply the circuit to the Boolean sahres
  auto output = backend_post_compaction.make_circuit(gt_circuit, subtraction_result, casted_tau);

  // create an output gates of the result
  auto output_future = bool_factory.make_boolean_output_gate_my(MOTION::ALL_PARTIES, output);
  // reveal the indexes. just the output gate!
  

  backend_post_compaction.run();

  auto xx = zofut.get();
  std::cout << "Unordered : " << xx[0].AsString() << std::endl;

  // auto zoop = futzo.get();

  // auto idxop = futidx.get();

  // std::cout <<"ZERO ONE REDORDERED : "<< zoop[0].AsString() << std::endl;

  // auto idxxs = idx_fut.get();

  // auto tt = tgz_fut2.get();

  // std::vector<uint64_t> ttt(num_clients, 0);
  // assert(tt[0].GetSize() == num_clients);
  // assert(tt.size() == BIT_SIZE);
  // for (int i = 0 ; i < num_clients; ++i) {
  //     ttt[i] = 0;
  //     for (uint64_t j = 0 ; j < tt.size() ; ++j) {
  //         ttt[i] += (1LL << j)*tt[j].Get(i);
  //     }
  //     std::cout << "ttttttttttttt " << ttt[i] << std::endl;
  // }

  // std::vector<uint64_t> idxx(num_clients, 0);
  // assert(idxxs[0].GetSize() == num_clients);
  // assert(idxxs.size() == extra_wires);
  // for (int i = 0 ; i < num_clients; ++i) {
  //     idxx[i] = 0;
  //     for (uint64_t j = 0 ; j < idxxs.size() ; ++j) {
  //         idxx[i] += (1LL << j)*idxxs[j].Get(i);
  //     }
  //     std::cout << "bbbbbbbbbbbbb " << idxx[i] << std::endl;
  // }
  
  // std::vector<uint64_t> ans(inps.size(), 0);
  // for (int i = 0 ; i < num_clients; ++i) {
  //     ans[i] = 0;
  //     for (uint64_t j = 0 ; j < idxop.size() ; ++j) {
  //         ans[i] += (1LL << j)*idxop[j].Get(i);
  //     }
  // }
  // for (auto i : ans) {
  //     std::cout << i << " ---- ";
  // }

  // auto aaa = idx_sel.get();

  // std::vector<uint64_t> yo(num_clients, 0);
  // assert(aaa[0].GetSize() == num_clients);
  // assert(aaa.size() == extra_wires);
  // for (int i = 0 ; i < num_clients; ++i) {
  //     yo[i] = 0;
  //     for (uint64_t j = 0 ; j < aaa.size() ; ++j) {
  //         yo[i] += (1LL << j)*aaa[j].Get(i);
  //     }
  //     std::cout << "iiiiiiiiiiiiiiiii " << yo[i] << std::endl;
  // }


  auto phh_index = output_future.get();
  assert(phh_index.size() == 1);

  std::cout << phh_index[0].AsString() << std::endl;

  comm_layer2->sync();
  comm_stats2.add(comm_layer2->get_transport_statistics());
  comm_layer2->reset_transport_statistics();
  runtime_stats2.add(backend_post_compaction.get_run_time_stats());
  ////////////////////////////////////////// set the and etc gates here only!!

  // then go thru a subtraction adjacent gate!

  // A simple GT gate

  // Reveal the ones with gt  == 1.

  // Done for now!

  // auto sorted_boys = sorted_fut.get();

  // auto zo = zofut.get();

  // zero_one_arith[0]->wait_online();

  // for (auto x : zo) std::cout << " ZO : " << x << std::endl;



  // need to get the indexes now, and use a new backend!


  
  // assert(sort_op.size() == 256);

  // auto fut = boolean_tof.make_boolean_output_gate_my(MOTION::ALL_PARTIES, sort_op);
  
  // backend.run();
  // auto sorted_output = fut.get();
  // assert(sorted_output.size() == 256);
  // std::vector<uint64_t> ans(inps.size(), 0);
  // assert(ordering[0].GetSize() == inps.size());
  // for (int i = 0 ; i < inps.size(); ++i) {
  //     ans[i] = 0;
  //     for (uint64_t j = 0 ; j < ordering.size() ; ++j) {
  //         ans[i] += (1LL << j)*ordering[j].Get(i);
  //     }
  // }
  // for (auto i : ans) {
  //     std::cout << i << " ---- ";
  // }
  // assert(zero_one_arith.size() == 1);
  // auto cs = std::dynamic_pointer_cast<ArithmeticSWIFTWire<std::uint64_t>>(zero_one_arith[0]);
  // for (auto i : cs->get_public_share()) {
  //   std::cout << i << std::endl;
  // }
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
    auto comm_layer2 = setup_communication(*options, true);
    auto logger = std::make_shared<MOTION::Logger>(options->my_id,
                                                   boost::log::trivial::severity_level::trace);
    comm_layer->set_logger(logger);
    MOTION::Statistics::AccumulatedRunTimeStats run_time_stats;
    MOTION::Statistics::AccumulatedRunTimeStats run_time_stats2;
    MOTION::Statistics::AccumulatedCommunicationStats comm_stats;
    MOTION::Statistics::AccumulatedCommunicationStats comm_stats2;
    for (std::size_t i = 0; i < options->num_repetitions; ++i) {
      MOTION::SwiftBackend backend(*comm_layer, options->threads,
                                      options->sync_between_setup_and_online, logger);

      MOTION::SwiftBackend backend_post_compaction(*comm_layer2, options->threads,
      options->sync_between_setup_and_online, logger);
      run_circuit(*options, backend, backend_post_compaction, comm_layer, comm_layer2,
       comm_stats, comm_stats2, run_time_stats, run_time_stats2);
      // comm_layer->sync();
      // comm_layer2->sync();
      // comm_stats.add(comm_layer->get_transport_statistics());
      // comm_stats2.add(comm_layer2->get_transport_statistics());
      // comm_layer->reset_transport_statistics();
      // comm_layer2->reset_transport_statistics();
      // run_time_stats.add(backend.get_run_time_stats());
      // run_time_stats2.add(backend_post_compaction.get_run_time_stats());
    }
    comm_layer->shutdown();
    comm_layer2->shutdown();
    print_stats(*options, run_time_stats, comm_stats);
    std::cout << "\n\n\n\n-------------------------------------------------------------\n\n\n\n";
    print_stats(*options, run_time_stats2, comm_stats2);
  } catch (std::runtime_error& e) {
    std::cerr << "ERROR OCCURRED: " << e.what() << "\n";
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
