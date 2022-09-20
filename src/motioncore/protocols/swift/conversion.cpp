// MIT License
//
// Copyright (c) 2020 Lennart Braun
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

#include "conversion.h"

#include <cstdint>
#include <bitset>

#include <fmt/format.h>

#include "swift_provider.h"
#include "crypto/oblivious_transfer/ot_flavors.h"
#include "crypto/oblivious_transfer/ot_provider.h"
#include "protocols/gmw/wire.h"
#include "executor/execution_context.h"
#include "utility/fiber_thread_pool/fiber_thread_pool.hpp"
#include "algorithm/circuit_loader.h"
#include "algorithm/make_circuit.h"
#include "utility/constants.h"
#include "utility/logger.h"

namespace MOTION::proto::swift {

static std::shared_ptr<NewWire> cast_boolean_wire(BooleanSWIFTWireP wire) {
  return std::shared_ptr<NewWire>(wire);
}

static BooleanSWIFTWireVector cast_wires(std::vector<std::shared_ptr<NewWire>> wires) {
  BooleanSWIFTWireVector result(wires.size());
  std::transform(std::begin(wires), std::end(wires), std::begin(result),
                 [](auto& w) { return std::dynamic_pointer_cast<BooleanSWIFTWire>(w); });
  return result;
}

template <typename T>
BooleanBitToArithmeticSWIFTGate<T>::BooleanBitToArithmeticSWIFTGate(std::size_t gate_id,
                                                                    SWIFTProvider& swift_provider,
                                                                    BooleanSWIFTWireP in)
    : NewGate(gate_id), input_(std::move(in)), swift_provider_(swift_provider) {
  const auto num_simd = input_->get_num_simd();
  output_ = std::make_shared<swift::ArithmeticSWIFTWire<T>>(num_simd);
  const auto my_id = swift_provider_.get_my_id();
  // auto& ot_provider = swift_provider_.get_ot_manager().get_provider(1 - my_id);
  // if (my_id == 0) {
  //   ot_sender_ = ot_provider.RegisterSendACOT<T>(num_simd);
  // } else {
  //   assert(my_id == 1);
  //   ot_receiver_ = ot_provider.RegisterReceiveACOT<T>(num_simd);
  // }
  share_future_ = swift_provider_.register_for_ints_message<T>(1 - my_id, gate_id_, num_simd);
}

template <typename T>
BooleanBitToArithmeticSWIFTGate<T>::~BooleanBitToArithmeticSWIFTGate() = default;

template <typename T>
void BooleanBitToArithmeticSWIFTGate<T>::evaluate_setup() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: BooleanBitToArithmeticSWIFTGate<T>::evaluate_setup start", gate_id_));
    }
  }
  throw std::runtime_error("Conversion not yet implemented.");

  // const auto num_simd = input_->get_num_simd();

  // output_->get_secret_share() = Helpers::RandomVector<T>(num_simd);
  // output_->set_setup_ready();

  // input_->wait_setup();
  // const auto& secret_share = input_->get_secret_share();

  // std::vector<T> ot_output;
  // if (ot_sender_ != nullptr) {
  //   std::vector<T> correlations(num_simd);
  //   for (std::size_t simd_j = 0; simd_j < num_simd; ++simd_j) {
  //     if (secret_share.Get(simd_j)) {
  //       correlations[simd_j] = 1;
  //     }
  //   }
  //   ot_sender_->SetCorrelations(std::move(correlations));
  //   ot_sender_->SendMessages();
  //   ot_sender_->ComputeOutputs();
  //   ot_output = ot_sender_->GetOutputs();
  //   for (std::size_t simd_j = 0; simd_j < num_simd; ++simd_j) {
  //     T bit = secret_share.Get(simd_j);
  //     ot_output[simd_j] = bit + 2 * ot_output[simd_j];
  //   }
  // } else {
  //   assert(ot_receiver_ != nullptr);
  //   ot_receiver_->SetChoices(secret_share);
  //   ot_receiver_->SendCorrections();
  //   ot_receiver_->ComputeOutputs();
  //   ot_output = ot_receiver_->GetOutputs();
  //   for (std::size_t simd_j = 0; simd_j < num_simd; ++simd_j) {
  //     T bit = secret_share.Get(simd_j);
  //     ot_output[simd_j] = bit - 2 * ot_output[simd_j];
  //   }
  // }
  // arithmetized_secret_share_ = std::move(ot_output);

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanBitToArithmeticSWIFTGate<T>::evaluate_setup end", gate_id_));
    }
  }
}

template <typename T>
void BooleanBitToArithmeticSWIFTGate<T>::evaluate_online() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: BooleanBitToArithmeticSWIFTGate<T>::evaluate_online start", gate_id_));
    }
  }
  throw std::runtime_error("Conversion not yet implemented.");

  // const auto num_simd = input_->get_num_simd();
  // const auto my_id = swift_provider_.get_my_id();
  // std::vector<T> arithmetized_public_share(num_simd);
  // input_->wait_online();
  // const auto& public_share = input_->get_public_share();

  // for (std::size_t simd_j = 0; simd_j < num_simd; ++simd_j) {
  //   if (public_share.Get(simd_j)) {
  //     arithmetized_public_share[simd_j] = 1;
  //   }
  // }

  // const auto& secret_share = output_->get_secret_share();
  // std::vector<T> tmp(num_simd);
  // if (swift_provider_.is_my_job(gate_id_)) {
  //   for (std::size_t simd_j = 0; simd_j < num_simd; ++simd_j) {
  //     const auto p = arithmetized_public_share[simd_j];
  //     const auto s = arithmetized_secret_share_[simd_j];
  //     const auto delta = secret_share[simd_j];
  //     tmp[simd_j] = p + (1 - 2 * p) * s + delta;
  //   }
  // } else {
  //   for (std::size_t simd_j = 0; simd_j < num_simd; ++simd_j) {
  //     const auto p = arithmetized_public_share[simd_j];
  //     const auto s = arithmetized_secret_share_[simd_j];
  //     const auto delta = secret_share[simd_j];
  //     tmp[simd_j] = (1 - 2 * p) * s + delta;
  //   }
  // }
  // swift_provider_.send_ints_message(1 - my_id, gate_id_, tmp);
  // const auto other_share = share_future_.get();
  // std::transform(std::begin(tmp), std::end(tmp), std::begin(other_share), std::begin(tmp),
  //                std::plus{});
  // output_->get_public_share() = std::move(tmp);
  // output_->set_online_ready();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: BooleanBitToArithmeticSWIFTGate<T>::evaluate_online end", gate_id_));
    }
  }
}

template class BooleanBitToArithmeticSWIFTGate<std::uint8_t>;
template class BooleanBitToArithmeticSWIFTGate<std::uint16_t>;
template class BooleanBitToArithmeticSWIFTGate<std::uint32_t>;
template class BooleanBitToArithmeticSWIFTGate<std::uint64_t>;

template <typename T>
BooleanToArithmeticSWIFTGate<T>::BooleanToArithmeticSWIFTGate(std::size_t gate_id,
                                                              SWIFTProvider& swift_provider,
                                                              BooleanSWIFTWireVector&& in)
    : NewGate(gate_id), inputs_(std::move(in)), swift_provider_(swift_provider) {
  const auto num_wires = inputs_.size();
  if (num_wires != ENCRYPTO::bit_size_v<T>) {
    throw std::logic_error("number of wires need to be equal to bit size of T");
  }
  const auto num_simd = inputs_.at(0)->get_num_simd();
  output_ = std::make_shared<swift::ArithmeticSWIFTWire<T>>(num_simd);
  const auto my_id = swift_provider_.get_my_id();
  // auto& ot_provider = swift_provider_.get_ot_manager().get_provider(1 - my_id);
  // if (my_id == 0) {
  //   ot_sender_ = ot_provider.RegisterSendACOT<T>(num_wires * num_simd);
  // } else {
  //   assert(my_id == 1);
  //   ot_receiver_ = ot_provider.RegisterReceiveACOT<T>(num_wires * num_simd);
  // }
  share_future_ = swift_provider_.register_for_ints_message<T>(1 - my_id, gate_id_, num_simd);
}

template <typename T>
BooleanToArithmeticSWIFTGate<T>::~BooleanToArithmeticSWIFTGate() = default;

template <typename T>
void BooleanToArithmeticSWIFTGate<T>::evaluate_setup() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanToArithmeticSWIFTGate<T>::evaluate_setup start", gate_id_));
    }
  }
  throw std::runtime_error("Conversion not yet implemented.");

  // const auto num_wires = ENCRYPTO::bit_size_v<T>;
  // const auto num_simd = output_->get_num_simd();

  // output_->get_secret_share() = Helpers::RandomVector<T>(num_simd);
  // output_->set_setup_ready();

  // std::vector<T> ot_output;
  // if (ot_sender_ != nullptr) {
  //   std::vector<T> correlations(num_wires * num_simd);
  //   for (std::size_t wire_i = 0; wire_i < num_wires; ++wire_i) {
  //     const auto& wire_in = inputs_[wire_i];
  //     wire_in->wait_setup();
  //     const auto& secret_share = wire_in->get_secret_share();
  //     for (std::size_t simd_j = 0; simd_j < num_simd; ++simd_j) {
  //       if (secret_share.Get(simd_j)) {
  //         correlations[wire_i * num_simd + simd_j] = 1;
  //       }
  //     }
  //   }
  //   ot_sender_->SetCorrelations(std::move(correlations));
  //   ot_sender_->SendMessages();
  //   ot_sender_->ComputeOutputs();
  //   ot_output = ot_sender_->GetOutputs();
  //   for (std::size_t wire_i = 0; wire_i < num_wires; ++wire_i) {
  //     const auto& secret_share = inputs_[wire_i]->get_secret_share();
  //     for (std::size_t simd_j = 0; simd_j < num_simd; ++simd_j) {
  //       T bit = secret_share.Get(simd_j);
  //       ot_output[wire_i * num_simd + simd_j] = bit + 2 * ot_output[wire_i * num_simd + simd_j];
  //     }
  //   }
  // } else {
  //   assert(ot_receiver_ != nullptr);
  //   ENCRYPTO::BitVector<> choices;
  //   choices.Reserve(Helpers::Convert::BitsToBytes(num_wires * num_simd));
  //   for (std::size_t wire_i = 0; wire_i < num_wires; ++wire_i) {
  //     const auto& wire_in = inputs_[wire_i];
  //     wire_in->wait_setup();
  //     choices.Append(wire_in->get_secret_share());
  //   }
  //   ot_receiver_->SetChoices(std::move(choices));
  //   ot_receiver_->SendCorrections();
  //   ot_receiver_->ComputeOutputs();
  //   ot_output = ot_receiver_->GetOutputs();
  //   for (std::size_t wire_i = 0; wire_i < num_wires; ++wire_i) {
  //     const auto& secret_share = inputs_[wire_i]->get_secret_share();
  //     for (std::size_t simd_j = 0; simd_j < num_simd; ++simd_j) {
  //       T bit = secret_share.Get(simd_j);
  //       ot_output[wire_i * num_simd + simd_j] = bit - 2 * ot_output[wire_i * num_simd + simd_j];
  //     }
  //   }
  // }
  // arithmetized_secret_share_ = std::move(ot_output);

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanToArithmeticSWIFTGate<T>::evaluate_setup end", gate_id_));
    }
  }
}

template <typename T>
void BooleanToArithmeticSWIFTGate<T>::evaluate_online() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanToArithmeticSWIFTGate<T>::evaluate_online start", gate_id_));
    }
  }
  throw std::runtime_error("Conversion not yet implemented.");

  // const auto num_wires = ENCRYPTO::bit_size_v<T>;
  // const auto num_simd = output_->get_num_simd();
  // const auto my_id = swift_provider_.get_my_id();
  // std::vector<T> arithmetized_public_share(num_wires * num_simd);

  // for (std::size_t wire_i = 0; wire_i < num_wires; ++wire_i) {
  //   const auto& wire_in = inputs_[wire_i];
  //   wire_in->wait_online();
  //   const auto& public_share = wire_in->get_public_share();
  //   for (std::size_t simd_j = 0; simd_j < num_simd; ++simd_j) {
  //     if (public_share.Get(simd_j)) {
  //       arithmetized_public_share[wire_i * num_simd + simd_j] = 1;
  //     }
  //   }
  // }

  // auto tmp = output_->get_secret_share();
  // if (swift_provider_.is_my_job(gate_id_)) {
  //   for (std::size_t wire_i = 0; wire_i < num_wires; ++wire_i) {
  //     for (std::size_t simd_j = 0; simd_j < num_simd; ++simd_j) {
  //       const auto p = arithmetized_public_share[wire_i * num_simd + simd_j];
  //       const auto s = arithmetized_secret_share_[wire_i * num_simd + simd_j];
  //       tmp[simd_j] += (p + (1 - 2 * p) * s) << wire_i;
  //     }
  //   }
  // } else {
  //   for (std::size_t wire_i = 0; wire_i < num_wires; ++wire_i) {
  //     for (std::size_t simd_j = 0; simd_j < num_simd; ++simd_j) {
  //       const auto p = arithmetized_public_share[wire_i * num_simd + simd_j];
  //       const auto s = arithmetized_secret_share_[wire_i * num_simd + simd_j];
  //       tmp[simd_j] += ((1 - 2 * p) * s) << wire_i;
  //     }
  //   }
  // }
  // swift_provider_.send_ints_message(1 - my_id, gate_id_, tmp);
  // const auto other_share = share_future_.get();
  // std::transform(std::begin(tmp), std::end(tmp), std::begin(other_share), std::begin(tmp),
  //                std::plus{});
  // output_->get_public_share() = std::move(tmp);
  // output_->set_online_ready();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanToArithmeticSWIFTGate<T>::evaluate_online end", gate_id_));
    }
  }
}

template class BooleanToArithmeticSWIFTGate<std::uint8_t>;
template class BooleanToArithmeticSWIFTGate<std::uint16_t>;
template class BooleanToArithmeticSWIFTGate<std::uint32_t>;
template class BooleanToArithmeticSWIFTGate<std::uint64_t>;

template <typename T>
ArithmeticToBooleanSWIFTGate<T>::ArithmeticToBooleanSWIFTGate(std::size_t gate_id,
                                                              SWIFTProvider& swift_provider,
                                                              const ArithmeticSWIFTWireP<T> in)
    : NewGate(gate_id), input_(std::move(in)), swift_provider_(swift_provider) {
  const auto num_wires = ENCRYPTO::bit_size_v<T>;
  const auto num_simd = input_->get_num_simd();
  // create num_wires amount of output wires output wires!
  output_.reserve(num_wires);
  std::generate_n(std::back_inserter(output_), num_wires,
                  [num_simd] { return std::make_shared<BooleanSWIFTWire>(num_simd); });
  const auto my_id = swift_provider_.get_my_id();
  if (my_id != 2) {
    share_future_ = swift_provider_.register_for_ints_message<T>(1 - my_id, gate_id_, num_simd);
  }

  // Addition gate stuff.
  // The addition gate will be inside this gate, and will be run in the ONLINE phase of this gate.
  auto& addition_circuit =
      swift_provider_.get_circuit_loader().load_circuit(fmt::format("int_add{}_depth.bristol", num_wires),
          CircuitFormat::Bristol);
  
  // apply the circuit to the Boolean shares.
  WireVector A(ENCRYPTO::bit_size_v<T>);
  WireVector B(ENCRYPTO::bit_size_v<T>);
  output_public_.resize(num_wires);
  output_random_.resize(num_wires);
  for (std::size_t bit_pos = 0; bit_pos < num_wires; ++bit_pos) {
    output_public_[bit_pos] = std::make_shared<BooleanSWIFTWire>(num_simd);
    output_random_[bit_pos] = std::make_shared<BooleanSWIFTWire>(num_simd);
    A[bit_pos] = cast_boolean_wire(output_public_[bit_pos]);
    B[bit_pos] = cast_boolean_wire(output_random_[bit_pos]);
  }
  A.insert(
      A.end(),
      std::make_move_iterator(B.begin()),
      std::make_move_iterator(B.end())
    );
  auto [gates, output_wires] = construct_two_input_circuit(swift_provider_, addition_circuit, A);
  // TODO(pranav): Check this step's correctness.
  gates_ = std::move(gates);
  addition_result_ = cast_wires(output_wires);
}

template <typename T>
ArithmeticToBooleanSWIFTGate<T>::~ArithmeticToBooleanSWIFTGate() = default;

template <typename T>
void ArithmeticToBooleanSWIFTGate<T>::evaluate_setup() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticToBooleanSWIFTGate<T>::evaluate_setup start", gate_id_));
    }
  }
  // TODO(pranav): Make this really random.
  std::size_t cleartext_r = 3;
  constexpr std::size_t bit_size = 8 * sizeof(T);
  const auto bit_converted = std::bitset<bit_size>(cleartext_r);
  assert(bit_converted.size() == bit_size);

  auto num_simd = input_->get_num_simd();

  for (int bit_pos = 0; bit_pos < bit_size; ++bit_pos) {
    auto& pub_share = output_random_[bit_pos]->get_public_share();
    pub_share = ENCRYPTO::BitVector<>(num_simd, bit_converted[bit_pos]);
    output_random_[bit_pos]->set_setup_ready();
    // This wire will contain the public value of Z-r, all publicly known.
    // Therefore, this wire's setup is by default always ready.
    output_public_[bit_pos]->set_setup_ready();
  }

  for (auto& gate : gates_) {
    gate->evaluate_setup();
  }

  for (std::size_t bit_pos = 0; bit_pos < bit_size; ++bit_pos) {
      addition_result_[bit_pos]->wait_setup();
      // Copy the wire vector values to the output.
      output_[bit_pos]->get_secret_share() = addition_result_[bit_pos]->get_secret_share();
      output_[bit_pos]->set_setup_ready();
    }

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticToBooleanSWIFTGate<T>::evaluate_setup end", gate_id_));
    }
  }
}

template <typename T>
void ArithmeticToBooleanSWIFTGate<T>::evaluate_setup_with_context(MOTION::ExecutionContext& exec_ctx) {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticToBooleanSWIFTGate<T>::evaluate_setup start", gate_id_));
    }
  }
  // TODO(pranav): Make this really random.
  std::size_t cleartext_r = 3;
  constexpr std::size_t bit_size = 8 * sizeof(T);
  const auto bit_converted = std::bitset<bit_size>(cleartext_r);
  assert(bit_converted.size() == bit_size);

  auto num_simd = input_->get_num_simd();

  for (int bit_pos = 0; bit_pos < bit_size; ++bit_pos) {
    auto& pub_share = output_random_[bit_pos]->get_public_share();
    pub_share = ENCRYPTO::BitVector<>(num_simd, bit_converted[bit_pos]);
    output_random_[bit_pos]->set_setup_ready();
    // This wire will contain the public value of Z-r, all publicly known.
    // Therefore, this wire's setup is by default always ready.
    output_public_[bit_pos]->set_setup_ready();
  }

  for (auto& gate : gates_) {
    exec_ctx.fpool_->post([&] { gate->evaluate_setup(); });
  }

  for (std::size_t bit_pos = 0; bit_pos < bit_size; ++bit_pos) {
      addition_result_[bit_pos]->wait_setup();
      // Copy the wire vector values to the output.
      output_[bit_pos]->get_secret_share() = addition_result_[bit_pos]->get_secret_share();
      output_[bit_pos]->set_setup_ready();
    }
  this->set_setup_ready();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticToBooleanSWIFTGate<T>::evaluate_setup end", gate_id_));
    }
  }
}

template <typename T>
void ArithmeticToBooleanSWIFTGate<T>::evaluate_online() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticToBooleanSWIFTGate<T>::evaluate_online start", gate_id_));
    }
  }

  input_->wait_setup();
  input_->wait_online();
  const auto my_id = swift_provider_.get_my_id();
  const auto num_wires = ENCRYPTO::bit_size_v<T>;
  const auto num_simd = input_->get_num_simd();
  if (my_id == 2) {
    for (std::size_t wire_i = 0; wire_i < num_wires; ++wire_i) {
      output_[wire_i]->set_online_ready();
    }
    return;
  }

  auto ZminusR = input_->get_public_share();
  std::vector<T> for_other_party(num_simd);
  if (my_id == 0) {
    for (std::size_t i = 0; i < num_simd; ++i) {
      ZminusR[i] -= (input_->get_secret_share()[0][i] + input_->get_secret_share()[2][i] + 2);
      for_other_party[i] = input_->get_secret_share()[0][i];
    }
  } else {
    for (std::size_t i = 0; i < num_simd; ++i) {
      ZminusR[i] -= (input_->get_secret_share()[1][i] + input_->get_secret_share()[2][i] + 3);
      for_other_party[i] = input_->get_secret_share()[1][i] + 1;
    }
  }

  swift_provider_.send_ints_message<T>(1 - my_id, this->gate_id_, for_other_party);
  auto from_other_party = share_future_.get();
  std::transform(std::begin(ZminusR), std::end(ZminusR),
   std::begin(from_other_party), std::begin(ZminusR), std::minus{});

  for (std::size_t wire_i = 0; wire_i < num_wires; ++wire_i) {
    for (std::size_t ele = 0; ele < num_simd; ++ele) {
      const auto E = ZminusR[ele];
      auto& pub_share = output_public_[wire_i]->get_public_share();
      // output_public_[wire_i]->get_public_share()[ele] = ((E&(1LL << wire_i)) ? 1 : 0);
      pub_share.Set(((E&(1LL << wire_i)) ? 1 : 0), ele);
    }
    output_public_[wire_i]->set_online_ready();
    output_random_[wire_i]->set_online_ready();
  }

  for (auto& gate : gates_) {
    gate->evaluate_online();
  }

  for (std::size_t bit_pos = 0; bit_pos < num_wires; ++bit_pos) {
    addition_result_[bit_pos]->wait_online();
    // Copy the wire vector values to the output.
    output_[bit_pos]->get_public_share() = addition_result_[bit_pos]->get_public_share();
    output_[bit_pos]->set_online_ready();
  }




  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticToBooleanSWIFTGate<T>::evaluate_online end", gate_id_));
    }
  }
}

template <typename T>
void ArithmeticToBooleanSWIFTGate<T>::evaluate_online_with_context(MOTION::ExecutionContext& exec_ctx) {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticToBooleanSWIFTGate<T>::evaluate_online start", gate_id_));
    }
  }

  this->wait_setup();

  input_->wait_setup();
  input_->wait_online();
  const auto my_id = swift_provider_.get_my_id();
  const auto num_wires = ENCRYPTO::bit_size_v<T>;
  const auto num_simd = input_->get_num_simd();
  if (my_id == 2) {
    for (std::size_t wire_i = 0; wire_i < num_wires; ++wire_i) {
      output_[wire_i]->set_online_ready();
    }
    return;
  }

  auto ZminusR = input_->get_public_share();
  std::vector<T> for_other_party(num_simd);
  if (my_id == 0) {
    for (std::size_t i = 0; i < num_simd; ++i) {
      ZminusR[i] -= (input_->get_secret_share()[0][i] + input_->get_secret_share()[2][i] + 2);
      for_other_party[i] = input_->get_secret_share()[0][i];
    }
  } else {
    for (std::size_t i = 0; i < num_simd; ++i) {
      ZminusR[i] -= (input_->get_secret_share()[1][i] + input_->get_secret_share()[2][i] + 3);
      for_other_party[i] = input_->get_secret_share()[1][i] + 1;
    }
  }

  swift_provider_.send_ints_message<T>(1 - my_id, this->gate_id_, for_other_party);
  auto from_other_party = share_future_.get();
  std::transform(std::begin(ZminusR), std::end(ZminusR),
   std::begin(from_other_party), std::begin(ZminusR), std::minus{});

  for (std::size_t wire_i = 0; wire_i < num_wires; ++wire_i) {
    for (std::size_t ele = 0; ele < num_simd; ++ele) {
      const auto E = ZminusR[ele];
      auto& pub_share = output_public_[wire_i]->get_public_share();
      // output_public_[wire_i]->get_public_share()[ele] = ((E&(1LL << wire_i)) ? 1 : 0);
      pub_share.Set(((E&(1LL << wire_i)) ? 1 : 0), ele);
    }
    output_public_[wire_i]->set_online_ready();
    output_random_[wire_i]->set_online_ready();
  }

  for (auto& gate : gates_) {
    exec_ctx.fpool_->post([&] { gate->evaluate_online(); });
  }

  for (std::size_t bit_pos = 0; bit_pos < num_wires; ++bit_pos) {
    addition_result_[bit_pos]->wait_online();
    // Copy the wire vector values to the output.
    output_[bit_pos]->get_public_share() = addition_result_[bit_pos]->get_public_share();
    output_[bit_pos]->set_online_ready();
  }




  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticToBooleanSWIFTGate<T>::evaluate_online end", gate_id_));
    }
  }
}

template class ArithmeticToBooleanSWIFTGate<std::uint8_t>;
template class ArithmeticToBooleanSWIFTGate<std::uint16_t>;
template class ArithmeticToBooleanSWIFTGate<std::uint32_t>;
template class ArithmeticToBooleanSWIFTGate<std::uint64_t>;

BooleanSWIFTToGMWGate::BooleanSWIFTToGMWGate(std::size_t gate_id, SWIFTProvider& swift_provider,
                                             BooleanSWIFTWireVector&& in)
    : NewGate(gate_id), swift_provider_(swift_provider), inputs_(std::move(in)) {
  const auto num_wires = inputs_.size();
  const auto num_simd = inputs_.at(0)->get_num_simd();
  outputs_.reserve(num_wires);
  std::generate_n(std::back_inserter(outputs_), num_wires,
                  [num_simd] { return std::make_shared<gmw::BooleanGMWWire>(num_simd); });
}

void BooleanSWIFTToGMWGate::evaluate_online() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanSWIFTToGMWGate::evaluate_online start", gate_id_));
    }
  }
  throw std::runtime_error("Conversion not yet implemented.");

  // const auto num_wires = inputs_.size();
  // if (swift_provider_.is_my_job(gate_id_)) {
  //   for (std::size_t wire_i = 0; wire_i < num_wires; ++wire_i) {
  //     const auto& wire_in = inputs_[wire_i];
  //     auto& wire_out = outputs_[wire_i];
  //     wire_in->wait_setup();
  //     wire_in->wait_online();
  //     wire_out->get_share() = wire_in->get_public_share() ^ wire_in->get_secret_share();
  //     wire_out->set_online_ready();
  //   }
  // } else {
  //   for (std::size_t wire_i = 0; wire_i < num_wires; ++wire_i) {
  //     const auto& wire_in = inputs_[wire_i];
  //     auto& wire_out = outputs_[wire_i];
  //     wire_in->wait_setup();
  //     wire_in->wait_online();
  //     wire_out->get_share() = wire_in->get_secret_share();
  //     wire_out->set_online_ready();
  //   }
  // }

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanSWIFTToGMWGate::evaluate_online end", gate_id_));
    }
  }
}

BooleanGMWToSWIFTGate::BooleanGMWToSWIFTGate(std::size_t gate_id, SWIFTProvider& swift_provider,
                                             gmw::BooleanGMWWireVector&& in)
    : NewGate(gate_id), swift_provider_(swift_provider), inputs_(std::move(in)) {
  const auto num_wires = inputs_.size();
  const auto num_simd = inputs_.at(0)->get_num_simd();
  const auto my_id = swift_provider_.get_my_id();
  outputs_.reserve(num_wires);
  std::generate_n(std::back_inserter(outputs_), num_wires,
                  [num_simd] { return std::make_shared<BooleanSWIFTWire>(num_simd); });
  share_future_ =
      swift_provider_.register_for_bits_message(1 - my_id, gate_id_, num_wires * num_simd);
}

void BooleanGMWToSWIFTGate::evaluate_setup() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanGMWToSWIFTGate::evaluate_setup start", gate_id_));
    }
  }
  throw std::runtime_error("Conversion not yet implemented.");

  // const auto num_simd = inputs_.at(0)->get_num_simd();
  // for (auto& wire_out : outputs_) {
  //   wire_out->get_secret_share() = ENCRYPTO::BitVector<>::Random(num_simd);
  //   wire_out->set_setup_ready();
  // }

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format("Gate {}: BooleanGMWToSWIFTGate::evaluate_setup end", gate_id_));
    }
  }
}

void BooleanGMWToSWIFTGate::evaluate_online() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanGMWToSWIFTGate::evaluate_online start", gate_id_));
    }
  }
  throw std::runtime_error("Conversion not yet implemented.");

  // const auto my_id = swift_provider_.get_my_id();
  // const auto num_wires = inputs_.size();
  // const auto num_simd = inputs_.at(0)->get_num_simd();
  // ENCRYPTO::BitVector<> my_share;
  // my_share.Reserve(Helpers::Convert::BitsToBytes(num_wires * num_simd));
  // for (std::size_t wire_i = 0; wire_i < num_wires; ++wire_i) {
  //   const auto& wire_in = inputs_[wire_i];
  //   const auto& wire_out = outputs_[wire_i];
  //   wire_in->wait_online();
  //   my_share.Append(wire_in->get_share() ^ wire_out->get_secret_share());
  // }
  // swift_provider_.send_bits_message(1 - my_id, gate_id_, my_share);
  // my_share ^= share_future_.get();
  // for (std::size_t wire_i = 0; wire_i < num_wires; ++wire_i) {
  //   const auto& wire_out = outputs_[wire_i];
  //   wire_out->get_public_share() = my_share.Subset(wire_i * num_simd, (wire_i + 1) * num_simd);
  //   wire_out->set_online_ready();
  // }

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanGMWToSWIFTGate::evaluate_online end", gate_id_));
    }
  }
}

template <typename T>
ArithmeticSWIFTToGMWGate<T>::ArithmeticSWIFTToGMWGate(std::size_t gate_id,
                                                      SWIFTProvider& swift_provider,
                                                      ArithmeticSWIFTWireP<T> in)
    : NewGate(gate_id), swift_provider_(swift_provider), input_(std::move(in)) {
  const auto num_simd = input_->get_num_simd();
  output_ = std::make_shared<gmw::ArithmeticGMWWire<T>>(num_simd);
  output_->get_share().resize(num_simd);
}

template <typename T>
void ArithmeticSWIFTToGMWGate<T>::evaluate_online() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticSWIFTToGMWGate<T>::evaluate_online start", gate_id_));
    }
  }
  throw std::runtime_error("Conversion not yet implemented.");

  // if (swift_provider_.is_my_job(gate_id_)) {
  //   input_->wait_setup();
  //   input_->wait_online();
  //   const auto& pshare = input_->get_public_share();
  //   const auto& sshare = input_->get_secret_share();
  //   std::transform(std::begin(pshare), std::end(pshare), std::begin(sshare),
  //                  std::begin(output_->get_share()), std::minus{});
  //   output_->set_online_ready();
  // } else {
  //   input_->wait_setup();
  //   const auto& sshare = input_->get_secret_share();
  //   std::transform(std::begin(sshare), std::end(sshare), std::begin(output_->get_share()),
  //                  std::negate{});
  //   output_->set_online_ready();
  // }

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticSWIFTToGMWGate<T>::evaluate_online end", gate_id_));
    }
  }
}

template class ArithmeticSWIFTToGMWGate<std::uint8_t>;
template class ArithmeticSWIFTToGMWGate<std::uint16_t>;
template class ArithmeticSWIFTToGMWGate<std::uint32_t>;
template class ArithmeticSWIFTToGMWGate<std::uint64_t>;

template <typename T>
ArithmeticGMWToSWIFTGate<T>::ArithmeticGMWToSWIFTGate(std::size_t gate_id,
                                                      SWIFTProvider& swift_provider,
                                                      gmw::ArithmeticGMWWireP<T> in)
    : NewGate(gate_id), swift_provider_(swift_provider), input_(std::move(in)) {
  const auto num_simd = input_->get_num_simd();
  const auto my_id = swift_provider_.get_my_id();
  output_ = std::make_shared<ArithmeticSWIFTWire<T>>(num_simd);
  share_future_ = swift_provider_.register_for_ints_message<T>(1 - my_id, gate_id_, num_simd);
}

template <typename T>
void ArithmeticGMWToSWIFTGate<T>::evaluate_setup() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticGMWToSWIFTGate<T>::evaluate_setup start", gate_id_));
    }
  }
  throw std::runtime_error("Conversion not yet implemented.");

  // const auto num_simd = input_->get_num_simd();
  // output_->get_secret_share() = Helpers::RandomVector<T>(num_simd);
  // output_->set_setup_ready();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticGMWToSWIFTGate<T>::evaluate_setup end", gate_id_));
    }
  }
}

template <typename T>
void ArithmeticGMWToSWIFTGate<T>::evaluate_online() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticGMWToSWIFTGate<T>::evaluate_online start", gate_id_));
    }
  }
  throw std::runtime_error("Conversion not yet implemented.");

  // const auto my_id = swift_provider_.get_my_id();
  // input_->wait_online();
  // auto my_share = input_->get_share();
  // std::transform(std::begin(my_share), std::end(my_share), std::begin(output_->get_secret_share()),
  //                std::begin(my_share), std::plus{});
  // swift_provider_.send_ints_message(1 - my_id, gate_id_, my_share);
  // const auto other_share = share_future_.get();
  // std::transform(std::begin(my_share), std::end(my_share), std::begin(other_share),
  //                std::begin(my_share), std::plus{});
  // output_->get_public_share() = std::move(my_share);
  // output_->set_online_ready();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticGMWToSWIFTGate<T>::evaluate_online end", gate_id_));
    }
  }
}

template class ArithmeticGMWToSWIFTGate<std::uint8_t>;
template class ArithmeticGMWToSWIFTGate<std::uint16_t>;
template class ArithmeticGMWToSWIFTGate<std::uint32_t>;
template class ArithmeticGMWToSWIFTGate<std::uint64_t>;

}  // namespace MOTION::proto::swift
