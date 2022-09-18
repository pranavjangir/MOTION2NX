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

#include <openssl/bn.h>
#include <algorithm>
#include <functional>
#include <stdexcept>
#include <unistd.h>
#include <random>
#include "gate.h"

#include "base/gate_factory.h"
#include "swift_provider.h"
#include "crypto/arithmetic_provider.h"
#include "crypto/motion_base_provider.h"
#include "algorithm/circuit_loader.h"
#include "algorithm/make_circuit.h"
#include "executor/execution_context.h"
#include "crypto/oblivious_transfer/ot_flavors.h"
#include "crypto/oblivious_transfer/ot_provider.h"
#include "utility/fiber_thread_pool/fiber_thread_pool.hpp"
#include "crypto/sharing_randomness_generator.h"
#include "utility/helpers.h"
#include "utility/logger.h"
#include "wire.h"

namespace MOTION::proto::swift {

// Determine the total number of bits in a collection of wires.
static std::size_t count_bits(const BooleanSWIFTWireVector& wires) {
  return std::transform_reduce(std::begin(wires), std::end(wires), 0, std::plus<>(),
                               [](const auto& a) { return a->get_num_simd(); });
}

static WireVector cast_wires(BooleanSWIFTWireVector wires) {
  WireVector result(wires.size());
  std::transform(std::begin(wires), std::end(wires), std::begin(result),
                 [](auto& w) { return std::shared_ptr<NewWire>(w); });
  return result;
}

ENCRYPTO::BitVector<> permute_with_seed(const ENCRYPTO::BitVector<> bv, const std::size_t seed) {
  ENCRYPTO::BitVector<> op(bv.GetSize());
  std::mt19937 rng(seed);
  std::vector<bool> tmp(bv.GetSize());
  for (int i = 0 ; i < bv.GetSize(); ++i) {
    tmp[i] = bv.Get(i);
  }
  std::shuffle(tmp.begin(), tmp.end(), rng);
  for (int i = 0 ; i < bv.GetSize(); ++i) {
    op.Set(tmp[i], i);
  }
  return op;
}

namespace detail {

BasicBooleanSWIFTBinaryGate::BasicBooleanSWIFTBinaryGate(std::size_t gate_id,
                                                         BooleanSWIFTWireVector&& in_b,
                                                         BooleanSWIFTWireVector&& in_a)
    : NewGate(gate_id),
      num_wires_(in_a.size()),
      inputs_a_(std::move(in_a)),
      inputs_b_(std::move(in_b)) {
  if (num_wires_ == 0) {
    throw std::logic_error("number of wires need to be positive");
  }
  if (num_wires_ != inputs_b_.size()) {
    throw std::logic_error("number of wires need to be the same for both inputs");
  }
  auto num_simd = inputs_a_[0]->get_num_simd();
  for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
    if (inputs_a_[wire_i]->get_num_simd() != num_simd ||
        inputs_b_[wire_i]->get_num_simd() != num_simd) {
      throw std::logic_error("number of SIMD values need to be the same for all wires");
    }
  }
  outputs_.reserve(num_wires_);
  std::generate_n(std::back_inserter(outputs_), num_wires_,
                  [num_simd] { return std::make_shared<BooleanSWIFTWire>(num_simd); });
}

BasicBooleanSWIFTUnaryGate::BasicBooleanSWIFTUnaryGate(std::size_t gate_id,
                                                       BooleanSWIFTWireVector&& in, bool forward)
    : NewGate(gate_id), num_wires_(in.size()), inputs_(std::move(in)) {
  if (num_wires_ == 0) {
    throw std::logic_error("number of wires need to be positive");
  }
  auto num_simd = inputs_[0]->get_num_simd();
  for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
    if (inputs_[wire_i]->get_num_simd() != num_simd) {
      throw std::logic_error("number of SIMD values need to be the same for all wires");
    }
  }
  // if (forward) {
  //   outputs_ = inputs_;
  // } else {
  //   outputs_.reserve(num_wires_);
  //   std::generate_n(std::back_inserter(outputs_), num_wires_,
  //                   [num_simd] { return std::make_shared<BooleanSWIFTWire>(num_simd); });
  // }
  outputs_.reserve(num_wires_);
    std::generate_n(std::back_inserter(outputs_), num_wires_,
                    [num_simd] { return std::make_shared<BooleanSWIFTWire>(num_simd); });
}
template <typename T>
BasicBooleanToArithmeticSWIFTUnaryGate<T>::BasicBooleanToArithmeticSWIFTUnaryGate(std::size_t gate_id,
                                                       BooleanSWIFTWireVector&& in, bool forward)
    : NewGate(gate_id), num_wires_(in.size()), inputs_(std::move(in)) {
  if (num_wires_ == 0) {
    throw std::logic_error("number of wires need to be positive");
  }
  auto num_simd = inputs_[0]->get_num_simd();
  for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
    if (inputs_[wire_i]->get_num_simd() != num_simd) {
      throw std::logic_error("number of SIMD values need to be the same for all wires");
    }
  }
  output_ = std::make_shared<ArithmeticSWIFTWire<T>>(num_simd);
}

}  // namespace detail

BooleanSWIFTInputGateSender::BooleanSWIFTInputGateSender(
    std::size_t gate_id, SWIFTProvider& swift_provider, std::size_t num_wires, std::size_t num_simd,
    ENCRYPTO::ReusableFiberFuture<std::vector<ENCRYPTO::BitVector<>>>&& input_future)
    : NewGate(gate_id),
      swift_provider_(swift_provider),
      num_wires_(num_wires),
      num_simd_(num_simd),
      input_id_(swift_provider.get_next_input_id(num_wires)),
      input_future_(std::move(input_future)) {
  outputs_.reserve(num_wires_);
  std::generate_n(std::back_inserter(outputs_), num_wires_,
                  [num_simd] { return std::make_shared<BooleanSWIFTWire>(num_simd); });
}

void BooleanSWIFTInputGateSender::evaluate_setup() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanSWIFTInputGateSender::evaluate_setup start", gate_id_));
    }
  }

  throw std::runtime_error("Not yet implemented");

  // auto my_id = swift_provider_.get_my_id();
  // auto num_parties = swift_provider_.get_num_parties();
  // auto& mbp = swift_provider_.get_motion_base_provider();
  // for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
  //   auto& wire = outputs_[wire_i];
  //   wire->get_secret_share() = ENCRYPTO::BitVector<>::Random(num_simd_);
  //   wire->set_setup_ready();
  //   wire->get_public_share() = wire->get_secret_share();
  //   for (std::size_t party_id = 0; party_id < num_parties; ++party_id) {
  //     if (party_id == my_id) {
  //       continue;
  //     }
  //     auto& rng = mbp.get_my_randomness_generator(party_id);
  //     wire->get_public_share() ^= rng.GetBits(input_id_ + wire_i, num_simd_);
  //   }
  // }

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanSWIFTInputGateSender::evaluate_setup end", gate_id_));
    }
  }
}

void BooleanSWIFTInputGateSender::evaluate_online() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanSWIFTInputGateSender::evaluate_online start", gate_id_));
    }
  }

  throw std::runtime_error("Not yet implemented");

  // // wait for input value
  // const auto inputs = input_future_.get();

  // ENCRYPTO::BitVector<> public_shares;
  // public_shares.Reserve(Helpers::Convert::BitsToBytes(num_wires_ * num_simd_));

  // // compute my share
  // for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
  //   auto& w_o = outputs_[wire_i];
  //   auto& public_share = w_o->get_public_share();
  //   const auto& input_bits = inputs.at(wire_i);
  //   if (input_bits.GetSize() != num_simd_) {
  //     throw std::runtime_error("size of input bit vector != num_simd_");
  //   }
  //   public_share ^= input_bits;
  //   w_o->set_online_ready();
  //   public_shares.Append(public_share);
  // }
  // swift_provider_.broadcast_bits_message(gate_id_, public_shares);

  // if constexpr (MOTION_VERBOSE_DEBUG) {
  //   auto logger = swift_provider_.get_logger();
  //   if (logger) {
  //     logger->LogTrace(
  //         fmt::format("Gate {}: BooleanSWIFTInputGateSender::evaluate_online end", gate_id_));
  //   }
  // }
}

BooleanSWIFTInputGateReceiver::BooleanSWIFTInputGateReceiver(std::size_t gate_id,
                                                             SWIFTProvider& swift_provider,
                                                             std::size_t num_wires,
                                                             std::size_t num_simd,
                                                             std::size_t input_owner)
    : NewGate(gate_id),
      swift_provider_(swift_provider),
      num_wires_(num_wires),
      num_simd_(num_simd),
      input_owner_(input_owner),
      input_id_(swift_provider.get_next_input_id(num_wires)) {
  outputs_.reserve(num_wires_);
  std::generate_n(std::back_inserter(outputs_), num_wires_,
                  [num_simd] { return std::make_shared<BooleanSWIFTWire>(num_simd); });
  public_share_future_ =
      swift_provider_.register_for_bits_message(input_owner_, gate_id_, num_wires * num_simd);
}

void BooleanSWIFTInputGateReceiver::evaluate_setup() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanSWIFTInputGateReceiver::evaluate_setup start", gate_id_));
    }
  }

  throw std::runtime_error("Not yet implemented");

  // auto& mbp = swift_provider_.get_motion_base_provider();
  // auto& rng = mbp.get_their_randomness_generator(input_owner_);
  // for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
  //   auto& wire = outputs_[wire_i];
  //   wire->get_secret_share() = rng.GetBits(input_id_ + wire_i, num_simd_);
  //   wire->set_setup_ready();
  // }

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanSWIFTInputGateReceiver::evaluate_setup end", gate_id_));
    }
  }
}

void BooleanSWIFTInputGateReceiver::evaluate_online() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanSWIFTInputGateReceiver::evaluate_online start", gate_id_));
    }
  }

  throw std::runtime_error("Not yet implemented");

  // auto public_shares = public_share_future_.get();
  // for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
  //   auto& wire = outputs_[wire_i];
  //   wire->get_public_share() = public_shares.Subset(wire_i * num_simd_, (wire_i + 1) * num_simd_);
  //   wire->set_online_ready();
  // }

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanSWIFTInputGateReceiver::evaluate_online end", gate_id_));
    }
  }
}

BooleanSWIFTOutputGate::BooleanSWIFTOutputGate(std::size_t gate_id, SWIFTProvider& swift_provider,
                                               BooleanSWIFTWireVector&& inputs,
                                               std::size_t output_owner)
    : NewGate(gate_id),
      swift_provider_(swift_provider),
      num_wires_(inputs.size()),
      output_owner_(output_owner),
      inputs_(std::move(inputs)) {
  std::size_t my_id = swift_provider_.get_my_id();
  auto num_bits = count_bits(inputs_);
  if (output_owner_ != ALL_PARTIES) {
    throw std::logic_error("BooleanSWIFT output gate only supports reconstruction towards all parties currently.");
  }
  my_secret_share_.Reserve(Helpers::Convert::BitsToBytes(num_bits));
  share_futures_ = swift_provider_.register_for_bits_messages(this->gate_id_, num_bits);
}

ENCRYPTO::ReusableFiberFuture<std::vector<ENCRYPTO::BitVector<>>>
BooleanSWIFTOutputGate::get_output_future() {
  if (output_owner_ == ALL_PARTIES) {
    return output_promise_.get_future();
  } else {
    throw std::logic_error("not this parties output");
  }
}

void BooleanSWIFTOutputGate::evaluate_setup() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanSWIFTOutputGate::evaluate_setup start", gate_id_));
    }
  }
  std::size_t my_id = swift_provider_.get_my_id();
  for (const auto& wire : inputs_) {
    wire->wait_setup();
    if (my_id == 0) {
      my_secret_share_.Append(wire->get_secret_share()[0]);
    } else if (my_id == 1) {
      my_secret_share_.Append(wire->get_secret_share()[1]);
    }
  }
  if (my_id != 2) {
    swift_provider_.send_bits_message(1 - my_id, gate_id_, my_secret_share_);
  }
  this->set_setup_ready();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanSWIFTOutputGate::evaluate_setup end", gate_id_));
    }
  }
}

void BooleanSWIFTOutputGate::evaluate_online() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanSWIFTOutputGate::evaluate_online start", gate_id_));
    }
  }

  this->wait_setup();
  const std::size_t my_id = swift_provider_.get_my_id();
  const std::size_t num_simd = inputs_[0]->get_num_simd();
  my_secret_share_.Clear();
  for (const auto& wire : inputs_) {
    wire->wait_setup();
    if (my_id == 0) {
      my_secret_share_.Append(wire->get_secret_share()[0]);
    } else if (my_id == 1) {
      my_secret_share_.Append(wire->get_secret_share()[1]);
    }
  }
  if (my_id == 2) {
    std::vector<ENCRYPTO::BitVector<>> outputs;
    const auto party0_result = share_futures_[0].get();
    const auto party1_result = share_futures_[1].get();
    assert(party0_result == party1_result);
    for (std::size_t wire_i = 0 ; wire_i < num_wires_; ++wire_i) {
      outputs.push_back(party0_result.Subset(wire_i * num_simd, (wire_i + 1) * num_simd));
    }
    output_promise_.set_value(std::move(outputs));
    return;
  }
  ENCRYPTO::BitVector<> bv;
  bv.Reserve(Helpers::Convert::BitsToBytes(num_simd * num_wires_));
  for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
    bv.Append(inputs_[wire_i]->get_secret_share()[2]);
  }
  const auto other_share = share_futures_[1 - my_id].get();
  bv ^= (other_share ^ my_secret_share_);

  std::vector<ENCRYPTO::BitVector<>> outputs;
  ENCRYPTO::BitVector<> for_offline_party;
  for_offline_party.Reserve(Helpers::Convert::BitsToBytes(num_simd * num_wires_));
  outputs.reserve(num_wires_);
  std::size_t bit_offset = 0;
  for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
    auto& output =
        outputs.emplace_back(bv.Subset(bit_offset, bit_offset + num_simd));
    inputs_[wire_i]->wait_online();
    output ^= inputs_[wire_i]->get_public_share();
    for_offline_party.Append(output);
    bit_offset += num_simd;
  }
  swift_provider_.send_bits_message(2, this->gate_id_, for_offline_party);
  output_promise_.set_value(std::move(outputs));

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanSWIFTOutputGate::evaluate_online end", gate_id_));
    }
  }
}

BooleanSWIFTINVGate::BooleanSWIFTINVGate(std::size_t gate_id, const SWIFTProvider& swift_provider,
                                         BooleanSWIFTWireVector&& in)
    : detail::BasicBooleanSWIFTUnaryGate(gate_id, std::move(in),
                                         !swift_provider.is_my_job(gate_id)),
      is_my_job_(swift_provider.is_my_job(gate_id)) {}

void BooleanSWIFTINVGate::evaluate_setup() {
  for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
    const auto& w_in = inputs_[wire_i];
    w_in->wait_setup();
    auto& w_o = outputs_[wire_i];
    for (std::size_t share_id = 0; share_id < 3; ++share_id) {
      w_o->get_secret_share()[share_id] = w_in->get_secret_share()[share_id];
    }
    w_o->set_setup_ready();
  }
  this->set_setup_ready();
}

void BooleanSWIFTINVGate::evaluate_online() {
  this->wait_setup();
  for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
    const auto& w_in = inputs_[wire_i];
    w_in->wait_online();
    auto& w_o = outputs_[wire_i];
    w_o->get_public_share() = ~w_in->get_public_share();
    w_o->set_online_ready();
  }
}

template <typename T>
BooleanSWIFTBitToArithmeticGate<T>::BooleanSWIFTBitToArithmeticGate(std::size_t gate_id,
 SWIFTProvider& swift_provider, BooleanSWIFTWireVector&& in)
:detail::BasicBooleanSWIFTUnaryGate(gate_id, std::move(in),
                                         !swift_provider.is_my_job(gate_id)),
                                          swift_provider_(swift_provider) {
  auto my_id = swift_provider.get_my_id();
  auto num_simd = in[0]->get_num_simd();
  share_futures_.resize(3);
  share_futures2_.resize(3);
  if (my_id == 0) {
    share_futures_ = swift_provider_.register_for_ints_messages<T>(this->gate_id, num_simd, 0);
    share_futures2_ = swift_provider_.register_for_ints_messages<T>(this->gate_id, num_simd, 1);
  } else if (my_id == 1) {
    share_futures_[0] = swift_provider_.register_for_ints_message<T>(0, this->gate_id, num_simd, 0);
    share_futures2_[0] = swift_provider_.register_for_ints_message<T>(0, this->gate_id, num_simd, 1);
  }
  if (in.size() != 1) {
    throw std::logic_error("B2A works only for num_wires = 1");
  }
}

template <typename T>
void BooleanSWIFTBitToArithmeticGate<T>::evaluate_setup() {
  // Prepare the lambda shares and all.
  // prepare the offline shares.
  auto my_id = swift_provider_.get_my_id();
  auto num_simd = this->inputs_[0]->get_num_simd();
  this->output_->get_secret_share()[0] = {0, 0, 0};
  this->output_->get_secret_share()[1] = {0, 0, 0};
  this->output_->get_secret_share()[2] = {0, 0, 0};

  std::array<std::array<std::vector<T>, 3>, 3> lambda;
  std::array<std::vector<T>, 3> sigma;
  sigma[0].resize(num_simd, 0); rss_sharing_mt_[0].resize(num_simd, 0);
  sigma[1].resize(num_simd, 0); rss_sharing_mt_[1].resize(num_simd, 0);
  sigma[2].resize(num_simd, 0); rss_sharing_mt_[2].resize(num_simd, 0);

  for(int i = 0 ; i < num_simd; ++i) {
    for (int j = 0; j < 3; ++j) {
      lambda[0][j].push_back(this->inputs_[0]->get_secret_share()[j].Get(i));
      lambda[1][j].push_back(this->inputs_[0]->get_secret_share()[j].Get(i));
      lambda[2][j].push_back(this->inputs_[0]->get_secret_share()[j].Get(i));
    }
  }
  std::vector<T> my_share_value1(num_simd, 0);
  // lambda0 and lambda1.
  // TODO(pranav): All the random values are "0" currently.
  // Add actual randomness.
  if (my_id == 0) {
    for (int i = 0 ; i < num_simd; ++i) {
      my_share_value1[i] = lambda[0][0][i]*lambda[1][2][i] + lambda[1][0][i]*lambda[0][2][i]
       + lambda[0][2][i]*lambda[1][2][i];
    }
    swift_provider_.send_ints_message(1, this->gate_id_, my_share_value1, 0);
    auto p1_msg = share_futures_[1].get();
    auto p2_msg = share_futures_[2].get();
    for (int i = 0 ; i < num_simd; ++i) {
      sigma[0][i] = (p2_msg[i]);
      sigma[2][i] = (p1_msg[i] + my_share_value1[i]);
    }
  } else if (my_id == 1) {
    for (int i = 0 ; i < num_simd; ++i) {
      my_share_value1[i] = lambda[0][1][i]*lambda[1][2][i] + lambda[1][1][i]*lambda[0][2][i];
    }
    swift_provider_.send_ints_message(0, this->gate_id_, my_share_value1, 0);
    auto p0_msg = share_futures_[0].get();
    for (int i = 0 ; i < num_simd; ++i) {
      sigma[2][i] = (p0_msg[i] + my_share_value1[i]);
    }
  } else {
    for (int i = 0; i < 2; ++i) {
      for (int j = 0; j < 2; ++j) {
        for (std::size_t k = 0; k < num_simd; ++k) {
          auto contrib = 
          lambda[0][i][k] * lambda[1][j][k];
          my_share_value1[k] += contrib;
        }
      }
    }
    // just share your own values.
    swift_provider_.send_ints_message(0, this->gate_id_, my_share_value1, 0);
    for (int i = 0 ; i < num_simd; ++i) {
      sigma[2][i] = (my_share_value1[i]);
    }
  }

  // sigma * lambda3 now.
  std::vector<T> my_share_value2(num_simd, 0);
  if (my_id == 0) {
    for (int i = 0 ; i < num_simd; ++i) {
      my_share_value2[i] = sigma[0][i]*lambda[2][2][i] + lambda[2][0][i]*sigma[2][i]
       + sigma[2][i]*lambda[2][2][i];
    }
    swift_provider_.send_ints_message(1, this->gate_id_, my_share_value2, 0);
    auto p1_msg = share_futures_[1].get();
    auto p2_msg = share_futures_[2].get();
    for (int i = 0 ; i < num_simd; ++i) {
      rss_sharing_mt_[0][i] = (p2_msg[i]);
      rss_sharing_mt_[2][i] = (p1_msg[i] + my_share_value2[i]);
    }
  } else if (my_id == 1) {
    for (int i = 0 ; i < num_simd; ++i) {
      my_share_value2[i] = sigma[1][i]*lambda[2][2][i] + lambda[2][1][i]*sigma[2][i];
    }
    swift_provider_.send_ints_message(0, this->gate_id_, my_share_value2, 0);
    auto p0_msg = share_futures_[0].get();
    for (int i = 0 ; i < num_simd; ++i) {
      rss_sharing_mt_[2][i] = (p0_msg[i] + my_share_value2[i]);
    }
  } else {
    for (int i = 0; i < 2; ++i) {
      for (int j = 0; j < 2; ++j) {
        for (std::size_t k = 0; k < num_simd; ++k) {
          auto contrib = 
          sigma[i][k] * lambda[2][j][k];
          my_share_value2[k] += contrib;
        }
      }
    }
    // just share your own values.
    swift_provider_.send_ints_message(0, this->gate_id_, my_share_value2, 0);
    for (int i = 0 ; i < num_simd; ++i) {
      rss_sharing_mt_[2][i] = (my_share_value2[i]);
    }
  }
  // `rss_sharing_mt_` now contains the arithmetic shares of (lambda0 * lambda1 * lambda2).
  this->output_->set_setup_ready();
  this->set_setup_ready();
}

template <typename T>
void BooleanSWIFTBitToArithmeticGate<T>::evaluate_online() {
  this->wait_setup();
  auto my_id = swift_provider_.get_my_id();
  auto num_simd = this->inputs_[0]->get_num_simd();

  if (my_id == 2) {
    this->output_->set_online_ready();
    return;
  }

  std::vector<T> yy0(num_simd, 0);
  std::vector<T> yy1(num_simd, 0);
  std::vector<T> yy2(num_simd, 0);
  for (int i = 0; i < num_simd; ++i) {
    yy2[i] = rss_sharing_mt_[2][i]* (1 - 2*this->inputs_[0]->get_public_share().Get(i));
  }
  if (my_id == 0) {
    for (int i = 0; i < num_simd; ++i) {
      yy0[i] = rss_sharing_mt_[0][i]* (1 - 2*this->inputs_[0]->get_public_share().Get(i)) + 
      this->inputs_[0]->get_public_share().Get(i);
    }
    swift_provider_.send_ints_message(1 - my_id, this->gate_id_, yy0, 1);
    yy1 = share_futures2_[1 - my_id].get();
  } else {
    for (int i = 0; i < num_simd; ++i) {
      yy1[i] = rss_sharing_mt_[1][i]* (1 - 2*this->inputs_[0]->get_public_share().Get(i));
    }
    swift_provider_.send_ints_message(1 - my_id, this->gate_id_, yy1, 1);
    yy0 = share_futures2_[1 - my_id].get();
  }

  for (int i = 0; i < num_simd; ++i) {
    this->output_->get_public_share()[i] = yy0[i] + yy1[i] + yy2[i];
  }

  this->output_->set_online_ready();
}

BooleanSWIFTSHUFFLEGate::BooleanSWIFTSHUFFLEGate(std::size_t gate_id, SWIFTProvider& swift_provider,
                                         BooleanSWIFTWireVector&& in)
    : detail::BasicBooleanSWIFTUnaryGate(gate_id, std::move(in),
                                         !swift_provider.is_my_job(gate_id)),
                                         swift_provider_(swift_provider) {
  auto my_id = swift_provider_.get_my_id();
  auto num_simd = inputs_[0]->get_num_simd();
  // Random seeds for different rounds.
  // These seeds determine the final permutation.
  if (my_id == 0) {
    for (int i = 0; i < 3; ++i) {
      seeds_[i][0] = (((1^2) + i)) ^ gate_id_;
      seeds_[i][2] = (((1^3) + i)) ^ gate_id_;
    }
  } else if (my_id == 1) {
    for (int i = 0; i < 3; ++i) {
      seeds_[i][0] = (((1^2) + i)) ^ gate_id_;
      seeds_[i][1] = (((2^3) + i)) ^ gate_id_;
    }
  } else {
    for (int i = 0; i < 3; ++i) {
      seeds_[i][1] = (((2^3) + i)) ^ gate_id_;
      seeds_[i][2] = (((1^3) + i)) ^ gate_id_;
    }
  }
  // TODO(pranav): Compress this loop.
  for (int round = 0; round < 3; ++round) {
    if (my_id == 0) {
      std::mt19937 rng12(seeds_[round][0]);
      std::mt19937 rng13(seeds_[round][2]);
      for (int i = 0; i < num_wires_; ++i) {
        ENCRYPTO::BitVector<> bv12(num_simd);
        ENCRYPTO::BitVector<> bv13(num_simd);
        for (int j = 0; j < num_simd; ++j) {
          bv12.Set(rng12()%2, j);
          bv13.Set(rng13()%2, j);
        }
        random_vectors_[round][0].push_back(bv12);
        random_vectors_[round][2].push_back(bv13);
      }
    } else if (my_id == 1) {
      std::mt19937 rng12(seeds_[round][0]);
      std::mt19937 rng23(seeds_[round][1]);
      for (int i = 0; i < num_wires_; ++i) {
        ENCRYPTO::BitVector<> bv12(num_simd);
        ENCRYPTO::BitVector<> bv23(num_simd);
        for (int j = 0; j < num_simd; ++j) {
          bv12.Set(rng12()%2, j);
          bv23.Set(rng23()%2, j);
        }
        random_vectors_[round][0].push_back(bv12);
        random_vectors_[round][1].push_back(bv23);
      }
    } else {
      std::mt19937 rng23(seeds_[round][1]);
      std::mt19937 rng13(seeds_[round][2]);
      for (int i = 0; i < num_wires_; ++i) {
        ENCRYPTO::BitVector<> bv23(num_simd);
        ENCRYPTO::BitVector<> bv13(num_simd);
        for (int j = 0; j < num_simd; ++j) {
          bv23.Set(rng23()%2, j);
          bv13.Set(rng13()%2, j);
        }
        random_vectors_[round][1].push_back(bv23);
        random_vectors_[round][2].push_back(bv13);
      }
    }
  }
  share_futures_ = swift_provider_.register_for_bits_messages(this->gate_id_, num_wires_ * num_simd);
}

void BooleanSWIFTSHUFFLEGate::evaluate_setup() {
  return;
  for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
    const auto& w_in = inputs_[wire_i];
    w_in->wait_setup();
  }
}

void BooleanSWIFTSHUFFLEGate::evaluate_setup_with_context(MOTION::ExecutionContext& exec_ctx) {
  return;
  for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
    const auto& w_in = inputs_[wire_i];
    w_in->wait_setup();
  }
  this->set_setup_ready();
}

void BooleanSWIFTSHUFFLEGate::evaluate_online() {
  // TODO(pranav): Implement this as well.
  throw std::runtime_error("Not yet implemented.");
  for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
    const auto& w_in = inputs_[wire_i];
    w_in->wait_online();
    auto& w_o = outputs_[wire_i];
    w_o->get_public_share() = ~w_in->get_public_share();
    w_o->set_online_ready();
  }
}

void BooleanSWIFTSHUFFLEGate::evaluate_online_with_context(MOTION::ExecutionContext& exec_ctx) {
  // THERE IS NO SETUP PHASE HERE!!!!!
  // this->wait_setup();
  // Get RSS sharing.
  BooleanSWIFTWireVector rss_shares = inputs_;
  for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
    const auto& w_in = inputs_[wire_i];
    w_in->wait_setup();
    w_in->wait_online();
  }
  for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
    auto& wire = rss_shares[wire_i];
    wire->get_secret_share()[0] ^= wire->get_public_share();
  }

  auto my_id = swift_provider_.get_my_id();
  auto num_simd = inputs_[0]->get_num_simd();

  // First round //////////////////////////////////////////////////////
  // Fix share[0] and share[1].
  if (my_id == 2) {
    for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
      auto& wire = rss_shares[wire_i];
      wire->get_secret_share()[0] = random_vectors_[0][2][wire_i];
      wire->get_secret_share()[1] = random_vectors_[0][1][wire_i];
    }
  } else {
    ENCRYPTO::BitVector<> for_other_party;
    for_other_party.Reserve(Helpers::Convert::BitsToBytes(num_wires_ * num_simd));
    for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
      auto& wire = rss_shares[wire_i];
      // gives us pi_A, pi_B, pi_C.
      for (int i = 0 ; i < 3; ++i) {
        wire->get_secret_share()[i] = permute_with_seed(wire->get_secret_share()[i], seeds_[0][0]);
      }
    }
    if (my_id == 0) {
      for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
        auto& wire = rss_shares[wire_i];
        auto wire_op = wire->get_secret_share()[0] ^ random_vectors_[0][2][wire_i];
        for_other_party.Append(wire_op);
      }
      assert(for_other_party.GetSize() == num_wires_ * num_simd);

      swift_provider_.send_bits_message(1, this->gate_id_, for_other_party);

      auto from_other_party = share_futures_[1].get();
      // for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
      //   auto& wire = rss_shares[wire_i];
      //   auto wire_op = wire->get_secret_share()[0] ^ random_vectors_[0][0][wire_i];
      //   for_other_party.Append(wire_op);
      // }
      for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
        auto& wire = rss_shares[wire_i];
        auto for_other = for_other_party.Subset(wire_i*num_simd, (wire_i+1)*num_simd);
        auto from_other = from_other_party.Subset(wire_i*num_simd, (wire_i+1)*num_simd);
        wire->get_secret_share()[0] = random_vectors_[0][2][wire_i];
        wire->get_secret_share()[2] = wire->get_secret_share()[2] ^
        for_other ^ from_other;
      }
    } else {
      for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
        auto& wire = rss_shares[wire_i];
        auto wire_op = wire->get_secret_share()[1] ^ random_vectors_[0][1][wire_i];
        for_other_party.Append(wire_op);
      }
      assert(for_other_party.GetSize() == num_wires_ * num_simd);

      swift_provider_.send_bits_message(0, this->gate_id_, for_other_party);

      auto from_other_party = share_futures_[0].get();
      // for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
      //   auto& wire = rss_shares[wire_i];
      //   auto wire_op = wire->get_secret_share()[0] ^ random_vectors_[0][0][wire_i];
      //   for_other_party.Append(wire_op);
      // }
      for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
        auto& wire = rss_shares[wire_i];
        auto for_other = for_other_party.Subset(wire_i*num_simd, (wire_i+1)*num_simd);
        auto from_other = from_other_party.Subset(wire_i*num_simd, (wire_i+1)*num_simd);
        wire->get_secret_share()[1] = random_vectors_[0][1][wire_i];
        wire->get_secret_share()[2] = wire->get_secret_share()[2] ^
        for_other ^ from_other;
      }
    }
  }
  // Second round //////////////////////////////////////////////////////
  // Fix share[1] and share[2].
  if (my_id == 1) {
    for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
      auto& wire = rss_shares[wire_i];
      wire->get_secret_share()[1] = random_vectors_[1][1][wire_i];
      wire->get_secret_share()[2] = random_vectors_[1][0][wire_i];
    }
  } else {
    ENCRYPTO::BitVector<> for_other_party;
    for_other_party.Reserve(Helpers::Convert::BitsToBytes(num_wires_ * num_simd));
    for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
      auto& wire = rss_shares[wire_i];
      // gives us pi_A, pi_B, pi_C.
      for (int i = 0 ; i < 3; ++i) {
        wire->get_secret_share()[i] = permute_with_seed(wire->get_secret_share()[i], seeds_[1][2]);
      }
    }
    if (my_id == 0) {
      for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
        auto& wire = rss_shares[wire_i];
        auto wire_op = wire->get_secret_share()[2] ^ random_vectors_[1][0][wire_i];
        for_other_party.Append(wire_op);
      }
      assert(for_other_party.GetSize() == num_wires_ * num_simd);

      swift_provider_.send_bits_message(2, this->gate_id_, for_other_party);

      auto from_other_party = share_futures_[2].get();
      for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
        auto& wire = rss_shares[wire_i];
        auto for_other = for_other_party.Subset(wire_i*num_simd, (wire_i+1)*num_simd);
        auto from_other = from_other_party.Subset(wire_i*num_simd, (wire_i+1)*num_simd);
        wire->get_secret_share()[2] = random_vectors_[1][0][wire_i];
        wire->get_secret_share()[0] = wire->get_secret_share()[0] ^
        for_other ^ from_other;
      }
    } else {
      for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
        auto& wire = rss_shares[wire_i];
        auto wire_op = wire->get_secret_share()[1] ^ random_vectors_[1][1][wire_i];
        for_other_party.Append(wire_op);
      }
      assert(for_other_party.GetSize() == num_wires_ * num_simd);

      swift_provider_.send_bits_message(0, this->gate_id_, for_other_party);

      auto from_other_party = share_futures_[0].get();
      for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
        auto& wire = rss_shares[wire_i];
        auto for_other = for_other_party.Subset(wire_i*num_simd, (wire_i+1)*num_simd);
        auto from_other = from_other_party.Subset(wire_i*num_simd, (wire_i+1)*num_simd);
        wire->get_secret_share()[1] = random_vectors_[1][1][wire_i];
        wire->get_secret_share()[0] = wire->get_secret_share()[0] ^
        for_other ^ from_other;
      }
    }
  }

  // Third round //////////////////////////////////////////////////////
  // Fix share[0] and share[2].
  if (my_id == 0) {
    for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
      auto& wire = rss_shares[wire_i];
      wire->get_secret_share()[0] = random_vectors_[2][2][wire_i];
      wire->get_secret_share()[2] = random_vectors_[2][0][wire_i];
    }
  } else {
    ENCRYPTO::BitVector<> for_other_party;
    for_other_party.Reserve(Helpers::Convert::BitsToBytes(num_wires_ * num_simd));
    for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
      auto& wire = rss_shares[wire_i];
      // gives us pi_A, pi_B, pi_C.
      for (int i = 0 ; i < 3; ++i) {
        wire->get_secret_share()[i] = permute_with_seed(wire->get_secret_share()[i], seeds_[2][1]);
      }
    }
    if (my_id == 1) {
      for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
        auto& wire = rss_shares[wire_i];
        auto wire_op = wire->get_secret_share()[2] ^ random_vectors_[2][0][wire_i];
        for_other_party.Append(wire_op);
      }
      assert(for_other_party.GetSize() == num_wires_ * num_simd);

      swift_provider_.send_bits_message(2, this->gate_id_, for_other_party);

      auto from_other_party = share_futures_[2].get();
      for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
        auto& wire = rss_shares[wire_i];
        auto for_other = for_other_party.Subset(wire_i*num_simd, (wire_i+1)*num_simd);
        auto from_other = from_other_party.Subset(wire_i*num_simd, (wire_i+1)*num_simd);
        wire->get_secret_share()[2] = random_vectors_[2][0][wire_i];
        wire->get_secret_share()[1] = wire->get_secret_share()[1] ^
        for_other ^ from_other;
      }
    } else {
      for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
        auto& wire = rss_shares[wire_i];
        auto wire_op = wire->get_secret_share()[0] ^ random_vectors_[2][2][wire_i];
        for_other_party.Append(wire_op);
      }
      assert(for_other_party.GetSize() == num_wires_ * num_simd);

      swift_provider_.send_bits_message(1, this->gate_id_, for_other_party);

      auto from_other_party = share_futures_[1].get();
      for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
        auto& wire = rss_shares[wire_i];
        auto for_other = for_other_party.Subset(wire_i*num_simd, (wire_i+1)*num_simd);
        auto from_other = from_other_party.Subset(wire_i*num_simd, (wire_i+1)*num_simd);
        wire->get_secret_share()[0] = random_vectors_[2][2][wire_i];
        wire->get_secret_share()[1] = wire->get_secret_share()[1] ^
        for_other ^ from_other;
      }
    }
  }

  for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
    auto& wire = outputs_[wire_i];
    for (int i = 0; i < 3; ++i) {
      wire->get_secret_share()[i] = rss_shares[wire_i]->get_secret_share()[i];
    }
    wire->set_setup_ready();
    wire->set_online_ready();
  }
}

BooleanSWIFTSORTGate::BooleanSWIFTSORTGate(std::size_t gate_id, SWIFTProvider& swift_provider,
                                         BooleanSWIFTWireVector&& in)
    : detail::BasicBooleanSWIFTUnaryGate(gate_id, std::move(in),
                                         !swift_provider.is_my_job(gate_id)),
                                         swift_provider_(swift_provider) {
  // num of elements to be sorted = num_simd
  auto my_id = swift_provider_.get_my_id();
  auto num_simd = inputs_[0]->get_num_simd();
  gt_circuit_ =
        circuit_loader_.load_gt_circuit(64, /*depth_optimized=*/true);
  permutation_.resize(num_simd);
  for (std::size_t i = 0; i < num_simd ; ++i) {
    // Set initial permutation as the identity permutation.
    permutation_[i] = i;
  }
  // Specify that the interval [0 ... n-1] is currently unsorted.
  unsorted_intervals_ = {{0, num_simd - 1}};
  if (my_id == 0 || my_id == 1) {
    share_future_ = swift_provider_.register_for_bits_message(1 - my_id, this->gate_id_, num_wires_ * num_simd);
  }
}

void BooleanSWIFTSORTGate::evaluate_setup() {

  for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
    const auto& w_in = inputs_[wire_i];
    w_in->wait_setup();
    auto& w_o = outputs_[wire_i];
    for (std::size_t share_id = 0; share_id < 3; ++share_id) {
      // Output wire secret shares = input wire secret shares.
      w_o->get_secret_share()[share_id] = w_in->get_secret_share()[share_id];
    }
    w_o->set_setup_ready();
  }
}

void BooleanSWIFTSORTGate::evaluate_setup_with_context(MOTION::ExecutionContext& exec_ctx) {

  for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
    const auto& w_in = inputs_[wire_i];
    w_in->wait_setup();
    auto& w_o = outputs_[wire_i];
    for (std::size_t share_id = 0; share_id < 3; ++share_id) {
      // Output wire secret shares = input wire secret shares.
      w_o->get_secret_share()[share_id] = w_in->get_secret_share()[share_id];
    }
    w_o->set_setup_ready();
  }
  this->set_setup_ready();
}

void BooleanSWIFTSORTGate::evaluate_online() {

  auto my_id = swift_provider_.get_my_id();
  auto num_simd = inputs_[0]->get_num_simd();
  for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
    const auto& w_in = inputs_[wire_i];
    w_in->wait_online();
  }
  while(!unsorted_intervals_.empty()) {
    // Make a new gate!
    std::vector<std::pair<std::size_t, std::size_t> > future_intervals_;
    std::size_t new_gate_num_simd = 0;
    for (auto& it : unsorted_intervals_) {
      new_gate_num_simd += (it.second - it.first + 1);
    }
    BooleanSWIFTWireVector A(num_wires_);
    BooleanSWIFTWireVector B(num_wires_);
    for (int wire_i = 0; wire_i < num_wires_; ++wire_i) {
      A[wire_i] = std::make_shared<BooleanSWIFTWire>(new_gate_num_simd);
      B[wire_i] = std::make_shared<BooleanSWIFTWire>(new_gate_num_simd);
    }
    std::size_t cur_idx = 0;
    for (auto &it : unsorted_intervals_) {
      const std::size_t strt = it.first;
      const std::size_t ed = it.second;
      if (strt == ed) {
        continue;
      }
      assert(strt < ed);
      const std::size_t pivot_idx = strt;

      for (std::size_t i = strt; i <= ed; ++i) {
        for (std::size_t j = 0; j < num_wires_; ++j) {
          const auto& ia = inputs_[j];
          A[j]->get_secret_share()[0].Set(
            ia->get_secret_share()[0].
          Get(permutation_[i]),
           cur_idx);
          A[j]->get_secret_share()[1].Set(ia->get_secret_share()[1].
          Get(permutation_[i]), cur_idx);
          A[j]->get_secret_share()[2].Set(ia->get_secret_share()[1].
          Get(permutation_[i]), cur_idx);

          A[j]->get_public_share().Set(ia->get_public_share().
          Get(permutation_[i]), cur_idx);

          //////////////

          B[j]->get_secret_share()[0].Set(
            ia->get_secret_share()[0].
          Get(permutation_[pivot_idx]),
           cur_idx);
          B[j]->get_secret_share()[1].Set(ia->get_secret_share()[1].
          Get(permutation_[pivot_idx]), cur_idx);
          B[j]->get_secret_share()[2].Set(ia->get_secret_share()[1].
          Get(permutation_[pivot_idx]), cur_idx);

          B[j]->get_public_share().Set(ia->get_public_share().
          Get(permutation_[pivot_idx]), cur_idx);
        }
        ++cur_idx;
      }
    }
    for (std::size_t j = 0; j < num_wires_; ++j) {
      A[j]->set_setup_ready();
      A[j]->set_online_ready();
      B[j]->set_setup_ready();
      B[j]->set_online_ready();
    }
      WireVector AA = cast_wires(A);
      WireVector BB = cast_wires(B);
      AA.insert(
        AA.end(),
        std::make_move_iterator(BB.begin()),
        std::make_move_iterator(BB.end())
      );
      auto [gates, output_wires] = construct_two_input_circuit(swift_provider_, gt_circuit_, AA);
      assert(output_wires.size() == 1);
      for (auto& gate : gates) {
        gate->evaluate_setup();
      }

      for (auto& gate : gates) {
        gate->evaluate_online();
      }
      auto comparision_results_future = swift_provider_.make_boolean_output_gate_my(MOTION::ALL_PARTIES, output_wires);
      auto comparision_results = comparision_results_future.get();
      assert(comparision_results.size() == 1);
      cur_idx = 0;
      assert(comparision_results[0].GetSize() == new_gate_num_simd);
      std::vector<std::pair<std::size_t, std::size_t>> new_intervals;
      for (const auto& it : unsorted_intervals_) {
        const std::size_t strt = it.first;
        const std::size_t ed = it.second;
        std::size_t p = ed + 1;
        for (std::size_t i = strt; i < ed; ++i) {
          std::size_t result_idx = cur_idx + (i - strt);
          // Means array elemet at i is greater than pivot element.
          if (comparision_results[0].Get(result_idx) == 1) {
            p--;
            std::swap(permutation_[i], permutation_[p]);
          }
        }
        p--; std::swap(permutation_[strt], permutation_[p]);
        // insert strt, p-1 as a new interval.
        if (strt < p-1) {
          new_intervals.push_back({strt, p-1});
        }
        // insert p+1, ed as a new interval.
        if (p+1 < ed) {
          new_intervals.push_back({p+1, ed});
        }
        cur_idx += (ed - strt + 1);
      }
      assert(cur_idx == new_gate_num_simd);
      unsorted_intervals_.clear(); unsorted_intervals_ = new_intervals;
    
  } // One sorting pass finishes. ~log(n) total of these.

  if (my_id != 2) {
    ENCRYPTO::BitVector<> for_other_party(num_wires_ * num_simd);
    for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
      for (std::size_t i = 0; i < num_simd; ++i) {
        bool to_send = false;
        if (my_id == 0) {
          to_send = outputs_[wire_i]->get_secret_share()[0].Get(i) ^ 
          inputs_[wire_i]->get_secret_share()[0].Get(permutation_[i]);
        } else {
          to_send = outputs_[wire_i]->get_secret_share()[1].Get(i) ^ 
          inputs_[wire_i]->get_secret_share()[1].Get(permutation_[i]);
        }
        for_other_party.Set(to_send, wire_i*num_simd + i);
      }
    }
    swift_provider_.send_bits_message(1 - my_id, this->gate_id_, for_other_party);
    const auto from_other_party = share_future_.get();

    for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
      for (std::size_t i = 0; i < num_simd; ++i) {
        bool new_public_value = from_other_party.Get(wire_i*num_simd + i) ^ 
        inputs_[wire_i]->get_public_share().Get(permutation_[i]) ^
        outputs_[wire_i]->get_secret_share()[2].Get(i) ^
        inputs_[wire_i]->get_secret_share()[2].Get(permutation_[i]);
        if (my_id == 0) {
          new_public_value ^= outputs_[wire_i]->get_secret_share()[0].Get(i) ^
          inputs_[wire_i]->get_secret_share()[0].Get(permutation_[i]);
        } else {
          new_public_value ^= outputs_[wire_i]->get_secret_share()[1].Get(i) ^
          inputs_[wire_i]->get_secret_share()[1].Get(permutation_[i]);
        }
        outputs_[wire_i]->get_public_share().Set(new_public_value, i);
      }
      outputs_[wire_i]->set_online_ready();
    }
  } else {
    for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
      outputs_[wire_i]->set_online_ready();
    }
  }
}

void BooleanSWIFTSORTGate::evaluate_online_with_context(MOTION::ExecutionContext& exec_ctx) {

  this->wait_setup();
  auto my_id = swift_provider_.get_my_id();
  auto num_simd = inputs_[0]->get_num_simd();
  for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
    const auto& w_in = inputs_[wire_i];
    w_in->wait_online();
  }
  while(!unsorted_intervals_.empty()) {
    ENCRYPTO::FiberThreadPool local_setup_pool(0);
    ENCRYPTO::FiberThreadPool local_online_pool(0);
    // Make a new gate!
    std::vector<std::pair<std::size_t, std::size_t> > future_intervals_;
    std::size_t new_gate_num_simd = 0;
    for (auto& it : unsorted_intervals_) {
      new_gate_num_simd += (it.second - it.first + 1);
    }
    BooleanSWIFTWireVector A(num_wires_);
    BooleanSWIFTWireVector B(num_wires_);
    for (int wire_i = 0; wire_i < num_wires_; ++wire_i) {
      A[wire_i] = std::make_shared<BooleanSWIFTWire>(new_gate_num_simd);
      B[wire_i] = std::make_shared<BooleanSWIFTWire>(new_gate_num_simd);
    }
    std::size_t cur_idx = 0;
    for (auto &it : unsorted_intervals_) {
      const std::size_t strt = it.first;
      const std::size_t ed = it.second;
      if (strt == ed) {
        continue;
      }
      assert(strt < ed);
      const std::size_t pivot_idx = strt;

      for (std::size_t i = strt; i <= ed; ++i) {
        for (std::size_t j = 0; j < num_wires_; ++j) {
          const auto& ia = inputs_[j];
          A[j]->get_secret_share()[0].Set(
            ia->get_secret_share()[0].
          Get(permutation_[i]),
           cur_idx);
          A[j]->get_secret_share()[1].Set(ia->get_secret_share()[1].
          Get(permutation_[i]), cur_idx);
          A[j]->get_secret_share()[2].Set(ia->get_secret_share()[2].
          Get(permutation_[i]), cur_idx);

          A[j]->get_public_share().Set(ia->get_public_share().
          Get(permutation_[i]), cur_idx);

          //////////////

          B[j]->get_secret_share()[0].Set(
            ia->get_secret_share()[0].
          Get(permutation_[pivot_idx]),
           cur_idx);
          B[j]->get_secret_share()[1].Set(ia->get_secret_share()[1].
          Get(permutation_[pivot_idx]), cur_idx);
          B[j]->get_secret_share()[2].Set(ia->get_secret_share()[2].
          Get(permutation_[pivot_idx]), cur_idx);

          B[j]->get_public_share().Set(ia->get_public_share().
          Get(permutation_[pivot_idx]), cur_idx);
        }
        ++cur_idx;
      }
    }
    for (std::size_t j = 0; j < num_wires_; ++j) {
      A[j]->set_setup_ready();
      A[j]->set_online_ready();
      B[j]->set_setup_ready();
      B[j]->set_online_ready();
    }
      WireVector AA = cast_wires(A);
      WireVector BB = cast_wires(B);
      AA.insert(
        AA.end(),
        std::make_move_iterator(BB.begin()),
        std::make_move_iterator(BB.end())
      );
      
      auto [gates, output_wires] = construct_two_input_circuit(swift_provider_, gt_circuit_, AA);
      gates_.push_back(std::move(gates));
      all_wires_.push_back(std::move(output_wires));
      assert(all_wires_.back().size() == 1);
      auto [opgate, comparision_results_future] = swift_provider_.
      make_external_boolean_output_gate_my(MOTION::ALL_PARTIES, all_wires_.back());
      gates_.back().push_back(std::move(opgate));
      swift_provider_.wait_for_others();
      for (auto& gate : gates_.back()) {
        local_setup_pool.post([&] { gate->evaluate_setup(); });
      }
      // local_setup_pool.join();
      // opgate->evaluate_setup();
      // swift_provider_.wait_for_others();

      for (auto& gate : gates_.back()) {
        local_online_pool.post([&] { gate->evaluate_online(); });
      }
      // local_online_pool.join();
      // opgate->evaluate_online();
      // local_setup_pool.join();
      // local_online_pool.join();
      // swift_provider_.wait_for_others();
      auto comparision_results = comparision_results_future.get();
      // comparision_results.push_back(res[0]);
      assert(comparision_results.size() == 1);
      cur_idx = 0;
      assert(comparision_results[0].GetSize() == new_gate_num_simd);
      std::vector<std::pair<std::size_t, std::size_t>> new_intervals;
      for (const auto& it : unsorted_intervals_) {
        const int strt = it.first;
        const int ed = it.second;
        int p = ed + 1;
        for (int i = ed; i >= strt; i--) {
          int result_idx = cur_idx + (i - strt);
          // Means array elemet at i is greater than pivot element.
          if (comparision_results[0].Get(result_idx) == 1) {
            p--;
            std::swap(permutation_[i], permutation_[p]);
          }
        }
        p--; std::swap(permutation_[strt], permutation_[p]);
        // insert strt, p-1 as a new interval.
        if (strt < p-1 && p > 0) {
          new_intervals.push_back({strt, p-1});
        }
        // insert p+1, ed as a new interval.
        if (p+1 < ed) {
          new_intervals.push_back({p+1, ed});
        }
        cur_idx += (ed - strt + 1);
      }
      assert(cur_idx == new_gate_num_simd);
      unsorted_intervals_.clear(); unsorted_intervals_ = new_intervals;
    
  } // One sorting pass finishes. ~log(n) total of these.

  if (my_id != 2) {
    ENCRYPTO::BitVector<> for_other_party(num_wires_ * num_simd);
    for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
      for (std::size_t i = 0; i < num_simd; ++i) {
        bool to_send = false;
        if (my_id == 0) {
          to_send = outputs_[wire_i]->get_secret_share()[0].Get(i) ^ 
          inputs_[wire_i]->get_secret_share()[0].Get(permutation_[i]);
        } else {
          to_send = outputs_[wire_i]->get_secret_share()[1].Get(i) ^ 
          inputs_[wire_i]->get_secret_share()[1].Get(permutation_[i]);
        }
        for_other_party.Set(to_send, wire_i*num_simd + i);
      }
    }
    swift_provider_.send_bits_message(1 - my_id, this->gate_id_, for_other_party);
    const auto from_other_party = share_future_.get();

    for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
      for (std::size_t i = 0; i < num_simd; ++i) {
        bool new_public_value = from_other_party.Get(wire_i*num_simd + i) ^ 
        inputs_[wire_i]->get_public_share().Get(permutation_[i]) ^
        outputs_[wire_i]->get_secret_share()[2].Get(i) ^
        inputs_[wire_i]->get_secret_share()[2].Get(permutation_[i]);
        if (my_id == 0) {
          new_public_value ^= outputs_[wire_i]->get_secret_share()[0].Get(i) ^
          inputs_[wire_i]->get_secret_share()[0].Get(permutation_[i]);
        } else {
          new_public_value ^= outputs_[wire_i]->get_secret_share()[1].Get(i) ^
          inputs_[wire_i]->get_secret_share()[1].Get(permutation_[i]);
        }
        outputs_[wire_i]->get_public_share().Set(new_public_value, i);
      }
      outputs_[wire_i]->set_online_ready();
    }
  } else {
    for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
      outputs_[wire_i]->set_online_ready();
    }
  }
  
}

BooleanSWIFTXORGate::BooleanSWIFTXORGate(std::size_t gate_id, SWIFTProvider&,
                                         BooleanSWIFTWireVector&& in_a,
                                         BooleanSWIFTWireVector&& in_b)
    : detail::BasicBooleanSWIFTBinaryGate(gate_id, std::move(in_a), std::move(in_b)) {}

void BooleanSWIFTXORGate::evaluate_setup() {
  for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
    const auto& w_a = inputs_a_[wire_i];
    const auto& w_b = inputs_b_[wire_i];
    w_a->wait_setup();
    w_b->wait_setup();
    auto& w_o = outputs_[wire_i];
    for (std::size_t share_id = 0; share_id < 3; ++share_id) {
      w_o->get_secret_share()[share_id] =
       w_a->get_secret_share()[share_id] ^ w_b->get_secret_share()[share_id];
    }
    w_o->set_setup_ready();
  }
  this->set_setup_ready();
}

void BooleanSWIFTXORGate::evaluate_online() {
  this->wait_setup();
  for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
    const auto& w_a = inputs_a_[wire_i];
    const auto& w_b = inputs_b_[wire_i];
    w_a->wait_online();
    w_b->wait_online();
    auto& w_o = outputs_[wire_i];
    w_o->get_public_share() = w_a->get_public_share() ^ w_b->get_public_share();
    w_o->set_online_ready();
  }
}

BooleanSWIFTANDGate::BooleanSWIFTANDGate(std::size_t gate_id, SWIFTProvider& swift_provider,
                                         BooleanSWIFTWireVector&& in_a,
                                         BooleanSWIFTWireVector&& in_b)
    : detail::BasicBooleanSWIFTBinaryGate(gate_id, std::move(in_a), std::move(in_b)),
      swift_provider_(swift_provider) {
  auto num_bits = count_bits(inputs_a_);
  auto my_id = swift_provider_.get_my_id();
  delta_ab_.Reserve(Helpers::Convert::BitsToBytes(num_bits));
  if (my_id != 2) {
    share_future_ = swift_provider_.register_for_bits_message(1 - my_id, this->gate_id_,
                                                                num_bits, 0);
    share_future_offline_ = swift_provider_.register_for_bits_message(2, this->gate_id_,
                                                                        num_bits, 1);
  }
}

BooleanSWIFTANDGate::~BooleanSWIFTANDGate() = default;

void BooleanSWIFTANDGate::evaluate_setup() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format("Gate {}: BooleanSWIFTANDGate::evaluate_setup start", gate_id_));
    }
  }

  auto my_id = swift_provider_.get_my_id();
  auto num_simd = inputs_a_[0]->get_num_simd();
  auto num_bytes = Helpers::Convert::BitsToBytes(num_wires_ * num_simd);

  for (auto& wire_o : outputs_) {
    for (int share_id = 0; share_id < 3; ++share_id) {
      int modd = (share_id  % 2);
      wire_o->get_secret_share()[share_id] = ENCRYPTO::BitVector<>(wire_o->get_num_simd(), modd);
    }
    // wire_o->set_setup_ready();
  }

  for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
    const auto& wire_a = inputs_a_[wire_i];
    const auto& wire_b = inputs_b_[wire_i];
    const auto& wire_o = outputs_[wire_i];
    wire_a->wait_setup();
    wire_b->wait_setup();
    if (my_id == 2) {
      ENCRYPTO::BitVector<> wire_share(num_simd, 0);
      for (int i = 0; i < 2; ++i) {
        for (int j=0;j < 2; ++j) {
          auto bitsett = wire_a->get_secret_share()[i] & wire_b->get_secret_share()[j];
          wire_share ^= bitsett;
        }
      }
      delta_ab_.Append(wire_share);
    }
  }
  if (my_id == 2) {
    assert(delta_ab_.GetSize() == num_simd * num_wires_);
  }
  if (my_id == 0 || my_id == 1) {
      delta_ab_ = share_future_offline_.get();
  } else {
      swift_provider_.send_bits_message(0, this->gate_id_, delta_ab_, 1);
      swift_provider_.send_bits_message(1, this->gate_id_, delta_ab_, 1);
  }

  for (auto& wire_o : outputs_) {
    wire_o->set_setup_ready();
  }
  this->set_setup_ready();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format("Gate {}: BooleanSWIFTANDGate::evaluate_setup end", gate_id_));
    }
  }
}

void BooleanSWIFTANDGate::evaluate_online() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format("Gate {}: BooleanSWIFTANDGate::evaluate_online start", gate_id_));
    }
  }

  this->wait_setup();

  auto my_id = swift_provider_.get_my_id();
  auto num_simd = inputs_a_[0]->get_num_simd();
  auto num_bits = num_wires_ * num_simd;

  if (my_id == 2) {
    for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
      this->outputs_[wire_i]->set_online_ready();
    }
    return;
  }

  ENCRYPTO::BitVector<> for_other_party;
  for_other_party.Reserve(Helpers::Convert::BitsToBytes(num_bits));

  for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
    auto& wire_a = this->inputs_a_[wire_i];
    auto& wire_b = this->inputs_b_[wire_i];
    wire_a->wait_online();
    wire_b->wait_online();
    this->outputs_[wire_i]->wait_setup();
    auto& a_sec_share = wire_a->get_secret_share();
    auto& b_sec_share = wire_b->get_secret_share();
    auto& a_pub_share = wire_a->get_public_share();
    auto& b_pub_share = wire_b->get_public_share();
    const auto& op_sec_share = this->outputs_[wire_i]->get_secret_share();

    ENCRYPTO::BitVector<> wire_data(num_simd, 0);
    // TODO(pranav): Check the correctness of this complication again.
    auto y1 = (a_sec_share[0]&b_pub_share) ^ (a_pub_share&b_sec_share[0]) ^ (op_sec_share[0]);
    auto y2 = (a_sec_share[1]&b_pub_share) ^ (a_pub_share&b_sec_share[1]) ^ (op_sec_share[1]);
    auto y3 = (a_sec_share[2]&b_pub_share) ^ (a_pub_share&b_sec_share[2]) ^ (op_sec_share[2]);

    if (my_id == 0) {
      for_other_party.Append(y1 ^ (a_sec_share[0]&b_sec_share[2]) ^ (a_sec_share[2]&b_sec_share[0]));
    } else {
      for_other_party.Append(y2 ^ (a_sec_share[1]&b_sec_share[2]) ^ (a_sec_share[2]&b_sec_share[1]));
    }
  }
  assert(for_other_party.GetSize() == num_bits);
  assert(delta_ab_.GetSize() == num_bits);
  swift_provider_.send_bits_message(1 - my_id, this->gate_id_, for_other_party, 0);
  auto from_other_party = share_future_.get();

  for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
    const auto& part1 = delta_ab_.Subset(num_simd*wire_i, num_simd*(wire_i + 1));
    const auto& part2 = from_other_party.Subset(num_simd*wire_i, num_simd*(wire_i + 1));
    auto& wire_a = this->inputs_a_[wire_i];
    auto& wire_b = this->inputs_b_[wire_i];
    auto& a_sec_share = wire_a->get_secret_share();
    auto& b_sec_share = wire_b->get_secret_share();
    auto& a_pub_share = wire_a->get_public_share();
    auto& b_pub_share = wire_b->get_public_share();
    const auto& op_sec_share = this->outputs_[wire_i]->get_secret_share();

    auto& opshare = this->outputs_[wire_i]->get_public_share();
    opshare = (part1 ^ part2);

    auto y1 = (a_sec_share[0]&b_pub_share) ^ (a_pub_share&b_sec_share[0]) ^ (op_sec_share[0]);
    auto y2 = (a_sec_share[1]&b_pub_share) ^ (a_pub_share&b_sec_share[1]) ^ (op_sec_share[1]);
    auto y3 = (a_sec_share[2]&b_pub_share) ^ (a_pub_share&b_sec_share[2]) ^ (op_sec_share[2]);

    opshare ^= (y3 ^ (a_pub_share & b_pub_share));

    if (my_id == 0) {
      opshare ^= (a_sec_share[0]&b_sec_share[2]) ^ (a_sec_share[2]&b_sec_share[0]) ^ (a_sec_share[2]&b_sec_share[2]) ^ 
                  y1;
    } else {
      opshare ^= (a_sec_share[1]&b_sec_share[2]) ^ (a_sec_share[2]&b_sec_share[1]) ^ (a_sec_share[2]&b_sec_share[2]) ^
                   y2;
    }
    this->outputs_[wire_i]->set_online_ready();
  }

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format("Gate {}: BooleanSWIFTANDGate::evaluate_online end", gate_id_));
    }
  }
}

template <typename T>
ArithmeticSWIFTInputGateSender<T>::ArithmeticSWIFTInputGateSender(
    std::size_t gate_id, SWIFTProvider& swift_provider, std::size_t num_simd,
    ENCRYPTO::ReusableFiberFuture<std::vector<T>>&& input_future)
    : NewGate(gate_id),
      swift_provider_(swift_provider),
      num_simd_(num_simd),
      input_id_(swift_provider.get_next_input_id(1)),
      input_future_(std::move(input_future)),
      output_(std::make_shared<ArithmeticSWIFTWire<T>>(num_simd)) {
  output_->get_public_share().resize(num_simd, 0);
}

template <typename T>
void ArithmeticSWIFTInputGateSender<T>::evaluate_setup() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: ArithmeticSWIFTInputGateSender<T>::evaluate_setup start", gate_id_));
    }
  }
  throw std::runtime_error("Not yet implemented");

  // auto my_id = swift_provider_.get_my_id();
  // auto num_parties = swift_provider_.get_num_parties();
  // auto& mbp = swift_provider_.get_motion_base_provider();
  // auto& my_secret_share = output_->get_secret_share();
  // auto& my_public_share = output_->get_public_share();
  // my_secret_share = Helpers::RandomVector<T>(num_simd_);
  // output_->set_setup_ready();
  // my_public_share = my_secret_share;
  // for (std::size_t party_id = 0; party_id < num_parties; ++party_id) {
  //   if (party_id == my_id) {
  //     continue;
  //   }
  //   auto& rng = mbp.get_my_randomness_generator(party_id);
  //   std::transform(std::begin(my_public_share), std::end(my_public_share),
  //                  std::begin(rng.GetUnsigned<T>(input_id_, num_simd_)),
  //                  std::begin(my_public_share), std::plus{});
  // }

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticSWIFTInputGateSender<T>::evaluate_setup end", gate_id_));
    }
  }
}

template <typename T>
void ArithmeticSWIFTInputGateSender<T>::evaluate_online() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: ArithmeticSWIFTInputGateSender<T>::evaluate_online start", gate_id_));
    }
  }

  throw std::runtime_error("Not yet implemented");

  // // wait for input value
  // const auto input = input_future_.get();
  // if (input.size() != num_simd_) {
  //   throw std::runtime_error("size of input bit vector != num_simd_");
  // }

  // // compute my share
  // auto& my_public_share = output_->get_public_share();
  // std::transform(std::begin(my_public_share), std::end(my_public_share), std::begin(input),
  //                std::begin(my_public_share), std::plus{});
  // output_->set_online_ready();
  // swift_provider_.broadcast_ints_message(gate_id_, my_public_share);

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticSWIFTInputGateSender<T>::evaluate_online end", gate_id_));
    }
  }
}

template class ArithmeticSWIFTInputGateSender<std::uint8_t>;
template class ArithmeticSWIFTInputGateSender<std::uint16_t>;
template class ArithmeticSWIFTInputGateSender<std::uint32_t>;
template class ArithmeticSWIFTInputGateSender<std::uint64_t>;

template <typename T>
ArithmeticSWIFTInputGateReceiver<T>::ArithmeticSWIFTInputGateReceiver(std::size_t gate_id,
                                                                      SWIFTProvider& swift_provider,
                                                                      std::size_t num_simd,
                                                                      std::size_t input_owner)
    : NewGate(gate_id),
      swift_provider_(swift_provider),
      num_simd_(num_simd),
      input_owner_(input_owner),
      input_id_(swift_provider.get_next_input_id(1)),
      output_(std::make_shared<ArithmeticSWIFTWire<T>>(num_simd)) {
  public_share_future_ =
      swift_provider_.register_for_ints_message<T>(input_owner_, gate_id_, num_simd);
}

template <typename T>
void ArithmeticSWIFTInputGateReceiver<T>::evaluate_setup() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: ArithmeticSWIFTInputGateReceiver<T>::evaluate_setup start", gate_id_));
    }
  }
  throw std::runtime_error("Not yet implemented");

  // auto& mbp = swift_provider_.get_motion_base_provider();
  // auto& rng = mbp.get_their_randomness_generator(input_owner_);
  // output_->get_secret_share() = rng.GetUnsigned<T>(input_id_, num_simd_);
  // output_->set_setup_ready();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: ArithmeticSWIFTInputGateReceiver<T>::evaluate_setup end", gate_id_));
    }
  }
}

template <typename T>
void ArithmeticSWIFTInputGateReceiver<T>::evaluate_online() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: ArithmeticSWIFTInputGateReceiver<T>::evaluate_online start", gate_id_));
    }
  }
  throw std::runtime_error("Not yet implemented");

  // output_->get_public_share() = public_share_future_.get();
  // output_->set_online_ready();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: ArithmeticSWIFTInputGateReceiver<T>::evaluate_online end", gate_id_));
    }
  }
}

template class ArithmeticSWIFTInputGateReceiver<std::uint8_t>;
template class ArithmeticSWIFTInputGateReceiver<std::uint16_t>;
template class ArithmeticSWIFTInputGateReceiver<std::uint32_t>;
template class ArithmeticSWIFTInputGateReceiver<std::uint64_t>;

template <typename T>
ArithmeticSWIFTOutputGate<T>::ArithmeticSWIFTOutputGate(std::size_t gate_id,
                                                        SWIFTProvider& swift_provider,
                                                        ArithmeticSWIFTWireP<T>&& input,
                                                        std::size_t output_owner)
    : NewGate(gate_id),
      swift_provider_(swift_provider),
      output_owner_(output_owner),
      input_(std::move(input)) {
  std::size_t my_id = swift_provider_.get_my_id();
  if (output_owner_ == ALL_PARTIES || output_owner_ == my_id) {
    share_future_ =
        swift_provider_.register_for_ints_message<T>(1 - my_id, gate_id_, input_->get_num_simd());
  }
}

template <typename T>
ENCRYPTO::ReusableFiberFuture<std::vector<T>> ArithmeticSWIFTOutputGate<T>::get_output_future() {
  std::size_t my_id = swift_provider_.get_my_id();
  if (output_owner_ == ALL_PARTIES || output_owner_ == my_id) {
    return output_promise_.get_future();
  } else {
    throw std::logic_error("not this parties output");
  }
}

template <typename T>
void ArithmeticSWIFTOutputGate<T>::evaluate_setup() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticSWIFTOutputGate<T>::evaluate_setup start", gate_id_));
    }
  }

  throw std::runtime_error("Not yet implemented");

  // std::size_t my_id = swift_provider_.get_my_id();
  // if (output_owner_ != my_id) {
  //   input_->wait_setup();
  //   auto my_secret_share = input_->get_secret_share();
  //   if (output_owner_ == ALL_PARTIES) {
  //     swift_provider_.broadcast_ints_message(gate_id_, my_secret_share);
  //   } else {
  //     swift_provider_.send_ints_message(output_owner_, gate_id_, my_secret_share);
  //   }
  // }

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticSWIFTOutputGate<T>::evaluate_setup end", gate_id_));
    }
  }
}

template <typename T>
void ArithmeticSWIFTOutputGate<T>::evaluate_online() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticSWIFTOutputGate<T>::evaluate_online start", gate_id_));
    }
  }
  throw std::runtime_error("Not yet implemented");

  // std::size_t my_id = swift_provider_.get_my_id();
  // if (output_owner_ == ALL_PARTIES || output_owner_ == my_id) {
  //   input_->wait_setup();
  //   auto my_secret_share = input_->get_secret_share();
  //   const auto other_secret_share = share_future_.get();
  //   std::transform(std::begin(my_secret_share), std::end(my_secret_share),
  //                  std::begin(other_secret_share), std::begin(my_secret_share), std::plus{});
  //   input_->wait_online();
  //   std::transform(std::begin(input_->get_public_share()), std::end(input_->get_public_share()),
  //                  std::begin(my_secret_share), std::begin(my_secret_share), std::minus{});
  //   output_promise_.set_value(std::move(my_secret_share));
  // }

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticSWIFTOutputGate<T>::evaluate_online end", gate_id_));
    }
  }
}

template class ArithmeticSWIFTOutputGate<std::uint8_t>;
template class ArithmeticSWIFTOutputGate<std::uint16_t>;
template class ArithmeticSWIFTOutputGate<std::uint32_t>;
template class ArithmeticSWIFTOutputGate<std::uint64_t>;

template <typename T>
ArithmeticSWIFTOutputShareGate<T>::ArithmeticSWIFTOutputShareGate(std::size_t gate_id,
                                                    ArithmeticSWIFTWireP<T>&& input)
    : NewGate(gate_id),
      input_(std::move(input)) {
}

template <typename T>
ENCRYPTO::ReusableFiberFuture<std::vector<T>> ArithmeticSWIFTOutputShareGate<T>::get_public_share_future() {
  return public_share_promise_.get_future();
}

template <typename T>
ENCRYPTO::ReusableFiberFuture<std::vector<T>> ArithmeticSWIFTOutputShareGate<T>::get_secret_share_future() {
  return secret_share_promise_.get_future();
}

template <typename T>
void ArithmeticSWIFTOutputShareGate<T>::evaluate_setup() {
  throw std::runtime_error("Not yet implemented");
  // input_->wait_setup();
  // secret_share_promise_.set_value(input_->get_secret_share());
}

template <typename T>
void ArithmeticSWIFTOutputShareGate<T>::evaluate_online() {
  throw std::runtime_error("Not yet implemented");
  // input_->wait_online();
  // public_share_promise_.set_value(input_->get_public_share());
}

template class ArithmeticSWIFTOutputShareGate<std::uint8_t>;
template class ArithmeticSWIFTOutputShareGate<std::uint16_t>;
template class ArithmeticSWIFTOutputShareGate<std::uint32_t>;
template class ArithmeticSWIFTOutputShareGate<std::uint64_t>;

namespace detail {

template <typename T>
BasicArithmeticSWIFTBinaryGate<T>::BasicArithmeticSWIFTBinaryGate(std::size_t gate_id,
                                                                  SWIFTProvider&,
                                                                  ArithmeticSWIFTWireP<T>&& in_a,
                                                                  ArithmeticSWIFTWireP<T>&& in_b)
    : NewGate(gate_id),
      input_a_(std::move(in_a)),
      input_b_(std::move(in_b)),
      output_(std::make_shared<ArithmeticSWIFTWire<T>>(input_a_->get_num_simd())) {
  if (input_a_->get_num_simd() != input_b_->get_num_simd()) {
    throw std::logic_error("number of SIMD values need to be the same for all wires");
  }
}

template class BasicArithmeticSWIFTBinaryGate<std::uint8_t>;
template class BasicArithmeticSWIFTBinaryGate<std::uint16_t>;
template class BasicArithmeticSWIFTBinaryGate<std::uint32_t>;
template class BasicArithmeticSWIFTBinaryGate<std::uint64_t>;

template <typename T>
BasicArithmeticSWIFTUnaryGate<T>::BasicArithmeticSWIFTUnaryGate(std::size_t gate_id, SWIFTProvider&,
                                                                ArithmeticSWIFTWireP<T>&& in)
    : NewGate(gate_id),
      input_(std::move(in)),
      output_(std::make_shared<ArithmeticSWIFTWire<T>>(input_->get_num_simd())) {}

template class BasicArithmeticSWIFTUnaryGate<std::uint8_t>;
template class BasicArithmeticSWIFTUnaryGate<std::uint16_t>;
template class BasicArithmeticSWIFTUnaryGate<std::uint32_t>;
template class BasicArithmeticSWIFTUnaryGate<std::uint64_t>;

// template <typename T>
// BasicBooleanXArithmeticSWIFTBinaryGate<T>::BasicBooleanXArithmeticSWIFTBinaryGate(
//     std::size_t gate_id, SWIFTProvider&, BooleanSWIFTWireP&& in_a, ArithmeticSWIFTWireP<T>&& in_b)
//     : NewGate(gate_id),
//       input_bool_(std::move(in_a)),
//       input_arith_(std::move(in_b)),
//       output_(std::make_shared<ArithmeticSWIFTWire<T>>(input_arith_->get_num_simd())) {
//   if (input_arith_->get_num_simd() != input_bool_->get_num_simd()) {
//     throw std::logic_error("number of SIMD values need to be the same for all wires");
//   }
// }

// template class BasicBooleanXArithmeticSWIFTBinaryGate<std::uint8_t>;
// template class BasicBooleanXArithmeticSWIFTBinaryGate<std::uint16_t>;
// template class BasicBooleanXArithmeticSWIFTBinaryGate<std::uint32_t>;
// template class BasicBooleanXArithmeticSWIFTBinaryGate<std::uint64_t>;

}  // namespace detail

// template <typename T>
// ArithmeticSWIFTNEGGate<T>::ArithmeticSWIFTNEGGate(std::size_t gate_id,
//                                                   SWIFTProvider& swift_provider,
//                                                   ArithmeticSWIFTWireP<T>&& in)
//     : detail::BasicArithmeticSWIFTUnaryGate<T>(gate_id, swift_provider, std::move(in)) {
//   this->output_->get_public_share().resize(this->input_->get_num_simd());
//   this->output_->get_secret_share().resize(this->input_->get_num_simd());
// }

// template <typename T>
// void ArithmeticSWIFTNEGGate<T>::evaluate_setup() {
//   this->input_->wait_setup();
//   assert(this->output_->get_secret_share().size() == this->input_->get_num_simd());
//   std::transform(std::begin(this->input_->get_secret_share()),
//                  std::end(this->input_->get_secret_share()),
//                  std::begin(this->output_->get_secret_share()), std::negate{});
//   this->output_->set_setup_ready();
// }

// template <typename T>
// void ArithmeticSWIFTNEGGate<T>::evaluate_online() {
//   this->input_->wait_online();
//   assert(this->output_->get_public_share().size() == this->input_->get_num_simd());
//   std::transform(std::begin(this->input_->get_public_share()),
//                  std::end(this->input_->get_public_share()),
//                  std::begin(this->output_->get_public_share()), std::negate{});
//   this->output_->set_online_ready();
// }

// template class ArithmeticSWIFTNEGGate<std::uint8_t>;
// template class ArithmeticSWIFTNEGGate<std::uint16_t>;
// template class ArithmeticSWIFTNEGGate<std::uint32_t>;
// template class ArithmeticSWIFTNEGGate<std::uint64_t>;

template <typename T>
ArithmeticSWIFTADDGate<T>::ArithmeticSWIFTADDGate(std::size_t gate_id,
                                                  SWIFTProvider& swift_provider,
                                                  ArithmeticSWIFTWireP<T>&& in_a,
                                                  ArithmeticSWIFTWireP<T>&& in_b)
    : detail::BasicArithmeticSWIFTBinaryGate<T>(gate_id, swift_provider, std::move(in_a),
                                                std::move(in_b)) {
  this->output_->get_public_share().resize(this->input_a_->get_num_simd(), 0);
  for (std::size_t share_id = 0; share_id < 3; ++share_id) {
    this->output_->get_secret_share()[share_id].resize(this->input_a_->get_num_simd(), 0);
  }
}

template <typename T>
void ArithmeticSWIFTADDGate<T>::evaluate_setup() {
  this->input_a_->wait_setup();
  this->input_b_->wait_setup();
  assert(this->output_->get_secret_share().size() == this->input_a_->get_num_simd());
  assert(this->output_->get_secret_share().size() == this->input_b_->get_num_simd());
  for (std::size_t share_id = 0; share_id < 3; ++share_id) {
    std::transform(std::begin(this->input_a_->get_secret_share()[share_id]),
                  std::end(this->input_a_->get_secret_share()[share_id]),
                  std::begin(this->input_b_->get_secret_share()[share_id]),
                  std::begin(this->output_->get_secret_share()[share_id]), std::plus{});
  }
  this->output_->set_setup_ready();
}

template <typename T>
void ArithmeticSWIFTADDGate<T>::evaluate_online() {
  this->input_a_->wait_online();
  this->input_b_->wait_online();
  assert(this->output_->get_public_share().size() == this->input_a_->get_num_simd());
  std::transform(std::begin(this->input_a_->get_public_share()),
                 std::end(this->input_a_->get_public_share()),
                 std::begin(this->input_b_->get_public_share()),
                 std::begin(this->output_->get_public_share()), std::plus{});
  this->output_->set_online_ready();
}

template class ArithmeticSWIFTADDGate<std::uint8_t>;
template class ArithmeticSWIFTADDGate<std::uint16_t>;
template class ArithmeticSWIFTADDGate<std::uint32_t>;
template class ArithmeticSWIFTADDGate<std::uint64_t>;

template <typename T>
ArithmeticSWIFTMULGate<T>::ArithmeticSWIFTMULGate(std::size_t gate_id,
                                                  SWIFTProvider& swift_provider,
                                                  ArithmeticSWIFTWireP<T>&& in_a,
                                                  ArithmeticSWIFTWireP<T>&& in_b)
    : detail::BasicArithmeticSWIFTBinaryGate<T>(gate_id, swift_provider, std::move(in_a),
                                                std::move(in_b)),
      swift_provider_(swift_provider) {
  auto my_id = swift_provider_.get_my_id();
  auto num_simd = this->input_a_->get_num_simd();
  delta_ab_.resize(num_simd, 0);
  if (my_id != 2) {
    share_future_ = swift_provider_.register_for_ints_message<T>(1 - my_id, this->gate_id_,
                                                                num_simd, 0);
    share_future_offline_ = swift_provider_.register_for_ints_message<T>(2, this->gate_id_,
                                                                        num_simd, 1);
  }
}

template <typename T>
ArithmeticSWIFTMULGate<T>::~ArithmeticSWIFTMULGate() = default;

template <typename T>
void ArithmeticSWIFTMULGate<T>::evaluate_setup() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticSWIFTMULGate<T>::evaluate_setup start", this->gate_id_));
    }
  }
  auto my_id = swift_provider_.get_my_id();
  auto num_simd = this->input_a_->get_num_simd();

  // TODO(pranav): Add actual randomness here.
  for (std::size_t share_id = 0; share_id < 3; ++share_id) {
    this->output_->get_secret_share()[share_id] = std::vector<T>(num_simd, -1*share_id);
  }

  this->input_a_->wait_setup();
  this->input_b_->wait_setup();

  // Get the sharing of the muliplation triples.
  if (my_id == 0 || my_id == 1) {
    delta_ab_ = share_future_offline_.get();
  } else {
    for (int i = 0; i < 2; ++i) {
      for (int j = 0; j < 2; ++j) {
        // TODO(pranav): make this parallel.
        for (std::size_t k = 0; k < num_simd; ++k) {
          auto contrib = 
          this->input_a_->get_secret_share()[i][k] * this->input_b_->get_secret_share()[j][k];
          delta_ab_[k] += contrib;
        }
      }
    }
    swift_provider_.send_ints_message(0, this->gate_id_, delta_ab_, 1);
    swift_provider_.send_ints_message(1, this->gate_id_, delta_ab_, 1);
  }

  this->output_->set_setup_ready();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticSWIFTMULGate::evaluate_setup end", this->gate_id_));
    }
  }
}

template <typename T>
void ArithmeticSWIFTMULGate<T>::evaluate_online() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticSWIFTMULGate<T>::evaluate_online start", this->gate_id_));
    }
  }
  auto my_id = swift_provider_.get_my_id();
  auto num_simd = this->input_a_->get_num_simd();
  if (my_id == 2) {
    this->output_->set_online_ready();
    return;
  }

  this->input_a_->wait_online();
  this->input_b_->wait_online();
  this->output_->wait_setup();
  auto& a_sec_share = this->input_a_->get_secret_share();
  auto& b_sec_share = this->input_b_->get_secret_share();
  auto& a_pub_share = this->input_a_->get_public_share();
  auto& b_pub_share = this->input_b_->get_public_share();
  const auto& op_sec_share = this->output_->get_secret_share();

  auto& opshare = this->output_->get_public_share();
  opshare = delta_ab_;
  std::vector<T> for_other_party(num_simd, 0);
  for (std::size_t i = 0; i < num_simd; ++i) {
    auto y1 = -1*a_sec_share[0][i]*b_pub_share[i] - a_pub_share[i]*b_sec_share[0][i] + op_sec_share[0][i];
    auto y2 = -1*a_sec_share[1][i]*b_pub_share[i] - a_pub_share[i]*b_sec_share[1][i] + op_sec_share[1][i];
    auto y3 = -1*a_sec_share[2][i]*b_pub_share[i] - a_pub_share[i]*b_sec_share[2][i] + op_sec_share[2][i];
    opshare[i] += y3 + a_pub_share[i]*b_pub_share[i];
    if (my_id == 0) {
      for_other_party[i] = y1 + a_sec_share[0][i]*b_sec_share[2][i] + a_sec_share[2][i]*b_sec_share[0][i];
      opshare[i] += a_sec_share[0][i]*b_sec_share[2][i] + a_sec_share[2][i]*b_sec_share[0][i] + a_sec_share[2][i]*b_sec_share[2][i] + 
      // op_sec_share[2][i] + y1;
      y1;
    } else {
      for_other_party[i] = y2 + a_sec_share[1][i]*b_sec_share[2][i] + a_sec_share[2][i]*b_sec_share[1][i];
      opshare[i] += a_sec_share[1][i]*b_sec_share[2][i] + a_sec_share[2][i]*b_sec_share[1][i] + a_sec_share[2][i]*b_sec_share[2][i] +
      // op_sec_share[2][i] + y2;
      y2;
    }
  }
  swift_provider_.send_ints_message(1 - my_id, this->gate_id_, for_other_party, 0);
  const auto other_party_share = share_future_.get();
  std::transform(std::begin(opshare), std::end(opshare), std::begin(other_party_share),
                 std::begin(opshare), std::plus{});
  
  this->output_->set_online_ready();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticSWIFTMULGate<T>::evaluate_online end", this->gate_id_));
    }
  }
}

template class ArithmeticSWIFTMULGate<std::uint8_t>;
template class ArithmeticSWIFTMULGate<std::uint16_t>;
template class ArithmeticSWIFTMULGate<std::uint32_t>;
template class ArithmeticSWIFTMULGate<std::uint64_t>;

template <typename T>
ArithmeticSWIFTDummyGate<T>::ArithmeticSWIFTDummyGate(std::size_t gate_id,
                                                  SWIFTProvider& swift_provider,
                                                  ArithmeticSWIFTWireP<T>&& in)
    : detail::BasicArithmeticSWIFTUnaryGate<T>(gate_id, swift_provider, std::move(in)),
      swift_provider_(swift_provider) {
  auto my_id = swift_provider_.get_my_id();
  auto num_simd = this->input_->get_num_simd();
  if (my_id != 2) {
    share_future_offline_ = swift_provider_.register_for_ints_message<T>(2, this->gate_id_, msg_snd_ * num_simd, 0);
    share_future_ = swift_provider_.register_for_ints_message<T>(1 - my_id, this->gate_id_, msg_snd_ * num_simd, 1);
  }
}

template <typename T>
ArithmeticSWIFTDummyGate<T>::~ArithmeticSWIFTDummyGate() = default;

template <typename T>
void ArithmeticSWIFTDummyGate<T>::evaluate_setup() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticSWIFTDummyGate<T>::evaluate_setup start", this->gate_id_));
    }
  }
  auto my_id = swift_provider_.get_my_id();
  auto num_simd = this->input_->get_num_simd();

  this->output_->get_secret_share() = {Helpers::RandomVector<T>(num_simd),
  Helpers::RandomVector<T>(num_simd),
  Helpers::RandomVector<T>(num_simd)};
  this->output_->set_setup_ready();

  if (my_id == 2) {
    auto rand_vector = Helpers::RandomVector<T>(msg_snd_ * num_simd);
    swift_provider_.send_ints_message(0, this->gate_id_, rand_vector, 0);
    swift_provider_.send_ints_message(1, this->gate_id_, rand_vector, 0);
  } else {
    auto vec = share_future_offline_.get();
    for (std::size_t i = 0; i < vec.size(); ++i) {
      vec[i] = vec[i]*vec[i];
    }
  }

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticSWIFTDummyGate::evaluate_setup end", this->gate_id_));
    }
  }
}

template <typename T>
void ArithmeticSWIFTDummyGate<T>::evaluate_online() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticSWIFTDummyGate<T>::evaluate_online start", this->gate_id_));
    }
  }

  auto my_id = swift_provider_.get_my_id();
  auto num_simd = this->input_->get_num_simd();
  this->input_->wait_online();
  if (my_id == 2) {
    this->output_->set_online_ready();
    return;
  }
  auto rand_vector = Helpers::RandomVector<T>(msg_snd_ * num_simd);
  swift_provider_.send_ints_message(1 - my_id, this->gate_id_, rand_vector, 1);

  auto vec = share_future_.get();
  for (std::size_t i = 0; i < vec.size(); ++i) {
      vec[i] = vec[i]*vec[i];
      if (i < num_simd) {
        this->output_->get_public_share()[i] = vec[i];
      }
  }

  this->output_->set_online_ready();
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticSWIFTDummyGate<T>::evaluate_online end", this->gate_id_));
    }
  }
}

template class ArithmeticSWIFTDummyGate<std::uint8_t>;
template class ArithmeticSWIFTDummyGate<std::uint16_t>;
template class ArithmeticSWIFTDummyGate<std::uint32_t>;
template class ArithmeticSWIFTDummyGate<std::uint64_t>;

// template <typename T>
// ArithmeticSWIFTSQRGate<T>::ArithmeticSWIFTSQRGate(std::size_t gate_id,
//                                                   SWIFTProvider& swift_provider,
//                                                   ArithmeticSWIFTWireP<T>&& in)
//     : detail::BasicArithmeticSWIFTUnaryGate<T>(gate_id, swift_provider, std::move(in)),
//       swift_provider_(swift_provider) {
//   auto my_id = swift_provider_.get_my_id();
//   auto num_simd = this->input_->get_num_simd();
//   share_future_ = swift_provider_.register_for_ints_message<T>(1 - my_id, this->gate_id_, num_simd);
//   auto& ap = swift_provider_.get_arith_manager().get_provider(1 - my_id);
//   if (my_id == 0) {
//     mult_sender_ = ap.template register_integer_multiplication_send<T>(num_simd);
//     mult_receiver_ = nullptr;
//   } else {
//     mult_receiver_ = ap.template register_integer_multiplication_receive<T>(num_simd);
//     mult_sender_ = nullptr;
//   }
// }

// template <typename T>
// ArithmeticSWIFTSQRGate<T>::~ArithmeticSWIFTSQRGate() = default;

// template <typename T>
// void ArithmeticSWIFTSQRGate<T>::evaluate_setup() {
//   if constexpr (MOTION_VERBOSE_DEBUG) {
//     auto logger = swift_provider_.get_logger();
//     if (logger) {
//       logger->LogTrace(
//           fmt::format("Gate {}: ArithmeticSWIFTSQRGate<T>::evaluate_setup start", this->gate_id_));
//     }
//   }

//   auto num_simd = this->input_->get_num_simd();

//   this->output_->get_secret_share() = Helpers::RandomVector<T>(num_simd);
//   this->output_->set_setup_ready();

//   const auto& delta_a_share = this->input_->get_secret_share();
//   const auto& delta_y_share = this->output_->get_secret_share();

//   if (mult_sender_) {
//     mult_sender_->set_inputs(delta_a_share);
//   } else {
//     mult_receiver_->set_inputs(delta_a_share);
//   }

//   Delta_y_share_.resize(num_simd);
//   // [Delta_y]_i = [delta_a]_i * [delta_a]_i
//   std::transform(std::begin(delta_a_share), std::end(delta_a_share), std::begin(Delta_y_share_),
//                  [](auto x) { return x * x; });
//   // [Delta_y]_i += [delta_y]_i
//   std::transform(std::begin(Delta_y_share_), std::end(Delta_y_share_), std::begin(delta_y_share),
//                  std::begin(Delta_y_share_), std::plus{});

//   // [[delta_a]_i * [delta_a]_(1-i)]_i
//   std::vector<T> delta_aa_share;
//   if (mult_sender_) {
//     mult_sender_->compute_outputs();
//     delta_aa_share = mult_sender_->get_outputs();
//   } else {
//     mult_receiver_->compute_outputs();
//     delta_aa_share = mult_receiver_->get_outputs();
//   }
//   // [Delta_y]_i += 2 * [[delta_a]_i * [delta_a]_(1-i)]_i
//   std::transform(std::begin(Delta_y_share_), std::end(Delta_y_share_), std::begin(delta_aa_share),
//                  std::begin(Delta_y_share_), [](auto x, auto y) { return x + 2 * y; });

//   if constexpr (MOTION_VERBOSE_DEBUG) {
//     auto logger = swift_provider_.get_logger();
//     if (logger) {
//       logger->LogTrace(
//           fmt::format("Gate {}: ArithmeticSWIFTSQRGate::evaluate_setup end", this->gate_id_));
//     }
//   }
// }

// template <typename T>
// void ArithmeticSWIFTSQRGate<T>::evaluate_online() {
//   if constexpr (MOTION_VERBOSE_DEBUG) {
//     auto logger = swift_provider_.get_logger();
//     if (logger) {
//       logger->LogTrace(
//           fmt::format("Gate {}: ArithmeticSWIFTSQRGate<T>::evaluate_online start", this->gate_id_));
//     }
//   }

//   auto num_simd = this->input_->get_num_simd();
//   this->input_->wait_online();
//   const auto& Delta_a = this->input_->get_public_share();
//   const auto& delta_a_share = this->input_->get_secret_share();
//   std::vector<T> tmp(num_simd);

//   // after setup phase, `Delta_y_share_` contains [delta_y]_i + [delta_ab]_i

//   // [Delta_y]_i -= 2 * Delta_a * [delta_a]_i
//   std::transform(std::begin(Delta_a), std::end(Delta_a), std::begin(delta_a_share), std::begin(tmp),
//                  [](auto x, auto y) { return 2 * x * y; });
//   std::transform(std::begin(Delta_y_share_), std::end(Delta_y_share_), std::begin(tmp),
//                  std::begin(Delta_y_share_), std::minus{});

//   // [Delta_y]_i += Delta_aa (== Delta_a * Delta_a)
//   if (swift_provider_.is_my_job(this->gate_id_)) {
//     std::transform(std::begin(Delta_y_share_), std::end(Delta_y_share_), std::begin(Delta_a),
//                    std::begin(Delta_y_share_), [](auto x, auto y) { return x + y * y; });
//   }
//   // broadcast [Delta_y]_i
//   swift_provider_.broadcast_ints_message(this->gate_id_, Delta_y_share_);
//   // Delta_y = [Delta_y]_i + [Delta_y]_(1-i)
//   std::transform(std::begin(Delta_y_share_), std::end(Delta_y_share_),
//                  std::begin(share_future_.get()), std::begin(Delta_y_share_), std::plus{});
//   this->output_->get_public_share() = std::move(Delta_y_share_);
//   this->output_->set_online_ready();

//   if constexpr (MOTION_VERBOSE_DEBUG) {
//     auto logger = swift_provider_.get_logger();
//     if (logger) {
//       logger->LogTrace(
//           fmt::format("Gate {}: ArithmeticSWIFTSQRGate<T>::evaluate_online end", this->gate_id_));
//     }
//   }
// }

// template class ArithmeticSWIFTSQRGate<std::uint8_t>;
// template class ArithmeticSWIFTSQRGate<std::uint16_t>;
// template class ArithmeticSWIFTSQRGate<std::uint32_t>;
// template class ArithmeticSWIFTSQRGate<std::uint64_t>;

// template <typename T>
// BooleanXArithmeticSWIFTMULGate<T>::BooleanXArithmeticSWIFTMULGate(std::size_t gate_id,
//                                                                   SWIFTProvider& swift_provider,
//                                                                   BooleanSWIFTWireP&& in_a,
//                                                                   ArithmeticSWIFTWireP<T>&& in_b)
//     : detail::BasicBooleanXArithmeticSWIFTBinaryGate<T>(gate_id, swift_provider, std::move(in_a),
//                                                         std::move(in_b)),
//       swift_provider_(swift_provider) {
//   if (swift_provider_.get_num_parties() != 2) {
//     throw std::logic_error("currently only two parties are supported");
//   }
//   const auto my_id = swift_provider_.get_my_id();
//   auto num_simd = this->input_arith_->get_num_simd();
//   auto& ap = swift_provider_.get_arith_manager().get_provider(1 - my_id);
//   if (swift_provider_.is_my_job(this->gate_id_)) {
//     mult_int_side_ = ap.register_bit_integer_multiplication_int_side<T>(num_simd, 2);
//     mult_bit_side_ = ap.register_bit_integer_multiplication_bit_side<T>(num_simd, 1);
//   } else {
//     mult_int_side_ = ap.register_bit_integer_multiplication_int_side<T>(num_simd, 1);
//     mult_bit_side_ = ap.register_bit_integer_multiplication_bit_side<T>(num_simd, 2);
//   }
//   delta_b_share_.resize(num_simd);
//   delta_b_x_delta_n_share_.resize(num_simd);
//   share_future_ = swift_provider_.register_for_ints_message<T>(1 - my_id, this->gate_id_, num_simd);
// }

// template <typename T>
// BooleanXArithmeticSWIFTMULGate<T>::~BooleanXArithmeticSWIFTMULGate() = default;

// template <typename T>
// void BooleanXArithmeticSWIFTMULGate<T>::evaluate_setup() {
//   if constexpr (MOTION_VERBOSE_DEBUG) {
//     auto logger = swift_provider_.get_logger();
//     if (logger) {
//       logger->LogTrace(fmt::format(
//           "Gate {}: BooleanXArithmeticSWIFTMULGate<T>::evaluate_setup start", this->gate_id_));
//     }
//   }

//   auto num_simd = this->input_arith_->get_num_simd();

//   this->output_->get_secret_share() = Helpers::RandomVector<T>(num_simd);
//   this->output_->set_setup_ready();

//   this->input_arith_->wait_setup();
//   this->input_bool_->wait_setup();
//   const auto& int_sshare = this->input_arith_->get_secret_share();
//   assert(int_sshare.size() == num_simd);
//   const auto& bit_sshare = this->input_bool_->get_secret_share();
//   assert(bit_sshare.GetSize() == num_simd);

//   // Use the optimized variant from Lennart's thesis to compute the setup phase
//   // using only two (vector) OTs per multiplication.

//   std::vector<T> bit_sshare_as_ints(num_simd);
//   for (std::size_t int_i = 0; int_i < num_simd; ++int_i) {
//     bit_sshare_as_ints[int_i] = bit_sshare.Get(int_i);
//   }

//   mult_bit_side_->set_inputs(bit_sshare);

//   if (swift_provider_.is_my_job(this->gate_id_)) {
//     std::vector<T> mult_inputs(2 * num_simd);
//     for (std::size_t int_i = 0; int_i < num_simd; ++int_i) {
//       mult_inputs[2 * int_i] = bit_sshare_as_ints[int_i];
//       mult_inputs[2 * int_i + 1] =
//           int_sshare[int_i] - 2 * bit_sshare_as_ints[int_i] * int_sshare[int_i];
//     }
//     mult_int_side_->set_inputs(std::move(mult_inputs));
//   } else {
//     std::vector<T> mult_inputs(num_simd);
//     std::transform(std::begin(int_sshare), std::end(int_sshare), std::begin(bit_sshare_as_ints),
//                    std::begin(mult_inputs), [](auto n, auto b) { return n - 2 * b * n; });
//     mult_int_side_->set_inputs(std::move(mult_inputs));
//   }

//   mult_bit_side_->compute_outputs();
//   mult_int_side_->compute_outputs();
//   auto mult_bit_side_out = mult_bit_side_->get_outputs();
//   auto mult_int_side_out = mult_int_side_->get_outputs();

//   // compute [delta_b]^A and [delta_b * delta_n]^A
//   if (swift_provider_.is_my_job(this->gate_id_)) {
//     for (std::size_t int_i = 0; int_i < num_simd; ++int_i) {
//       delta_b_share_[int_i] = bit_sshare_as_ints[int_i] - 2 * mult_int_side_out[2 * int_i];
//       delta_b_x_delta_n_share_[int_i] = bit_sshare_as_ints[int_i] * int_sshare[int_i] +
//                                         mult_int_side_out[2 * int_i + 1] + mult_bit_side_out[int_i];
//     }
//   } else {
//     for (std::size_t int_i = 0; int_i < num_simd; ++int_i) {
//       delta_b_share_[int_i] = bit_sshare_as_ints[int_i] - 2 * mult_bit_side_out[2 * int_i];
//       delta_b_x_delta_n_share_[int_i] = bit_sshare_as_ints[int_i] * int_sshare[int_i] +
//                                         mult_bit_side_out[2 * int_i + 1] + mult_int_side_out[int_i];
//     }
//   }

//   if constexpr (MOTION_VERBOSE_DEBUG) {
//     auto logger = swift_provider_.get_logger();
//     if (logger) {
//       logger->LogTrace(fmt::format("Gate {}: BooleanXArithmeticSWIFTMULGate<T>::evaluate_setup end",
//                                    this->gate_id_));
//     }
//   }
// }

// template <typename T>
// void BooleanXArithmeticSWIFTMULGate<T>::evaluate_online() {
//   if constexpr (MOTION_VERBOSE_DEBUG) {
//     auto logger = swift_provider_.get_logger();
//     if (logger) {
//       logger->LogTrace(fmt::format(
//           "Gate {}: BooleanXArithmeticSWIFTMULGate<T>::evaluate_online start", this->gate_id_));
//     }
//   }

//   auto num_simd = this->input_arith_->get_num_simd();

//   this->input_bool_->wait_online();
//   this->input_arith_->wait_online();
//   const auto& int_sshare = this->input_arith_->get_secret_share();
//   const auto& int_pshare = this->input_arith_->get_public_share();
//   assert(int_pshare.size() == num_simd);
//   const auto& bit_pshare = this->input_bool_->get_public_share();
//   assert(bit_pshare.GetSize() == num_simd);

//   const auto& sshare = this->output_->get_secret_share();
//   std::vector<T> pshare(num_simd);

//   for (std::size_t simd_j = 0; simd_j < num_simd; ++simd_j) {
//     T Delta_b = bit_pshare.Get(simd_j);
//     auto Delta_n = int_pshare[simd_j];
//     pshare[simd_j] = delta_b_share_[simd_j] * (Delta_n - 2 * Delta_b * Delta_n) -
//                     Delta_b * int_sshare[simd_j] -
//                     delta_b_x_delta_n_share_[simd_j] * (1 - 2 * Delta_b) + sshare[simd_j];
//     if (swift_provider_.is_my_job(this->gate_id_)) {
//       pshare[simd_j] += Delta_b * Delta_n;
//     }
//   }

//   swift_provider_.broadcast_ints_message(this->gate_id_, pshare);
//   const auto other_pshare = share_future_.get();
//   std::transform(std::begin(pshare), std::end(pshare), std::begin(other_pshare), std::begin(pshare),
//                  std::plus{});

//   this->output_->get_public_share() = std::move(pshare);
//   this->output_->set_online_ready();

//   if constexpr (MOTION_VERBOSE_DEBUG) {
//     auto logger = swift_provider_.get_logger();
//     if (logger) {
//       logger->LogTrace(fmt::format(
//           "Gate {}: BooleanXArithmeticSWIFTMULGate<T>::evaluate_online end", this->gate_id_));
//     }
//   }
// }

// template class BooleanXArithmeticSWIFTMULGate<std::uint8_t>;
// template class BooleanXArithmeticSWIFTMULGate<std::uint16_t>;
// template class BooleanXArithmeticSWIFTMULGate<std::uint32_t>;
// template class BooleanXArithmeticSWIFTMULGate<std::uint64_t>;

}  // namespace MOTION::proto::swift
