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

#include "plain.h"

#include <fmt/format.h>
#include <iterator>
#include <memory>

#include "swift_provider.h"
#include "protocols/plain/wire.h"
#include "utility/constants.h"
#include "utility/logger.h"
#include "wire.h"

namespace MOTION::proto::swift {

namespace detail {

BasicBooleanSWIFTPlainBinaryGate::BasicBooleanSWIFTPlainBinaryGate(
    std::size_t gate_id, SWIFTProvider& swift_provider, BooleanSWIFTWireVector&& in_swift,
    plain::BooleanPlainWireVector&& in_plain)
    : NewGate(gate_id),
      swift_provider_(swift_provider),
      num_wires_(in_swift.size()),
      inputs_swift_(std::move(in_swift)),
      inputs_plain_(std::move(in_plain)) {
  if (num_wires_ == 0) {
    throw std::logic_error("number of wires need to be positive");
  }
  if (num_wires_ != inputs_plain_.size()) {
    throw std::logic_error("number of wires need to be the same for both inputs");
  }
  auto num_simd = inputs_swift_[0]->get_num_simd();
  for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
    if (inputs_swift_[wire_i]->get_num_simd() != num_simd ||
        inputs_plain_[wire_i]->get_num_simd() != num_simd) {
      throw std::logic_error("number of SIMD values need to be the same for all wires");
    }
  }
  outputs_.reserve(num_wires_);
  std::generate_n(std::back_inserter(outputs_), num_wires_,
                  [num_simd] { return std::make_shared<BooleanSWIFTWire>(num_simd); });
}

template <typename T>
BasicArithmeticSWIFTPlainBinaryGate<T>::BasicArithmeticSWIFTPlainBinaryGate(
    std::size_t gate_id, SWIFTProvider& swift_provider, ArithmeticSWIFTWireP<T>&& in_swift,
    plain::ArithmeticPlainWireP<T>&& in_plain)
    : NewGate(gate_id),
      swift_provider_(swift_provider),
      input_swift_(std::move(in_swift)),
      input_plain_(std::move(in_plain)),
      output_(std::make_shared<ArithmeticSWIFTWire<T>>(input_swift_->get_num_simd())) {
  if (input_swift_->get_num_simd() != input_plain_->get_num_simd()) {
    throw std::logic_error("number of SIMD values need to be the same for all wires");
  }
}

template class BasicArithmeticSWIFTPlainBinaryGate<std::uint8_t>;
template class BasicArithmeticSWIFTPlainBinaryGate<std::uint16_t>;
template class BasicArithmeticSWIFTPlainBinaryGate<std::uint32_t>;
template class BasicArithmeticSWIFTPlainBinaryGate<std::uint64_t>;

}  // namespace detail

void BooleanSWIFTXORPlainGate::evaluate_setup() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanSWIFTXORPlainGate::evaluate_setup start", gate_id_));
    }
  }

  for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
    const auto& wire_swift = inputs_swift_[wire_i];
    auto& wire_out = outputs_[wire_i];
    wire_swift->wait_setup();
    wire_out->get_secret_share() = wire_swift->get_secret_share();
    wire_out->set_setup_ready();
  }

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanSWIFTXORPlainGate::evaluate_setup end", gate_id_));
    }
  }
}

void BooleanSWIFTXORPlainGate::evaluate_online() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanSWIFTXORPlainGate::evaluate_online start", gate_id_));
    }
  }

  for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
    const auto& wire_swift = inputs_swift_[wire_i];
    const auto& wire_plain = inputs_plain_[wire_i];
    auto& wire_out = outputs_[wire_i];
    wire_swift->wait_online();
    wire_plain->wait_online();
    wire_out->get_public_share() = wire_swift->get_public_share() ^ wire_plain->get_data();
    wire_out->set_online_ready();
  }

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanSWIFTXORPlainGate::evaluate_online end", gate_id_));
    }
  }
}

void BooleanSWIFTANDPlainGate::evaluate_setup() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanSWIFTANDPlainGate::evaluate_setup start", gate_id_));
    }
  }

  for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
    const auto& wire_swift = inputs_swift_[wire_i];
    const auto& wire_plain = inputs_plain_[wire_i];
    auto& wire_out = outputs_[wire_i];
    wire_swift->wait_setup();
    wire_plain->wait_online();
    for (std::size_t share_id = 0; share_id < 3; ++share_id) {
      wire_out->get_secret_share()[share_id] = wire_swift->get_secret_share()[share_id] & wire_plain->get_data();
    }
    wire_out->set_setup_ready();
  }

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanSWIFTANDPlainGate::evaluate_setup end", gate_id_));
    }
  }
}

void BooleanSWIFTANDPlainGate::evaluate_online() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanSWIFTANDPlainGate::evaluate_online start", gate_id_));
    }
  }

  for (std::size_t wire_i = 0; wire_i < num_wires_; ++wire_i) {
    const auto& wire_swift = inputs_swift_[wire_i];
    const auto& wire_plain = inputs_plain_[wire_i];
    auto& wire_out = outputs_[wire_i];
    wire_swift->wait_online();
    wire_plain->wait_online();
    wire_out->get_public_share() = wire_swift->get_public_share() & wire_plain->get_data();
    wire_out->set_online_ready();
  }

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanSWIFTANDPlainGate::evaluate_online end", gate_id_));
    }
  }
}

template <typename T>
void ArithmeticSWIFTADDPlainGate<T>::evaluate_setup() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = this->swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format("Gate {}: ArithmeticSWIFTADDPlainGate<T>::evaluate_setup start",
                                   this->gate_id_));
    }
  }

  this->input_swift_->wait_setup();
  this->output_->get_secret_share() = this->input_swift_->get_secret_share();
  this->output_->set_setup_ready();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = this->swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format("Gate {}: ArithmeticSWIFTADDPlainGate<T>::evaluate_setup end",
                                   this->gate_id_));
    }
  }
}

template <typename T>
void ArithmeticSWIFTADDPlainGate<T>::evaluate_online() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = this->swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format("Gate {}: ArithmeticSWIFTADDPlainGate<T>::evaluate_online start",
                                   this->gate_id_));
    }
  }

  this->input_swift_->wait_online();
  this->input_plain_->wait_online();
  this->output_->get_public_share() =
      Helpers::AddVectors(this->input_swift_->get_public_share(), this->input_plain_->get_data());
  this->output_->set_online_ready();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = this->swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format("Gate {}: ArithmeticSWIFTADDPlainGate<T>::evaluate_online end",
                                   this->gate_id_));
    }
  }
}

template class ArithmeticSWIFTADDPlainGate<std::uint8_t>;
template class ArithmeticSWIFTADDPlainGate<std::uint16_t>;
template class ArithmeticSWIFTADDPlainGate<std::uint32_t>;
template class ArithmeticSWIFTADDPlainGate<std::uint64_t>;

template <typename T>
void ArithmeticSWIFTMULPlainGate<T>::evaluate_setup() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = this->swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format("Gate {}: ArithmeticSWIFTMULPlainGate<T>::evaluate_setup start",
                                   this->gate_id_));
    }
  }

  this->input_swift_->wait_setup();
  this->input_plain_->wait_online();
  for (std::size_t share_id = 0; share_id < 3; ++share_id) {
    this->output_->get_secret_share()[share_id] = Helpers::MultiplyVectors(
      this->input_swift_->get_secret_share()[share_id], this->input_plain_->get_data());
  }
  this->output_->set_setup_ready();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = this->swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format("Gate {}: ArithmeticSWIFTMULPlainGate<T>::evaluate_setup end",
                                   this->gate_id_));
    }
  }
}

template <typename T>
void ArithmeticSWIFTMULPlainGate<T>::evaluate_online() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = this->swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format("Gate {}: ArithmeticSWIFTMULPlainGate<T>::evaluate_online start",
                                   this->gate_id_));
    }
  }

  this->input_swift_->wait_online();
  this->input_plain_->wait_online();
  this->output_->get_public_share() = Helpers::MultiplyVectors(
      this->input_swift_->get_public_share(), this->input_plain_->get_data());
  this->output_->set_online_ready();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = this->swift_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format("Gate {}: ArithmeticSWIFTMULPlainGate<T>::evaluate_online end",
                                   this->gate_id_));
    }
  }
}

template class ArithmeticSWIFTMULPlainGate<std::uint8_t>;
template class ArithmeticSWIFTMULPlainGate<std::uint16_t>;
template class ArithmeticSWIFTMULPlainGate<std::uint32_t>;
template class ArithmeticSWIFTMULPlainGate<std::uint64_t>;

}  // namespace MOTION::proto::swift
