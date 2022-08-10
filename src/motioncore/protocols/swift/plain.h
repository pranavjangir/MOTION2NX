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

#pragma once

#include "gate/new_gate.h"

namespace MOTION::proto::plain {
class BooleanPlainWire;
using BooleanPlainWireVector = std::vector<std::shared_ptr<BooleanPlainWire>>;
template <typename T>
class ArithmeticPlainWire;
template <typename T>
using ArithmeticPlainWireP = std::shared_ptr<ArithmeticPlainWire<T>>;
}  // namespace MOTION::proto::plain

namespace MOTION::proto::swift {

class SWIFTProvider;
class BooleanSWIFTWire;
using BooleanSWIFTWireVector = std::vector<std::shared_ptr<BooleanSWIFTWire>>;
template <typename T>
class ArithmeticSWIFTWire;
template <typename T>
using ArithmeticSWIFTWireP = std::shared_ptr<ArithmeticSWIFTWire<T>>;

namespace detail {

class BasicBooleanSWIFTPlainBinaryGate : public NewGate {
 public:
  BasicBooleanSWIFTPlainBinaryGate(std::size_t gate_id, SWIFTProvider&, BooleanSWIFTWireVector&&,
                                   plain::BooleanPlainWireVector&&);
  BooleanSWIFTWireVector& get_output_wires() noexcept { return outputs_; };

 protected:
  const SWIFTProvider& swift_provider_;
  std::size_t num_wires_;
  const BooleanSWIFTWireVector inputs_swift_;
  const plain::BooleanPlainWireVector inputs_plain_;
  BooleanSWIFTWireVector outputs_;
};

template <typename T>
class BasicArithmeticSWIFTPlainBinaryGate : public NewGate {
 public:
  BasicArithmeticSWIFTPlainBinaryGate(std::size_t gate_id, SWIFTProvider&,
                                      ArithmeticSWIFTWireP<T>&&, plain::ArithmeticPlainWireP<T>&&);
  ArithmeticSWIFTWireP<T>& get_output_wire() noexcept { return output_; };

 protected:
  const SWIFTProvider& swift_provider_;
  const ArithmeticSWIFTWireP<T> input_swift_;
  const plain::ArithmeticPlainWireP<T> input_plain_;
  ArithmeticSWIFTWireP<T> output_;
};

}  // namespace detail

class BooleanSWIFTXORPlainGate : public detail::BasicBooleanSWIFTPlainBinaryGate {
 public:
  using detail::BasicBooleanSWIFTPlainBinaryGate::BasicBooleanSWIFTPlainBinaryGate;
  bool need_setup() const noexcept override { return true; }
  bool need_online() const noexcept override { return true; }
  void evaluate_setup() override;
  void evaluate_online() override;
};

class BooleanSWIFTANDPlainGate : public detail::BasicBooleanSWIFTPlainBinaryGate {
 public:
  using detail::BasicBooleanSWIFTPlainBinaryGate::BasicBooleanSWIFTPlainBinaryGate;
  bool need_setup() const noexcept override { return true; }
  bool need_online() const noexcept override { return true; }
  void evaluate_setup() override;
  void evaluate_online() override;
};

template <typename T>
class ArithmeticSWIFTADDPlainGate : public detail::BasicArithmeticSWIFTPlainBinaryGate<T> {
 public:
  using detail::BasicArithmeticSWIFTPlainBinaryGate<T>::BasicArithmeticSWIFTPlainBinaryGate;
  bool need_setup() const noexcept override { return true; }
  bool need_online() const noexcept override { return true; }
  void evaluate_setup() override;
  void evaluate_online() override;
};

template <typename T>
class ArithmeticSWIFTMULPlainGate : public detail::BasicArithmeticSWIFTPlainBinaryGate<T> {
 public:
  using detail::BasicArithmeticSWIFTPlainBinaryGate<T>::BasicArithmeticSWIFTPlainBinaryGate;
  bool need_setup() const noexcept override { return true; }
  bool need_online() const noexcept override { return true; }
  void evaluate_setup() override;
  void evaluate_online() override;
};

}  // namespace MOTION::proto::swift
