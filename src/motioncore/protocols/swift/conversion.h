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

#include <cstddef>
#include <memory>
#include <vector>

#include "gate/new_gate.h"
#include "utility/bit_vector.h"
#include "utility/reusable_future.h"
#include "wire.h"

namespace ENCRYPTO::ObliviousTransfer {
template <typename T>
class ACOTSender;
template <typename T>
class ACOTReceiver;
}  // namespace ENCRYPTO::ObliviousTransfer

namespace MOTION::proto::gmw {
class BooleanGMWWire;
using BooleanGMWWireVector = std::vector<std::shared_ptr<BooleanGMWWire>>;
template <typename T>
class ArithmeticGMWWire;
template <typename T>
using ArithmeticGMWWireP = std::shared_ptr<ArithmeticGMWWire<T>>;
}  // namespace MOTION::proto::gmw

namespace MOTION::proto::swift {

class BooleanSWIFTWire;
using BooleanSWIFTWireP = std::shared_ptr<BooleanSWIFTWire>;
using BooleanSWIFTWireVector = std::vector<BooleanSWIFTWireP>;
template <typename T>
class ArithmeticSWIFTWire;
template <typename T>
using ArithmeticSWIFTWireP = std::shared_ptr<ArithmeticSWIFTWire<T>>;

class SWIFTProvider;

template <typename T>
class BooleanBitToArithmeticSWIFTGate : public NewGate {
 public:
  BooleanBitToArithmeticSWIFTGate(std::size_t gate_id, SWIFTProvider&, BooleanSWIFTWireP);
  ~BooleanBitToArithmeticSWIFTGate();
  bool need_setup() const noexcept override { return true; }
  bool need_online() const noexcept override { return true; }
  void evaluate_setup() override;
  void evaluate_online() override;
  swift::ArithmeticSWIFTWireP<T>& get_output_wire() noexcept { return output_; };

 private:
  using is_enabled_ = ENCRYPTO::is_unsigned_int_t<T>;
  swift::BooleanSWIFTWireP input_;
  swift::ArithmeticSWIFTWireP<T> output_;
  SWIFTProvider& swift_provider_;
  std::unique_ptr<ENCRYPTO::ObliviousTransfer::ACOTSender<T>> ot_sender_;
  std::unique_ptr<ENCRYPTO::ObliviousTransfer::ACOTReceiver<T>> ot_receiver_;
  std::vector<T> arithmetized_secret_share_;
  ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_future_;
};

template <typename T>
class BooleanToArithmeticSWIFTGate : public NewGate {
 public:
  BooleanToArithmeticSWIFTGate(std::size_t gate_id, SWIFTProvider&, BooleanSWIFTWireVector&&);
  ~BooleanToArithmeticSWIFTGate();
  bool need_setup() const noexcept override { return true; }
  bool need_online() const noexcept override { return true; }
  void evaluate_setup() override;
  void evaluate_online() override;
  swift::ArithmeticSWIFTWireP<T>& get_output_wire() noexcept { return output_; };

 private:
  using is_enabled_ = ENCRYPTO::is_unsigned_int_t<T>;
  swift::BooleanSWIFTWireVector inputs_;
  swift::ArithmeticSWIFTWireP<T> output_;
  SWIFTProvider& swift_provider_;
  std::unique_ptr<ENCRYPTO::ObliviousTransfer::ACOTSender<T>> ot_sender_;
  std::unique_ptr<ENCRYPTO::ObliviousTransfer::ACOTReceiver<T>> ot_receiver_;
  std::vector<T> arithmetized_secret_share_;
  ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_future_;
};

template <typename T>
class ArithmeticToBooleanSWIFTGate : public NewGate {
 public:
  ArithmeticToBooleanSWIFTGate(std::size_t gate_id, SWIFTProvider&, const ArithmeticSWIFTWireP<T>);
  ~ArithmeticToBooleanSWIFTGate();
  bool need_setup() const noexcept override { return true; }
  bool need_online() const noexcept override { return true; }
  void evaluate_setup() override;
  void evaluate_online() override;
  swift::BooleanSWIFTWireVector& get_output_wire() noexcept { return output_; };

 private:
  using is_enabled_ = ENCRYPTO::is_unsigned_int_t<T>;
  const swift::ArithmeticSWIFTWireP<T> input_;
  swift::BooleanSWIFTWireVector output_;
  SWIFTProvider& swift_provider_;
  std::vector<T> arithmetized_secret_share_;
  swift::BooleanSWIFTWireVector addition_result_;
  swift::BooleanSWIFTWireVector output_public_;
  swift::BooleanSWIFTWireVector output_random_;
  ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_future_;
  std::vector<std::unique_ptr<NewGate>> gates_;
};

class BooleanSWIFTToGMWGate : public NewGate {
 public:
  BooleanSWIFTToGMWGate(std::size_t gate_id, SWIFTProvider&, BooleanSWIFTWireVector&&);
  bool need_setup() const noexcept override { return false; }
  bool need_online() const noexcept override { return true; }
  void evaluate_setup() override {}
  void evaluate_online() override;
  gmw::BooleanGMWWireVector& get_output_wires() noexcept { return outputs_; };

 private:
  SWIFTProvider& swift_provider_;
  BooleanSWIFTWireVector inputs_;
  gmw::BooleanGMWWireVector outputs_;
};

class BooleanGMWToSWIFTGate : public NewGate {
 public:
  BooleanGMWToSWIFTGate(std::size_t gate_id, SWIFTProvider&, gmw::BooleanGMWWireVector&&);
  bool need_setup() const noexcept override { return true; }
  bool need_online() const noexcept override { return true; }
  void evaluate_setup() override;
  void evaluate_online() override;
  BooleanSWIFTWireVector& get_output_wires() noexcept { return outputs_; };

 private:
  SWIFTProvider& swift_provider_;
  gmw::BooleanGMWWireVector inputs_;
  BooleanSWIFTWireVector outputs_;
  ENCRYPTO::ReusableFiberFuture<ENCRYPTO::BitVector<>> share_future_;
};

template <typename T>
class ArithmeticSWIFTToGMWGate : public NewGate {
 public:
  ArithmeticSWIFTToGMWGate(std::size_t gate_id, SWIFTProvider&, ArithmeticSWIFTWireP<T>);
  bool need_setup() const noexcept override { return false; }
  bool need_online() const noexcept override { return true; }
  void evaluate_setup() override {}
  void evaluate_online() override;
  gmw::ArithmeticGMWWireP<T>& get_output_wire() noexcept { return output_; };

 private:
  using is_enabled_ = ENCRYPTO::is_unsigned_int_t<T>;
  SWIFTProvider& swift_provider_;
  ArithmeticSWIFTWireP<T> input_;
  gmw::ArithmeticGMWWireP<T> output_;
};

template <typename T>
class ArithmeticGMWToSWIFTGate : public NewGate {
 public:
  ArithmeticGMWToSWIFTGate(std::size_t gate_id, SWIFTProvider&, gmw::ArithmeticGMWWireP<T>);
  bool need_setup() const noexcept override { return true; }
  bool need_online() const noexcept override { return true; }
  void evaluate_setup() override;
  void evaluate_online() override;
  ArithmeticSWIFTWireP<T>& get_output_wire() noexcept { return output_; };

 private:
  using is_enabled_ = ENCRYPTO::is_unsigned_int_t<T>;
  SWIFTProvider& swift_provider_;
  gmw::ArithmeticGMWWireP<T> input_;
  ArithmeticSWIFTWireP<T> output_;
  ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_future_;
};

}  // namespace MOTION::proto::swift
