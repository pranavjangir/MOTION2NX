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

#include "gate/new_gate.h"
#include "utility/bit_vector.h"
#include "utility/reusable_future.h"
#include "utility/type_traits.hpp"
#include "wire.h"

namespace ENCRYPTO::ObliviousTransfer {
class XCOTBitSender;
class XCOTBitReceiver;
}  // namespace ENCRYPTO::ObliviousTransfer

namespace MOTION {
template <typename T>
class BitIntegerMultiplicationBitSide;
template <typename T>
class BitIntegerMultiplicationIntSide;
template <typename T>
class IntegerMultiplicationSender;
template <typename T>
class IntegerMultiplicationReceiver;
}  // namespace MOTION

namespace MOTION::proto::swift {

namespace detail {

class BasicBooleanSWIFTBinaryGate : public NewGate {
 public:
  BasicBooleanSWIFTBinaryGate(std::size_t gate_id, BooleanSWIFTWireVector&&,
                              BooleanSWIFTWireVector&&);
  BooleanSWIFTWireVector& get_output_wires() noexcept { return outputs_; }

 protected:
  std::size_t num_wires_;
  const BooleanSWIFTWireVector inputs_a_;
  const BooleanSWIFTWireVector inputs_b_;
  BooleanSWIFTWireVector outputs_;
};

class BasicBooleanSWIFTUnaryGate : public NewGate {
 public:
  BasicBooleanSWIFTUnaryGate(std::size_t gate_id, BooleanSWIFTWireVector&&, bool forward);
  BooleanSWIFTWireVector& get_output_wires() noexcept { return outputs_; }

 protected:
  std::size_t num_wires_;
  const BooleanSWIFTWireVector inputs_;
  BooleanSWIFTWireVector outputs_;
};

}  // namespace detail

class SWIFTProvider;
class BooleanSWIFTWire;
using BooleanSWIFTWireVector = std::vector<std::shared_ptr<BooleanSWIFTWire>>;

class BooleanSWIFTInputGateSender : public NewGate {
 public:
  BooleanSWIFTInputGateSender(std::size_t gate_id, SWIFTProvider&, std::size_t num_wires,
                              std::size_t num_simd,
                              ENCRYPTO::ReusableFiberFuture<std::vector<ENCRYPTO::BitVector<>>>&&);
  bool need_setup() const noexcept override { return true; }
  bool need_online() const noexcept override { return true; }
  void evaluate_setup() override;
  void evaluate_online() override;
  BooleanSWIFTWireVector& get_output_wires() noexcept { return outputs_; }

 private:
  SWIFTProvider& swift_provider_;
  std::size_t num_wires_;
  std::size_t num_simd_;
  std::size_t input_id_;
  ENCRYPTO::ReusableFiberFuture<std::vector<ENCRYPTO::BitVector<>>> input_future_;
  BooleanSWIFTWireVector outputs_;
};

class BooleanSWIFTInputGateReceiver : public NewGate {
 public:
  BooleanSWIFTInputGateReceiver(std::size_t gate_id, SWIFTProvider&, std::size_t num_wires,
                                std::size_t num_simd, std::size_t input_owner);
  bool need_setup() const noexcept override { return true; }
  bool need_online() const noexcept override { return true; }
  void evaluate_setup() override;
  void evaluate_online() override;
  BooleanSWIFTWireVector& get_output_wires() noexcept { return outputs_; }

 private:
  SWIFTProvider& swift_provider_;
  std::size_t num_wires_;
  std::size_t num_simd_;
  std::size_t input_owner_;
  std::size_t input_id_;
  BooleanSWIFTWireVector outputs_;
  ENCRYPTO::ReusableFiberFuture<ENCRYPTO::BitVector<>> public_share_future_;
};

class BooleanSWIFTOutputGate : public NewGate {
 public:
  BooleanSWIFTOutputGate(std::size_t gate_id, SWIFTProvider&, BooleanSWIFTWireVector&&,
                         std::size_t output_owner);
  ENCRYPTO::ReusableFiberFuture<std::vector<ENCRYPTO::BitVector<>>> get_output_future();
  bool need_setup() const noexcept override { return true; }
  bool need_online() const noexcept override { return true; }
  void evaluate_setup() override;
  void evaluate_online() override;

 private:
  SWIFTProvider& swift_provider_;
  std::size_t num_wires_;
  std::size_t output_owner_;
  ENCRYPTO::ReusableFiberPromise<std::vector<ENCRYPTO::BitVector<>>> output_promise_;
  std::vector<ENCRYPTO::ReusableFiberFuture<ENCRYPTO::BitVector<>>> share_futures_;
  const BooleanSWIFTWireVector inputs_;
  ENCRYPTO::BitVector<> my_secret_share_;
};

class BooleanSWIFTINVGate : public detail::BasicBooleanSWIFTUnaryGate {
 public:
  BooleanSWIFTINVGate(std::size_t gate_id, const SWIFTProvider&, BooleanSWIFTWireVector&&);
  bool need_setup() const noexcept override { return true; }
  bool need_online() const noexcept override { return true; }
  void evaluate_setup() override;
  void evaluate_online() override;

 private:
  bool is_my_job_;
};

class BooleanSWIFTXORGate : public detail::BasicBooleanSWIFTBinaryGate {
 public:
  BooleanSWIFTXORGate(std::size_t gate_id, SWIFTProvider&, BooleanSWIFTWireVector&&,
                      BooleanSWIFTWireVector&&);
  bool need_setup() const noexcept override { return true; }
  bool need_online() const noexcept override { return true; }
  void evaluate_setup() override;
  void evaluate_online() override;
};

class BooleanSWIFTANDGate : public detail::BasicBooleanSWIFTBinaryGate {
 public:
  BooleanSWIFTANDGate(std::size_t gate_id, SWIFTProvider&, BooleanSWIFTWireVector&&,
                      BooleanSWIFTWireVector&&);
  ~BooleanSWIFTANDGate();
  bool need_setup() const noexcept override { return true; }
  bool need_online() const noexcept override { return true; }
  void evaluate_setup() override;
  void evaluate_online() override;

 private:
  SWIFTProvider& swift_provider_;
  ENCRYPTO::ReusableFiberFuture<ENCRYPTO::BitVector<>> share_future_;
  ENCRYPTO::ReusableFiberFuture<ENCRYPTO::BitVector<>> share_future_offline_;
  ENCRYPTO::BitVector<> delta_ab_;
};

template <typename T>
class ArithmeticSWIFTInputGateSender : public NewGate {
 public:
  ArithmeticSWIFTInputGateSender(std::size_t gate_id, SWIFTProvider&, std::size_t num_simd,
                                 ENCRYPTO::ReusableFiberFuture<std::vector<T>>&&);
  bool need_setup() const noexcept override { return true; }
  bool need_online() const noexcept override { return true; }
  void evaluate_setup() override;
  void evaluate_online() override;
  ArithmeticSWIFTWireP<T>& get_output_wire() noexcept { return output_; }

 private:
  SWIFTProvider& swift_provider_;
  std::size_t num_wires_;
  std::size_t num_simd_;
  std::size_t input_id_;
  ENCRYPTO::ReusableFiberFuture<std::vector<T>> input_future_;
  ArithmeticSWIFTWireP<T> output_;
};

template <typename T>
class ArithmeticSWIFTInputGateReceiver : public NewGate {
 public:
  ArithmeticSWIFTInputGateReceiver(std::size_t gate_id, SWIFTProvider&, std::size_t num_simd,
                                   std::size_t input_owner);
  bool need_setup() const noexcept override { return true; }
  bool need_online() const noexcept override { return true; }
  void evaluate_setup() override;
  void evaluate_online() override;
  ArithmeticSWIFTWireP<T>& get_output_wire() noexcept { return output_; }

 private:
  SWIFTProvider& swift_provider_;
  std::size_t num_wires_;
  std::size_t num_simd_;
  std::size_t input_owner_;
  std::size_t input_id_;
  ArithmeticSWIFTWireP<T> output_;
  ENCRYPTO::ReusableFiberFuture<std::vector<T>> public_share_future_;
};

template <typename T>
class ArithmeticSWIFTOutputGate : public NewGate {
 public:
  ArithmeticSWIFTOutputGate(std::size_t gate_id, SWIFTProvider&, ArithmeticSWIFTWireP<T>&&,
                            std::size_t output_owner);
  ENCRYPTO::ReusableFiberFuture<std::vector<T>> get_output_future();
  bool need_setup() const noexcept override { return true; }
  bool need_online() const noexcept override { return true; }
  void evaluate_setup() override;
  void evaluate_online() override;

 private:
  SWIFTProvider& swift_provider_;
  std::size_t num_wires_;
  std::size_t output_owner_;
  ENCRYPTO::ReusableFiberPromise<std::vector<T>> output_promise_;
  ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_future_;
  const ArithmeticSWIFTWireP<T> input_;
};

template <typename T>
class ArithmeticSWIFTOutputShareGate : public NewGate {
 public:
  ArithmeticSWIFTOutputShareGate(std::size_t gate_id, ArithmeticSWIFTWireP<T>&&);
  ENCRYPTO::ReusableFiberFuture<std::vector<T>> get_public_share_future();
  ENCRYPTO::ReusableFiberFuture<std::vector<T>> get_secret_share_future();
  bool need_setup() const noexcept override { return true; }
  bool need_online() const noexcept override { return true; }
  void evaluate_setup() override;
  void evaluate_online() override;

 private:
  ENCRYPTO::ReusableFiberPromise<std::vector<T>> public_share_promise_;
  ENCRYPTO::ReusableFiberPromise<std::vector<T>> secret_share_promise_;
  const ArithmeticSWIFTWireP<T> input_;
};

namespace detail {

template <typename T>
class BasicArithmeticSWIFTBinaryGate : public NewGate {
 public:
  BasicArithmeticSWIFTBinaryGate(std::size_t gate_id, SWIFTProvider&, ArithmeticSWIFTWireP<T>&&,
                                 ArithmeticSWIFTWireP<T>&&);
  ArithmeticSWIFTWireP<T>& get_output_wire() noexcept { return output_; }

 protected:
  std::size_t num_wires_;
  const ArithmeticSWIFTWireP<T> input_a_;
  const ArithmeticSWIFTWireP<T> input_b_;
  ArithmeticSWIFTWireP<T> output_;
};

template <typename T>
class BasicArithmeticSWIFTUnaryGate : public NewGate {
 public:
  BasicArithmeticSWIFTUnaryGate(std::size_t gate_id, SWIFTProvider&, ArithmeticSWIFTWireP<T>&&);
  ArithmeticSWIFTWireP<T>& get_output_wire() noexcept { return output_; }

 protected:
  std::size_t num_wires_;
  const ArithmeticSWIFTWireP<T> input_;
  ArithmeticSWIFTWireP<T> output_;
};

// template <typename T>
// class BasicBooleanXArithmeticSWIFTBinaryGate : public NewGate {
//  public:
//   BasicBooleanXArithmeticSWIFTBinaryGate(std::size_t gate_id, SWIFTProvider&, BooleanSWIFTWireP&&,
//                                          ArithmeticSWIFTWireP<T>&&);
//   ArithmeticSWIFTWireP<T>& get_output_wire() noexcept { return output_; }

//  protected:
//   const BooleanSWIFTWireP input_bool_;
//   const ArithmeticSWIFTWireP<T> input_arith_;
//   ArithmeticSWIFTWireP<T> output_;
// };

}  // namespace detail

// template <typename T>
// class ArithmeticSWIFTNEGGate : public detail::BasicArithmeticSWIFTUnaryGate<T> {
//  public:
//   ArithmeticSWIFTNEGGate(std::size_t gate_id, SWIFTProvider&, ArithmeticSWIFTWireP<T>&&);
//   bool need_setup() const noexcept override { return true; }
//   bool need_online() const noexcept override { return true; }
//   void evaluate_setup() override;
//   void evaluate_online() override;

//  private:
//   using is_enabled_ = ENCRYPTO::is_unsigned_int_t<T>;
// };

template <typename T>
class ArithmeticSWIFTADDGate : public detail::BasicArithmeticSWIFTBinaryGate<T> {
 public:
  ArithmeticSWIFTADDGate(std::size_t gate_id, SWIFTProvider&, ArithmeticSWIFTWireP<T>&&,
                         ArithmeticSWIFTWireP<T>&&);
  bool need_setup() const noexcept override { return true; }
  bool need_online() const noexcept override { return true; }
  void evaluate_setup() override;
  void evaluate_online() override;
};

template <typename T>
class ArithmeticSWIFTMULGate : public detail::BasicArithmeticSWIFTBinaryGate<T> {
 public:
  ArithmeticSWIFTMULGate(std::size_t gate_id, SWIFTProvider&, ArithmeticSWIFTWireP<T>&&,
                         ArithmeticSWIFTWireP<T>&&);
  ~ArithmeticSWIFTMULGate();
  bool need_setup() const noexcept override { return true; }
  bool need_online() const noexcept override { return true; }
  void evaluate_setup() override;
  void evaluate_online() override;

 private:
  SWIFTProvider& swift_provider_;
  ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_future_;
  ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_future_offline_;
  std::vector<T> delta_ab_;
};

template <typename T>
class ArithmeticSWIFTDummyGate : public detail::BasicArithmeticSWIFTUnaryGate<T> {
 public:
  ArithmeticSWIFTDummyGate(std::size_t gate_id, SWIFTProvider&, ArithmeticSWIFTWireP<T>&&);
  ~ArithmeticSWIFTDummyGate();
  bool need_setup() const noexcept override { return true; }
  bool need_online() const noexcept override { return true; }
  void evaluate_setup() override;
  void evaluate_online() override;

 private:
  SWIFTProvider& swift_provider_;
  ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_future_;
  ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_future_offline_;
  const int msg_snd_ = 8;
};

// template <typename T>
// class ArithmeticSWIFTSQRGate : public detail::BasicArithmeticSWIFTUnaryGate<T> {
//  public:
//   ArithmeticSWIFTSQRGate(std::size_t gate_id, SWIFTProvider&, ArithmeticSWIFTWireP<T>&&);
//   ~ArithmeticSWIFTSQRGate();
//   bool need_setup() const noexcept override { return true; }
//   bool need_online() const noexcept override { return true; }
//   void evaluate_setup() override;
//   void evaluate_online() override;

//  private:
//   SWIFTProvider& swift_provider_;
//   ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_future_;
//   std::vector<T> Delta_y_share_;
//   std::unique_ptr<MOTION::IntegerMultiplicationSender<T>> mult_sender_;
//   std::unique_ptr<MOTION::IntegerMultiplicationReceiver<T>> mult_receiver_;
// };

// template <typename T>
// class BooleanXArithmeticSWIFTMULGate : public detail::BasicBooleanXArithmeticSWIFTBinaryGate<T> {
//  public:
//   BooleanXArithmeticSWIFTMULGate(std::size_t gate_id, SWIFTProvider&, BooleanSWIFTWireP&&,
//                                  ArithmeticSWIFTWireP<T>&&);
//   ~BooleanXArithmeticSWIFTMULGate();
//   bool need_setup() const noexcept override { return true; }
//   bool need_online() const noexcept override { return true; }
//   void evaluate_setup() override;
//   void evaluate_online() override;

//  private:
//   SWIFTProvider& swift_provider_;
//   std::unique_ptr<MOTION::BitIntegerMultiplicationBitSide<T>> mult_bit_side_;
//   std::unique_ptr<MOTION::BitIntegerMultiplicationIntSide<T>> mult_int_side_;
//   std::vector<T> delta_b_share_;
//   std::vector<T> delta_b_x_delta_n_share_;
//   ENCRYPTO::ReusableFiberFuture<std::vector<T>> share_future_;
// };

}  // namespace MOTION::proto::swift
