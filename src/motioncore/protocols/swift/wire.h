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

#include <memory>
#include <vector>

#include "utility/bit_vector.h"
#include "utility/type_traits.hpp"
#include "utility/typedefs.h"
#include "wire/new_wire.h"

namespace MOTION::proto::swift {
class SWIFTProvider;

class BooleanSWIFTWire : public NewWire, public ENCRYPTO::enable_wait_setup {
 public:
  BooleanSWIFTWire(std::size_t num_simd) : NewWire(num_simd) {
    public_share_.Resize(num_simd, /*zero_fill=*/true);
    secret_share_[0].Resize(num_simd, /*zero_fill=*/true);
    secret_share_[1].Resize(num_simd, /*zero_fill=*/true);
    secret_share_[2].Resize(num_simd, /*zero_fill=*/true);
  }
  MPCProtocol get_protocol() const noexcept override { return MPCProtocol::BooleanSWIFT; }
  std::size_t get_bit_size() const noexcept override { return 1; }
  std::pair<ENCRYPTO::BitVector<>&, std::array<ENCRYPTO::BitVector<>, 3>&> get_share() {
    return {public_share_, secret_share_};
  };
  std::pair<const ENCRYPTO::BitVector<>&, const std::array<ENCRYPTO::BitVector<>, 3>&> get_share() const {
    return {public_share_, secret_share_};
  };
  ENCRYPTO::BitVector<>& get_public_share() { return public_share_; };
  const ENCRYPTO::BitVector<>& get_public_share() const { return public_share_; };
  std::array<ENCRYPTO::BitVector<>, 3>& get_secret_share() { return secret_share_; };
  const std::array<ENCRYPTO::BitVector<>, 3>& get_secret_share() const { return secret_share_; };

 private:
  // Holds this party's shares
  ENCRYPTO::BitVector<> public_share_;
  // Holds this party's secret shares.
  // Placeholder for alpha0, alpha1 and alpha2.
  // For a particular party only 2 of the 3 are non-zero.
  std::array<ENCRYPTO::BitVector<>, 3> secret_share_;
};

using BooleanSWIFTWireP = std::shared_ptr<BooleanSWIFTWire>;
using BooleanSWIFTWireVector = std::vector<BooleanSWIFTWireP>;

inline std::ostream& operator<<(std::ostream& os, const BooleanSWIFTWire& w) {
  return os << "<BooleanSWIFTWire @ " << &w << ">";
}

template <typename T>
class ArithmeticSWIFTWire : public NewWire, public ENCRYPTO::enable_wait_setup {
 public:
  ArithmeticSWIFTWire(std::size_t num_simd)
      : NewWire(num_simd), public_share_(num_simd) {
        secret_share_[0].resize(num_simd, 0);
        secret_share_[1].resize(num_simd, 0);
        secret_share_[2].resize(num_simd, 0);
      }
  MPCProtocol get_protocol() const noexcept override { return MPCProtocol::ArithmeticSWIFT; }
  std::size_t get_bit_size() const noexcept override { return ENCRYPTO::bit_size_v<T>; }
  std::pair<std::vector<T>&, std::array<std::vector<T>, 3>&> get_share() {
    return {public_share_, secret_share_};
  };
  std::pair<const std::vector<T>&, const std::array<std::vector<T>, 3>&> get_share() const {
    return {public_share_, secret_share_};
  };
  std::vector<T>& get_public_share() { return public_share_; };
  const std::vector<T>& get_public_share() const { return public_share_; };
  std::array<std::vector<T>, 3>& get_secret_share() { return secret_share_; };
  const std::array<std::vector<T>, 3>& get_secret_share() const { return secret_share_; };

 private:
  using is_enabled_ = ENCRYPTO::is_unsigned_int_t<T>;

  // Holds this party shares
  std::vector<T> public_share_;
  // Holds this party's secret shares.
  // Placeholder for alpha0, alpha1 and alpha2.
  // For a particular party only 2 of the 3 are non-zero.
  std::array<std::vector<T>, 3> secret_share_;
};

template <typename T>
using ArithmeticSWIFTWireP = std::shared_ptr<ArithmeticSWIFTWire<T>>;
template <typename T>
using ArithmeticSWIFTWireVector = std::vector<std::shared_ptr<ArithmeticSWIFTWire<T>>>;

template <typename T>
std::ostream& operator<<(std::ostream& os, const ArithmeticSWIFTWire<T>& w) {
  return os << "<ArithmeticSWIFTWire<T> @ " << &w << ">";
}

}  // namespace MOTION::proto::swift
