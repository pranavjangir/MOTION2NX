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

namespace MOTION::proto::beavy {

class BEAVYProvider;

class BooleanBEAVYWire : public NewWire, public ENCRYPTO::enable_wait_setup {
 public:
  BooleanBEAVYWire(std::size_t num_simd, std::size_t num_parties = 10) : NewWire(num_simd) {
      // TODO(pranav): fix the number of parties issue.
      // Single public value per data instance.
      public_share_.Resize(num_simd);
      // We do not need different secret shares for different data instances.
      common_secret_share_.Resize((1LL << num_parties), /*zero_fill=*/true);
  }
  MPCProtocol get_protocol() const noexcept override { return MPCProtocol::BooleanBEAVY; }
  std::size_t get_bit_size() const noexcept override { return 1; }
  std::pair<ENCRYPTO::BitVector<>&, ENCRYPTO::BitVector<>&> get_share() {
    return {public_share_, secret_share_};
  };
  std::pair<const ENCRYPTO::BitVector<>&, const ENCRYPTO::BitVector<>&> get_share() const {
    return {public_share_, secret_share_};
  };
  std::pair<ENCRYPTO::BitVector<>&, ENCRYPTO::BitVector<>&> get_public_and_secret_share() {
    return {public_share_, common_secret_share_};
  };
  std::pair<const ENCRYPTO::BitVector<>&, const ENCRYPTO::BitVector<>&> get_public_and_secret_share() const {
    return {public_share_, common_secret_share_};
  };
  ENCRYPTO::BitVector<>& get_public_share() { return public_share_; };
  const ENCRYPTO::BitVector<>& get_public_share() const { return public_share_; };
  ENCRYPTO::BitVector<>& get_secret_share() { return secret_share_; };
  const ENCRYPTO::BitVector<>& get_secret_share() const { return secret_share_; };
  ENCRYPTO::BitVector<>& get_common_secret_share() { return common_secret_share_; };
  const ENCRYPTO::BitVector<>& get_common_secret_share() const { return common_secret_share_; };

 private:
  // holds this party shares
  ENCRYPTO::BitVector<> public_share_;
  ENCRYPTO::BitVector<> secret_share_;
  // Secret share common between all num_simds
  ENCRYPTO::BitVector<> common_secret_share_;
};

using BooleanBEAVYWireP = std::shared_ptr<BooleanBEAVYWire>;
using BooleanBEAVYWireVector = std::vector<BooleanBEAVYWireP>;

inline std::ostream& operator<<(std::ostream& os, const BooleanBEAVYWire& w) {
  return os << "<BooleanBEAVYWire @ " << &w << ">";
}

template <typename T>
class ArithmeticBEAVYWire : public NewWire, public ENCRYPTO::enable_wait_setup {
 public:
  ArithmeticBEAVYWire(std::size_t num_simd, std::size_t num_parties = 2)
      : NewWire(num_simd), public_share_(num_simd), secret_share_(num_simd) {
        // Assuming `num_simd` = 1, the vector for public shares and secret shares
        // are logically used to represent the many secret shares, instead of 
        // instances of the num_simd.
        // That is, each index in the vector represents a share.
        
        // TODO: Fix num_simd != 1 case.
        if (num_simd > 1 || num_parties == 2) {
          return;
        }
        std::cout << "PArties : " << num_parties << std::endl;
        // Set the corruption threshold to half of num_parties.
        // Explicit assumption that num_parties is odd integer.
        assert(num_parties%2 == 1);
        std::size_t t = num_parties / 2;
        // Each party will have a single public share.
        public_share_.resize(((1 << num_parties)), 0);
        // Each party will have (n-1 CHOOSE t) private shares.
        secret_share_.resize((1 << num_parties), 0);

        random_shares_.resize((1LL << num_parties), 0);

        std::cout << "Share size inside wire : " << secret_share_.size() << " " << public_share_.size() << std::endl;
      }
  MPCProtocol get_protocol() const noexcept override { return MPCProtocol::ArithmeticBEAVY; }
  std::size_t get_bit_size() const noexcept override { return ENCRYPTO::bit_size_v<T>; }
  std::pair<std::vector<T>&, std::vector<T>&> get_share() {
    return {public_share_, secret_share_};
  };
  std::pair<const std::vector<T>&, const std::vector<T>&> get_share() const {
    return {public_share_, secret_share_};
  };
  std::vector<T>& get_public_share() { return public_share_; };
  const std::vector<T>& get_public_share() const { return public_share_; };
  std::vector<T>& get_secret_share() { return secret_share_; };
  const std::vector<T>& get_secret_share() const { return secret_share_; };
  std::vector<T>& get_random_shares() { return random_shares_; };
  const std::vector<T>& get_random_shares() const { return random_shares_; };

 private:
  using is_enabled_ = ENCRYPTO::is_unsigned_int_t<T>;

  // holds this party shares
  std::vector<T> public_share_;
  std::vector<T> secret_share_;
  std::vector<T> random_shares_;
};

template <typename T>
using ArithmeticBEAVYWireP = std::shared_ptr<ArithmeticBEAVYWire<T>>;
template <typename T>
using ArithmeticBEAVYWireVector = std::vector<std::shared_ptr<ArithmeticBEAVYWire<T>>>;

template <typename T>
std::ostream& operator<<(std::ostream& os, const ArithmeticBEAVYWire<T>& w) {
  return os << "<ArithmeticBEAVYWire<T> @ " << &w << ">";
}

}  // namespace MOTION::proto::beavy
