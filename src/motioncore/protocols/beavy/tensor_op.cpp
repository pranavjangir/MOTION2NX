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

#include "tensor_op.h"

#include <parallel/algorithm>
#include <stdexcept>
#include <bitset>

#include "algorithm/circuit_loader.h"
#include "algorithm/make_circuit.h"
#include "beavy_provider.h"
#include "crypto/arithmetic_provider.h"
#include "crypto/motion_base_provider.h"
#include "crypto/multiplication_triple/linalg_triple_provider.h"
#include "crypto/multiplication_triple/sp_provider.h"
#include "crypto/oblivious_transfer/ot_flavors.h"
#include "crypto/oblivious_transfer/ot_provider.h"
#include "crypto/sharing_randomness_generator.h"
#include "executor/execution_context.h"
#include "utility/constants.h"
#include "utility/fiber_thread_pool/fiber_thread_pool.hpp"
#include "utility/fixed_point.h"
#include "utility/helpers.h"
#include "utility/linear_algebra.h"
#include "utility/logger.h"
#include "wire.h"

namespace MOTION::proto::beavy {

static std::shared_ptr<NewWire> cast_boolean_wire(BooleanBEAVYWireP wire) {
  return std::shared_ptr<NewWire>(wire);
}

static BooleanBEAVYWireVector cast_wires(std::vector<std::shared_ptr<NewWire>> wires) {
  BooleanBEAVYWireVector result(wires.size());
  std::transform(std::begin(wires), std::end(wires), std::begin(result),
                 [](auto& w) { return std::dynamic_pointer_cast<BooleanBEAVYWire>(w); });
  return result;
}

template <typename T>
ArithmeticBEAVYTensorInputSender<T>::ArithmeticBEAVYTensorInputSender(
    std::size_t gate_id, BEAVYProvider& beavy_provider, const tensor::TensorDimensions& dimensions,
    ENCRYPTO::ReusableFiberFuture<std::vector<T>>&& input_future)
    : NewGate(gate_id),
      beavy_provider_(beavy_provider),
      dimensions_(dimensions),
      input_id_(beavy_provider.get_next_input_id(1)),
      input_future_(std::move(input_future)),
      output_(std::make_shared<ArithmeticBEAVYTensor<T>>(dimensions)) {
  if (beavy_provider_.get_num_parties() != 2) {
    throw std::logic_error("only two parties are currently supported");
  }
  output_->get_public_share().resize(dimensions.get_data_size());
  output_->get_secret_share().resize(dimensions.get_data_size());

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticBEAVYTensorInputSender<T> created", gate_id_));
    }
  }
}

template <typename T>
void ArithmeticBEAVYTensorInputSender<T>::evaluate_setup() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: ArithmeticBEAVYTensorInputSender<T>::evaluate_setup start", gate_id_));
    }
  }

  const auto my_id = beavy_provider_.get_my_id();
  const auto data_size = dimensions_.get_data_size();
  auto& my_secret_share = output_->get_secret_share();
  auto& my_public_share = output_->get_public_share();
  my_secret_share = Helpers::RandomVector<T>(data_size);
  output_->set_setup_ready();
  auto& mbp = beavy_provider_.get_motion_base_provider();
  auto& rng = mbp.get_my_randomness_generator(1 - my_id);
  rng.GetUnsigned<T>(input_id_, data_size, my_public_share.data());
  __gnu_parallel::transform(std::begin(my_public_share), std::end(my_public_share),
                            std::begin(my_secret_share), std::begin(my_public_share), std::plus{});

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: ArithmeticBEAVYTensorInputSender<T>::evaluate_setup end", gate_id_));
    }
  }
}

template <typename T>
void ArithmeticBEAVYTensorInputSender<T>::evaluate_online() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: ArithmeticBEAVYTensorInputSender<T>::evaluate_online start", gate_id_));
    }
  }

  // wait for input value
  const auto input = input_future_.get();
  if (input.size() != output_->get_dimensions().get_data_size()) {
    throw std::runtime_error("size of input vector != product of expected dimensions");
  }

  // compute public share
  auto& my_public_share = output_->get_public_share();
  __gnu_parallel::transform(std::begin(input), std::end(input), std::begin(my_public_share),
                            std::begin(my_public_share), std::plus{});
  output_->set_online_ready();
  beavy_provider_.broadcast_ints_message(gate_id_, my_public_share);

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: ArithmeticBEAVYTensorInputSender<T>::evaluate_online end", gate_id_));
    }
  }
}

template class ArithmeticBEAVYTensorInputSender<std::uint32_t>;
template class ArithmeticBEAVYTensorInputSender<std::uint64_t>;

template <typename T>
ArithmeticBEAVYTensorInputReceiver<T>::ArithmeticBEAVYTensorInputReceiver(
    std::size_t gate_id, BEAVYProvider& beavy_provider, const tensor::TensorDimensions& dimensions)
    : NewGate(gate_id),
      beavy_provider_(beavy_provider),
      dimensions_(dimensions),
      input_id_(beavy_provider.get_next_input_id(1)),
      output_(std::make_shared<ArithmeticBEAVYTensor<T>>(dimensions)) {
  const auto my_id = beavy_provider_.get_my_id();
  public_share_future_ =
      beavy_provider_.register_for_ints_message<T>(1 - my_id, gate_id_, dimensions.get_data_size());
  output_->get_secret_share().resize(dimensions.get_data_size());

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticBEAVYTensorInputReceiver<T> created", gate_id_));
    }
  }
}

template <typename T>
void ArithmeticBEAVYTensorInputReceiver<T>::evaluate_setup() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: ArithmeticBEAVYTensorInputReceiver<T>::evaluate_setup start", gate_id_));
    }
  }

  const auto my_id = beavy_provider_.get_my_id();
  auto& mbp = beavy_provider_.get_motion_base_provider();
  auto& rng = mbp.get_their_randomness_generator(1 - my_id);
  rng.GetUnsigned<T>(input_id_, output_->get_dimensions().get_data_size(),
                     output_->get_secret_share().data());
  output_->set_setup_ready();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: ArithmeticBEAVYTensorInputReceiver<T>::evaluate_setup end", gate_id_));
    }
  }
}

template <typename T>
void ArithmeticBEAVYTensorInputReceiver<T>::evaluate_online() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: ArithmeticBEAVYTensorInputReceiver<T>::evaluate_online start", gate_id_));
    }
  }

  output_->get_public_share() = public_share_future_.get();
  output_->set_online_ready();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: ArithmeticBEAVYTensorInputReceiver<T>::evaluate_online end", gate_id_));
    }
  }
}

template class ArithmeticBEAVYTensorInputReceiver<std::uint32_t>;
template class ArithmeticBEAVYTensorInputReceiver<std::uint64_t>;

template <typename T>
ArithmeticBEAVYTensorOutput<T>::ArithmeticBEAVYTensorOutput(std::size_t gate_id,
                                                            BEAVYProvider& beavy_provider,
                                                            ArithmeticBEAVYTensorCP<T> input,
                                                            std::size_t output_owner)
    : NewGate(gate_id),
      beavy_provider_(beavy_provider),
      output_owner_(output_owner),
      input_(input) {
  auto my_id = beavy_provider_.get_my_id();
  if (output_owner_ == my_id) {
    secret_share_future_ = beavy_provider_.register_for_ints_message<T>(
        1 - my_id, gate_id_, input_->get_dimensions().get_data_size());
  }

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format("Gate {}: ArithmeticBEAVYTensorOutput<T> created", gate_id_));
    }
  }
}

template <typename T>
void ArithmeticBEAVYTensorOutput<T>::evaluate_setup() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticBEAVYTensorOutput<T>::evaluate_setup start", gate_id_));
    }
  }

  auto my_id = beavy_provider_.get_my_id();
  input_->wait_setup();
  const auto& my_secret_share = input_->get_secret_share();
  if (output_owner_ == my_id) {
    secret_shares_ = secret_share_future_.get();
    assert(my_secret_share.size() == input_->get_dimensions().get_data_size());
    assert(secret_shares_.size() == input_->get_dimensions().get_data_size());
    __gnu_parallel::transform(std::begin(secret_shares_), std::end(secret_shares_),
                              std::begin(my_secret_share), std::begin(secret_shares_), std::plus{});
  } else {
    beavy_provider_.send_ints_message<T>(1 - my_id, gate_id_, my_secret_share);
  }

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticBEAVYTensorOutput<T>::evaluate_setup end", gate_id_));
    }
  }
}

template <typename T>
void ArithmeticBEAVYTensorOutput<T>::evaluate_online() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticBEAVYTensorOutput<T>::evaluate_online start", gate_id_));
    }
  }

  auto my_id = beavy_provider_.get_my_id();
  if (output_owner_ == my_id) {
    input_->wait_online();
    const auto& public_share = input_->get_public_share();
    assert(public_share.size() == input_->get_dimensions().get_data_size());
    assert(secret_shares_.size() == input_->get_dimensions().get_data_size());
    __gnu_parallel::transform(std::begin(public_share), std::end(public_share),
                              std::begin(secret_shares_), std::begin(secret_shares_), std::minus{});
    output_promise_.set_value(std::move(secret_shares_));
  }

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticBEAVYTensorOutput<T>::evaluate_online end", gate_id_));
    }
  }
}

template <typename T>
ENCRYPTO::ReusableFiberFuture<std::vector<T>> ArithmeticBEAVYTensorOutput<T>::get_output_future() {
  std::size_t my_id = beavy_provider_.get_my_id();
  if (output_owner_ == ALL_PARTIES || output_owner_ == my_id) {
    return output_promise_.get_future();
  } else {
    throw std::logic_error("not this parties output");
  }
}

template class ArithmeticBEAVYTensorOutput<std::uint32_t>;
template class ArithmeticBEAVYTensorOutput<std::uint64_t>;

template <typename T>
ArithmeticBEAVYTensorFlatten<T>::ArithmeticBEAVYTensorFlatten(
    std::size_t gate_id, BEAVYProvider& beavy_provider, std::size_t axis,
    const ArithmeticBEAVYTensorCP<T> input)
    : NewGate(gate_id), beavy_provider_(beavy_provider), input_(input) {
  const auto& input_dims = input_->get_dimensions();
  output_ = std::make_shared<ArithmeticBEAVYTensor<T>>(flatten(input_dims, axis), beavy_provider.get_num_parties());

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format("Gate {}: ArithmeticBEAVYTensorFlatten<T> created", gate_id_));
    }
  }
}

template <typename T>
void ArithmeticBEAVYTensorFlatten<T>::evaluate_setup() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticBEAVYTensorFlatten<T>::evaluate_setup start", gate_id_));
    }
  }

  input_->wait_setup();
  output_->get_secret_share() = input_->get_secret_share();
  output_->get_common_secret_share() = input_->get_common_secret_share();
  output_->set_setup_ready();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticBEAVYTensorFlatten<T>::evaluate_setup end", gate_id_));
    }
  }
}

template <typename T>
void ArithmeticBEAVYTensorFlatten<T>::evaluate_online() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticBEAVYTensorFlatten<T>::evaluate_online start", gate_id_));
    }
  }

  input_->wait_online();
  output_->get_public_share() = input_->get_public_share();
  output_->set_online_ready();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticBEAVYTensorFlatten<T>::evaluate_online end", gate_id_));
    }
  }
}

template class ArithmeticBEAVYTensorFlatten<std::uint32_t>;
template class ArithmeticBEAVYTensorFlatten<std::uint64_t>;

template <typename T>
ArithmeticBEAVYTensorConv2D<T>::ArithmeticBEAVYTensorConv2D(
    std::size_t gate_id, BEAVYProvider& beavy_provider, tensor::Conv2DOp conv_op,
    const ArithmeticBEAVYTensorCP<T> input, const ArithmeticBEAVYTensorCP<T> kernel,
    const ArithmeticBEAVYTensorCP<T> bias, std::size_t fractional_bits)
    : NewGate(gate_id),
      beavy_provider_(beavy_provider),
      conv_op_(conv_op),
      fractional_bits_(fractional_bits),
      input_(input),
      kernel_(kernel),
      bias_(bias),
      output_(std::make_shared<ArithmeticBEAVYTensor<T>>(conv_op.get_output_tensor_dims(), beavy_provider.get_num_parties())) {
  // const auto my_id = beavy_provider_.get_my_id();
  // const auto output_size = conv_op_.compute_output_size();
  // share_future_ = beavy_provider_.register_for_ints_message<T>(1 - my_id, gate_id_, output_size);
  // auto& ap = beavy_provider_.get_arith_manager().get_provider(1 - my_id);
  // if (!beavy_provider_.get_fake_setup()) {
  //   conv_input_side_ = ap.template register_convolution_input_side<T>(conv_op);
  //   conv_kernel_side_ = ap.template register_convolution_kernel_side<T>(conv_op);
  // }
  // Delta_y_share_.resize(output_size);
  const auto my_id = beavy_provider_.get_my_id();
  const auto p_king = beavy_provider_.get_p_king();
  const auto num_parties = beavy_provider_.get_num_parties();
  const auto output_size = conv_op_.compute_output_size();
  share_future_.resize(num_parties);
  if (my_id == p_king) {
    share_future_ = beavy_provider_.register_for_ints_messages<T>(gate_id_, output_size);
  } else if (my_id <= (num_parties / 2)) {
    share_future_[p_king] = beavy_provider_.register_for_ints_message<T>(p_king, gate_id_, output_size);
  }

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format("Gate {}: ArithmeticBEAVYTensorConv2D<T> created", gate_id_));
    }
  }
}

template <typename T>
ArithmeticBEAVYTensorConv2D<T>::~ArithmeticBEAVYTensorConv2D() = default;

template <typename T>
void ArithmeticBEAVYTensorConv2D<T>::evaluate_setup() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticBEAVYTensorConv2D<T>::evaluate_setup start", gate_id_));
    }
  }

  // const auto output_size = conv_op_.compute_output_size();

  // output_->get_secret_share() = Helpers::RandomVector<T>(output_size);
  // output_->set_setup_ready();

  // input_->wait_setup();
  // kernel_->wait_setup();

  // const auto& delta_a_share = input_->get_secret_share();
  // const auto& delta_b_share = kernel_->get_secret_share();
  // const auto& delta_y_share = output_->get_secret_share();

  // if (!beavy_provider_.get_fake_setup()) {
  //   conv_input_side_->set_input(delta_a_share);
  //   conv_kernel_side_->set_input(delta_b_share);
  // }

  // // [Delta_y]_i = [delta_a]_i * [delta_b]_i
  // convolution(conv_op_, delta_a_share.data(), delta_b_share.data(), Delta_y_share_.data());

  // if (fractional_bits_ == 0) {
  //   // [Delta_y]_i += [delta_y]_i
  //   __gnu_parallel::transform(std::begin(Delta_y_share_), std::end(Delta_y_share_),
  //                             std::begin(delta_y_share), std::begin(Delta_y_share_), std::plus{});
  //   // NB: happens after truncation if that is requested
  // }

  // if (!beavy_provider_.get_fake_setup()) {
  //   conv_input_side_->compute_output();
  //   conv_kernel_side_->compute_output();
  // }
  // std::vector<T> delta_ab_share1;
  // std::vector<T> delta_ab_share2;
  // if (beavy_provider_.get_fake_setup()) {
  //   delta_ab_share1 = Helpers::RandomVector<T>(conv_op_.compute_output_size());
  //   delta_ab_share2 = Helpers::RandomVector<T>(conv_op_.compute_output_size());
  // } else {
  //   // [[delta_a]_i * [delta_b]_(1-i)]_i
  //   delta_ab_share1 = conv_input_side_->get_output();
  //   // [[delta_b]_i * [delta_a]_(1-i)]_i
  //   delta_ab_share2 = conv_kernel_side_->get_output();
  // }
  // // [Delta_y]_i += [[delta_a]_i * [delta_b]_(1-i)]_i
  // __gnu_parallel::transform(std::begin(Delta_y_share_), std::end(Delta_y_share_),
  //                           std::begin(delta_ab_share1), std::begin(Delta_y_share_), std::plus{});
  // // [Delta_y]_i += [[delta_b]_i * [delta_a]_(1-i)]_i
  // __gnu_parallel::transform(std::begin(Delta_y_share_), std::end(Delta_y_share_),
  //                           std::begin(delta_ab_share2), std::begin(Delta_y_share_), std::plus{});

  auto my_id = beavy_provider_.get_my_id();
  auto p_king = beavy_provider_.get_p_king();
  std::size_t num_parties = beavy_provider_.get_num_parties();
  auto& owned_shares = beavy_provider_.get_owned_shares();
  auto& mul_shares = beavy_provider_.get_mup_shares_for_p_king();

  auto& ss = output_->get_common_secret_share();
  for (auto share : owned_shares[my_id]) {
    //ss[share] = -1*(share + 10);
    // TODO(pranav): Change this when signed integers are supported.
    ss[share] = 0;
  }

  output_->set_setup_ready();

  input_->wait_setup();
  kernel_->wait_setup();
  const auto& input_a_ss = input_->get_common_secret_share();
  const auto& input_b_ss = kernel_->get_common_secret_share();
  if (my_id == p_king) {
    shares_from_D_.resize(conv_op_.compute_output_size(), 0);
    for (std::size_t party = (num_parties / 2) + 1; party < num_parties; ++party) {
      auto v = share_future_[party].get();
      assert(v.size() == shares_from_D_.size());
      for (int i = 0; i < shares_from_D_.size(); ++i) {
        shares_from_D_[i] += v[i];
      }
    }
  } else if (my_id > (num_parties / 2)) {
    std::size_t pking_share = 0;
    for (const auto [i, j]: mul_shares[my_id]) {
      pking_share += (input_a_ss[i] * input_b_ss[j]);
    }
    std::vector<T> v(conv_op_.compute_output_size(), pking_share);
    beavy_provider_.send_ints_message(p_king, gate_id_, v);
  }

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticBEAVYTensorConv2D<T>::evaluate_setup end", gate_id_));
    }
  }
}

template <typename T>
void ArithmeticBEAVYTensorConv2D<T>::evaluate_online() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticBEAVYTensorConv2D<T>::evaluate_online start", gate_id_));
    }
  }

  // const auto output_size = conv_op_.compute_output_size();
  // input_->wait_online();
  // kernel_->wait_online();
  // const auto& Delta_a = input_->get_public_share();
  // const auto& Delta_b = kernel_->get_public_share();
  // const auto& delta_a_share = input_->get_secret_share();
  // const auto& delta_b_share = kernel_->get_secret_share();
  // std::vector<T> tmp(output_size);

  // // after setup phase, `Delta_y_share_` contains [delta_y]_i + [delta_ab]_i

  // // [Delta_y]_i -= Delta_a * [delta_b]_i
  // convolution(conv_op_, Delta_a.data(), delta_b_share.data(), tmp.data());
  // __gnu_parallel::transform(std::begin(Delta_y_share_), std::end(Delta_y_share_), std::begin(tmp),
  //                           std::begin(Delta_y_share_), std::minus{});

  // // [Delta_y]_i -= Delta_b * [delta_a]_i
  // convolution(conv_op_, delta_a_share.data(), Delta_b.data(), tmp.data());
  // __gnu_parallel::transform(std::begin(Delta_y_share_), std::end(Delta_y_share_), std::begin(tmp),
  //                           std::begin(Delta_y_share_), std::minus{});

  // // [Delta_y]_i += Delta_ab (== Delta_a * Delta_b)
  // if (beavy_provider_.is_my_job(gate_id_)) {
  //   convolution(conv_op_, Delta_a.data(), Delta_b.data(), tmp.data());
  //   __gnu_parallel::transform(std::begin(Delta_y_share_), std::end(Delta_y_share_), std::begin(tmp),
  //                             std::begin(Delta_y_share_), std::plus{});
  // }

  // if (fractional_bits_ > 0) {
  //   fixed_point::truncate_shared<T>(Delta_y_share_.data(), fractional_bits_, Delta_y_share_.size(),
  //                                   beavy_provider_.is_my_job(gate_id_));
  //   // [Delta_y]_i += [delta_y]_i
  //   __gnu_parallel::transform(std::begin(Delta_y_share_), std::end(Delta_y_share_),
  //                             std::begin(output_->get_secret_share()), std::begin(Delta_y_share_),
  //                             std::plus{});
  //   // NB: happens in setup phase if no truncation is requested
  // }

  // // broadcast [Delta_y]_i
  // beavy_provider_.broadcast_ints_message(gate_id_, Delta_y_share_);
  // // Delta_y = [Delta_y]_i + [Delta_y]_(1-i)
  // __gnu_parallel::transform(std::begin(Delta_y_share_), std::end(Delta_y_share_),
  //                           std::begin(share_future_.get()), std::begin(Delta_y_share_),
  //                           std::plus{});
  // output_->get_public_share() = std::move(Delta_y_share_);
  // output_->set_online_ready();

  const auto output_size = conv_op_.compute_output_size();
  auto my_id = beavy_provider_.get_my_id();
  auto p_king = beavy_provider_.get_p_king();
  std::size_t num_parties = beavy_provider_.get_num_parties();
  auto& owned_shares = beavy_provider_.get_owned_shares();
  auto& mul_shares = beavy_provider_.get_mup_shares_for_p_king();
  auto& pking_shares = beavy_provider_.get_shares_for_p_king();

  if (my_id > num_parties / 2) {
    output_->set_online_ready();
    return;
  }
  input_->wait_online();
  kernel_->wait_online();
  const auto& pa = input_->get_public_share();
  const auto& pb = kernel_->get_public_share();
  const auto& sa = input_->get_common_secret_share();
  const auto& sb = kernel_->get_common_secret_share();
  auto& oa = output_->get_public_share();
  const auto& so = output_->get_common_secret_share();

  if (my_id == p_king) {
    convolution(conv_op_, pa.data(), pb.data(), oa.data());
    assert(oa.size() == shares_from_D_.size());
    __gnu_parallel::transform(oa.begin(), oa.end(),
     shares_from_D_.begin(),
      oa.begin(), std::plus{});
      for (const auto share : owned_shares[my_id]) {
        std::vector<T> ssb(pb.size(), sb[share]);
        std::vector<T> ssa(pa.size(), sa[share]);
        std::vector<T> public_a_times_sec_b(oa.size(), 0);
        std::vector<T> public_b_times_sec_a(oa.size(), 0);
        convolution(conv_op_, pa.data(), ssb.data(), public_a_times_sec_b.data());
        convolution(conv_op_, ssa.data(), pb.data(), public_b_times_sec_a.data());
        assert(public_a_times_sec_b.size() == oa.size());
        assert(public_b_times_sec_a.size() == oa.size());
        __gnu_parallel::transform(oa.begin(), oa.end(),
        public_a_times_sec_b.begin(),
          oa.begin(), std::minus<T>());
          __gnu_parallel::transform(oa.begin(), oa.end(),
        public_b_times_sec_a.begin(),
          oa.begin(), std::minus<T>());
        std::vector<T> rnd(oa.size(), so[share]);
        __gnu_parallel::transform(oa.begin(), oa.end(),
        rnd.begin(),
          oa.begin(), std::plus<T>());
        for (const auto share2: owned_shares[my_id]) {
          std::vector<T> ssb2(pb.size(), sb[share2]);
          // std::vector<T> ssa2(pa.size(), sa[share2]);
          std::vector<T> ssa_ssb(oa.size(), 0);
          convolution(conv_op_, ssa.data(), ssb2.data(), ssa_ssb.data());
          __gnu_parallel::transform(oa.begin(), oa.end(),
          ssa_ssb.begin(),
          oa.begin(), std::plus<T>());
        }
      }

    // get others shares.
    for (std::size_t party = 0; party <= (num_parties / 2); ++party) {
      if (party == my_id) continue;
      auto other_share = share_future_[party].get();
      assert(other_share.size() == oa.size());
      __gnu_parallel::transform(oa.begin(), oa.end(),
          other_share.begin(),
          oa.begin(), std::plus<T>());
    }
    // send to other parties in E.
    for (std::size_t party = 0; party <= (num_parties / 2); ++party) {
      if (party == my_id) continue;
      beavy_provider_.send_ints_message(party, gate_id_, oa);
    }
  } else {
    // Send the shares to pking.
    std::vector<T> for_pking(oa.size(), 0);
    for (const auto share : pking_shares[my_id]) {
      std::vector<T> ssb(pb.size(), sb[share]);
      std::vector<T> ssa(pa.size(), sa[share]);
      std::vector<T> public_a_times_sec_b(oa.size(), 0);
      std::vector<T> public_b_times_sec_a(oa.size(), 0);
      convolution(conv_op_, pa.data(), ssb.data(), public_a_times_sec_b.data());
      convolution(conv_op_, ssa.data(), pb.data(), public_b_times_sec_a.data());
      assert(public_a_times_sec_b.size() == for_pking.size());
      assert(public_b_times_sec_a.size() == for_pking.size());
      __gnu_parallel::transform(for_pking.begin(), for_pking.end(),
          public_a_times_sec_b.begin(),
          for_pking.begin(), std::minus<T>());
      __gnu_parallel::transform(for_pking.begin(), for_pking.end(),
          public_b_times_sec_a.begin(),
          for_pking.begin(), std::minus<T>());
      std::vector<T> rnd(for_pking.size(), so[share]);
      __gnu_parallel::transform(for_pking.begin(), for_pking.end(),
      rnd.begin(),
        for_pking.begin(), std::plus<T>());
    }
    for (const auto [i, j] : mul_shares[my_id]) {
      std::vector<T> ssb(pb.size(), sb[j]);
      std::vector<T> ssa(pa.size(), sa[i]);
      std::vector<T> ssa_ssb(oa.size(), 0);
      convolution(conv_op_, ssa.data(), ssb.data(), ssa_ssb.data());
      __gnu_parallel::transform(for_pking.begin(), for_pking.end(),
          ssa_ssb.begin(),
          for_pking.begin(), std::plus<T>());
    }
    beavy_provider_.send_ints_message(p_king, gate_id_, for_pking);
    // recieve the shares from pking.

    oa = share_future_[p_king].get();
  }

  // handle the fractional bits part as well. (maybe later)
  output_->set_online_ready();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticBEAVYTensorConv2D<T>::evaluate_online end", gate_id_));
    }
  }
}

template class ArithmeticBEAVYTensorConv2D<std::uint32_t>;
template class ArithmeticBEAVYTensorConv2D<std::uint64_t>;

template <typename T>
ArithmeticBEAVYTensorGemm<T>::ArithmeticBEAVYTensorGemm(std::size_t gate_id,
                                                        BEAVYProvider& beavy_provider,
                                                        tensor::GemmOp gemm_op,
                                                        const ArithmeticBEAVYTensorCP<T> input_A,
                                                        const ArithmeticBEAVYTensorCP<T> input_B,
                                                        std::size_t fractional_bits)
    : NewGate(gate_id),
      beavy_provider_(beavy_provider),
      gemm_op_(gemm_op),
      fractional_bits_(fractional_bits),
      input_A_(input_A),
      input_B_(input_B),
      output_(std::make_shared<ArithmeticBEAVYTensor<T>>(gemm_op.get_output_tensor_dims(),
       beavy_provider.get_num_parties())) {
  const auto my_id = beavy_provider_.get_my_id();
  const auto p_king = beavy_provider_.get_p_king();
  const auto num_parties = beavy_provider_.get_num_parties();
  const auto output_size = gemm_op_.compute_output_size();
  share_future_.resize(num_parties);
  if (my_id == p_king) {
    share_future_ = beavy_provider_.register_for_ints_messages<T>(gate_id_, output_size);
  } else if (my_id <= (num_parties / 2)) {
    share_future_[p_king] = beavy_provider_.register_for_ints_message<T>(p_king, gate_id_, output_size);
  }

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format("Gate {}: ArithmeticBEAVYTensorGemm<T> created", gate_id_));
    }
  }
}

template <typename T>
ArithmeticBEAVYTensorGemm<T>::~ArithmeticBEAVYTensorGemm() = default;

template <typename T>
void ArithmeticBEAVYTensorGemm<T>::evaluate_setup() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticBEAVYTensorGemm<T>::evaluate_setup start", gate_id_));
    }
  }

  auto my_id = beavy_provider_.get_my_id();
  auto p_king = beavy_provider_.get_p_king();
  std::size_t num_parties = beavy_provider_.get_num_parties();
  auto& owned_shares = beavy_provider_.get_owned_shares();
  auto& mul_shares = beavy_provider_.get_mup_shares_for_p_king();

  auto& ss = output_->get_common_secret_share();
  for (auto share : owned_shares[my_id]) {
    //ss[share] = -1*(share + 10);
    // TODO(pranav): Change this when signed integers are supported.
    ss[share] = 0;
  }

  output_->set_setup_ready();

  input_A_->wait_setup();
  input_B_->wait_setup();
  const auto& input_a_ss = input_A_->get_common_secret_share();
  const auto& input_b_ss = input_B_->get_common_secret_share();
  if (my_id == p_king) {
    shares_from_D_.resize(gemm_op_.compute_output_size(), 0);
    for (std::size_t party = (num_parties / 2) + 1; party < num_parties; ++party) {
      auto v = share_future_[party].get();
      assert(v.size() == shares_from_D_.size());
      for (int i = 0; i < shares_from_D_.size(); ++i) {
        shares_from_D_[i] += v[i];
      }
    }
  } else if (my_id > (num_parties / 2)) {
    std::size_t pking_share = 0;
    for (const auto [i, j]: mul_shares[my_id]) {
      pking_share += (input_a_ss[i] * input_b_ss[j]);
    }
    std::vector<T> v(gemm_op_.compute_output_size(), pking_share);
    beavy_provider_.send_ints_message(p_king, gate_id_, v);
  }

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticBEAVYTensorGemm<T>::evaluate_setup end", gate_id_));
    }
  }
}

template <typename T>
void ArithmeticBEAVYTensorGemm<T>::evaluate_online() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticBEAVYTensorGemm<T>::evaluate_online start", gate_id_));
    }
  }

  const auto output_size = gemm_op_.compute_output_size();
  auto my_id = beavy_provider_.get_my_id();
  auto p_king = beavy_provider_.get_p_king();
  std::size_t num_parties = beavy_provider_.get_num_parties();
  auto& owned_shares = beavy_provider_.get_owned_shares();
  auto& mul_shares = beavy_provider_.get_mup_shares_for_p_king();
  auto& pking_shares = beavy_provider_.get_shares_for_p_king();

  if (my_id > num_parties / 2) {
    output_->set_online_ready();
    return;
  }
  input_A_->wait_online();
  input_B_->wait_online();
  const auto& pa = input_A_->get_public_share();
  const auto& pb = input_B_->get_public_share();
  const auto& sa = input_A_->get_common_secret_share();
  const auto& sb = input_B_->get_common_secret_share();
  auto& oa = output_->get_public_share();
  const auto& so = output_->get_common_secret_share();

  if (my_id == p_king) {
    matrix_multiply(gemm_op_, pa.data(), pb.data(), oa.data());
    assert(oa.size() == shares_from_D_.size());
    __gnu_parallel::transform(oa.begin(), oa.end(),
     shares_from_D_.begin(),
      oa.begin(), std::plus{});
      for (const auto share : owned_shares[my_id]) {
        std::vector<T> ssb(pb.size(), sb[share]);
        std::vector<T> ssa(pa.size(), sa[share]);
        std::vector<T> public_a_times_sec_b(oa.size(), 0);
        std::vector<T> public_b_times_sec_a(oa.size(), 0);
        matrix_multiply(gemm_op_, pa.data(), ssb.data(), public_a_times_sec_b.data());
        matrix_multiply(gemm_op_, ssa.data(), pb.data(), public_b_times_sec_a.data());
        assert(public_a_times_sec_b.size() == oa.size());
        assert(public_b_times_sec_a.size() == oa.size());
        __gnu_parallel::transform(oa.begin(), oa.end(),
        public_a_times_sec_b.begin(),
          oa.begin(), std::minus<T>());
          __gnu_parallel::transform(oa.begin(), oa.end(),
        public_b_times_sec_a.begin(),
          oa.begin(), std::minus<T>());
        std::vector<T> rnd(oa.size(), so[share]);
        __gnu_parallel::transform(oa.begin(), oa.end(),
        rnd.begin(),
          oa.begin(), std::plus<T>());
        for (const auto share2: owned_shares[my_id]) {
          std::vector<T> ssb2(pb.size(), sb[share2]);
          // std::vector<T> ssa2(pa.size(), sa[share2]);
          std::vector<T> ssa_ssb(oa.size(), 0);
          matrix_multiply(gemm_op_, ssa.data(), ssb2.data(), ssa_ssb.data());
          __gnu_parallel::transform(oa.begin(), oa.end(),
          ssa_ssb.begin(),
          oa.begin(), std::plus<T>());
        }
      }

    // get others shares.
    for (std::size_t party = 0; party <= (num_parties / 2); ++party) {
      if (party == my_id) continue;
      auto other_share = share_future_[party].get();
      assert(other_share.size() == oa.size());
      __gnu_parallel::transform(oa.begin(), oa.end(),
          other_share.begin(),
          oa.begin(), std::plus<T>());
    }
    // send to other parties in E.
    for (std::size_t party = 0; party <= (num_parties / 2); ++party) {
      if (party == my_id) continue;
      beavy_provider_.send_ints_message(party, gate_id_, oa);
    }
  } else {
    // Send the shares to pking.
    std::vector<T> for_pking(oa.size(), 0);
    for (const auto share : pking_shares[my_id]) {
      std::vector<T> ssb(pb.size(), sb[share]);
      std::vector<T> ssa(pa.size(), sa[share]);
      std::vector<T> public_a_times_sec_b(oa.size(), 0);
      std::vector<T> public_b_times_sec_a(oa.size(), 0);
      matrix_multiply(gemm_op_, pa.data(), ssb.data(), public_a_times_sec_b.data());
      matrix_multiply(gemm_op_, ssa.data(), pb.data(), public_b_times_sec_a.data());
      assert(public_a_times_sec_b.size() == for_pking.size());
      assert(public_b_times_sec_a.size() == for_pking.size());
      __gnu_parallel::transform(for_pking.begin(), for_pking.end(),
          public_a_times_sec_b.begin(),
          for_pking.begin(), std::minus<T>());
      __gnu_parallel::transform(for_pking.begin(), for_pking.end(),
          public_b_times_sec_a.begin(),
          for_pking.begin(), std::minus<T>());
      std::vector<T> rnd(for_pking.size(), so[share]);
      __gnu_parallel::transform(for_pking.begin(), for_pking.end(),
      rnd.begin(),
        for_pking.begin(), std::plus<T>());
    }
    for (const auto [i, j] : mul_shares[my_id]) {
      std::vector<T> ssb(pb.size(), sb[j]);
      std::vector<T> ssa(pa.size(), sa[i]);
      std::vector<T> ssa_ssb(oa.size(), 0);
      matrix_multiply(gemm_op_, ssa.data(), ssb.data(), ssa_ssb.data());
      __gnu_parallel::transform(for_pking.begin(), for_pking.end(),
          ssa_ssb.begin(),
          for_pking.begin(), std::plus<T>());
    }
    beavy_provider_.send_ints_message(p_king, gate_id_, for_pking);
    // recieve the shares from pking.

    oa = share_future_[p_king].get();
  }

  // handle the fractional bits part as well. (maybe later)
  output_->set_online_ready();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticBEAVYTensorGemm<T>::evaluate_online end", gate_id_));
    }
  }
}

template class ArithmeticBEAVYTensorGemm<std::uint32_t>;
template class ArithmeticBEAVYTensorGemm<std::uint64_t>;

template <typename T>
ArithmeticBEAVYTensorMul<T>::ArithmeticBEAVYTensorMul(std::size_t gate_id,
                                                      BEAVYProvider& beavy_provider,
                                                      const ArithmeticBEAVYTensorCP<T> input_A,
                                                      const ArithmeticBEAVYTensorCP<T> input_B,
                                                      std::size_t fractional_bits)
    : NewGate(gate_id),
      beavy_provider_(beavy_provider),
      fractional_bits_(fractional_bits),
      input_A_(input_A),
      input_B_(input_B),
      output_(std::make_shared<ArithmeticBEAVYTensor<T>>(input_A_->get_dimensions())) {
  if (input_A_->get_dimensions() != input_B_->get_dimensions()) {
    throw std::logic_error("mismatch of dimensions");
  }
  const auto my_id = beavy_provider_.get_my_id();
  const auto data_size = input_A_->get_dimensions().get_data_size();
  share_future_ = beavy_provider_.register_for_ints_message<T>(1 - my_id, gate_id_, data_size);
  auto& ap = beavy_provider_.get_arith_manager().get_provider(1 - my_id);
  mult_sender_ = ap.template register_integer_multiplication_send<T>(data_size);
  mult_receiver_ = ap.template register_integer_multiplication_receive<T>(data_size);
  Delta_y_share_.resize(data_size);

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format("Gate {}: ArithmeticBEAVYTensorMul<T> created", gate_id_));
    }
  }
}

template <typename T>
ArithmeticBEAVYTensorMul<T>::~ArithmeticBEAVYTensorMul() = default;

template <typename T>
void ArithmeticBEAVYTensorMul<T>::evaluate_setup() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticBEAVYTensorMul<T>::evaluate_setup start", gate_id_));
    }
  }

  const auto data_size = input_A_->get_dimensions().get_data_size();

  output_->get_secret_share() = Helpers::RandomVector<T>(data_size);
  output_->set_setup_ready();

  const auto& delta_a_share = input_A_->get_secret_share();
  const auto& delta_b_share = input_B_->get_secret_share();
  const auto& delta_y_share = output_->get_secret_share();

  mult_receiver_->set_inputs(delta_a_share);
  mult_sender_->set_inputs(delta_b_share);

  // [Delta_y]_i = [delta_a]_i * [delta_b]_i
  __gnu_parallel::transform(std::begin(delta_a_share), std::end(delta_a_share),
                            std::begin(delta_b_share), std::begin(Delta_y_share_),
                            std::multiplies{});

  if (fractional_bits_ == 0) {
    // [Delta_y]_i += [delta_y]_i
    __gnu_parallel::transform(std::begin(Delta_y_share_), std::end(Delta_y_share_),
                              std::begin(delta_y_share), std::begin(Delta_y_share_), std::plus{});
    // NB: happens after truncation if that is requested
  }

  mult_receiver_->compute_outputs();
  mult_sender_->compute_outputs();
  // [[delta_a]_i * [delta_b]_(1-i)]_i
  auto delta_ab_share1 = mult_receiver_->get_outputs();
  // [[delta_b]_i * [delta_a]_(1-i)]_i
  auto delta_ab_share2 = mult_sender_->get_outputs();
  // [Delta_y]_i += [[delta_a]_i * [delta_b]_(1-i)]_i
  __gnu_parallel::transform(std::begin(Delta_y_share_), std::end(Delta_y_share_),
                            std::begin(delta_ab_share1), std::begin(Delta_y_share_), std::plus{});
  // [Delta_y]_i += [[delta_b]_i * [delta_a]_(1-i)]_i
  __gnu_parallel::transform(std::begin(Delta_y_share_), std::end(Delta_y_share_),
                            std::begin(delta_ab_share2), std::begin(Delta_y_share_), std::plus{});

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticBEAVYTensorMul<T>::evaluate_setup end", gate_id_));
    }
  }
}

template <typename T>
void ArithmeticBEAVYTensorMul<T>::evaluate_online() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticBEAVYTensorMul<T>::evaluate_online start", gate_id_));
    }
  }

  const auto data_size = input_A_->get_dimensions().get_data_size();
  input_A_->wait_online();
  input_B_->wait_online();
  const auto& Delta_a = input_A_->get_public_share();
  const auto& Delta_b = input_B_->get_public_share();
  const auto& delta_a_share = input_A_->get_secret_share();
  const auto& delta_b_share = input_B_->get_secret_share();
  std::vector<T> tmp(data_size);

  // after setup phase, `Delta_y_share_` contains [delta_y]_i + [delta_ab]_i

  // [Delta_y]_i -= Delta_a * [delta_b]_i
  __gnu_parallel::transform(std::begin(Delta_a), std::end(Delta_a), std::begin(delta_b_share),
                            std::begin(tmp), std::multiplies{});
  __gnu_parallel::transform(std::begin(Delta_y_share_), std::end(Delta_y_share_), std::begin(tmp),
                            std::begin(Delta_y_share_), std::minus{});

  // [Delta_y]_i -= Delta_b * [delta_a]_i
  __gnu_parallel::transform(std::begin(Delta_b), std::end(Delta_b), std::begin(delta_a_share),
                            std::begin(tmp), std::multiplies{});
  __gnu_parallel::transform(std::begin(Delta_y_share_), std::end(Delta_y_share_), std::begin(tmp),
                            std::begin(Delta_y_share_), std::minus{});

  // [Delta_y]_i += Delta_ab (== Delta_a * Delta_b)
  if (beavy_provider_.is_my_job(gate_id_)) {
    __gnu_parallel::transform(std::begin(Delta_a), std::end(Delta_a), std::begin(Delta_b),
                              std::begin(tmp), std::multiplies{});
    __gnu_parallel::transform(std::begin(Delta_y_share_), std::end(Delta_y_share_), std::begin(tmp),
                              std::begin(Delta_y_share_), std::plus{});
  }

  if (fractional_bits_ > 0) {
    fixed_point::truncate_shared<T>(Delta_y_share_.data(), fractional_bits_, Delta_y_share_.size(),
                                    beavy_provider_.is_my_job(gate_id_));
    // [Delta_y]_i += [delta_y]_i
    __gnu_parallel::transform(std::begin(Delta_y_share_), std::end(Delta_y_share_),
                              std::begin(output_->get_secret_share()), std::begin(Delta_y_share_),
                              std::plus{});
    // NB: happens in setup phase if no truncation is requested
  }

  // broadcast [Delta_y]_i
  beavy_provider_.broadcast_ints_message(gate_id_, Delta_y_share_);
  // Delta_y = [Delta_y]_i + [Delta_y]_(1-i)
  __gnu_parallel::transform(std::begin(Delta_y_share_), std::end(Delta_y_share_),
                            std::begin(share_future_.get()), std::begin(Delta_y_share_),
                            std::plus{});
  output_->get_public_share() = std::move(Delta_y_share_);
  output_->set_online_ready();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticBEAVYTensorMul<T>::evaluate_online end", gate_id_));
    }
  }
}

template class ArithmeticBEAVYTensorMul<std::uint32_t>;
template class ArithmeticBEAVYTensorMul<std::uint64_t>;

template <typename T>
ArithmeticBEAVYTensorAveragePool<T>::ArithmeticBEAVYTensorAveragePool(
    std::size_t gate_id, BEAVYProvider& beavy_provider, tensor::AveragePoolOp avgpool_op,
    const ArithmeticBEAVYTensorCP<T> input, std::size_t fractional_bits)
    : NewGate(gate_id),
      beavy_provider_(beavy_provider),
      avgpool_op_(avgpool_op),
      data_size_(input->get_dimensions().get_data_size()),
      fractional_bits_(fractional_bits),
      input_(input),
      output_(std::make_shared<ArithmeticBEAVYTensor<T>>(avgpool_op_.get_output_tensor_dims())) {
  if (!avgpool_op_.verify()) {
    throw std::invalid_argument("invalid AveragePoolOp");
  }
  auto kernel_size = avgpool_op_.compute_kernel_size();
  if (kernel_size > (T(1) << fractional_bits_)) {
    throw std::invalid_argument(
        "ArithmeticBEAVYTensorAveragePool: not enough fractional bits to represent factor");
  }
  factor_ = fixed_point::encode<T>(1.0 / kernel_size, fractional_bits_);
  output_->get_public_share().resize(avgpool_op_.compute_output_size());
  tmp_in_.resize(data_size_);
  tmp_out_.resize(avgpool_op_.compute_output_size());
  const auto my_id = beavy_provider_.get_my_id();
  share_future_ = beavy_provider_.register_for_ints_message<T>(1 - my_id, gate_id_,
                                                               avgpool_op_.compute_output_size());
}

template <typename T>
void ArithmeticBEAVYTensorAveragePool<T>::evaluate_setup() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticBEAVYTensorSqr<T>::evaluate_setup start", gate_id_));
    }
  }

  output_->get_secret_share() = Helpers::RandomVector<T>(avgpool_op_.compute_output_size());
  output_->set_setup_ready();

  if (!beavy_provider_.is_my_job(gate_id_)) {
    input_->wait_setup();
    // convert: alpha -> A
    __gnu_parallel::transform(std::begin(input_->get_secret_share()),
                              std::end(input_->get_secret_share()), std::begin(tmp_in_),
                              std::negate{});
    // compute AveragePool on A share
    sum_pool(avgpool_op_, tmp_in_.data(), tmp_out_.data());
    __gnu_parallel::transform(std::begin(tmp_out_), std::end(tmp_out_), std::begin(tmp_out_),
                              [this](auto x) { return x * factor_; });
    fixed_point::truncate_shared(tmp_out_.data(), fractional_bits_, tmp_out_.size(),
                                 beavy_provider_.is_my_job(gate_id_));
    // convert: A -> alpha, mask with secret_share + send
    __gnu_parallel::transform(std::begin(tmp_out_), std::end(tmp_out_),
                              std::begin(output_->get_secret_share()), std::begin(tmp_out_),
                              std::plus{});
    beavy_provider_.broadcast_ints_message(gate_id_, tmp_out_);
  }

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticBEAVYTensorSqr<T>::evaluate_setup end", gate_id_));
    }
  }
}

template <typename T>
void ArithmeticBEAVYTensorAveragePool<T>::evaluate_online() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticBEAVYTensorSqr<T>::evaluate_online start", gate_id_));
    }
  }

  if (beavy_provider_.is_my_job(gate_id_)) {
    input_->wait_online();
    // convert: alpha -> A
    __gnu_parallel::transform(
        std::begin(input_->get_public_share()), std::end(input_->get_public_share()),
        std::begin(input_->get_secret_share()), std::begin(tmp_in_), std::minus{});
    // compute AveragePool on A share
    sum_pool(avgpool_op_, tmp_in_.data(), tmp_out_.data());
    __gnu_parallel::transform(std::begin(tmp_out_), std::end(tmp_out_), std::begin(tmp_out_),
                              [this](auto x) { return x * factor_; });
    fixed_point::truncate_shared(tmp_out_.data(), fractional_bits_, tmp_out_.size(),
                                 beavy_provider_.is_my_job(gate_id_));
    // convert: A -> alpha, mask with secret_share + send
    __gnu_parallel::transform(std::begin(tmp_out_), std::end(tmp_out_),
                              std::begin(output_->get_secret_share()), std::begin(tmp_out_),
                              std::plus{});
    beavy_provider_.broadcast_ints_message(gate_id_, tmp_out_);
  }

  auto other_share = share_future_.get();
  __gnu_parallel::transform(std::begin(tmp_out_), std::end(tmp_out_), std::begin(other_share),
                            std::begin(tmp_out_), std::plus{});
  output_->get_public_share() = std::move(tmp_out_);
  output_->set_online_ready();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticBEAVYTensorSqr<T>::evaluate_online end", gate_id_));
    }
  }
}

template class ArithmeticBEAVYTensorAveragePool<std::uint32_t>;
template class ArithmeticBEAVYTensorAveragePool<std::uint64_t>;

template <typename T>
BooleanToArithmeticBEAVYTensorConversion<T>::BooleanToArithmeticBEAVYTensorConversion(
    std::size_t gate_id, BEAVYProvider& beavy_provider, const BooleanBEAVYTensorCP input)
    : NewGate(gate_id),
      beavy_provider_(beavy_provider),
      data_size_(input->get_dimensions().get_data_size()),
      input_(std::move(input)),
      output_(std::make_shared<ArithmeticBEAVYTensor<T>>(input_->get_dimensions(), beavy_provider.get_num_parties())) {
  const auto my_id = beavy_provider_.get_my_id();
  const auto p_king = beavy_provider_.get_p_king();
  const auto num_parties = beavy_provider_.get_num_parties();

  if (my_id == p_king) {
    // share_future_ = beavy_provider_.register_for_ints_messages<T>(gate_id_, data_size_);
    bits_share_future_ = beavy_provider_.register_for_bits_messages(
      gate_id_, data_size_ * bit_size_);
  } else if (my_id <= num_parties / 2) {
    share_future_ = beavy_provider_.register_for_ints_message<T>(p_king, gate_id_, data_size_ * bit_size_);
  }
  random_bit_ = 1;
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanToArithmeticBEAVYTensorConversion<T> created", gate_id_));
    }
  }
}

template <typename T>
BooleanToArithmeticBEAVYTensorConversion<T>::~BooleanToArithmeticBEAVYTensorConversion() = default;

template <typename T>
void BooleanToArithmeticBEAVYTensorConversion<T>::evaluate_setup() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: BooleanToArithmeticBEAVYTensorConversion<T>::evaluate_setup start", gate_id_));
    }
  }
  const auto my_id = beavy_provider_.get_my_id();
  const auto p_king = beavy_provider_.get_p_king();
  const auto& owned_shares = beavy_provider_.get_owned_shares();
  auto& output_ss = output_->get_common_secret_share();

  for (const auto share : owned_shares[my_id]) {
    output_ss[share] = 0;
  }
  output_->set_setup_ready();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: BooleanToArithmeticBEAVYTensorConversion<T>::evaluate_setup end", gate_id_));
    }
  }
}

template <typename T>
void BooleanToArithmeticBEAVYTensorConversion<T>::evaluate_online() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: BooleanToArithmeticBEAVYTensorConversion<T>::evaluate_online start", gate_id_));
    }
  }

  const auto my_id = beavy_provider_.get_my_id();
  const auto p_king = beavy_provider_.get_p_king();
  const auto num_parties = beavy_provider_.get_num_parties();
  const auto& owned_shares = beavy_provider_.get_owned_shares();
  const auto& pking_shares = beavy_provider_.get_shares_for_p_king();

  input_->wait_setup();
  input_->wait_online();

  if (my_id > (num_parties / 2)) {
    output_->set_online_ready();
    return;
  }

  ENCRYPTO::BitVector<> r(data_size_, random_bit_);
  std::vector<ENCRYPTO::BitVector<>> C_boolean(bit_size_);
#pragma omp parallel for
  for (std::size_t bit_pos = 0; bit_pos < bit_size_; ++bit_pos) {
    const auto& ps = input_->get_public_share()[bit_pos];
    assert(r.GetSize() == ps.GetSize());
    C_boolean[bit_pos] = (ps ^ r);
  }

// Sending and recieving phase to constuct C = b XOR r (arithmetic) in clear.
std::vector<T> C_arith(data_size_ * bit_size_);
if (my_id == p_king) {
  // p_king will recieve the shares to construct b XOR r in clear.
  // It will then send the arithmetic values to other parties in E.
  ENCRYPTO::BitVector<> shares_from_others(data_size_ * bit_size_, 0);
  for (std::size_t party = 0; party <= num_parties / 2; ++party) {
    if (party == my_id) continue;
    shares_from_others ^= bits_share_future_[party].get();
  }
#pragma omp parallel for
  for (std::size_t bit_pos = 0; bit_pos < bit_size_; ++bit_pos) {
    bool own_random_val = false;
    const auto& css = input_->get_common_secret_share()[bit_pos];
    for (const auto share : owned_shares[my_id]) {
      own_random_val ^= css[share];
    }
    ENCRYPTO::BitVector<> bv(data_size_, own_random_val);
    bv ^= C_boolean[bit_pos];
    bv ^= shares_from_others.Subset(bit_pos*data_size_, (bit_pos + 1)*data_size_);
    assert(bv.GetSize() == data_size_);
#pragma omp parallel for
    for (std::size_t i = 0; i < data_size_; ++i) {
      C_arith[bit_pos*data_size_ + i] = bv.Get(i);
    }
  }

  for (std::size_t party = 0; party <= (num_parties / 2); ++party) {
    if (party == my_id) continue;
    beavy_provider_.send_ints_message(party, gate_id_, C_arith);
  }
} else {
  // Send the shares to p_king.
  // Recieve the arithmetic shares from p_king.
  ENCRYPTO::BitVector<> shares_for_pking;
  for (std::size_t bit_pos = 0; bit_pos < bit_size_; ++bit_pos) {
    bool value = false;
    auto& css = input_->get_common_secret_share()[bit_pos];
    for (const auto share : pking_shares[my_id]) {
      value ^= css[share];
    }
    ENCRYPTO::BitVector<> wire_share(data_size_, value);
    shares_for_pking.Append(wire_share);
  }
  assert(shares_for_pking.GetSize() == bit_size_ * data_size_);
  beavy_provider_.send_bits_message(p_king, gate_id_, shares_for_pking);

  C_arith = share_future_.get();
}

// calculate the b2A for every bit.
// calculate the actual integers in the op tensor.
#pragma omp parallel for
  for (std::size_t i = 0; i < data_size_; ++i) {
    auto& ps = output_->get_public_share();
    ps[i] = 0;
    for (std::size_t bit_pos = 0; bit_pos < bit_size_; ++bit_pos) {
      ps[i] += (1LL << bit_pos)*(random_bit_ + C_arith[bit_pos*data_size_ + i] - 2*random_bit_*C_arith[bit_pos*data_size_ + i]);
    }
  }
  output_->set_online_ready();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: BooleanToArithmeticBEAVYTensorConversion<T>::evaluate_online end", gate_id_));
    }
  }
}

template class BooleanToArithmeticBEAVYTensorConversion<std::uint32_t>;
template class BooleanToArithmeticBEAVYTensorConversion<std::uint64_t>;

template <typename T>
ArithmeticToBooleanBEAVYTensorConversion<T>::ArithmeticToBooleanBEAVYTensorConversion(
    std::size_t gate_id, BEAVYProvider& beavy_provider, const ArithmeticBEAVYTensorCP<T> input)
    : NewGate(gate_id),
      beavy_provider_(beavy_provider),
      data_size_(input->get_dimensions().get_data_size()),
      input_(std::move(input)),
      output_(std::make_shared<BooleanBEAVYTensor>(input_->get_dimensions(), ENCRYPTO::bit_size_v<T>, beavy_provider.get_num_parties())),
      output_public_(ENCRYPTO::bit_size_v<T>),
      output_random_(ENCRYPTO::bit_size_v<T>) {
  const auto my_id = beavy_provider_.get_my_id();
  const auto p_king = beavy_provider_.get_p_king();
  const auto num_parties = beavy_provider_.get_num_parties();
  share_future_.resize(num_parties);
  arithmetized_secret_share_.resize(beavy_provider_.get_total_shares());
  if (my_id == p_king) {
    share_future_ = beavy_provider_.register_for_ints_messages<T>(gate_id_, data_size_);
  } else {
    share_future_[p_king] = beavy_provider_.register_for_ints_message<T>(p_king, gate_id_, data_size_);
  }

  // Spawn the depth optimized addition circuit.
  auto& addition_circuit =
      beavy_provider_.get_circuit_loader().load_circuit(
          fmt::format("int_add{}_depth.bristol", ENCRYPTO::bit_size_v<T>),
          CircuitFormat::Bristol);

  // apply the circuit to the Boolean shares.
  WireVector A(ENCRYPTO::bit_size_v<T>);
  WireVector B(ENCRYPTO::bit_size_v<T>);
  for (std::size_t bit_pos = 0; bit_pos < ENCRYPTO::bit_size_v<T>; ++bit_pos) {
    output_public_[bit_pos] = std::make_shared<BooleanBEAVYWire>(data_size_, beavy_provider_.get_num_parties());
    output_random_[bit_pos] = std::make_shared<BooleanBEAVYWire>(data_size_, beavy_provider_.get_num_parties());
    A[bit_pos] = cast_boolean_wire(output_public_[bit_pos]);
    B[bit_pos] = cast_boolean_wire(output_random_[bit_pos]);
  }
  A.insert(
      A.end(),
      std::make_move_iterator(B.begin()),
      std::make_move_iterator(B.end())
    );
  auto [gates, output_wires] = construct_two_input_circuit(beavy_provider_, addition_circuit, A);
  // TODO(pranav): Check this step's correctness.
  gates_ = std::move(gates);
  addition_result_ = cast_wires(output_wires);

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: ArithmeticToBooleanBEAVYTensorConversion<T> created", gate_id_));
    }
  }
}

template <typename T>
ArithmeticToBooleanBEAVYTensorConversion<T>::~ArithmeticToBooleanBEAVYTensorConversion() = default;

template <typename T>
void ArithmeticToBooleanBEAVYTensorConversion<T>::evaluate_setup_with_context(ExecutionContext& exec_ctx) {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: ArithmeticToBooleanBEAVYTensorConversion<T>::evaluate_setup_with_context start", gate_id_));
    }
  }

  const auto my_id = beavy_provider_.get_my_id();
  const auto& owned_shares = beavy_provider_.get_owned_shares();

  for (const auto indx : owned_shares[my_id]) {
    arithmetized_secret_share_[indx] = indx + 10;
  }
  std::size_t cleartext_r = 0;
  for (int indx = 0; indx < beavy_provider_.get_total_shares(); ++indx) {
    cleartext_r += indx + 10;
  }
  constexpr std::size_t bit_size = 8 * sizeof(T);
  const auto bit_converted = std::bitset<bit_size>(cleartext_r);
  assert(bit_converted.size() == bit_size);

  // auto& r_boolean_public_shares = output_random_->get_public_share();
  for (int bit_pos = 0; bit_pos < bit_size; ++bit_pos) {
    auto& pub_share = output_random_[bit_pos]->get_public_share();
    pub_share = ENCRYPTO::BitVector<>(input_->get_dimensions().get_data_size(),
     bit_converted[bit_pos]);
    output_random_[bit_pos]->set_setup_ready();
    // This wire will contain the public value of Z-r, all publicly known.
    // Therefore, this wire's setup is by default always ready.
    output_public_[bit_pos]->set_setup_ready();
  }

  for (auto& gate : gates_) {
    exec_ctx.fpool_->post([&] { gate->evaluate_setup(); });
  }

  auto& common_secret_share = output_->get_common_secret_share();
#pragma omp parallel for
    for (std::size_t bit_pos = 0; bit_pos < bit_size; ++bit_pos) {
      addition_result_[bit_pos]->wait_setup();
      // Copy the wire vector values to the tensor.
      common_secret_share[bit_pos] = addition_result_[bit_pos]->get_common_secret_share();
    }
  output_->set_setup_ready();


  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: ArithmeticToBooleanBEAVYTensorConversion<T>::evaluate_setup_with_context end", gate_id_));
    }
  }
}

template <typename T>
void ArithmeticToBooleanBEAVYTensorConversion<T>::evaluate_online_with_context(ExecutionContext& exec_ctx) {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: ArithmeticToBooleanBEAVYTensorConversion<T>::evaluate_online_with_context start", gate_id_));
    }
  }

  const auto my_id = beavy_provider_.get_my_id();
  const auto num_parties = beavy_provider_.get_num_parties();
  const auto p_king = beavy_provider_.get_p_king();
  const auto& owned_shares = beavy_provider_.get_owned_shares();
  const auto& shares_for_p_king = beavy_provider_.get_shares_for_p_king();

  input_->wait_setup();
  input_->wait_online();
  // This value will be converted to binary format.
  std::vector<T> Z_minus_r;

  if (my_id == p_king) {
    Z_minus_r = input_->get_public_share();
    std::size_t arithmetic_r_shares = 0;
    const auto& input_ss = input_->get_common_secret_share();
    std::size_t input_ss_pking = 0;
    for (const auto share : owned_shares[my_id]) {
      arithmetic_r_shares += arithmetized_secret_share_[share];
      input_ss_pking += input_ss[share];
    }
    __gnu_parallel::transform(std::begin(Z_minus_r), std::end(Z_minus_r),
                            std::begin(Z_minus_r), std::bind2nd(std::minus<T>(),
                             arithmetic_r_shares + input_ss_pking));
    for (int party = 0; party <= (num_parties / 2); ++party) {
      if (party == my_id) continue;
      const auto& party_share = share_future_[party].get();
      __gnu_parallel::transform(std::begin(Z_minus_r), std::end(Z_minus_r),
                                std::begin(party_share),
                            std::begin(Z_minus_r), std::minus<T>());
    }
    for (int party = 0; party <= (num_parties / 2); ++party) {
      if (party == my_id) continue;
      beavy_provider_.send_ints_message(party, gate_id_, Z_minus_r);
    }

  } else if (my_id <= (num_parties / 2)) {
    std::size_t share_for_king = 0;
    const auto& input_ss = input_->get_common_secret_share();
    assert(input_ss.size() >= beavy_provider_.get_total_shares());
    for (const auto indx : shares_for_p_king[my_id]) {
      share_for_king += arithmetized_secret_share_[indx] + input_ss[indx];
    }
    // send to pking.
    std::vector<T> data(data_size_, share_for_king);
    beavy_provider_.send_ints_message(p_king, gate_id_, data);
    std::cout << "sent the shares to pking." << std::endl;

    // wait to recieve the public value from p_king.
    Z_minus_r = share_future_[p_king].get();
    std::cout << "recieved the shares from pking." << std::endl;
  }

  if (my_id <= (num_parties / 2)) {
    constexpr std::size_t bit_size = 8 * sizeof(T);
    // Binary form of the Z-r values. One per data element.
    std::vector<std::bitset<bit_size>>binary_Z(data_size_);
#pragma omp parallel for
    for (std::size_t i = 0; i < data_size_; ++i) {
      binary_Z[i] = std::bitset<bit_size>(Z_minus_r[i]);
    }

    // TODO(pranav): Check if this can be optimized.
    for (std::size_t bit_pos = 0; bit_pos < bit_size; ++bit_pos) {
      auto& pub_share = output_public_[bit_pos]->get_public_share();
      pub_share.Resize(data_size_);
#pragma omp parallel for
      for (std::size_t i = 0; i < data_size_; ++i) {
        pub_share.Set((binary_Z[i][bit_pos]), i);
      }
      output_public_[bit_pos]->set_online_ready();
      output_random_[bit_pos]->set_online_ready();
    }
    for (auto& gate : gates_) {
      exec_ctx.fpool_->post([&] { gate->evaluate_online(); });
    }

    assert(addition_result_.size() == bit_size);

    // auto& common_secret_share = output_->get_common_secret_share();
    auto& public_share = output_->get_public_share();
    // auto& secret_share = output_->get_secret_share();
#pragma omp parallel for
    for (std::size_t bit_pos = 0; bit_pos < bit_size; ++bit_pos) {
      addition_result_[bit_pos]->wait_online();
      // Copy the wire vector values to the tensor.
      public_share[bit_pos] = addition_result_[bit_pos]->get_public_share();
      // common_secret_share[bit_pos] = addition_result_[bit_pos]->get_common_secret_share();
      // std::cout << "Size of common_secret_share while making == " 
      // << common_secret_share[bit_pos].GetSize() << std::endl;
    }
  }
  // TODO(pranav): Move this to setup phase, to optimize.
  // output_->set_setup_ready();
  output_->set_online_ready();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: ArithmeticToBooleanBEAVYTensorConversion<T>::evaluate_online_with_context end", gate_id_));
    }
  }
}

template <typename T>
void ArithmeticToBooleanBEAVYTensorConversion<T>::evaluate_setup() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: ArithmeticToBooleanBEAVYTensorConversion<T>::evaluate_setup start", gate_id_));
    }
  }

  const auto my_id = beavy_provider_.get_my_id();
  const auto& owned_shares = beavy_provider_.get_owned_shares();

  for (const auto indx : owned_shares[my_id]) {
    arithmetized_secret_share_[indx] = indx + 10;
  }
  std::size_t cleartext_r = 0;
  for (int indx = 0; indx < beavy_provider_.get_total_shares(); ++indx) {
    cleartext_r += indx + 10;
  }
  constexpr std::size_t bit_size = 8 * sizeof(T);
  const auto bit_converted = std::bitset<bit_size>(cleartext_r);
  assert(bit_converted.size() == bit_size);

  // auto& r_boolean_public_shares = output_random_->get_public_share();
  for (int bit_pos = 0; bit_pos < bit_size; ++bit_pos) {
    auto& pub_share = output_random_[bit_pos]->get_public_share();
    pub_share = ENCRYPTO::BitVector<>(input_->get_dimensions().get_data_size(),
     bit_converted[bit_pos]);
    output_random_[bit_pos]->set_setup_ready();
    output_random_[bit_pos]->set_online_ready();
    // This wire will contain the public value of Z-r, all publicly known.
    // Therefore, this wire's setup is by default always ready.
    output_public_[bit_pos]->set_setup_ready();
  }

  for (auto& gate : gates_) {
    gate->evaluate_setup();
  }

  auto& common_secret_share = output_->get_common_secret_share();
#pragma omp parallel for
    for (std::size_t bit_pos = 0; bit_pos < bit_size; ++bit_pos) {
      addition_result_[bit_pos]->wait_setup();
      // Copy the wire vector values to the tensor.
      common_secret_share[bit_pos] = addition_result_[bit_pos]->get_common_secret_share();
    }
  output_->set_setup_ready();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: ArithmeticToBooleanBEAVYTensorConversion<T>::evaluate_setup end", gate_id_));
    }
  }
}

template <typename T>
void ArithmeticToBooleanBEAVYTensorConversion<T>::evaluate_online() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: ArithmeticToBooleanBEAVYTensorConversion<T>::evaluate_online start", gate_id_));
    }
  }

  const auto my_id = beavy_provider_.get_my_id();
  const auto num_parties = beavy_provider_.get_num_parties();
  const auto p_king = beavy_provider_.get_p_king();
  const auto& owned_shares = beavy_provider_.get_owned_shares();
  const auto& shares_for_p_king = beavy_provider_.get_shares_for_p_king();

  input_->wait_setup();
  input_->wait_online();
  // This value will be converted to binary format.
  std::vector<T> Z_minus_r;

  if (my_id == p_king) {
    Z_minus_r = input_->get_public_share();
    for (int party = 0; party <= (num_parties / 2); ++party) {
      if (party == my_id) continue;
      const auto& party_share = share_future_[party].get();
      __gnu_parallel::transform(std::begin(Z_minus_r), std::end(Z_minus_r),
                                std::begin(party_share),
                            std::begin(Z_minus_r), std::minus<T>());
    }
    for (int party = 0; party <= (num_parties / 2); ++party) {
      if (party == my_id) continue;
      beavy_provider_.send_ints_message(party, gate_id_, Z_minus_r);
    }

  } else if (my_id <= (num_parties / 2)) {
    std::size_t share_for_king = 0;
    const auto& input_ss = input_->get_common_secret_share();
    assert(input_ss.size() >= beavy_provider_.get_total_shares());
    for (const auto indx : shares_for_p_king[my_id]) {
      share_for_king += arithmetized_secret_share_[indx] + input_ss[indx];
    }
    // send to pking.
    std::vector<T> data(data_size_, share_for_king);
    beavy_provider_.send_ints_message(p_king, gate_id_, data);

    // wait to recieve the public value from p_king.
    Z_minus_r = share_future_[p_king].get();
  }

// const auto& pshares = input_->get_public_share();

// #pragma omp parallel for
//   for (std::size_t bit_j = 0; bit_j < bit_size_; ++bit_j) {
//     for (std::size_t int_i = 0; int_i < data_size_; ++int_i) {
//       if (pshares[bit_j].Get(int_i)) {
//         arithmetized_public_share[bit_j * data_size_ + int_i] = 1;
//       }
//     }
//   }

//   auto tmp = output_->get_secret_share();
//   if (beavy_provider_.is_my_job(gate_id_)) {
// #pragma omp parallel for
//     for (std::size_t int_i = 0; int_i < data_size_; ++int_i) {
//       for (std::size_t bit_j = 0; bit_j < bit_size_; ++bit_j) {
//         const auto p = arithmetized_public_share[bit_j * data_size_ + int_i];
//         const auto s = arithmetized_secret_share_[bit_j * data_size_ + int_i];
//         tmp[int_i] += (p + (1 - 2 * p) * s) << bit_j;
//       }
//     }
//   } else {
// #pragma omp parallel for
//     for (std::size_t int_i = 0; int_i < data_size_; ++int_i) {
//       for (std::size_t bit_j = 0; bit_j < bit_size_; ++bit_j) {
//         const auto p = arithmetized_public_share[bit_j * data_size_ + int_i];
//         const auto s = arithmetized_secret_share_[bit_j * data_size_ + int_i];
//         tmp[int_i] += ((1 - 2 * p) * s) << bit_j;
//       }
//     }
//   }

  if (my_id <= (num_parties / 2)) {
    constexpr std::size_t bit_size = 8 * sizeof(T);
    // Binary form of the Z-r values. One per data element.
    std::vector<std::bitset<bit_size>>binary_Z(data_size_);
#pragma omp parallel for
    for (std::size_t i = 0; i < data_size_; ++i) {
      binary_Z[i] = std::bitset<bit_size>(Z_minus_r[i]);
    }

    // TODO(pranav): Check if this can be optimized.
    for (std::size_t bit_pos = 0; bit_pos < bit_size; ++bit_pos) {
      auto& pub_share = output_public_[bit_pos]->get_public_share();
      pub_share.Resize(data_size_);
#pragma omp parallel for
      for (std::size_t i = 0; i < data_size_; ++i) {
        pub_share.Set((binary_Z[i][bit_pos]), i);
      }
      output_public_[bit_pos]->set_online_ready();
    }

    for (auto& gate : gates_) {
      gate->evaluate_online();
    }

    assert(addition_result_.size() == bit_size);

    // -------auto& common_secret_share = output_->get_common_secret_share();
    auto& public_share = output_->get_public_share();
    // auto& secret_share = output_->get_secret_share();
#pragma omp parallel for
    for (std::size_t bit_pos = 0; bit_pos < bit_size; ++bit_pos) {
      addition_result_[bit_pos]->wait_online();
      // Copy the wire vector values to the tensor.
      public_share[bit_pos] = addition_result_[bit_pos]->get_public_share();
      // ---------- common_secret_share[bit_pos] = addition_result_[bit_pos]->get_common_secret_share();
    }
  }
  // // TODO(pranav): Move this to setup phase, to optimize.
  // output_->set_setup_ready();
  output_->set_online_ready();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: ArithmeticToBooleanBEAVYTensorConversion<T>::evaluate_online end", gate_id_));
    }
  }
}

template class ArithmeticToBooleanBEAVYTensorConversion<std::uint32_t>;
template class ArithmeticToBooleanBEAVYTensorConversion<std::uint64_t>;

BooleanBEAVYTensorRelu::BooleanBEAVYTensorRelu(std::size_t gate_id, BEAVYProvider& beavy_provider,
                                               const BooleanBEAVYTensorCP input)
    : NewGate(gate_id),
      beavy_provider_(beavy_provider),
      bit_size_(input->get_bit_size()),
      data_size_(input->get_dimensions().get_data_size()),
      input_(std::move(input)),
      output_(std::make_shared<BooleanBEAVYTensor>(input_->get_dimensions(), bit_size_, beavy_provider.get_num_parties())) {
  const auto my_id = beavy_provider_.get_my_id();
  // share_future_ =
  //     beavy_provider_.register_for_bits_message(1 - my_id, gate_id_, data_size_ * (bit_size_ - 1));

  // 1. Make the wire vector.
  // 2. Spawn the AND gate.
  // 3. Wire the input wires into the AND gate, and take the output.
  // 4. Use the output wire vector to set the output of this gate!
  A_.resize((bit_size_ - 1));
  B_.resize((bit_size_ - 1));

  auto msb_bit_vector = input->get_public_share()[bit_size_ - 1];
  auto ss_msb = input->get_common_secret_share()[bit_size_ - 1];
  A_boolean_.resize((bit_size_ - 1));
  B_boolean_.resize((bit_size_ - 1));
  A_boolean_[0] = std::make_shared<BooleanBEAVYWire>(
    data_size_, beavy_provider_.get_num_parties());
  A_[0] = cast_boolean_wire(A_boolean_[0]);

#pragma omp parallel for
  for (std::size_t bit_pos = 0; bit_pos < bit_size_ - 1; ++bit_pos) {
    if (bit_pos > 0) {
      A_boolean_[bit_pos] = A_boolean_[0];
      A_[bit_pos] = A_[0];
    }
    B_boolean_[bit_pos] = std::make_shared<BooleanBEAVYWire>(
    data_size_, beavy_provider_.get_num_parties());
    B_[bit_pos] = cast_boolean_wire(B_boolean_[bit_pos]);
  }
  // Get the gate, send the values inside the gate somehow.
  auto [gates, output_wires] = beavy_provider_.construct_binary_gate(
    ENCRYPTO::PrimitiveOperationType::AND, A_, B_);
  gates_ = std::move(gates);
  and_result_ = cast_wires(output_wires);

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format("Gate {}: BooleanGMWTensorRelu created", gate_id_));
    }
  }
}

BooleanBEAVYTensorRelu::~BooleanBEAVYTensorRelu() = default;

void BooleanBEAVYTensorRelu::evaluate_setup_with_context(ExecutionContext& exec_ctx) {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanBEAVYTensorRelu::evaluate_setup_with_context start", gate_id_));
    }
  }
  input_->wait_setup();
#pragma omp parallel for
  for (std::size_t bit_pos = 0; bit_pos < bit_size_; ++bit_pos) {
    if (bit_pos == bit_size_ - 1) {
      A_boolean_[0]->get_common_secret_share() = input_->get_common_secret_share()[bit_size_ - 1];
      A_boolean_[0]->set_setup_ready();
      continue;
    }
    B_boolean_[bit_pos]->get_common_secret_share() = input_->get_common_secret_share()[bit_pos];
    B_boolean_[bit_pos]->set_setup_ready();
  }
  // TODO(pranav): Check if the exec_ctx thread spawning is necessary here or not.
  exec_ctx.fpool_->post([&] { gates_->evaluate_setup(); });
  assert(and_result_.size() == bit_size_ - 1);
  for (std::size_t bit_pos = 0; bit_pos < bit_size_; ++bit_pos) {
    if (bit_pos == bit_size_ - 1) {
      auto& ss = output_->get_common_secret_share()[bit_size_ - 1];
      // MSB is always zero.
      ss = ENCRYPTO::BitVector<>(data_size_, 0);
      continue;
    }
    and_result_[bit_pos]->wait_setup();
    output_->get_common_secret_share()[bit_pos] = 
    and_result_[bit_pos]->get_common_secret_share();
  }
  output_->set_setup_ready();

//   // generate the secret shares
//   auto& out_sshares = output_->get_secret_share();
//   assert(out_sshares.size() == bit_size_);
// #pragma omp parallel for
//   for (std::size_t bit_j = 0; bit_j < bit_size_ - 1; ++bit_j) {
//     out_sshares[bit_j] = ENCRYPTO::BitVector<>::Random(data_size_);
//   }
//   // the last bit is always 0
//   out_sshares[bit_size_ - 1] = ENCRYPTO::BitVector<>(data_size_, false);
//   output_->set_setup_ready();

//   input_->wait_setup();
//   const auto& sshares = input_->get_secret_share();
//   const auto& my_msb_sshare = sshares[bit_size_ - 1];

//   ot_receiver_->SetChoices(my_msb_sshare);
//   ot_receiver_->SendCorrections();
//   ENCRYPTO::BitVector<> ot_inputs((bit_size_ - 1) * data_size_);
//   // inefficient, but works ...
//   for (std::size_t bit_j = 0; bit_j < bit_size_ - 1; ++bit_j) {
//     for (std::size_t int_i = 0; int_i < data_size_; ++int_i) {
//       ot_inputs.Set(sshares[bit_j].Get(int_i), int_i * (bit_size_ - 1) + bit_j);
//     }
//   }
//   ot_sender_->SetCorrelations(std::move(ot_inputs));
//   ot_sender_->SendMessages();
//   ot_sender_->ComputeOutputs();
//   ot_receiver_->ComputeOutputs();

//   // compute the products of the msb_mask with all other masks
//   for (std::size_t bit_j = 0; bit_j < bit_size_ - 1; ++bit_j) {
//     // local part
//     auto tmp = my_msb_sshare & sshares[bit_j];
//     // output mask
//     tmp ^= out_sshares[bit_j];
//     Delta_y_share_.Append(tmp);
//   }
//   const auto ot_snd_out = ot_sender_->GetOutputs();
//   const auto ot_rcv_out = ot_receiver_->GetOutputs();
//   // inefficient, but works ...
//   for (std::size_t bit_j = 0; bit_j < bit_size_ - 1; ++bit_j) {
//     for (std::size_t int_i = 0; int_i < data_size_; ++int_i) {
//       bool tmp = Delta_y_share_.Get(bit_j * data_size_ + int_i);
//       // product of other msb_mask with my sshare masks
//       tmp ^= ot_snd_out.Get(int_i * (bit_size_ - 1) + bit_j);
//       // product of my_msb_mask with other sshare masks
//       tmp ^= ot_rcv_out.Get(int_i * (bit_size_ - 1) + bit_j);
//       Delta_y_share_.Set(tmp, bit_j * data_size_ + int_i);
//     }
//   }
//   // => Delta_y_share_ contains now [delta_ab]_i ^ [delta_y]_i

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanBEAVYTensorRelu::evaluate_setup_with_context end", gate_id_));
    }
  }
}

void BooleanBEAVYTensorRelu::evaluate_online_with_context(ExecutionContext& exec_ctx) {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanBEAVYTensorRelu::evaluate_online_with_context start", gate_id_));
    }
  }
  input_->wait_online();
#pragma omp parallel for
  for (std::size_t bit_pos = 0; bit_pos < bit_size_; ++bit_pos) {
    if (bit_pos == bit_size_ - 1) {
      A_boolean_[0]->get_public_share() = ~(input_->get_public_share()[bit_size_ - 1]);
      A_boolean_[0]->set_online_ready();
      continue;
    }
    B_boolean_[bit_pos]->get_public_share() = input_->get_public_share()[bit_pos];
    B_boolean_[bit_pos]->set_online_ready();
  }
  // TODO(pranav): Check if the exec_ctx thread spawning is necessary here or not.
  exec_ctx.fpool_->post([&] { gates_->evaluate_online(); });
  for (std::size_t bit_pos = 0; bit_pos < bit_size_; ++bit_pos) {
    if (bit_pos == bit_size_ - 1) {
      auto& ps = output_->get_public_share()[bit_size_ - 1];
      // MSB is always zero.
      ps = ENCRYPTO::BitVector<>(data_size_, 0);
      continue;
    }
    and_result_[bit_pos]->wait_online();
    output_->get_public_share()[bit_pos] = and_result_[bit_pos]->get_public_share();
  }
  output_->set_online_ready();

  // input_->wait_online();
  // const auto& pshares = input_->get_public_share();
  // const auto my_msb_pshare = ~pshares[bit_size_ - 1];
  // const auto& sshares = input_->get_secret_share();
  // const auto& my_msb_sshare = sshares[bit_size_ - 1];

//   ENCRYPTO::BitVector tmp;
//   tmp.Reserve(Helpers::Convert::BitsToBytes((bit_size_ - 1) * data_size_));
//   const bool my_job = beavy_provider_.is_my_job(gate_id_);
//   for (std::size_t bit_j = 0; bit_j < bit_size_ - 1; ++bit_j) {
//     // Delta_y_share_ ^= Delta_a & [delta_b]_i
//     auto tmp2 = my_msb_pshare & sshares[bit_j];
//     // Delta_y_share_ ^= [delta_a]_i & Delta_b
//     tmp2 ^= my_msb_sshare & pshares[bit_j];
//     if (my_job) {
//       // Delta_y_share_ ^= Delta_a & Delta_b
//       tmp2 ^= my_msb_pshare & pshares[bit_j];
//     }
//     tmp.Append(tmp2);
//   }
//   Delta_y_share_ ^= tmp;
//   const auto my_id = beavy_provider_.get_my_id();
//   beavy_provider_.send_bits_message(1 - my_id, gate_id_, Delta_y_share_);
//   Delta_y_share_ ^= share_future_.get();

//   auto& out_pshares = output_->get_public_share();
// #pragma omp parallel for
//   for (std::size_t bit_j = 0; bit_j < bit_size_ - 1; ++bit_j) {
//     out_pshares[bit_j] = Delta_y_share_.Subset(bit_j * data_size_, (bit_j + 1) * data_size_);
//   }
//   out_pshares[bit_size_ - 1].Resize(data_size_, true);  // fill with zeros
//   output_->set_online_ready();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanBEAVYTensorRelu::evaluate_online_with_context end", gate_id_));
    }
  }
}

void BooleanBEAVYTensorRelu::evaluate_setup() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanBEAVYTensorRelu::evaluate_setup start", gate_id_));
    }
  }
  throw std::logic_error("Not yet implemented.");

//   // generate the secret shares
//   auto& out_sshares = output_->get_secret_share();
//   assert(out_sshares.size() == bit_size_);
// #pragma omp parallel for
//   for (std::size_t bit_j = 0; bit_j < bit_size_ - 1; ++bit_j) {
//     out_sshares[bit_j] = ENCRYPTO::BitVector<>::Random(data_size_);
//   }
//   // the last bit is always 0
//   out_sshares[bit_size_ - 1] = ENCRYPTO::BitVector<>(data_size_, false);
//   output_->set_setup_ready();

//   input_->wait_setup();
//   const auto& sshares = input_->get_secret_share();
//   const auto& my_msb_sshare = sshares[bit_size_ - 1];

//   ot_receiver_->SetChoices(my_msb_sshare);
//   ot_receiver_->SendCorrections();
//   ENCRYPTO::BitVector<> ot_inputs((bit_size_ - 1) * data_size_);
//   // inefficient, but works ...
//   for (std::size_t bit_j = 0; bit_j < bit_size_ - 1; ++bit_j) {
//     for (std::size_t int_i = 0; int_i < data_size_; ++int_i) {
//       ot_inputs.Set(sshares[bit_j].Get(int_i), int_i * (bit_size_ - 1) + bit_j);
//     }
//   }
//   ot_sender_->SetCorrelations(std::move(ot_inputs));
//   ot_sender_->SendMessages();
//   ot_sender_->ComputeOutputs();
//   ot_receiver_->ComputeOutputs();

//   // compute the products of the msb_mask with all other masks
//   for (std::size_t bit_j = 0; bit_j < bit_size_ - 1; ++bit_j) {
//     // local part
//     auto tmp = my_msb_sshare & sshares[bit_j];
//     // output mask
//     tmp ^= out_sshares[bit_j];
//     Delta_y_share_.Append(tmp);
//   }
//   const auto ot_snd_out = ot_sender_->GetOutputs();
//   const auto ot_rcv_out = ot_receiver_->GetOutputs();
//   // inefficient, but works ...
//   for (std::size_t bit_j = 0; bit_j < bit_size_ - 1; ++bit_j) {
//     for (std::size_t int_i = 0; int_i < data_size_; ++int_i) {
//       bool tmp = Delta_y_share_.Get(bit_j * data_size_ + int_i);
//       // product of other msb_mask with my sshare masks
//       tmp ^= ot_snd_out.Get(int_i * (bit_size_ - 1) + bit_j);
//       // product of my_msb_mask with other sshare masks
//       tmp ^= ot_rcv_out.Get(int_i * (bit_size_ - 1) + bit_j);
//       Delta_y_share_.Set(tmp, bit_j * data_size_ + int_i);
//     }
//   }
  // => Delta_y_share_ contains now [delta_ab]_i ^ [delta_y]_i

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanBEAVYTensorRelu::evaluate_setup end", gate_id_));
    }
  }
}

void BooleanBEAVYTensorRelu::evaluate_online() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanBEAVYTensorRelu::evaluate_online start", gate_id_));
    }
  }

  throw std::logic_error("Not yet implemented.");

//   input_->wait_online();
//   const auto& pshares = input_->get_public_share();
//   const auto my_msb_pshare = ~pshares[bit_size_ - 1];
//   const auto& sshares = input_->get_secret_share();
//   const auto& my_msb_sshare = sshares[bit_size_ - 1];

//   ENCRYPTO::BitVector tmp;
//   tmp.Reserve(Helpers::Convert::BitsToBytes((bit_size_ - 1) * data_size_));
//   const bool my_job = beavy_provider_.is_my_job(gate_id_);
//   for (std::size_t bit_j = 0; bit_j < bit_size_ - 1; ++bit_j) {
//     // Delta_y_share_ ^= Delta_a & [delta_b]_i
//     auto tmp2 = my_msb_pshare & sshares[bit_j];
//     // Delta_y_share_ ^= [delta_a]_i & Delta_b
//     tmp2 ^= my_msb_sshare & pshares[bit_j];
//     if (my_job) {
//       // Delta_y_share_ ^= Delta_a & Delta_b
//       tmp2 ^= my_msb_pshare & pshares[bit_j];
//     }
//     tmp.Append(tmp2);
//   }
//   Delta_y_share_ ^= tmp;
//   const auto my_id = beavy_provider_.get_my_id();
//   beavy_provider_.send_bits_message(1 - my_id, gate_id_, Delta_y_share_);
//   Delta_y_share_ ^= share_future_.get();

//   auto& out_pshares = output_->get_public_share();
// #pragma omp parallel for
//   for (std::size_t bit_j = 0; bit_j < bit_size_ - 1; ++bit_j) {
//     out_pshares[bit_j] = Delta_y_share_.Subset(bit_j * data_size_, (bit_j + 1) * data_size_);
//   }
//   out_pshares[bit_size_ - 1].Resize(data_size_, true);  // fill with zeros
//   output_->set_online_ready();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanBEAVYTensorRelu::evaluate_online end", gate_id_));
    }
  }
}

template <typename T>
BooleanXArithmeticBEAVYTensorRelu<T>::BooleanXArithmeticBEAVYTensorRelu(
    std::size_t gate_id, BEAVYProvider& beavy_provider, const BooleanBEAVYTensorCP input_bool,
    const ArithmeticBEAVYTensorCP<T> input_arith)
    : NewGate(gate_id),
      beavy_provider_(beavy_provider),
      data_size_(input_bool->get_dimensions().get_data_size()),
      input_bool_(std::move(input_bool)),
      input_arith_(std::move(input_arith)),
      output_(std::make_shared<ArithmeticBEAVYTensor<T>>(input_arith_->get_dimensions())) {
  if (input_bool_->get_dimensions() != input_arith_->get_dimensions()) {
    throw std::invalid_argument("dimension mismatch");
  }
  if (input_bool_->get_bit_size() != input_arith_->get_bit_size()) {
    throw std::invalid_argument("bit size mismatch");
  }
  const auto my_id = beavy_provider_.get_my_id();
  auto& ap = beavy_provider_.get_arith_manager().get_provider(1 - my_id);
  if (beavy_provider_.is_my_job(gate_id_)) {
    mult_int_side_ = ap.register_bit_integer_multiplication_int_side<T>(data_size_, 2);
    mult_bit_side_ = ap.register_bit_integer_multiplication_bit_side<T>(data_size_, 1);
  } else {
    mult_int_side_ = ap.register_bit_integer_multiplication_int_side<T>(data_size_, 1);
    mult_bit_side_ = ap.register_bit_integer_multiplication_bit_side<T>(data_size_, 2);
  }
  delta_b_share_.resize(data_size_);
  delta_b_x_delta_n_share_.resize(data_size_);
  share_future_ = beavy_provider_.register_for_ints_message<T>(1 - my_id, gate_id_, data_size_);

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format("Gate {}: BooleanXArithmeticBEAVYTensorRelu created", gate_id_));
    }
  }
}

template <typename T>
BooleanXArithmeticBEAVYTensorRelu<T>::~BooleanXArithmeticBEAVYTensorRelu() = default;

template <typename T>
void BooleanXArithmeticBEAVYTensorRelu<T>::evaluate_setup() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: BooleanXArithmeticBEAVYTensorRelu::evaluate_setup start", gate_id_));
    }
  }

  output_->get_secret_share() = Helpers::RandomVector<T>(data_size_);
  output_->set_setup_ready();

  input_bool_->wait_setup();
  input_arith_->wait_setup();
  const auto& int_sshare = input_arith_->get_secret_share();
  assert(int_sshare.size() == data_size_);
  const auto& msb_sshare = input_bool_->get_secret_share()[bit_size_ - 1];
  assert(msb_sshare.GetSize() == data_size_);

  std::vector<T> msb_sshare_as_ints(data_size_);
  for (std::size_t int_i = 0; int_i < data_size_; ++int_i) {
    msb_sshare_as_ints[int_i] = msb_sshare.Get(int_i);
  }

  mult_bit_side_->set_inputs(msb_sshare);

  if (beavy_provider_.is_my_job(gate_id_)) {
    std::vector<T> mult_inputs(2 * data_size_);
    for (std::size_t int_i = 0; int_i < data_size_; ++int_i) {
      mult_inputs[2 * int_i] = msb_sshare_as_ints[int_i];
      mult_inputs[2 * int_i + 1] =
          int_sshare[int_i] - 2 * msb_sshare_as_ints[int_i] * int_sshare[int_i];
    }
    mult_int_side_->set_inputs(std::move(mult_inputs));
  } else {
    std::vector<T> mult_inputs(data_size_);
    std::transform(std::begin(int_sshare), std::end(int_sshare), std::begin(msb_sshare_as_ints),
                   std::begin(mult_inputs), [](auto n, auto b) { return n - 2 * b * n; });
    mult_int_side_->set_inputs(std::move(mult_inputs));
  }

  mult_bit_side_->compute_outputs();
  mult_int_side_->compute_outputs();
  auto mult_bit_side_out = mult_bit_side_->get_outputs();
  auto mult_int_side_out = mult_int_side_->get_outputs();

  // compute [delta_b]^A and [delta_b * delta_n]^A
  if (beavy_provider_.is_my_job(gate_id_)) {
    for (std::size_t int_i = 0; int_i < data_size_; ++int_i) {
      delta_b_share_[int_i] = msb_sshare_as_ints[int_i] - 2 * mult_int_side_out[2 * int_i];
      delta_b_x_delta_n_share_[int_i] = msb_sshare_as_ints[int_i] * int_sshare[int_i] +
                                        mult_int_side_out[2 * int_i + 1] + mult_bit_side_out[int_i];
    }
  } else {
    for (std::size_t int_i = 0; int_i < data_size_; ++int_i) {
      delta_b_share_[int_i] = msb_sshare_as_ints[int_i] - 2 * mult_bit_side_out[2 * int_i];
      delta_b_x_delta_n_share_[int_i] = msb_sshare_as_ints[int_i] * int_sshare[int_i] +
                                        mult_bit_side_out[2 * int_i + 1] + mult_int_side_out[int_i];
    }
  }

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanXArithmeticBEAVYTensorRelu::evaluate_setup end", gate_id_));
    }
  }
}

template <typename T>
void BooleanXArithmeticBEAVYTensorRelu<T>::evaluate_online() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: BooleanXArithmeticBEAVYTensorRelu::evaluate_online start", gate_id_));
    }
  }

  input_bool_->wait_online();
  input_arith_->wait_online();
  const auto& int_sshare = input_arith_->get_secret_share();
  const auto& int_pshare = input_arith_->get_public_share();
  assert(int_pshare.size() == data_size_);
  const auto& msb_pshare = input_bool_->get_public_share()[bit_size_ - 1];
  assert(msb_pshare.GetSize() == data_size_);

  const auto& sshare = output_->get_secret_share();
  std::vector<T> pshare(data_size_);

#pragma omp parallel for
  for (std::size_t int_i = 0; int_i < data_size_; ++int_i) {
    T Delta_b = !msb_pshare.Get(int_i);
    auto Delta_n = int_pshare[int_i];
    pshare[int_i] = delta_b_share_[int_i] * (Delta_n - 2 * Delta_b * Delta_n) -
                    Delta_b * int_sshare[int_i] -
                    delta_b_x_delta_n_share_[int_i] * (1 - 2 * Delta_b) + sshare[int_i];
    if (beavy_provider_.is_my_job(gate_id_)) {
      pshare[int_i] += Delta_b * Delta_n;
    }
  }

  beavy_provider_.broadcast_ints_message(gate_id_, pshare);
  const auto other_pshare = share_future_.get();
  __gnu_parallel::transform(std::begin(pshare), std::end(pshare), std::begin(other_pshare),
                            std::begin(pshare), std::plus{});

  output_->get_public_share() = std::move(pshare);
  output_->set_online_ready();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanXArithmeticBEAVYTensorRelu::evaluate_online end", gate_id_));
    }
  }
}

template class BooleanXArithmeticBEAVYTensorRelu<std::uint32_t>;
template class BooleanXArithmeticBEAVYTensorRelu<std::uint64_t>;

BooleanBEAVYTensorMaxPool::BooleanBEAVYTensorMaxPool(std::size_t gate_id,
                                                     BEAVYProvider& beavy_provider,
                                                     tensor::MaxPoolOp maxpool_op,
                                                     const BooleanBEAVYTensorCP input)
    : NewGate(gate_id),
      beavy_provider_(beavy_provider),
      maxpool_op_(maxpool_op),
      bit_size_(input->get_bit_size()),
      data_size_(input->get_dimensions().get_data_size()),
      input_(input),
      output_(
          std::make_shared<BooleanBEAVYTensor>(maxpool_op_.get_output_tensor_dims(), bit_size_, beavy_provider.get_num_parties())),
      // XXX: use depth-optimized circuit here
      maxpool_algo_(beavy_provider_.get_circuit_loader().load_maxpool_circuit(
          bit_size_, maxpool_op_.compute_kernel_size(), true)) {
  if (!maxpool_op_.verify()) {
    throw std::invalid_argument("invalid MaxPoolOp");
  }
  const auto kernel_size = maxpool_op_.compute_kernel_size();
  const auto output_size = maxpool_op_.compute_output_size();
  input_wires_.resize(bit_size_ * kernel_size);
  std::generate(std::begin(input_wires_), std::end(input_wires_), [output_size, this] {
    auto w = std::make_shared<BooleanBEAVYWire>(output_size, beavy_provider_.get_num_parties());
    w->get_secret_share().Resize(output_size);
    w->get_public_share().Resize(output_size);
    return w;
  });
  {
    WireVector in(bit_size_ * kernel_size);
    std::transform(std::begin(input_wires_), std::end(input_wires_), std::begin(in),
                   [](auto w) { return std::dynamic_pointer_cast<BooleanBEAVYWire>(w); });
    auto [gates, out] = construct_circuit(beavy_provider_, maxpool_algo_, in);
    gates_ = std::move(gates);
    assert(out.size() == bit_size_);
    output_wires_.resize(bit_size_);
    std::transform(std::begin(out), std::end(out), std::begin(output_wires_),
                   [](auto w) { return std::dynamic_pointer_cast<BooleanBEAVYWire>(w); });
  }

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format("Gate {}: BooleanBEAVYTensorMaxPool created", gate_id_));
    }
  }
}

template <bool setup>
static void prepare_wires(std::size_t bit_size, const tensor::MaxPoolOp& maxpool_op,
                          BooleanBEAVYWireVector& circuit_wires,
                          const std::vector<ENCRYPTO::BitVector<>>& input_shares) {
  const auto& input_shape = maxpool_op.input_shape_;
  const auto& output_shape = maxpool_op.output_shape_;
  const auto& kernel_shape = maxpool_op.kernel_shape_;
  const auto& strides = maxpool_op.strides_;

  // compute the index in the (tensor) input shares
  const auto in_idx = [input_shape](auto channel, auto row, auto column) {
    assert(channel < input_shape[0]);
    assert(row < input_shape[1]);
    assert(column < input_shape[2]);
    return channel * (input_shape[1] * input_shape[2]) + row * input_shape[2] + column;
  };

  // compute the index of the input wire of the circuit
  const auto mpin_wires_idx = [bit_size, &kernel_shape](auto bit_j, auto k_row, auto k_column) {
    assert(bit_j < bit_size);
    assert(k_row < kernel_shape[0]);
    assert(k_column < kernel_shape[1]);
    return (k_row * kernel_shape[1] + k_column) * bit_size + bit_j;
  };

  // compute the index in the output shares and circuit input shares
  const auto out_idx = [&output_shape](auto channel, auto row, auto column) {
    assert(channel < output_shape[0]);
    assert(row < output_shape[1]);
    assert(column < output_shape[2]);
    return channel * (output_shape[1] * output_shape[2]) + row * output_shape[2] + column;
  };

#pragma omp parallel for
  for (std::size_t bit_j = 0; bit_j < bit_size; ++bit_j) {
    const auto& in_share = input_shares[bit_j];
    for (std::size_t channel_i = 0; channel_i < output_shape[0]; ++channel_i) {
      std::size_t i_row = 0;
      for (std::size_t o_row = 0; o_row < output_shape[1]; ++o_row) {
        std::size_t i_col = 0;
        for (std::size_t o_col = 0; o_col < output_shape[2]; ++o_col) {
          for (std::size_t k_row = 0; k_row < kernel_shape[0]; ++k_row) {
            for (std::size_t k_col = 0; k_col < kernel_shape[0]; ++k_col) {
              // auto bit = in_share.Get(in_idx(channel_i, i_row + k_row, i_col + k_col));
              if constexpr (setup) {
                auto& bv = circuit_wires[mpin_wires_idx(bit_j, k_row, k_col)]->get_common_secret_share();
                // bv.Set(bit, out_idx(channel_i, o_row, o_col));
                bv = in_share;
              } else {
                auto bit = in_share.Get(in_idx(channel_i, i_row + k_row, i_col + k_col));
                auto& bv = circuit_wires[mpin_wires_idx(bit_j, k_row, k_col)]->get_public_share();
                bv.Set(bit, out_idx(channel_i, o_row, o_col));
              }
            }
          }

          i_col += strides[1];
        }
        i_row += strides[0];
      }
    }
  }
  for (auto& wire : circuit_wires) {
    if constexpr (setup) {
      wire->set_setup_ready();
    } else {
      wire->set_online_ready();
    }
  }
}

void BooleanBEAVYTensorMaxPool::evaluate_setup() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanBEAVYTensorMaxPool::evaluate_setup start", gate_id_));
    }
  }

  input_->wait_setup();

  prepare_wires<true>(bit_size_, maxpool_op_, input_wires_, input_->get_common_secret_share());

  for (auto& gate : gates_) {
    // should work since its a Boolean circuit consisting of AND, XOR, INV gates
    gate->evaluate_setup();
  }

  auto& output_shares = output_->get_secret_share();
  for (std::size_t bit_j = 0; bit_j < bit_size_; ++bit_j) {
    auto& wire = output_wires_[bit_j];
    wire->wait_setup();
    output_shares[bit_j] = std::move(wire->get_secret_share());
  }
  output_->set_setup_ready();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanBEAVYTensorMaxPool::evaluate_setup end", gate_id_));
    }
  }
}

void BooleanBEAVYTensorMaxPool::evaluate_setup_with_context(ExecutionContext& exec_ctx) {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: BooleanBEAVYTensorMaxPool::evaluate_setup_with_context start", gate_id_));
    }
  }

  input_->wait_setup();

  prepare_wires<true>(bit_size_, maxpool_op_, input_wires_, input_->get_common_secret_share());

  for (auto& gate : gates_) {
    exec_ctx.fpool_->post([&] { gate->evaluate_setup(); });
  }

  auto& output_shares = output_->get_secret_share();
  for (std::size_t bit_j = 0; bit_j < bit_size_; ++bit_j) {
    auto& wire = output_wires_[bit_j];
    wire->wait_setup();
    output_shares[bit_j] = std::move(wire->get_secret_share());
  }
  output_->set_setup_ready();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: BooleanBEAVYTensorMaxPool::evaluate_setup_with_context end", gate_id_));
    }
  }
}

void BooleanBEAVYTensorMaxPool::evaluate_online() {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanBEAVYTensorMaxPool::evaluate_online start", gate_id_));
    }
  }

  input_->wait_online();

  prepare_wires<false>(bit_size_, maxpool_op_, input_wires_, input_->get_public_share());

  for (auto& gate : gates_) {
    // should work since its a Boolean circuit consisting of AND, XOR, INV gates
    gate->evaluate_online();
  }

  auto& output_shares = output_->get_public_share();
  for (std::size_t bit_j = 0; bit_j < bit_size_; ++bit_j) {
    auto& wire = output_wires_[bit_j];
    wire->wait_online();
    output_shares[bit_j] = std::move(wire->get_public_share());
  }
  output_->set_online_ready();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(
          fmt::format("Gate {}: BooleanBEAVYTensorMaxPool::evaluate_online end", gate_id_));
    }
  }
}

void BooleanBEAVYTensorMaxPool::evaluate_online_with_context(ExecutionContext& exec_ctx) {
  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: BooleanBEAVYTensorMaxPool::evaluate_online_with_context start", gate_id_));
    }
  }

  input_->wait_online();

  prepare_wires<false>(bit_size_, maxpool_op_, input_wires_, input_->get_public_share());

  for (auto& gate : gates_) {
    exec_ctx.fpool_->post([&] { gate->evaluate_online(); });
  }

  auto& output_shares = output_->get_public_share();
  for (std::size_t bit_j = 0; bit_j < bit_size_; ++bit_j) {
    auto& wire = output_wires_[bit_j];
    wire->wait_online();
    output_shares[bit_j] = std::move(wire->get_public_share());
  }
  output_->set_online_ready();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto logger = beavy_provider_.get_logger();
    if (logger) {
      logger->LogTrace(fmt::format(
          "Gate {}: BooleanBEAVYTensorMaxPool::evaluate_online_with_context end", gate_id_));
    }
  }
}

}  // namespace MOTION::proto::beavy
