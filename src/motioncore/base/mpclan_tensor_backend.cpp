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

#include "mpclan_tensor_backend.h"

#include <memory>
#include <stdexcept>

#include <fmt/format.h>

#include "algorithm/circuit_loader.h"
#include "base/gate_register.h"
#include "communication/communication_layer.h"
#include "crypto/arithmetic_provider.h"
#include "crypto/base_ots/base_ot_provider.h"
#include "crypto/motion_base_provider.h"
#include "crypto/multiplication_triple/linalg_triple_provider.h"
#include "crypto/multiplication_triple/mt_provider.h"
#include "crypto/multiplication_triple/sb_provider.h"
#include "crypto/multiplication_triple/sp_provider.h"
#include "crypto/oblivious_transfer/ot_provider.h"
#include "executor/tensor_op_executor.h"
#include "protocols/beavy/beavy_provider.h"
#include "protocols/gmw/gmw_provider.h"
#include "protocols/yao/yao_provider.h"
#include "statistics/run_time_stats.h"
#include "tensor/tensor_op_factory.h"
#include "utility/logger.h"
#include "utility/typedefs.h"

namespace MOTION {

MPCLanTensorBackend::MPCLanTensorBackend(Communication::CommunicationLayer& comm_layer,
                                             std::size_t num_threads,
                                             bool sync_between_setup_and_online,
                                             std::shared_ptr<Logger> logger, bool fake_triples)
    : comm_layer_(comm_layer),
      my_id_(comm_layer_.get_my_id()),
      logger_(logger),
      gate_register_(std::make_unique<GateRegister>()),
      gate_executor_(std::make_unique<TensorOpExecutor>(
          *gate_register_, [this] { run_preprocessing(); }, sync_between_setup_and_online,
          [this] { comm_layer_.sync(); }, num_threads, logger_)),
      circuit_loader_(std::make_unique<CircuitLoader>()),
      run_time_stats_(1),
      motion_base_provider_(std::make_unique<Crypto::MotionBaseProvider>(comm_layer_, logger_)),
      base_ot_provider_(
          std::make_unique<BaseOTProvider>(comm_layer_, &run_time_stats_.back(), logger_)),
      ot_manager_(std::make_unique<ENCRYPTO::ObliviousTransfer::OTProviderManager>(
          comm_layer_, *base_ot_provider_, *motion_base_provider_, &run_time_stats_.back(),
          logger_)),
      arithmetic_manager_(
          std::make_unique<ArithmeticProviderManager>(comm_layer_, *ot_manager_, logger_)),
      linalg_triple_provider_(fake_triples ? (std::dynamic_pointer_cast<LinAlgTripleProvider>(
                                                 std::make_shared<FakeLinAlgTripleProvider>()))
                                           : (std::dynamic_pointer_cast<LinAlgTripleProvider>(
                                                 std::make_shared<LinAlgTriplesFromAP>(
                                                     arithmetic_manager_->get_provider(1 - my_id_),
                                                     ot_manager_->get_provider(1 - my_id_),
                                                     run_time_stats_.back(), logger_)))),
      mt_provider_(std::make_unique<MTProviderFromOTs>(my_id_, comm_layer_.get_num_parties(), true,
                                                       *arithmetic_manager_, *ot_manager_,
                                                       run_time_stats_.back(), logger_)),
      sp_provider_(std::make_unique<SPProviderFromOTs>(ot_manager_->get_providers(), my_id_,
                                                       run_time_stats_.back(), logger_)),
      beavy_provider_(std::make_unique<proto::beavy::BEAVYProvider>(
          comm_layer_, *gate_register_, *circuit_loader_, *motion_base_provider_, *ot_manager_,
          *arithmetic_manager_, logger_, fake_triples)) {
  tensor_op_factories_.emplace(MPCProtocol::ArithmeticBEAVY, *beavy_provider_);
  tensor_op_factories_.emplace(MPCProtocol::BooleanBEAVY, *beavy_provider_);
  comm_layer_.start();
}

MPCLanTensorBackend::~MPCLanTensorBackend() = default;

void MPCLanTensorBackend::run_preprocessing() {
  run_time_stats_.back().record_start<Statistics::RunTimeStats::StatID::preprocessing>();

  motion_base_provider_->setup();
  base_ot_provider_->ComputeBaseOTs();
  mt_provider_->PreSetup();
  sp_provider_->PreSetup();
  ot_manager_->run_setup();
  linalg_triple_provider_->setup();
  mt_provider_->Setup();
  sp_provider_->Setup();
  beavy_provider_->setup();

  run_time_stats_.back().record_end<Statistics::RunTimeStats::StatID::preprocessing>();
}

void MPCLanTensorBackend::run() {
  gate_executor_->evaluate_setup_online(run_time_stats_.back());
}

tensor::TensorOpFactory& MPCLanTensorBackend::get_tensor_op_factory(MPCProtocol proto) {
  try {
    return tensor_op_factories_.at(proto);
  } catch (std::out_of_range& e) {
    throw std::logic_error(
        fmt::format("MPCLanTensorBackend::get_tensor_op_factory: no TensorOpFactory for protocol "
                    "{} available",
                    ToString(proto)));
  }
}

std::optional<MPCProtocol> MPCLanTensorBackend::convert_via(MPCProtocol src_proto,
                                                              MPCProtocol dst_proto) {
  if (src_proto == MPCProtocol::ArithmeticGMW && dst_proto == MPCProtocol::BooleanGMW) {
    return MPCProtocol::Yao;
  }
  return std::nullopt;
}

const Statistics::RunTimeStats& MPCLanTensorBackend::get_run_time_stats() const noexcept {
  return run_time_stats_.back();
}

}  // namespace MOTION
