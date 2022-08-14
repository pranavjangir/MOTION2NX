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
#include <unordered_map>

#include "circuit_builder.h"
#include "gate_factory.h"

namespace ENCRYPTO::ObliviousTransfer {
class OTProviderManager;
}

namespace MOTION {

class CircuitLoader;
class GateFactory;
class GateRegister;
class Logger;
class NewGateExecutor;
enum class MPCProtocol : unsigned int;

namespace Communication {
class CommunicationLayer;
}

namespace Crypto {
class MotionBaseProvider;
}

namespace proto {
namespace swift {
class SWIFTProvider;
} // namespace swift
}  // namespace proto

namespace Statistics {
struct RunTimeStats;
}

class SwiftBackend : public CircuitBuilder {
 public:
  SwiftBackend(Communication::CommunicationLayer&, std::size_t num_threads,
                  bool sync_between_setup_and_online, std::shared_ptr<Logger>);
  ~SwiftBackend();

  void run_preprocessing();
  void run();

  std::optional<MPCProtocol> convert_via(MPCProtocol src_proto, MPCProtocol dst_proto) override;
  GateFactory& get_gate_factory(MPCProtocol proto) override;

  const Statistics::RunTimeStats& get_run_time_stats() const noexcept;

 private:
  Communication::CommunicationLayer& comm_layer_;
  std::size_t my_id_;
  std::shared_ptr<Logger> logger_;
  std::unique_ptr<GateRegister> gate_register_;
  std::unique_ptr<NewGateExecutor> gate_executor_;
  std::unique_ptr<CircuitLoader> circuit_loader_;
  std::unordered_map<MPCProtocol, std::reference_wrapper<GateFactory>> gate_factories_;
  std::vector<Statistics::RunTimeStats> run_time_stats_;

  std::unique_ptr<Crypto::MotionBaseProvider> motion_base_provider_;
  std::unique_ptr<proto::swift::SWIFTProvider> swift_provider_;
};

}  // namespace MOTION
