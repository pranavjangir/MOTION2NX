#include <map>

#include "abynparty.h"
#include "communication/hellomessage.h"

namespace ABYN {

  void ABYNParty::Connect() {
//assign 1 thread for each connection
    auto n = configuration_->GetNumOfParties();
#pragma omp parallel num_threads(n)
    {
#pragma omp single
#pragma omp taskloop num_tasks(n) default(shared)
      for (auto i = 0u; i < n; ++i) {
        auto &&p = configuration_->GetParty(i);
        backend_->LogDebug(fmt::format("Trying to connect {}:{}\n", p.GetIp().data(), p.GetPort()));

        auto &&result = configuration_->GetParty(i).Connect();
        backend_->LogInfo(std::move(result));
      }
    }
    backend_->InitializeCommunicationHandlers();
  };

  //TODO below
  void ABYNParty::SendHelloToOthers() {
    std::vector<flatbuffers::FlatBufferBuilder> messages;
    for (auto i = 0u; i < backend_->GetConfig()->GetNumOfParties(); ++i)
      messages.push_back(ABYN::Communication::BuildHelloMessage(backend_->GetConfig()->GetMyId()));
  }

  std::vector<std::unique_ptr<ABYNParty>> ABYNParty::GetNLocalConnectedParties(size_t num_parties, u16 port) {
    if (num_parties < 3) {
      throw (std::runtime_error(fmt::format("Can generate only >= 3 local parties, current input: {}", num_parties)));
    }

    std::vector<ABYNPartyPtr> abyn_parties(0);
    std::vector<std::future<ABYNPartyPtr>> futures(0);
    std::map<u32, u16> assigned_ports;

    //portid generation function - we require symmetric port generation for parties, e.g., parties #4 and #7
    //independent of the position of the ids, i.e., sort them always in ascending order and generate a bigger number
    //out of two ids.
    auto portid = [](u32 my_id, u32 other_id) -> u32 {
      return other_id < my_id ?
             (other_id << 16) + (my_id) :
             (my_id << 16) + (other_id);
    };

    //generate ports sequentially using the map data structure using the offset @param port
    //the generated ports given port=10000 and 4 parties are 10000--10005
    for (auto my_id = 0ul; my_id < num_parties; ++my_id) {
      for (auto other_id = 0ul; other_id < num_parties; ++other_id) {
        if (my_id == other_id) continue;
        u32 port_id = portid(my_id, other_id);
        if (assigned_ports.find(port_id) == assigned_ports.end()) {
          assigned_ports.insert({port_id, port++});
        }
      }
    }

    //generate parties using separate threads
    for (auto my_id = 0ul; my_id < num_parties; ++my_id) {
      futures.push_back(std::async(std::launch::async,
                                   [num_parties, my_id, &assigned_ports, &portid]() mutable {
                                     std::vector<Party> parties;
                                     for (auto other_id = 0ul; other_id < num_parties; ++other_id) {
                                       if (my_id == other_id) continue;
                                       ABYN::Role role = other_id < my_id ?
                                                         ABYN::Role::Client : ABYN::Role::Server;

                                       u32 port_id = portid(my_id, other_id);

                                       u16 this_port;
                                       auto search = assigned_ports.find(port_id);
                                       if (search != assigned_ports.end()) {
                                         this_port = search->second;
                                       } else {
                                         throw (std::runtime_error(
                                             fmt::format("Didn't find the port id in the lookup table: {}", port_id)));
                                       };

                                       parties.emplace_back("127.0.0.1", this_port, role, 1);
                                     }
                                     auto abyn = std::move(std::make_unique<ABYNParty>(parties, my_id));
                                     abyn->Connect();
                                     return std::move(abyn);
                                   }));
    }
    for (auto &f : futures)
      abyn_parties.push_back(f.get());

    return std::move(abyn_parties);
  };

}