#include "AMClient/Base.hpp"
#include "AMClient/IOCore.hpp"
#include "AMManager/Client.hpp"

/*
namespace AMClientManage {

Manager::Manager() {
  SetPasswordCallback();
  SetDisconnectCallback();

  auto local_client = CreateLocalClient_(hostm_, log_manager_);
  auto local_base = std::dynamic_pointer_cast<BaseClient>(local_client);
  auto clients =
      std::make_shared<ClientMaintainer>(60, disconnect_cb_, local_client);

  ConfigureState(clients, local_base, 10);
  InitClientWorkdir(local_base);
}

} // namespace AMClientManage
*/

void AMClientManager::Init() {
  SetPasswordCallback();
  SetDisconnectCallback();
  std::shared_ptr<BaseClient> local_client =
      CreateLocalClient_(hostm_, log_manager_);
  auto clients =
      std::make_shared<ClientMaintainer>(60, disconnect_cb_, local_client);
  ConfigureState(clients, local_client, 10);
}
