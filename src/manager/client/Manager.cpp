#include "AMManager/Client.hpp"
#include <cstdlib>

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

std::shared_ptr<AMLocalClient>
Manager::CreateLocalClient_(AMHostManager &hostm, AMLogManager &log_manager) {
  auto trace_cb = log_manager.TraceCallbackFunc();

  std::string local_user = "";
#ifdef _WIN32
  const char *env_user = std::getenv("USERNAME");
#else
  const char *env_user = std::getenv("USER");
#endif
  if (env_user) {
    local_user = env_user;
  }
  if (local_user.empty()) {
    local_user = "local";
  }
  ConRequst request("local", "localhost", local_user, 22, "", "", false, "");
  int64_t buffer_size = AMDefaultRemoteBufferSize;
  std::string login_dir;

  auto cfg_result = hostm.GetClientConfig("local");
  if (cfg_result.first.first == EC::Success) {
    request = cfg_result.second.request;
    buffer_size = cfg_result.second.buffer_size;
    login_dir = cfg_result.second.login_dir;
  } else {
    ClientConfig local_cfg;
    local_cfg.request = request;
    local_cfg.protocol = ClientProtocol::LOCAL;
    local_cfg.buffer_size = AMDefaultRemoteBufferSize;
    local_cfg.login_dir = "";
    (void)hostm.UpsertHost(local_cfg, false);
    (void)hostm.Save();
  }

  auto client =
      std::make_shared<AMLocalClient>(request, 10, std::move(trace_cb));

  if (!request.trash_dir.empty()) {
    auto result = client->TrashDir(request.trash_dir);
    if (std::holds_alternative<ECM>(result)) {
      const auto &ecm = std::get<ECM>(result);
      if (ecm.first != EC::Success) {
        prompt_.ErrorFormat(ecm);
      }
    }
  }

  if (buffer_size > 0) {
    client->TransferRingBufferSize(buffer_size);
  }

  if (login_dir.empty()) {
    login_dir = client->GetHomeDir();
  }
  const std::string normalized = AMPathStr::UnifyPathSep(login_dir, "/");
  (void)client->SetPulbicValue("workdir", normalized, true);
  (void)client->SetPulbicValue("login_dir", normalized, true);
  return client;
}

} // namespace AMClientManage
