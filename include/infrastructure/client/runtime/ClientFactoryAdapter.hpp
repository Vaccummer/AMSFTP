#pragma once

#include "domain/client/ClientPort.hpp"
#include "domain/host/HostManager.hpp"
#include "infrastructure/client/runtime/Builder.hpp"

namespace AMInfra::ClientRuntime {
/**
 * @brief Infrastructure adapter exposing runtime client construction as a
 * domain factory port.
 */
class ClientFactoryAdapter final : public AMDomain::client::IClientFactoryPort {
public:
  /**
   * @brief Construct factory adapter from host config manager.
   */
  explicit ClientFactoryAdapter(
      AMDomain::host::AMHostConfigManager &host_config_manager)
      : host_config_manager_(host_config_manager) {}

  /**
   * @brief Virtual destructor for polymorphic use.
   */
  ~ClientFactoryAdapter() override = default;

  /**
   * @brief Create one concrete client from request data.
   */
  std::pair<ECM, std::shared_ptr<AMDomain::client::IClientPort>>
  CreateClient(const ConRequest &request) override {
    std::vector<std::string> keys;
    if (!AMStr::Strip(request.keyfile).empty()) {
      keys.push_back(request.keyfile);
    } else {
      keys = host_config_manager_.PrivateKeys();
    }
    auto client = AMInfra::ClientRuntime::CreateClient(request, 10, {}, keys);
    if (!client) {
      return {Err(EC::OperationUnsupported, "Unsupported protocol"), nullptr};
    }
    return {Ok(), std::move(client)};
  }

private:
  AMDomain::host::AMHostConfigManager &host_config_manager_;
};
} // namespace AMInfra::ClientRuntime
