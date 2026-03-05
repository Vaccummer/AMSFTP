#pragma once
#include "foundation/DataClass.hpp"
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace AMDomain::client {
/**
 * @brief Abstract domain-facing client handle.
 */
class IClientHandle {
public:
  virtual ~IClientHandle() = default;

  /**
   * @brief Return client nickname.
   */
  [[nodiscard]] virtual std::string Nickname() const = 0;

  /**
   * @brief Return protocol for this client.
   */
  [[nodiscard]] virtual ClientProtocol Protocol() const = 0;
};

/**
 * @brief Domain port for client registry/operator operations.
 */
class IClientOperatorPort {
public:
  virtual ~IClientOperatorPort() = default;

  /**
   * @brief Return all managed client nicknames.
   */
  [[nodiscard]] virtual std::vector<std::string> ListNicknames() const = 0;

  /**
   * @brief Get one managed client by nickname.
   */
  [[nodiscard]] virtual std::shared_ptr<IClientHandle>
  GetClient(const std::string &nickname) const = 0;

  /**
   * @brief Ensure one client is available and ready.
   */
  virtual std::pair<ECM, std::shared_ptr<IClientHandle>>
  EnsureClient(const std::string &nickname, amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Create/connect one client from connection request.
   */
  virtual std::pair<ECM, std::shared_ptr<IClientHandle>>
  Connect(const ConRequest &request, amf interrupt_flag = nullptr) = 0;
};
} // namespace AMDomain::client
