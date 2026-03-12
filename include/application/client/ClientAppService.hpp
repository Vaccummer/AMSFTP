#pragma once

#include "application/client/runtime/ClientMaintainer.hpp"
#include "application/client/runtime/ClientPublicPool.hpp"
#include "domain/client/ClientPort.hpp"
#include <atomic>
#include <functional>
#include <memory>

namespace AMDomain::host {
class AMHostConfigManager;
}

namespace AMApplication::client {
/**
 * @brief Application runtime owner for client registry, lifecycle, and
 * session-path state.
 */
class ClientAppService final : private NonCopyableNonMovable,
                               public AMDomain::client::IClientRuntimePort,
                               public AMDomain::client::IClientLifecyclePort,
                               public AMDomain::client::IClientPathPort {
public:
  using ECM = std::pair<ErrorCode, std::string>;
  using EC = ErrorCode;
  using ClientHandle = AMDomain::client::ClientHandle;
  using TraceCallback = AMDomain::client::TraceCallback;
  using AuthCallback = AMDomain::client::AuthCallback;
  using KnownHostCallback = AMDomain::client::KnownHostCallback;
  using DisconnectCallback =
      std::function<void(const ClientHandle &, const ECM &)>;
  using ClientConnectOptions = AMDomain::client::ClientConnectOptions;
  using ClientConnectContext = AMDomain::client::ClientConnectContext;
  using ClientWorkdirState = AMDomain::client::ClientWorkdirState;
  using ParsedClientPath = AMDomain::client::ParsedClientPath;

  /**
   * @brief Construct app service from host config manager and client factory.
   */
  ClientAppService(AMDomain::host::AMHostConfigManager &host_config_manager,
                   AMDomain::client::IClientFactoryPort &client_factory);

  /**
   * @brief Destroy app service.
   */
  ~ClientAppService() override;

  /**
   * @brief Initialize local/current client state and maintainer registry.
   */
  ECM Init();

  /**
   * @brief Set heartbeat timeout for application-owned maintainer.
   */
  void SetHeartbeatTimeoutMs(int timeout_ms);

  /**
   * @brief Return current heartbeat timeout.
   */
  [[nodiscard]] int HeartbeatTimeoutMs() const;

  /**
   * @brief Set known-host callback provider.
   */
  void SetKnownHostCallback(KnownHostCallback cb = {});

  /**
   * @brief Set auth callback provider.
   */
  void SetAuthCallback(AuthCallback cb = {});

  /**
   * @brief Set disconnect callback provider.
   */
  void SetDisconnectCallback(DisconnectCallback cb = {});

  /**
   * @brief Bind shared interactive-state flag.
   */
  void SetInteractiveFlag(const std::shared_ptr<std::atomic<bool>> &flag);

  /**
   * @brief Return bound interactive-state flag.
   */
  [[nodiscard]] std::shared_ptr<std::atomic<bool>> GetInteractiveFlag() const;

  /**
   * @brief Return current maintainer reference.
   */
  [[nodiscard]] ClientMaintainer &Maintainer();

  /**
   * @brief Return current maintainer reference.
   */
  [[nodiscard]] const ClientMaintainer &Maintainer() const;

  /**
   * @brief Return shared transfer client pool.
   */
  [[nodiscard]] std::shared_ptr<ClientPublicPool> PublicPool() const;

  /**
   * @brief Create one transfer-only client instance by nickname.
   */
  std::pair<ECM, ClientHandle>
  CreateTransferClient(const std::string &nickname, int timeout_ms = -1,
                       int64_t start_time = -1);

  /**
   * @brief Return one client by nickname.
   */
  [[nodiscard]] ClientHandle
  GetClient(const std::string &nickname) const override;

  /**
   * @brief Return local client instance.
   */
  [[nodiscard]] ClientHandle GetLocalClient() const override;

  /**
   * @brief Return current active client instance.
   */
  [[nodiscard]] ClientHandle GetCurrentClient() const override;

  /**
   * @brief Return current active nickname.
   */
  [[nodiscard]] std::string CurrentNickname() const override;

  /**
   * @brief Set current active client instance.
   */
  void SetCurrentClient(const ClientHandle &client) override;

  /**
   * @brief Return all client nicknames.
   */
  [[nodiscard]] std::vector<std::string> GetClientNames() const override;

  /**
   * @brief Return all client handles.
   */
  [[nodiscard]] std::vector<ClientHandle> GetClients() const override;

  /**
   * @brief Connect one configured nickname.
   */
  std::pair<ECM, ClientHandle>
  ConnectNickname(const std::string &nickname,
                  const ClientConnectOptions &options = {},
                  TraceCallback trace_cb = {},
                  amf interrupt_flag = nullptr) override;

  /**
   * @brief Connect one explicit request payload.
   */
  std::pair<ECM, ClientHandle>
  ConnectRequest(const ClientConnectContext &context,
                 TraceCallback trace_cb = {},
                 amf interrupt_flag = nullptr) override;

  /**
   * @brief Ensure one client exists and is connected.
   */
  std::pair<ECM, ClientHandle>
  EnsureClient(const std::string &nickname,
               amf interrupt_flag = nullptr) override;

  /**
   * @brief Check one client by nickname.
   */
  std::pair<ECM, ClientHandle>
  CheckClient(const std::string &nickname, bool update = false,
              amf interrupt_flag = nullptr, int timeout_ms = -1,
              int64_t start_time = -1) override;

  /**
   * @brief Remove one client from runtime registry.
   */
  ECM RemoveClient(const std::string &nickname) override;

  /**
   * @brief Parse one raw path token into nickname/path/client form.
   */
  [[nodiscard]] ParsedClientPath
  ParseScopedPath(const std::string &input,
                  amf interrupt_flag = nullptr) override;

  /**
   * @brief Resolve one raw path into absolute path.
   */
  [[nodiscard]] std::string
  ResolveClientPath(const std::string &path,
                    const ClientHandle &client = nullptr) const override;

  /**
   * @brief Return stored workdir state for one nickname.
   */
  [[nodiscard]] ClientWorkdirState
  GetWorkdirState(const std::string &nickname) const override;

  /**
   * @brief Store workdir state for one nickname.
   */
  ECM SetWorkdirState(const std::string &nickname,
                      const ClientWorkdirState &state) override;

  /**
   * @brief Return current workdir, initializing when absent.
   */
  [[nodiscard]] std::string
  GetOrInitWorkdir(const ClientHandle &client) override;

  /**
   * @brief Build absolute path from client workdir/home context.
   */
  [[nodiscard]] std::string
  BuildAbsolutePath(const ClientHandle &client,
                    const std::string &path) const override;

private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};
} // namespace AMApplication::client
