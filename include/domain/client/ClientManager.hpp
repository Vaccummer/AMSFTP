#pragma once
#include "domain/client/ClientPort.hpp"
#include "foundation/DataClass.hpp"
#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <tuple>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

class ClientMaintainer;
class KnownHostQuery;

namespace AMDomain::client {
using AMClientAuthCallback =
    std::function<std::optional<std::string>(const AuthCBInfo &)>;
using AMClientTraceCallback = std::function<void(const TraceInfo &)>;
using AMClientHandle = std::shared_ptr<IClientPort>;

class AMClientOperator {
public:
  using AuthCallback = AMClientAuthCallback;
  using TraceCallback = AMClientTraceCallback;
  using ClientHandle = AMClientHandle;
  using KnownHostCallback = std::function<ECM(const KnownHostQuery &)>;
  using DisconnectCallback =
      std::function<void(const ClientHandle &, const ECM &)>;

  void SetHeartbeatTimeoutMs(int timeout_ms);
  [[nodiscard]] int HeartbeatTimeoutMs() const;
  void SetKnownHostCallback(KnownHostCallback cb = {});
  void SetDefaultPasswordCallback(AuthCallback cb = {});
  void SetDefaultDisconnectCallback(DisconnectCallback cb = {});
  void SetPasswordCallback(AuthCallback cb = {});
  void SetDisconnectCallback(DisconnectCallback cb = {});
  ClientMaintainer &Clients();
  [[nodiscard]] std::vector<std::string> GetClientNames();
  [[nodiscard]] std::vector<ClientHandle> GetClients();
  /**
   * @brief Return one managed client by nickname.
   *
   * Empty/"local" resolves to local client.
   */
  [[nodiscard]] ClientHandle GetClient(const std::string &nickname) const;
  [[nodiscard]] ClientHandle LocalClient() const;
  [[nodiscard]] ClientHandle CurrentClient() const;
  [[nodiscard]] std::string CurrentNickname() const;
  void SetCurrentClient(const ClientHandle &client);
  void ConfigureState(const std::shared_ptr<ClientMaintainer> &clients,
                      const ClientHandle &local_client_base, ssize_t trace_num);
  void ResetSpinnerState();
  void SetSpinnerLineLen(size_t line_len);
  [[nodiscard]] bool SpinnerStopRequested() const;
  void RequestSpinnerStop();

  std::pair<ECM, ClientHandle>
  AddClient(const std::string &nickname,
            std::shared_ptr<ClientMaintainer> maintainer = nullptr,
            bool force = false, bool quiet = false, TraceCallback trace_cb = {},
            amf interrupt_flag = nullptr);

  std::pair<ECM, ClientHandle> AddClient(const std::string &nickname,
                                         bool force, bool quiet,
                                         TraceCallback trace_cb = {},
                                         amf interrupt_flag = nullptr,
                                         bool register_to_manager = true);

  std::pair<ECM, ClientHandle>
  Connect(const std::string &nickname, const std::string &hostname,
          const std::string &username, ClientProtocol protocol, int64_t port,
          const std::string &password, const std::string &keyfile,
          std::shared_ptr<ClientMaintainer> maintainer = nullptr,
          bool quiet = false, TraceCallback trace_cb = {},
          amf interrupt_flag = nullptr);

  ECM RemoveClient(const std::string &nickname,
                   std::shared_ptr<ClientMaintainer> maintainer = nullptr);

  std::pair<ECM, ClientHandle>
  CheckClient(const std::string &nickname,
              const std::shared_ptr<ClientMaintainer> &maintainer = nullptr,
              bool update = false, amf interrupt_flag = nullptr,
              int timeout_ms = -1, int64_t start_time = -1);

  std::pair<ECM, ClientHandle> EnsureClient(const std::string &nickname,
                                            amf interrupt_flag = nullptr);

  void SetIsInteractiveFlag(
      const std::shared_ptr<std::atomic<bool>> &is_interactive);

  bool IsInteractive() const;

  std::shared_ptr<std::atomic<bool>> GetIsInteractiveFlag() const;

protected:
  ClientHandle current_client_;
  ClientHandle local_client_base_;
  std::shared_ptr<ClientMaintainer> clients_;
  std::shared_ptr<std::atomic<bool>> is_interactive_ =
      std::make_shared<std::atomic<bool>>(false);
  int heartbeat_timeout_ms_ = 100;
  bool heartbeat_timeout_overridden_ = false;
  KnownHostCallback known_host_cb_ = {};
  AuthCallback default_password_cb_ = {};
  DisconnectCallback default_disconnect_cb_ = {};
  AuthCallback password_cb_ = {};
  DisconnectCallback disconnect_cb_ = {};
  bool use_custom_password_cb_ = false;
  bool use_custom_disconnect_cb_ = false;
  mutable std::mutex auth_io_mtx_;
  std::atomic<bool> spinner_stop_requested_{false};
  std::atomic<size_t> spinner_line_len_{0};

  AuthCallback BuildAuthCallback_(const AuthCallback &auth_cb, bool quiet,
                                  std::atomic<bool> *spinner_running);
  void ApplyKnownHostCallback_(const ClientHandle &client);
  ECM DefaultKnownHostCallback(const KnownHostQuery &query);
  std::optional<std::string> DefaultPasswordCallback(const AuthCBInfo &info);
  void DefaultDisconnectCallback(const ClientHandle &client, const ECM &ecm);
  ClientHandle CreateLocalClient_();
};

class AMClientPathOps : public AMClientOperator {
public:
  std::tuple<std::string, std::string, ClientHandle, ECM>
  ParsePath(const std::string &input);

  std::tuple<std::string, std::string, ClientHandle, ECM>
  ParsePath(const std::string &input, amf interrupt_flag);

  [[nodiscard]] std::string AbsPath(const std::string &path,
                                    const ClientHandle &client = nullptr) const;

  [[nodiscard]] std::string GetOrInitWorkdir(const ClientHandle &client) const;

  void SetClientWorkdir(const ClientHandle &client,
                        const std::string &path) const;

  [[nodiscard]] std::string BuildPath(const ClientHandle &client,
                                      const std::string &path) const;

  void InitClientWorkdir(const ClientHandle &client) const;

  void ApplyLoginDir(const std::string &nickname, const ClientHandle &client,
                     const std::string &login_dir, amf flag) const;
};

class AMClientManager : public AMClientPathOps, private NonCopyableNonMovable {
public:
  explicit AMClientManager() = default;

  ECM Init() override;

  static AMClientManager &Instance() {
    static AMClientManager instance;
    return instance;
  }
};
} // namespace AMDomain::client
