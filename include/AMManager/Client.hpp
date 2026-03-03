#pragma once
#include "AMBase/DataClass.hpp"
#include "AMBase/Path.hpp"
#include "AMClient/Base.hpp"
#include "AMClient/IOCore.hpp"
#include "AMManager/Config.hpp"
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

namespace AMClientManage {
/**
 * @brief Resolve heartbeat check timeout from settings with clamped range.
 */
inline int ResolveHeartbeatTimeoutMsFromSettings() {
  auto clamp_timeout = [](int value) {
    if (value < 10) {
      return 10;
    }
    if (value > 10000) {
      return 10000;
    }
    return value;
  };
  return AMConfigManager::Instance().ResolveArg(
      DocumentKind::Settings, {"Options", "ClientManager", "heartbeat_timeout_ms"},
      100, clamp_timeout);
}

class Operator {
public:
  using DisconnectCallback =
      std::function<void(const std::shared_ptr<BaseClient> &, const ECM &)>;

  void SetPasswordCallback(AuthCallback cb = {});
  void SetDisconnectCallback(DisconnectCallback cb = {});
  ClientMaintainer &Clients();
  [[nodiscard]] std::vector<std::string> GetClientNames();
  [[nodiscard]] std::vector<std::shared_ptr<BaseClient>> GetClients();
  /**
   * @brief Return one managed client by nickname.
   *
   * Empty/"local" resolves to local client.
   */
  [[nodiscard]] std::shared_ptr<BaseClient>
  GetClient(const std::string &nickname) const;
  [[nodiscard]] std::shared_ptr<BaseClient> LocalClient() const;
  [[nodiscard]] std::shared_ptr<BaseClient> CurrentClient() const;
  [[nodiscard]] std::string CurrentNickname() const;
  void SetCurrentClient(const std::shared_ptr<BaseClient> &client);
  void ConfigureState(const std::shared_ptr<ClientMaintainer> &clients,
                      const std::shared_ptr<BaseClient> &local_client_base,
                      ssize_t trace_num);
  void ResetSpinnerState();
  void SetSpinnerLineLen(size_t line_len);
  [[nodiscard]] bool SpinnerStopRequested() const;
  void RequestSpinnerStop();

  std::pair<ECM, std::shared_ptr<BaseClient>>
  AddClient(const std::string &nickname,
            std::shared_ptr<ClientMaintainer> maintainer = nullptr,
            bool force = false, bool quiet = false, TraceCallback trace_cb = {},
            amf interrupt_flag = nullptr);

  std::pair<ECM, std::shared_ptr<BaseClient>>
  AddClient(const std::string &nickname, bool force, bool quiet,
            TraceCallback trace_cb = {}, amf interrupt_flag = nullptr,
            bool register_to_manager = true);

  std::pair<ECM, std::shared_ptr<BaseClient>>
  Connect(const std::string &nickname, const std::string &hostname,
          const std::string &username, ClientProtocol protocol, int64_t port,
          const std::string &password, const std::string &keyfile,
          std::shared_ptr<ClientMaintainer> maintainer = nullptr,
          bool quiet = false, TraceCallback trace_cb = {},
          amf interrupt_flag = nullptr);

  ECM RemoveClient(const std::string &nickname,
                   std::shared_ptr<ClientMaintainer> maintainer = nullptr);

  std::pair<ECM, std::shared_ptr<BaseClient>>
  CheckClient(const std::string &nickname,
              const std::shared_ptr<ClientMaintainer> &maintainer = nullptr,
              bool update = false, amf interrupt_flag = nullptr,
              int timeout_ms = -1, int64_t start_time = -1);

  std::pair<ECM, std::shared_ptr<BaseClient>>
  EnsureClient(const std::string &nickname, amf interrupt_flag = nullptr);

  void SetIsInteractiveFlag(
      const std::shared_ptr<std::atomic<bool>> &is_interactive);

  bool IsInteractive() const;

  std::shared_ptr<std::atomic<bool>> GetIsInteractiveFlag() const;

protected:
  std::shared_ptr<BaseClient> current_client_;
  std::shared_ptr<BaseClient> local_client_base_;
  std::shared_ptr<ClientMaintainer> clients_;
  std::shared_ptr<std::atomic<bool>> is_interactive_ =
      std::make_shared<std::atomic<bool>>(false);
  AuthCallback password_cb_ = {};
  DisconnectCallback disconnect_cb_ = {};
  mutable std::mutex auth_io_mtx_;
  std::atomic<bool> spinner_stop_requested_{false};
  std::atomic<size_t> spinner_line_len_{0};

  AuthCallback BuildAuthCallback_(const AuthCallback &auth_cb, bool quiet,
                                  std::atomic<bool> *spinner_running);
  void ApplyKnownHostCallback_(const std::shared_ptr<BaseClient> &client);
  std::optional<std::string> DefaultPasswordCallback(const AuthCBInfo &info);
  void DefaultDisconnectCallback(const std::shared_ptr<BaseClient> &client,
                                 const ECM &ecm);
  AuthCallback BuiltinPasswordCallback_();
  DisconnectCallback BuiltinDisconnectCallback_();
  std::shared_ptr<BaseClient> CreateLocalClient_();
};

class PathOps : public Operator {
public:
  std::tuple<std::string, std::string, std::shared_ptr<BaseClient>, ECM>
  ParsePath(const std::string &input);

  std::tuple<std::string, std::string, std::shared_ptr<BaseClient>, ECM>
  ParsePath(const std::string &input, amf interrupt_flag);

  [[nodiscard]] std::string
  AbsPath(const std::string &path,
          const std::shared_ptr<BaseClient> &client = nullptr) const;

  [[nodiscard]] std::string
  GetOrInitWorkdir(const std::shared_ptr<BaseClient> &client) const;

  void SetClientWorkdir(const std::shared_ptr<BaseClient> &client,
                        const std::string &path) const;

  [[nodiscard]] std::string BuildPath(const std::shared_ptr<BaseClient> &client,
                                      const std::string &path) const;

  void InitClientWorkdir(const std::shared_ptr<BaseClient> &client) const;

  void ApplyLoginDir(const std::string &nickname,
                     const std::shared_ptr<BaseClient> &client,
                     const std::string &login_dir, amf flag) const;
};

class Manager : public PathOps, private NonCopyableNonMovable {
public:
  explicit Manager() = default;

  ECM Init() override {
    SetPasswordCallback();
    SetDisconnectCallback();
    local_client_base_ = CreateLocalClient_();
    if (!local_client_base_) {
      return Err(EC::ProgrammInitializeFailed, "Failed to create local client");
    }
    const int heartbeat_timeout_ms = ResolveHeartbeatTimeoutMsFromSettings();
    clients_ = std::make_shared<ClientMaintainer>(
        60, heartbeat_timeout_ms, disconnect_cb_, local_client_base_);
    clients_->disconnect_cb = disconnect_cb_;
    clients_->is_disconnect_cb = static_cast<bool>(disconnect_cb_);
    current_client_ = local_client_base_;
    return Ok();
  }

  static Manager &Instance() {
    static Manager instance;
    return instance;
  }
};

} // namespace AMClientManage

using AMClientManager = AMClientManage::Manager;
