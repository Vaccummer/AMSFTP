#pragma once
#include "AMBase/Path.hpp"
#include "AMClient/Base.hpp"
#include "AMClient/IOCore.hpp"
#include "AMManager/Logger.hpp"
#include "AMManager/Prompt.hpp"
#include "AMManager/SignalMonitor.hpp"
#include <atomic>
#include <memory>
#include <optional>
#include <tuple>
#include <utility>

#ifdef _WIN32
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

inline std::atomic<bool> AMIsInteractive = false;

namespace AMClientManage {

class Reader {
public:
  explicit Reader(AMConfigManager &config);

  [[nodiscard]] std::pair<ECM, AMConfigManager::ClientConfig>
  GetClientConfig(const std::string &nickname);

  [[nodiscard]] std::pair<ECM, std::optional<AMConfigManager::KnownHostEntry>>
  FindKnownHost(const std::string &hostname, int port,
                const std::string &protocol) const;

  [[nodiscard]] AMConfigManager::KnownHostCallback BuildKnownHostCallback();

  [[nodiscard]] ECM
  UpsertKnownHost(const AMConfigManager::KnownHostEntry &entry,
                  bool dump_now = true);

protected:
  AMConfigManager &config_;
  AMConfigManager::KnownHostCallback known_host_cb_ = {};
};

class Operator : public Reader {
public:
  using DisconnectCallback =
      std::function<void(const std::shared_ptr<BaseClient> &, const ECM &)>;

  void SetPasswordCallback(AuthCallback cb = {});
  void SetDisconnectCallback(DisconnectCallback cb = {});
  ClientMaintainer &Clients();
  [[nodiscard]] std::vector<std::string> GetClientNames();
  [[nodiscard]] std::vector<std::shared_ptr<BaseClient>> GetClients();
  [[nodiscard]] std::shared_ptr<AMLocalClient> LocalClient() const;
  [[nodiscard]] std::shared_ptr<BaseClient> LocalClientBase() const;
  [[nodiscard]] std::shared_ptr<BaseClient> CurrentClient() const;
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

protected:
  std::shared_ptr<BaseClient> current_client_;
  std::shared_ptr<BaseClient> local_client_base_;
  std::shared_ptr<ClientMaintainer> clients_;
  ssize_t trace_num_ = 10;
  std::atomic<bool> spinner_stop_requested_{false};
  std::atomic<size_t> spinner_line_len_{0};
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
                     const std::string &login_dir, const amf &flag) const;
};

class Manager : public PathOps, private NonCopyableNonMovable {
public:
  using ClientMaintainerRef = ClientMaintainer;
  using ClientMaintainerPtr = std::shared_ptr<ClientMaintainer>;
  using PasswordCallback = AuthCallback;
  using DisconnectCallback =
      std::function<void(const std::shared_ptr<BaseClient> &, const ECM &)>;
  inline static amf global_interrupt_flag = amgif;

  static Manager &Instance(AMConfigManager &cfg);

  explicit Manager(AMConfigManager &cfg);

private:
  friend class Operator;
  friend class PathOps;

  AMLogManager &log_manager_;
  AMPromptManager &prompt_ = AMPromptManager::Instance();
  std::shared_ptr<AMLocalClient> local_client_;
  PasswordCallback password_cb_ = {};
  DisconnectCallback disconnect_cb_ = {};
  std::mutex auth_io_mtx_;

  AuthCallback BuildAuthCallback_(const AuthCallback &auth_cb, bool quiet,
                                  std::atomic<bool> *spinner_running);

  void ApplyKnownHostCallback_(const std::shared_ptr<BaseClient> &client);

  void ResetSpinnerStop_();
  void RequestSpinnerStop_();

  std::shared_ptr<AMLocalClient> CreateLocalClient_(AMConfigManager &cfg,
                                                    AMLogManager &log_manager);

  void OnDisconnect(const std::shared_ptr<BaseClient> &client, const ECM &ecm);

  std::optional<std::string> DefaultPasswordCallback(const AuthCBInfo &info);
  void DefaultDisconnectCallback(const std::shared_ptr<BaseClient> &client,
                                 const ECM &ecm);

  PasswordCallback BuiltinPasswordCallback_();
  DisconnectCallback BuiltinDisconnectCallback_();
};

} // namespace AMClientManage

using AMClientManager = AMClientManage::Manager;
