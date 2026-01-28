#pragma once
#include "AMClient/AMCore.hpp"
#include "AMConfigManager.hpp"
#include "AMLogManager.hpp"
#include <iostream>
#include <optional>
#include <utility>
#include <variant>
#ifdef _WIN32
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

class AMClientManager {
public:
  enum class PoolKind { Transfer, Operation };
  using ClientMaintainerRef = ClientMaintainer;
  using PasswordCallback = AuthCallback;
  using DisconnectCallback = std::function<void(
      PoolKind, const std::shared_ptr<BaseClient> &, const ECM &)>;
  /** Global interrupt flag used when no flag is provided. */
  inline static amf global_interrupt_flag = std::make_shared<InterruptFlag>();

  /** Return the singleton instance (requires a valid config manager). */
  static AMClientManager &Instance(AMConfigManager &cfg) {
    static AMClientManager instance(cfg);
    return instance;
  }

  /** Disable copy construction. */
  AMClientManager(const AMClientManager &) = delete;
  /** Disable copy assignment. */
  AMClientManager &operator=(const AMClientManager &) = delete;
  /** Disable move construction. */
  AMClientManager(AMClientManager &&) = delete;
  /** Disable move assignment. */
  AMClientManager &operator=(AMClientManager &&) = delete;

  /** Initialize client manager with heartbeat interval from config. */
  explicit AMClientManager(AMConfigManager &cfg)
      : config_(cfg), log_manager_(AMLogManager::Instance(cfg)),
        local_client_(CreateLocalClient_(cfg, log_manager_)),
        transfer_clients_(
            ResolveHeartbeatInterval(cfg),
            [this](const auto &client, const ECM &ecm) {
              OnDisconnect(PoolKind::Transfer, client, ecm);
            },
            local_client_),
        op_clients_(
            ResolveHeartbeatInterval(cfg),
            [this](const auto &client, const ECM &ecm) {
              OnDisconnect(PoolKind::Operation, client, ecm);
            },
            local_client_) {
    trace_num_ = ResolveTraceNum(cfg);
    if (!password_cb_) {
      password_cb_ = [this](const AuthCBInfo &info) {
        return DefaultPasswordCallback(info);
      };
    }
    LOCAL = transfer_clients_.GetHost("");
    CLIENT = LOCAL;
    InitClientWorkdir(LOCAL);
  }

  /** Current active client (public, managed by callers). */
  std::shared_ptr<BaseClient> CLIENT;
  /** Local client instance (public). */
  std::shared_ptr<BaseClient> LOCAL;

  /** Return the shared local client instance. */
  [[nodiscard]] std::shared_ptr<AMLocalClient> LocalClient() const {
    return local_client_;
  }

  /** Set password callback for new clients. */
  void SetPasswordCallback(PasswordCallback cb = {}) {
    password_cb_ = std::move(cb);
  }

  /** Set disconnect callback for both pools. */
  void SetDisconnectCallback(DisconnectCallback cb = {}) {
    disconnect_cb_ = std::move(cb);
  }

  /** Access transfer client pool. */
  ClientMaintainerRef &TransferClients() { return transfer_clients_; }
  /** Access operation client pool. */
  ClientMaintainerRef &OperationClients() { return op_clients_; }

  /** Return client nicknames for a pool. */
  std::vector<std::string> GetClientNames(PoolKind pool) {
    return ClientPool(pool).get_nicknames();
  }

  /** Return typed client list for a pool. */
  std::vector<AMCilent> GetClients(PoolKind pool) {
    return ClientPool(pool).get_clients();
  }

  /**
   * @brief Create a client instance without adding it to a pool.
   *
   * This binds the Python tracer to the global log manager callback and
   * binds the authentication callback to the manager's auth callback.
   */
  std::pair<ECM, std::shared_ptr<BaseClient>>
  CreClient(const std::string &nickname, amf interrupt_flag = nullptr) {
    (void)interrupt_flag;
    if (nickname.empty() || nickname == "local") {
      return {ECM{EC::Success, ""}, local_client_};
    }

    auto client_config = config_.GetClientConfig(nickname);
    if (client_config.first.second != 0) {
      EC ec = static_cast<EC>(client_config.first.second);
      return {ECM{ec, client_config.first.first}, nullptr};
    }

    auto keys_result = config_.PrivateKeys(false);
    if (keys_result.first.second != 0) {
      EC ec = static_cast<EC>(keys_result.first.second);
      return {ECM{ec, keys_result.first.first}, nullptr};
    }

    auto trace_cb = log_manager_.TraceCallbackFunc();
    auto base_client = CreateClient(
        client_config.second.request, client_config.second.protocol, trace_num_,
        std::move(trace_cb), client_config.second.buffer_size,
        keys_result.second, password_cb_);
    if (!base_client) {
      return {ECM{EC::OperationUnsupported, "Unsupported protocol"}, nullptr};
    }

    // Ensure Python tracer is bound to the logger callback.
    base_client->SetPyTrace(log_manager_.TraceCallbackFunc());
    InitClientWorkdir(base_client);
    return {ECM{EC::Success, ""}, base_client};
  }

  /** Create or reuse a client and connect it immediately. */
  std::pair<ECM, std::shared_ptr<BaseClient>>
  AddClient(const std::string &nickname, PoolKind pool, bool force = false,
            TraceCallback trace_cb = {}, amf interrupt_flag = nullptr) {
    amf flag = interrupt_flag ? interrupt_flag : global_interrupt_flag;
    if (!trace_cb) {
      trace_cb = log_manager_.TraceCallbackFunc();
    }
    if (nickname.empty() || nickname == "local") {
      return {ECM{EC::Success, ""}, ClientPool(pool).GetHost("")};
    }

    auto existing = ClientPool(pool).GetHost(nickname);
    if (existing) {
      ECM rcm = existing->Connect(force, flag);
      if (rcm.first != EC::Success) {
        return {rcm, existing};
      }
      InitClientWorkdir(existing);
      return {ECM{EC::Success, ""}, existing};
    }

    auto client_config = config_.GetClientConfig(nickname);
    if (client_config.first.second != 0) {
      EC ec = static_cast<EC>(client_config.first.second);
      return {ECM{ec, client_config.first.first}, nullptr};
    }

    auto keys_result = config_.PrivateKeys(false);
    if (keys_result.first.second != 0) {
      EC ec = static_cast<EC>(keys_result.first.second);
      return {ECM{ec, keys_result.first.first}, nullptr};
    }

    auto base_client = CreateClient(
        client_config.second.request, client_config.second.protocol, trace_num_,
        std::move(trace_cb), client_config.second.buffer_size,
        keys_result.second, password_cb_);
    if (!base_client) {
      return {ECM{EC::OperationUnsupported, "Unsupported protocol"}, nullptr};
    }

    ECM rcm = base_client->Connect(force, flag);
    if (rcm.first != EC::Success) {
      return {rcm, base_client};
    }
    InitClientWorkdir(base_client);
    ClientPool(pool).add_client(nickname, base_client, true);
    return {ECM{EC::Success, ""}, base_client};
  }

  /** Remove a client from the pool without editing config. */
  ECM RemoveClient(const std::string &nickname, PoolKind pool) {
    if (nickname.empty() || nickname == "local") {
      return {EC::InvalidArg, "Local client cannot be removed"};
    }
    auto existing = ClientPool(pool).GetHost(nickname);
    if (!existing) {
      return {EC::ClientNotFound, "Client not found"};
    }
    ClientPool(pool).remove_client(nickname);
    return {EC::Success, ""};
  }

  /** Check client status; optionally force update. */
  std::pair<ECM, std::shared_ptr<BaseClient>>
  CheckClient(const std::string &nickname, PoolKind pool, bool update = false,
              amf interrupt_flag = nullptr, int timeout_ms = -1,
              int64_t start_time = -1) {
    amf flag = interrupt_flag ? interrupt_flag : global_interrupt_flag;
    auto result = ClientPool(pool).test_client(nickname, update, flag,
                                               timeout_ms, start_time);
    return result;
  }

private:
  AMConfigManager &config_;
  AMLogManager &log_manager_;
  std::shared_ptr<AMLocalClient> local_client_;
  ClientMaintainerRef transfer_clients_;
  ClientMaintainerRef op_clients_;
  PasswordCallback password_cb_ = {};
  DisconnectCallback disconnect_cb_ = {};
  std::mutex auth_io_mtx_;
  ssize_t trace_num_ = 10;

  /** Read heartbeat interval from settings; fallback to 60 seconds. */
  static int ResolveHeartbeatInterval(AMConfigManager &cfg) {
    int value =
        cfg.GetSettingInt({"client_manager", "heartbeat_interval_s"}, 60);
    if (value <= 0) {
      value = cfg.GetSettingInt({"ClientManager", "heartbeat_interval_s"}, 60);
    }
    return value > 0 ? value : 60;
  }

  /** Read trace buffer size from settings; default 10 and minimum 5. */
  static ssize_t ResolveTraceNum(AMConfigManager &cfg) {
    int value = cfg.GetSettingInt({"client_manager", "trace_num"}, 10);
    if (value <= 0) {
      value = cfg.GetSettingInt({"ClientManager", "trace_num"}, 10);
    }
    if (value < 5) {
      value = 5;
    }
    return static_cast<ssize_t>(value);
  }

  /**
   * @brief Create the shared local client using config settings.
   */
  static std::shared_ptr<AMLocalClient>
  CreateLocalClient_(AMConfigManager &cfg, AMLogManager &log_manager) {
    auto trace_cb = log_manager.TraceCallbackFunc();
    auto client =
        std::make_shared<AMLocalClient>(ConRequst("local", "", ""), 10,
                                        std::move(trace_cb));

    std::string work_dir = cfg.GetSettingString({"LocalClient", "work_dir"}, "");
    if (!work_dir.empty()) {
      client->home_dir = AMPathStr::UnifyPathSep(work_dir, "/");
      std::lock_guard<std::recursive_mutex> lock(client->public_kv_mtx);
      client->public_kv["workdir"] = client->home_dir;
    }

    std::string trash_dir =
        cfg.GetSettingString({"LocalClient", "trash_dir"}, "");
    if (!trash_dir.empty()) {
      auto result = client->TrashDir(trash_dir);
      if (std::holds_alternative<ECM>(result)) {
        const auto &ecm = std::get<ECM>(result);
        if (ecm.first != EC::Success) {
          AM_PROMPT_ERROR("LocalClient", ecm.second, false, 0);
        }
      }
    }

    int buffer_size = cfg.GetSettingInt({"LocalClient", "buffer_size"}, -1);
    if (buffer_size > 0) {
      client->TransferRingBufferSize(buffer_size);
    }

    return client;
  }

  /** Select pool by kind. */
  ClientMaintainerRef &ClientPool(PoolKind pool) {
    return pool == PoolKind::Transfer ? transfer_clients_ : op_clients_;
  }

  /** Initialize client workdir in public map if missing. */
  void InitClientWorkdir(const std::shared_ptr<BaseClient> &client) {
    if (!client) {
      return;
    }
    std::lock_guard<std::recursive_mutex> lock(client->public_kv_mtx);
    if (client->public_kv.find("workdir") == client->public_kv.end()) {
      client->public_kv["workdir"] =
          AMPathStr::UnifyPathSep(client->GetHomeDir(), "/");
    }
  }

  /** Forward disconnect notifications with pool kind. */
  void OnDisconnect(PoolKind pool, const std::shared_ptr<BaseClient> &client,
                    const ECM &ecm) {
    if (disconnect_cb_) {
      CallCallbackSafe(disconnect_cb_, pool, client, ecm);
    }
  }

  /**
   * @brief Read a password from the console with masked input.
   */
  static std::string ReadMaskedPassword(const std::string &prompt) {
    std::string password;
    std::cout << prompt << std::flush;
#ifdef _WIN32
    while (true) {
      int ch = _getch();
      if (ch == '\r' || ch == '\n') {
        break;
      }
      if (ch == '\b') {
        if (!password.empty()) {
          password.pop_back();
          std::cout << "\b \b" << std::flush;
        }
        continue;
      }
      if (ch == 0 || ch == 224) {
        (void)_getch();
        continue;
      }
      password.push_back(static_cast<char>(ch));
      std::cout << "•" << std::flush;
    }
#else
    termios oldt{};
    termios newt{};
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= static_cast<unsigned long>(~(ECHO | ICANON));
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    while (true) {
      int ch = ::getchar();
      if (ch == '\n' || ch == '\r' || ch == EOF) {
        break;
      }
      if (ch == 127 || ch == 8) {
        if (!password.empty()) {
          password.pop_back();
          std::cout << "\b \b" << std::flush;
        }
        continue;
      }
      password.push_back(static_cast<char>(ch));
      std::cout << "•" << std::flush;
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif
    std::cout << std::endl;
    return password;
  }

  /**
   * @brief Default password callback with thread-safe, privacy-aware IO.
   */
  std::optional<std::string> DefaultPasswordCallback(const AuthCBInfo &info) {
    std::lock_guard<std::mutex> lock(auth_io_mtx_);

    const std::string client_name =
        info.request.nickname.empty() ? "unknown" : info.request.nickname;

    if (info.NeedPassword) {
      const std::string prompt =
          AMStr::amfmt("❔ [{}] Require Password: ", client_name);
      return ReadMaskedPassword(prompt);
    }

    if (!info.iscorrect) {
      if (info.password_n.empty()) {
        return std::nullopt;
      }
      AMPromptManager::Instance().Print(
          AMStr::amfmt("❌ [{}] Wrong Password!", client_name));
      return std::nullopt;
    }

    AMPromptManager::Instance().Print(AMStr::amfmt(
        "✅ [{}] Password authorization successful!", client_name));
    (void)config_.SetClientPasswordEncrypted(client_name, info.password_n,
                                             true);
    return std::nullopt;
  }
};
