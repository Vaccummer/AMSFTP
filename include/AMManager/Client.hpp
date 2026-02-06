#pragma once
#include "AMBase/CommonTools.hpp"
#include "AMBase/Path.hpp"
#include "AMClient/IOCore.hpp"
#include "AMManager/Config.hpp"
#include "AMManager/Logger.hpp"
#include "AMManager/Prompt.hpp"
#include <atomic>
#include <chrono>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <thread>
#include <tuple>
#include <utility>
#include <variant>

#ifdef _WIN32
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

inline std::atomic<bool> AMIsInteractive = false;

class AMClientManager {
public:
  using ClientMaintainerRef = ClientMaintainer;
  using ClientMaintainerPtr = std::shared_ptr<ClientMaintainer>;
  using PasswordCallback = AuthCallback;
  using DisconnectCallback =
      std::function<void(const std::shared_ptr<BaseClient> &, const ECM &)>;
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
      : config_(cfg), log_manager_(AMLogManager::Instance(cfg)) {
    trace_num_ = ResolveTraceNum(cfg);
    if (!password_cb_) {
      password_cb_ = [this](const AuthCBInfo &info) {
        return DefaultPasswordCallback(info);
      };
    }
    local_client_ = CreateLocalClient_(cfg, log_manager_);
    clients_ = std::make_shared<ClientMaintainer>(
        ResolveHeartbeatInterval(cfg),
        [this](const auto &client, const ECM &ecm) {
          OnDisconnect(client, ecm);
        },
        local_client_);
    LOCAL = clients_->GetHost("");
    CLIENT = LOCAL;
    auto local_cfg = config_.GetClientConfig("local");
    if (local_cfg.first.first == EC::Success) {
      ApplyLoginDir_("local", LOCAL, local_cfg.second.login_dir,
                     global_interrupt_flag);
    } else {
      InitClientWorkdir(LOCAL);
    }
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

  /** Set disconnect callback for the client maintainer. */
  void SetDisconnectCallback(DisconnectCallback cb = {}) {
    disconnect_cb_ = std::move(cb);
  }

  /** Access the default client maintainer. */
  ClientMaintainerRef &Clients() { return *clients_; }

  /** Return client nicknames. */
  std::vector<std::string> GetClientNames() {
    return clients_ ? clients_->get_nicknames() : std::vector<std::string>{};
  }

  /** Return typed client list. */
  std::vector<AMCilent> GetClients() {
    return clients_ ? clients_->get_clients() : std::vector<AMCilent>{};
  }

  /** Create or reuse a client and connect it immediately. */
  std::pair<ECM, std::shared_ptr<BaseClient>>
  AddClient(const std::string &nickname,
            ClientMaintainerPtr maintainer = nullptr, bool force = false,
            bool quiet = false, TraceCallback trace_cb = {},
            amf interrupt_flag = nullptr) {
    amf flag = interrupt_flag ? interrupt_flag : global_interrupt_flag;
    ClientMaintainerRef &target = maintainer ? *maintainer : *clients_;

    if (!trace_cb) {
      trace_cb = log_manager_.TraceCallbackFunc();
    }
    if (nickname.empty() || nickname == "local") {
      return {ECM{EC::Success, ""}, target.GetHost("")};
    }

    auto existing = target.GetHost(nickname);
    if (existing) {
      ApplyKnownHostCallback_(existing);
      ECM rcm = existing->Connect(force, flag);
      if (rcm.first != EC::Success) {
        return {rcm, existing};
      }
      auto existing_cfg = config_.GetClientConfig(nickname);
      if (existing_cfg.first.first == EC::Success) {
        ApplyLoginDir_(nickname, existing, existing_cfg.second.login_dir, flag);
      } else {
        InitClientWorkdir(existing);
      }
      return {ECM{EC::Success, ""}, existing};
    }

    auto client_config = config_.GetClientConfig(nickname);
    // print(AMStr::amfmt("hostname: {}",
    // client_config.second.request.hostname)); print(AMStr::amfmt("username:
    // {}", client_config.second.request.username)); print(AMStr::amfmt("port:
    // {}", client_config.second.request.port)); print(AMStr::amfmt("password:
    // {}", client_config.second.request.password));
    if (client_config.first.first != EC::Success) {
      return {client_config.first, nullptr};
    }

    auto keys_result = config_.PrivateKeys(false);
    if (keys_result.first.first != EC::Success) {
      return {keys_result.first, nullptr};
    }

    std::atomic<bool> spinner_running(false);
    ResetSpinnerStop_();
    auto auth_cb = BuildAuthCallback_(password_cb_, quiet, &spinner_running);
    auto base_client = CreateClient(
        client_config.second.request, client_config.second.protocol, trace_num_,
        std::move(trace_cb), client_config.second.buffer_size,
        keys_result.second, std::move(auth_cb));
    if (!base_client) {
      return {ECM{EC::OperationUnsupported, "Unsupported protocol"}, nullptr};
    }
    ApplyKnownHostCallback_(base_client);

    std::thread spinner_thread;
    std::string spinner_line;
    size_t spinner_line_len = 0;
    if (!quiet) {
      const std::string protocol_label =
          AM_ENUM_NAME(base_client->GetProtocol());
      spinner_line = AMStr::amfmt("Connecting to {} Server   [{}]",
                                  protocol_label, nickname);
      spinner_line_len = spinner_line.size() + 3;
      spinner_line_len_.store(spinner_line_len);
      spinner_running.store(true);
      spinner_thread = std::thread([&spinner_running, spinner_line, this]() {
        const std::vector<std::string> frames = {"▖", "▘", "▝", "▗"};
        size_t idx = 0;
        while (spinner_running.load() && !spinner_stop_requested_.load()) {
          std::string indicator = frames[idx % frames.size()];
          std::cout << '\r' << indicator << "  " << spinner_line << std::flush;
          idx++;
          std::this_thread::sleep_for(std::chrono::milliseconds(120));
        }
      });
    }

    ECM rcm = base_client->Connect(force, flag);
    spinner_running.store(false);
    if (spinner_thread.joinable()) {
      spinner_thread.join();
      if (spinner_line_len > 0) {
        std::cout << '\r' << std::string(spinner_line_len, ' ') << '\r'
                  << std::flush;
      }
    }
    if (rcm.first != EC::Success) {
      return {rcm, base_client};
    }
    ApplyLoginDir_(nickname, base_client, client_config.second.login_dir, flag);
    target.add_client(nickname, base_client, true);
    return {ECM{EC::Success, ""}, base_client};
  }

  /**
   * @brief Create a client and connect it without registering to maintainer.
   */
  std::pair<ECM, std::shared_ptr<BaseClient>>
  AddClient(const std::string &nickname, bool force, bool quiet,
            TraceCallback trace_cb = {}, amf interrupt_flag = nullptr,
            bool register_to_manager = true) {
    if (register_to_manager) {
      return AddClient(nickname, nullptr, force, quiet, std::move(trace_cb),
                       interrupt_flag);
    }

    amf flag = interrupt_flag ? interrupt_flag : global_interrupt_flag;
    if (nickname.empty() || nickname == "local") {
      return {ECM{EC::Success, ""}, LOCAL};
    }

    if (!trace_cb) {
      trace_cb = log_manager_.TraceCallbackFunc();
    }

    auto client_config = config_.GetClientConfig(nickname);
    if (client_config.first.first != EC::Success) {
      return {client_config.first, nullptr};
    }

    auto keys_result = config_.PrivateKeys(false);
    if (keys_result.first.first != EC::Success) {
      return {keys_result.first, nullptr};
    }

    std::atomic<bool> spinner_running(false);
    ResetSpinnerStop_();
    auto auth_cb = BuildAuthCallback_(password_cb_, quiet, &spinner_running);
    auto base_client = CreateClient(
        client_config.second.request, client_config.second.protocol, trace_num_,
        std::move(trace_cb), client_config.second.buffer_size,
        keys_result.second, std::move(auth_cb));
    if (!base_client) {
      return {ECM{EC::OperationUnsupported, "Unsupported protocol"}, nullptr};
    }

    ApplyKnownHostCallback_(base_client);

    std::thread spinner_thread;
    std::string spinner_line;
    size_t spinner_line_len = 0;
    if (!quiet) {
      const std::string protocol_label =
          ProtocolLabel_(base_client->GetProtocol());
      spinner_line = AMStr::amfmt("Connecting to {} Server   [{}]",
                                  protocol_label, nickname);
      spinner_line_len = spinner_line.size() + 3;
      spinner_line_len_.store(spinner_line_len);
      spinner_running.store(true);
      spinner_thread = std::thread([&spinner_running, spinner_line, this]() {
        const std::vector<std::string> frames = {"▖", "▘", "▝", "▗"};
        size_t idx = 0;
        while (spinner_running.load() && !spinner_stop_requested_.load()) {
          std::string indicator = frames[idx % frames.size()];
          std::cout << '\r' << indicator << "  " << spinner_line << std::flush;
          idx++;
          std::this_thread::sleep_for(std::chrono::milliseconds(120));
        }
      });
    }

    ECM rcm = base_client->Connect(force, flag);
    spinner_running.store(false);
    if (spinner_thread.joinable()) {
      spinner_thread.join();
      if (spinner_line_len > 0) {
        std::cout << '\r' << std::string(spinner_line_len, ' ') << '\r'
                  << std::flush;
      }
    }
    if (rcm.first != EC::Success) {
      return {rcm, base_client};
    }
    ApplyLoginDir_(nickname, base_client, client_config.second.login_dir, flag);
    return {ECM{EC::Success, ""}, base_client};
  }

  /**
   * @brief Connect to an unknown host, validate nickname, and persist on
   * success.
   */
  std::pair<ECM, std::shared_ptr<BaseClient>>
  Connect(const std::string &nickname, const std::string &hostname,
          const std::string &username, ClientProtocol protocol, int64_t port,
          const std::string &password, const std::string &keyfile,
          ClientMaintainerPtr maintainer = nullptr, bool quiet = false,
          TraceCallback trace_cb = {}, amf interrupt_flag = nullptr) {
    amf flag = interrupt_flag ? interrupt_flag : global_interrupt_flag;
    ClientMaintainerRef &target = maintainer ? *maintainer : *clients_;

    if (protocol == ClientProtocol::LOCAL ||
        protocol == ClientProtocol::Unknown) {
      return {ECM{EC::InvalidArg, "Unsupported protocol for remote connect"},
              nullptr};
    }

    AMPromptManager &prompt = AMPromptManager::Instance();
    std::string resolved_nickname = nickname;
    std::string error;
    bool canceled = false;
    while (true) {
      error.clear();
      if (resolved_nickname == "local") {
        error = "Nickname cannot be 'local'.";
      }
      if (error.empty() &&
          config_.ValidateNickname(resolved_nickname, &error)) {
        break;
      }
      if (!error.empty()) {
        prompt.Print(AMStr::amfmt("Invalid nickname: {}", error));
      }
      const bool ok =
          prompt.PromptLine("Enter a legal nickname: ", &resolved_nickname, "",
                            false, &canceled, false);
      if (!ok && canceled) {
        return {ECM{EC::ConfigCanceled, "Nickname input canceled"}, nullptr};
      }
      if (!ok) {
        continue;
      }
    }

    std::vector<std::string> keys;
    if (keyfile.empty()) {
      auto keys_result = config_.PrivateKeys(false);
      if (keys_result.first.first != EC::Success) {
        return {keys_result.first, nullptr};
      }
      keys = std::move(keys_result.second);
    } else {
      keys.push_back(keyfile);
    }

    const std::string password_enc = AMAuth::EncryptPassword(password);
    ConRequst request(resolved_nickname, hostname, username,
                      static_cast<int>(port), password_enc, keyfile, false, "");
    if (!trace_cb) {
      trace_cb = log_manager_.TraceCallbackFunc();
    }
    auto auth_cb = BuildAuthCallback_(password_cb_, quiet, nullptr);
    auto base_client =
        CreateClient(request, protocol, trace_num_, std::move(trace_cb), -1,
                     std::move(keys), std::move(auth_cb));
    if (!base_client) {
      return {ECM{EC::OperationUnsupported, "Unsupported protocol"}, nullptr};
    }

    ApplyKnownHostCallback_(base_client);

    ECM rcm = base_client->Connect(false, flag);
    if (rcm.first != EC::Success) {
      return {rcm, base_client};
    }

    ECM save_rcm =
        config_.SetHostField(resolved_nickname, "hostname", hostname, false);
    if (save_rcm.first != EC::Success) {
      return {save_rcm, base_client};
    }
    save_rcm =
        config_.SetHostField(resolved_nickname, "username", username, false);
    if (save_rcm.first != EC::Success) {
      return {save_rcm, base_client};
    }
    save_rcm = config_.SetHostField(resolved_nickname, "port", port, false);
    if (save_rcm.first != EC::Success) {
      return {save_rcm, base_client};
    }
    save_rcm =
        config_.SetHostField(resolved_nickname, "keyfile", keyfile, false);
    if (save_rcm.first != EC::Success) {
      return {save_rcm, base_client};
    }
    save_rcm = config_.SetHostField(resolved_nickname, "protocol",
                                    ProtocolConfigValue_(protocol), false);
    if (save_rcm.first != EC::Success) {
      return {save_rcm, base_client};
    }
    save_rcm = config_.SetHostField(resolved_nickname, "buffer_size",
                                    int64_t(-1), false);
    if (save_rcm.first != EC::Success) {
      return {save_rcm, base_client};
    }
    save_rcm = config_.SetClientPasswordEncrypted(resolved_nickname,
                                                  password_enc, false);
    if (save_rcm.first != EC::Success) {
      return {save_rcm, base_client};
    }
    save_rcm = config_.SetHostField(resolved_nickname, "login_dir",
                                    std::string(""), true);
    if (save_rcm.first != EC::Success) {
      return {save_rcm, base_client};
    }

    ApplyLoginDir_(resolved_nickname, base_client, "", flag);
    target.add_client(resolved_nickname, base_client, true);
    return {ECM{EC::Success, ""}, base_client};
  }

  /** Remove a client from the pool without editing config. */
  ECM RemoveClient(const std::string &nickname,
                   ClientMaintainerPtr maintainer = nullptr) {
    if (nickname.empty() || nickname == "local") {
      return {EC::InvalidArg, "Local client cannot be removed"};
    }
    ClientMaintainerRef &target = maintainer ? *maintainer : *clients_;
    auto existing = target.GetHost(nickname);
    if (!existing) {
      return {EC::ClientNotFound, "Client not found"};
    }
    target.remove_client(nickname);
    return {EC::Success, ""};
  }

  /** Check client status; optionally force update. */
  std::pair<ECM, std::shared_ptr<BaseClient>>
  CheckClient(const std::string &nickname,
              const ClientMaintainerPtr &maintainer = nullptr,
              bool update = false, amf interrupt_flag = nullptr,
              int timeout_ms = -1, int64_t start_time = -1) {
    amf flag = interrupt_flag ? interrupt_flag : global_interrupt_flag;
    ClientMaintainerRef &target = maintainer ? *maintainer : *clients_;
    auto result =
        target.test_client(nickname, update, flag, timeout_ms, start_time);
    return result;
  }

  /**
   * @brief Parse an input in the form "nickname@path" into nickname and path.
   */
  static std::pair<std::string, std::string>
  ParseAddress(const std::string &input) {
    auto pos = input.find('@');
    if (pos == std::string::npos) {
      return {"", input};
    }
    return {input.substr(0, pos), input.substr(pos + 1)};
  }

  /**
   * @brief Parse input into nickname, path, client pointer, and status.
   */
  std::tuple<std::string, std::string, std::shared_ptr<BaseClient>, ECM>
  ParsePath(const std::string &input) {
    if (!input.empty() && input.front() == '@') {
      std::string path = input.substr(1);
      return {"local", path, LOCAL, ECM{EC::Success, ""}};
    }

    auto pos = input.find('@');
    if (pos == std::string::npos || pos + 1 >= input.size()) {
      std::shared_ptr<BaseClient> current = CLIENT ? CLIENT : LOCAL;
      std::string nickname = current ? current->GetNickname() : "local";
      return {nickname, input, current, ECM{EC::Success, ""}};
    }

    std::string prefix = input.substr(0, pos);
    std::string path = input.substr(pos + 1);
    std::string lowered = AMStr::lowercase(prefix);
    if (prefix.empty() || lowered == "local") {
      return {"local", path, LOCAL, ECM{EC::Success, ""}};
    }

    auto cfg = config_.GetClientConfig(prefix);
    if (cfg.first.first != EC::Success) {
      return {prefix, path, nullptr,
              ECM{EC::HostConfigNotFound, "Host config not found"}};
    }

    auto existing = Clients().GetHost(prefix);
    if (!existing) {
      return {prefix, path, nullptr,
              ECM{EC::ClientNotFound, "Client not found"}};
    }
    return {prefix, path, existing, ECM{EC::Success, ""}};
  }

  /**
   * @brief Parse input into nickname, path, client pointer, and status.
   */
  std::tuple<std::string, std::string, std::shared_ptr<BaseClient>, ECM>
  ParsePath(const std::string &input, amf interrupt_flag) {
    if (!input.empty() && input.front() == '@') {
      std::string path = input.substr(1);
      return {"local", path, LOCAL, ECM{EC::Success, ""}};
    }

    auto pos = input.find('@');
    if (pos == std::string::npos || pos + 1 >= input.size()) {
      std::shared_ptr<BaseClient> current = CLIENT ? CLIENT : LOCAL;
      std::string nickname = current ? current->GetNickname() : "local";
      return {nickname, input, current, ECM{EC::Success, ""}};
    }

    std::string prefix = input.substr(0, pos);
    std::string path = input.substr(pos + 1);
    std::string lowered = AMStr::lowercase(prefix);
    if (prefix.empty() || lowered == "local") {
      return {"local", path, LOCAL, ECM{EC::Success, ""}};
    }

    auto cfg = config_.GetClientConfig(prefix);
    if (cfg.first.first != EC::Success) {
      return {prefix, path, nullptr,
              ECM{EC::HostConfigNotFound, "Host config not found"}};
    }

    auto existing = Clients().GetHost(prefix);
    if (!existing) {
      if (AMIsInteractive.load()) {
        bool canceled = false;
        if (!AMPromptManager::Instance().PromptYesNo(
                "Client not found. Create it? (y/N): ", &canceled)) {
          return {prefix, path, nullptr,
                  ECM{EC::Terminate, "Operation aborted"}};
        }
      }
      auto created =
          AddClient(prefix, nullptr, false, false, {}, interrupt_flag);
      if (created.first.first != EC::Success) {
        return {prefix, path, created.second, created.first};
      }
      return {prefix, path, created.second, ECM{EC::Success, ""}};
    }
    return {prefix, path, existing, ECM{EC::Success, ""}};
  }

  /**
   * @brief Build an absolute path based on client home/workdir (or
   * passthrough).
   */
  [[nodiscard]] std::string
  AbsPath(const std::string &path,
          const std::shared_ptr<BaseClient> &client = nullptr) const {
    if (!client) {
      return path;
    }
    if (path.empty()) {
      return GetOrInitWorkdir(client);
    }
    std::string cwd = GetOrInitWorkdir(client);
    std::string home = client->GetHomeDir();
    return AMFS::abspath(path, true, home, cwd, "/");
  }

  /**
   * @brief Ensure a client exists and is connected; create it if missing.
   */
  std::pair<ECM, std::shared_ptr<BaseClient>>
  EnsureClient(const std::string &nickname, amf interrupt_flag = nullptr) {
    amf flag = interrupt_flag ? interrupt_flag : global_interrupt_flag;
    if (nickname.empty() || nickname == "local") {
      return {ECM{EC::Success, ""}, LOCAL};
    }

    auto existing = Clients().GetHost(nickname);
    if (!existing) {
      std::cout << "Connecting to " << nickname << "..." << std::endl;
      return AddClient(nickname, nullptr, false, true, {}, flag);
    }

    ECM rcm = existing->Connect(false, flag);
    if (rcm.first != EC::Success) {
      return {rcm, existing};
    }
    return {ECM{EC::Success, ""}, existing};
  }

  /**
   * @brief Get workdir for a client, initializing it from home if missing.
   */
  [[nodiscard]] std::string
  GetOrInitWorkdir(const std::shared_ptr<BaseClient> &client) const {
    if (!client) {
      return "";
    }
    {
      std::lock_guard<std::recursive_mutex> lock(client->public_kv_mtx);
      auto it = client->public_kv.find("workdir");
      if (it != client->public_kv.end()) {
        std::string workdir = AMPathStr::UnifyPathSep(it->second, "/");
        if (workdir.empty()) {
          workdir = AMPathStr::UnifyPathSep(client->GetHomeDir(), "/");
          client->public_kv["workdir"] = workdir;
          return workdir;
        }
        if (!workdir.empty() && !AMPathStr::IsAbs(workdir, "/")) {
          const std::string home =
              AMPathStr::UnifyPathSep(client->GetHomeDir(), "/");
          workdir = AMFS::abspath(workdir, true, home, home, "/");
          client->public_kv["workdir"] = workdir;
        }
        return workdir;
      }
    }
    std::string home = AMPathStr::UnifyPathSep(client->GetHomeDir(), "/");
    {
      std::lock_guard<std::recursive_mutex> lock(client->public_kv_mtx);
      client->public_kv["workdir"] = home;
    }
    return home;
  }

  /**
   * @brief Build an absolute path based on the client's home/workdir.
   */
  [[nodiscard]] std::string BuildPath(const std::shared_ptr<BaseClient> &client,
                                      const std::string &path) const {
    if (!client) {
      return path;
    }
    if (path.empty()) {
      return GetOrInitWorkdir(client);
    }
    std::string cwd = GetOrInitWorkdir(client);
    std::string home = client->GetHomeDir();
    return AMFS::abspath(path, true, home, cwd, "/");
  }

  /**
   * @brief Format a size value to a human-readable string.
   */
  static std::string FormatSize(size_t size) {
    const char *units[] = {"B", "KB", "MB", "GB", "TB"};
    double value = static_cast<double>(size);
    size_t idx = 0;
    while (value >= 1024.0 && idx < 4) {
      value /= 1024.0;
      ++idx;
    }
    std::ostringstream oss;
    if (value == static_cast<size_t>(value)) {
      oss << static_cast<size_t>(value);
    } else {
      oss << std::fixed << std::setprecision(1) << value;
    }
    oss << units[idx];
    return oss.str();
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

private:
  AMConfigManager &config_;
  AMLogManager &log_manager_;
  std::shared_ptr<AMLocalClient> local_client_;
  ClientMaintainerPtr clients_;
  PasswordCallback password_cb_ = {};
  DisconnectCallback disconnect_cb_ = {};
  std::mutex auth_io_mtx_;
  ssize_t trace_num_ = 10;
  std::atomic<bool> spinner_stop_requested_{false};
  std::atomic<size_t> spinner_line_len_{0};

  /**
   * @brief Build an auth callback wrapper with optional log suppression and
   *        spinner canceling.
   */
  AuthCallback BuildAuthCallback_(const AuthCallback &auth_cb, bool quiet,
                                  std::atomic<bool> *spinner_running) {
    if (!auth_cb) {
      return {};
    }
    return [this, auth_cb, quiet, spinner_running](const AuthCBInfo &info) {
      RequestSpinnerStop_();
      if (spinner_running) {
        spinner_running->store(false);
      }
      int prev_level = -99999;
      if (quiet) {
        prev_level = log_manager_.TraceLevel();
        log_manager_.TraceLevel(-1);
      }
      std::optional<std::string> result;
      if (auth_cb) {
        result = auth_cb(info);
      }
      if (quiet) {
        log_manager_.TraceLevel(prev_level);
      }
      return result;
    };
  }

  /**
   * @brief Attach known host verification callback for SFTP clients.
   */
  void ApplyKnownHostCallback_(const std::shared_ptr<BaseClient> &client) {
    if (!client) {
      return;
    }
    if (client->GetProtocol() != ClientProtocol::SFTP) {
      return;
    }
    auto sftp_client = std::dynamic_pointer_cast<AMSFTPClient>(client);
    if (!sftp_client) {
      return;
    }
    auto known_cb = config_.BuildKnownHostCallback();
    sftp_client->SetKnownHostCallback(
        [this, known_cb](AMConfigManager::KnownHostEntry entry) -> ECM {
          RequestSpinnerStop_();
          if (!known_cb) {
            return {EC::Success, ""};
          }
          return known_cb(std::move(entry));
        });
  }

  /**
   * @brief Reset spinner stop state before starting a new spinner thread.
   */
  void ResetSpinnerStop_() {
    spinner_stop_requested_.store(false);
    spinner_line_len_.store(0);
  }

  /**
   * @brief Stop spinner output permanently for the current connect attempt.
   */
  void RequestSpinnerStop_() {
    if (spinner_stop_requested_.exchange(true)) {
      return;
    }
    const size_t line_len = spinner_line_len_.load();
    if (line_len > 0) {
      std::cout << '\r' << std::string(line_len, ' ') << '\r' << std::flush;
    }
  }

  /**
   * @brief Convert protocol enum into a user-facing label for connection
   * status.
   */
  static std::string ProtocolLabel_(ClientProtocol protocol) {
    switch (protocol) {
    case ClientProtocol::SFTP:
      return "SFTP";
    case ClientProtocol::FTP:
      return "FTP";
    case ClientProtocol::LOCAL:
      return "LOCAL";
    default:
      return "Remote";
    }
  }

  /**
   * @brief Convert protocol enum into config protocol field text.
   */
  static std::string ProtocolConfigValue_(ClientProtocol protocol) {
    switch (protocol) {
    case ClientProtocol::SFTP:
      return "sftp";
    case ClientProtocol::FTP:
      return "ftp";
    case ClientProtocol::LOCAL:
      return "local";
    default:
      return "unknown";
    }
  }

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
    ECM cfg_status = cfg.Init();
    if (cfg_status.first != EC::Success) {
      auto client = std::make_shared<AMLocalClient>(ConRequst("local", "", ""),
                                                    10, std::move(trace_cb));
      return client;
    }

    auto cfg_result = cfg.GetClientConfig("local");
    if (cfg_result.first.first != EC::Success) {
      (void)cfg.SetHostField("local", "hostname", std::string("localhost"),
                             false);
      (void)cfg.SetHostField("local", "protocol", std::string("local"), false);
      (void)cfg.SetHostField("local", "port", int64_t(22), false);
      (void)cfg.SetHostField("local", "buffer_size", int64_t(-1), false);
      (void)cfg.SetHostField("local", "login_dir", std::string(""), true);
      cfg_result = cfg.GetClientConfig("local");
    }

    ConRequst request = cfg_result.second.request;
    auto client =
        std::make_shared<AMLocalClient>(request, 10, std::move(trace_cb));

    if (!request.trash_dir.empty()) {
      auto result = client->TrashDir(request.trash_dir);
      if (std::holds_alternative<ECM>(result)) {
        const auto &ecm = std::get<ECM>(result);
        if (ecm.first != EC::Success) {
          AM_PROMPT_ERROR("LocalClient", ecm.second, false, 0);
        }
      }
    }

    if (cfg_result.second.buffer_size > 0) {
      client->TransferRingBufferSize(cfg_result.second.buffer_size);
    }

    return client;
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

  /** Resolve workdir from login_dir/home_dir and persist if needed. */
  void ApplyLoginDir_(const std::string &nickname,
                      const std::shared_ptr<BaseClient> &client,
                      const std::string &login_dir, const amf &flag) {
    if (!client) {
      return;
    }

    std::string resolved = login_dir;
    bool need_persist = false;
    if (resolved.empty()) {
      resolved = client->GetHomeDir();
      need_persist = true;
    } else {
      bool exists = false;
      if (client->GetProtocol() == ClientProtocol::LOCAL) {
        std::error_code ec;
        exists = std::filesystem::exists(resolved, ec);
      } else {
        auto [rcm, info] = client->stat(resolved, false, flag);
        exists = rcm.first == EC::Success && info.type == PathType::DIR;
      }
      if (!exists) {
        resolved = client->GetHomeDir();
        need_persist = true;
      }
    }

    {
      std::lock_guard<std::recursive_mutex> lock(client->public_kv_mtx);
      const std::string normalized = AMPathStr::UnifyPathSep(resolved, "/");
      client->public_kv["workdir"] = normalized;
      client->public_kv["login_dir"] = normalized;
    }

    if (need_persist) {
      (void)config_.SetHostField(nickname, "login_dir", resolved, true);
    }
  }

  /** Forward disconnect notifications. */
  void OnDisconnect(const std::shared_ptr<BaseClient> &client, const ECM &ecm) {
    if (disconnect_cb_) {
      CallCallbackSafe(disconnect_cb_, client, ecm);
    }
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
