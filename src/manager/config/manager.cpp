#include "AMManager/Client.hpp"
#include "internal_func.hpp"

using namespace AMConfigInternal;

AMConfigManager &AMConfigManager::Instance() {
  static AMConfigManager instance;
  return instance;
}

/** @brief Stop the background writer and release config handles. */
AMConfigManager::~AMConfigManager() { CloseHandles(); }

/**
 * @brief Submit a no-arg write task to the background writer thread.
 */
void AMConfigManager::SubmitWriteTask(std::function<void()> task) {
  storage_.SubmitWriteTaskVoid(std::move(task));
}

ECM AMConfigManager::Init() {
  const std::string root_env = GetEnvCopy("AMSFTP_ROOT");
  if (root_env.empty()) {
    prompt.ErrorFormat("ConfigInit",
                       "$AMSFTP_ROOT environment variable is not set", true, 2);
    return Err(EC::ConfigInvalid,
               "AMSFTP_ROOT environment variable is not set");
  }

  std::filesystem::path root_dir(root_env);
  std::error_code ec;
  std::filesystem::create_directories(root_dir, ec);
  if (ec) {
    prompt.ErrorFormat("ConfigInit",
                       "failed to create root directory " + root_dir.string() +
                           ": " + ec.message(),
                       true, 2);
    return Err(EC::ConfigLoadFailed, "failed to create root directory " +
                                         root_dir.string() + ": " +
                                         ec.message());
  }

  auto init_status = storage_.Init(root_dir);
  if (init_status.first != EC::Success) {
    prompt.ErrorFormat("ConfigInit", init_status.second, true, 2);
    return init_status;
  }

  auto load_status = storage_.LoadAll();
  if (load_status.first != EC::Success) {
    prompt.ErrorFormat("ConfigInit", load_status.second, true, 2);
    return load_status;
  }

  core_data_.BindStorage(&storage_);
  style_data_.BindStorage(&storage_);
  cli_adapter_.SetListCallback([this]() { return List(); });
  cli_adapter_.SetListNameCallback([this]() { return ListName(); });
  cli_adapter_.SetAddCallback([this]() { return Add(); });
  cli_adapter_.SetModifyCallback(
      [this](const std::string &nickname) { return Modify(nickname); });
  cli_adapter_.SetDeleteCallback(
      [this](const std::string &targets) { return Delete(targets); });
  cli_adapter_.SetDeleteListCallback(
      [this](const std::vector<std::string> &targets) {
        return Delete(targets);
      });
  cli_adapter_.SetQueryCallback(
      [this](const std::string &targets) { return Query(targets); });
  cli_adapter_.SetQueryListCallback(
      [this](const std::vector<std::string> &targets) {
        return Query(targets);
      });
  cli_adapter_.SetRenameCallback(
      [this](const std::string &old_name, const std::string &new_name) {
        return Rename(old_name, new_name);
      });
  cli_adapter_.SetSrcCallback([this]() { return Src(); });

  initialized_ = true;
  if (!exit_hook_installed_) {
    std::atexit(&AMConfigManager::OnExit);
    exit_hook_installed_ = true;
  }

  storage_.StartWriteThread();
  return Ok();
}

ECM AMConfigManager::Dump() {
  auto status = EnsureInitialized("Dump");
  if (status.first != EC::Success)
    return status;
  ECM rcm = storage_.DumpAll();
  if (rcm.first != EC::Success) {
    prompt.ErrorFormat("ConfigDumpError", rcm.second, true, 2);
  }
  return rcm;
}

/**
 * @brief Load history data from .AMSFTP_History.toml into memory.
 */
ECM AMConfigManager::LoadHistory() {
  auto status = EnsureInitialized("LoadHistory");
  if (status.first != EC::Success) {
    return status;
  }
  return core_data_.LoadHistory();
}

/**
 * @brief Fetch history commands for a nickname.
 */
ECM AMConfigManager::GetHistoryCommands(const std::string &nickname,
                                        std::vector<std::string> *out) {
  auto status = EnsureInitialized("GetHistoryCommands");
  if (status.first != EC::Success) {
    return status;
  }
  return core_data_.GetHistoryCommands(nickname, out);
}

/**
 * @brief Store history commands for a nickname and optionally persist.
 */
ECM AMConfigManager::SetHistoryCommands(
    const std::string &nickname, const std::vector<std::string> &commands,
    bool dump_now) {
  auto status = EnsureInitialized("SetHistoryCommands");
  if (status.first != EC::Success) {
    return status;
  }
  return core_data_.SetHistoryCommands(nickname, commands, dump_now);
}

/**
 * @brief Resolve history size limit from settings with minimum 10.
 */
int AMConfigManager::ResolveMaxHistoryCount(int default_value) const {
  return core_data_.ResolveMaxHistoryCount(default_value);
}

/**
 * @brief Persist in-memory history JSON to disk.
 */
ECM AMConfigManager::DumpHistory_() {
  return storage_.Dump(DocumentKind::History);
}

/**
 * @brief Backup config/settings/known_hosts when the interval elapses.
 */
ECM AMConfigManager::ConfigBackupIfNeeded() {
  auto status = EnsureInitialized("ConfigBackupIfNeeded");
  if (status.first != EC::Success)
    return status;
  return storage_.BackupIfNeeded();
}

/**
 * @brief Apply configured styles to text using path or input highlight rules.
 */
std::string AMConfigManager::Format(const std::string &ori_str_f,
                                    const std::string &style_name,
                                    const PathInfo *path_info) const {
  auto status = EnsureInitialized("Format");
  if (status.first != EC::Success) {
    return AMStr::BBCEscape(ori_str_f);
  }
  return style_data_.Format(ori_str_f, style_name, path_info);
}

ECM AMConfigManager::List() const {
  auto status = EnsureInitialized("List");
  if (status.first != EC::Success)
    return status;

  auto hosts = CollectHosts();
  if (hosts.empty()) {
    PrintLine("");
    return Ok();
  }

  for (const auto &item : hosts) {
    auto print_status = PrintHost(item.first, item.second);
    if (print_status.first != EC::Success)
      return print_status;
    PrintLine("");
  }
  return Ok();
}

ECM AMConfigManager::ListName() const {
  auto status = EnsureInitialized("ListName");
  if (status.first != EC::Success)
    return status;

  auto hosts = CollectHosts();
  if (hosts.empty()) {
    PrintLine("");
    return Ok();
  }

  const size_t max_width = 80;
  size_t current_width = 0;
  std::ostringstream line;

  for (auto it = hosts.begin(); it != hosts.end(); ++it) {
    const std::string &name = it->first;
    const std::string styled = Format(name, "nickname");
    size_t name_len = name.size();
    size_t extra = current_width == 0 ? 0 : 1;

    if (current_width + extra + name_len > max_width && current_width > 0) {
      PrintLine(line.str());
      line.str(std::string());
      line.clear();
      current_width = 0;
    }

    if (current_width > 0) {
      line << "   ";
      current_width += 3;
    }
    line << styled;
    current_width += name_len;
  }

  if (current_width > 0) {
    PrintLine(line.str());
  }
  return Ok();
}

std::pair<ECM, std::vector<std::string>>
AMConfigManager::PrivateKeys(bool print_sign) const {
  auto status = EnsureInitialized("PrivateKeys");
  if (status.first != EC::Success)
    return {status, {}};

  std::vector<std::string> keys;
  const Json *node = nullptr;
  const Json &config_json =
      storage_.GetJson(DocumentKind::Config).value().get();
  if (config_json.is_object()) {
    auto it = config_json.find("private_keys");
    if (it != config_json.end()) {
      node = &(*it);
    }
  }
  if (node && node->is_array()) {
    keys.reserve(node->size());
    for (const auto &item : *node) {
      if (item.is_string()) {
        keys.push_back(item.get<std::string>());
      }
    }
  }

  if (print_sign) {
    PrintLine("[!a][Private_keys][/a]");
    for (const auto &path : keys) {
      auto [path_rcm, path_info] = AMFS::stat(path, false);
      PathInfo missing_info;
      if (path_rcm.first != EC::Success) {
        missing_info.name = AMPathStr::basename(path);
      }
      const PathInfo *path_ptr =
          path_rcm.first == EC::Success ? &path_info : &missing_info;
      PrintLine(Format(path, "dir", path_ptr));
    }
  }

  return {Ok(), keys};
}

/**
 * @brief Find a known host entry by hostname, port, and protocol.
 */
std::pair<ECM, std::optional<AMConfigManager::KnownHostEntry>>
AMConfigManager::FindKnownHost(const std::string &hostname, int port,
                               const std::string &protocol) const {
  auto status = EnsureInitialized("FindKnownHost");
  if (status.first != EC::Success)
    return {status, std::nullopt};

  const Json *arr = GetKnownHostsArray(
      storage_.GetJson(DocumentKind::KnownHosts).value().get());
  if (!arr) {
    return {Ok(), std::nullopt};
  }

  for (const auto &item : *arr) {
    if (!KnownHostMatch(item, hostname, port, protocol)) {
      continue;
    }
    KnownHostEntry entry;
    if (auto nickname = GetStringField(item, "nickname")) {
      entry.nickname = *nickname;
    }
    if (auto host_value = GetStringField(item, "hostname")) {
      entry.hostname = *host_value;
    }
    if (auto port_value = GetIntField(item, "port")) {
      entry.port = static_cast<int>(*port_value);
    }
    if (auto protocol_value = GetStringField(item, "protocol")) {
      entry.protocol = *protocol_value;
    }
    if (auto fingerprint = GetStringField(item, "fingerprint")) {
      entry.fingerprint = *fingerprint;
    }
    return {Ok(), entry};
  }

  return {Ok(), std::nullopt};
}

/**
 * @brief Insert or update a known host entry and optionally persist it.
 */
ECM AMConfigManager::UpsertKnownHost(const KnownHostEntry &entry,
                                     bool dump_now) {
  auto status = EnsureInitialized("UpsertKnownHost");
  if (status.first != EC::Success) {
    return status;
  }

  if (entry.hostname.empty() || entry.protocol.empty() || entry.port <= 0) {
    return Err(EC::InvalidArg, "invalid known host entry");
  }

  Json *arr = EnsureKnownHostsArray(
      storage_.GetJson(DocumentKind::KnownHosts).value().get());
  if (!arr) {
    return Err(EC::ConfigInvalid, "known_hosts array not initialized");
  }

  Json *target = nullptr;
  for (auto &item : *arr) {
    if (KnownHostMatch(item, entry.hostname, entry.port, entry.protocol)) {
      target = &item;
      break;
    }
  }

  if (!target) {
    Json new_entry = Json::object();
    (*arr).push_back(new_entry);
    target = &(*arr)[arr->size() - 1];
  }

  (*target)["nickname"] = NormalizeKnownHostNickname(entry);
  (*target)["hostname"] = entry.hostname;
  (*target)["port"] = entry.port;
  (*target)["protocol"] = entry.protocol;
  (*target)["fingerprint"] = entry.fingerprint;

  if (dump_now) {
    return Dump();
  }
  return Ok();
}

/**
 * @brief Build a known host verification callback for SFTP clients.
 */
AMConfigManager::KnownHostCallback AMConfigManager::BuildKnownHostCallback() {
  if (known_host_cb_) {
    return known_host_cb_;
  }
  known_host_cb_ = [this](KnownHostEntry entry) -> ECM {
    auto status = EnsureInitialized("KnownHostCallback");
    if (status.first != EC::Success) {
      return status;
    }

    if (entry.hostname.empty() || entry.protocol.empty() || entry.port <= 0) {
      return Err(EC::InvalidArg, "invalid known host entry");
    }

    entry.fingerprint = AMStr::TrimWhitespaceCopy(entry.fingerprint);
    entry.fingerprint_sha256 =
        AMStr::TrimWhitespaceCopy(entry.fingerprint_sha256);
    if (entry.fingerprint.empty()) {
      return Err(EC::InvalidArg, "empty host fingerprint");
    }

    auto [find_status, existing] =
        FindKnownHost(entry.hostname, entry.port, entry.protocol);
    if (find_status.first != EC::Success) {
      return find_status;
    }

    if (!existing.has_value() ||
        AMStr::TrimWhitespaceCopy(existing->fingerprint).empty()) {
      bool canceled = false;
      const std::string question = AMStr::amfmt(
          "No known host fingerprint for {}:{} {}.\n"
          "Fingerprint: {}",
          entry.hostname, entry.port, entry.protocol, entry.fingerprint);
      prompt.Print(question);
      if (!prompt.PromptYesNo("Add it? (y/N): ", &canceled) || !canceled) {
        return Err(EC::ConfigCanceled, "Known host fingerprint add canceled");
      }
      return UpsertKnownHost(entry, true);
    }

    const std::string expected_fp =
        AMStr::TrimWhitespaceCopy(existing->fingerprint);
    const std::string expected_lower = AMStr::lowercase(expected_fp);
    if (expected_lower.rfind("sha256:", 0) == 0) {
      const std::string expected_body =
          AMStr::TrimWhitespaceCopy(expected_fp.substr(7));
      if (entry.fingerprint_sha256.empty() ||
          expected_body != entry.fingerprint_sha256) {
        return {EC::HostFingerprintMismatch,
                AMStr::amfmt("{}:{} {} fingerprint mismatches", entry.hostname,
                             entry.port, entry.protocol)};
      }
      return Ok();
    }

    if (expected_fp != entry.fingerprint) {
      return {EC::HostFingerprintMismatch,
              AMStr::amfmt("{}:{} {} fingerprint mismatches", entry.hostname,
                           entry.port, entry.protocol)};
    }

    return Ok();
  };
  return known_host_cb_;
}

/**
 * @brief Return the project root directory path.
 */
std::filesystem::path AMConfigManager::ProjectRoot() const {
  return storage_.RootDir();
}

std::pair<ECM, AMConfigManager::ClientConfig>
AMConfigManager::GetClientConfig(const std::string &nickname) {
  auto status = EnsureInitialized("GetClientConfig");
  if (status.first != EC::Success)
    return {status, ClientConfig{}};

  Json *host = FindHostJsonMutable(
      storage_.GetJson(DocumentKind::Config).value().get(), nickname);
  if (!host) {
    return {Err(EC::HostConfigNotFound, "client config not found"),
            ClientConfig{}};
  }

  if (!IsHostValid(*host)) {
    return {Err(EC::HostConfigNotFound, "invalid host entry"), ClientConfig{}};
  }

  ClientConfig config;
  bool updated = false;

  auto get_string = [&](const std::string &key,
                        const std::string &default_value) {
    auto value = GetStringField(*host, key);
    if (value) {
      return *value;
    }
    (*host)[key] = default_value;
    updated = true;
    return default_value;
  };

  auto get_int = [&](const std::string &key, int64_t default_value) {
    auto value = GetIntField(*host, key);
    if (value.has_value()) {
      return *value;
    }
    (*host)[key] = default_value;
    updated = true;
    return default_value;
  };

  (*host)["nickname"] = nickname;

  std::string hostname = get_string("hostname", "");
  std::string username = get_string("username", "");
  std::string password = get_string("password", "");
  std::string keyfile = get_string("keyfile", "");
  std::string trash_dir = get_string("trash_dir", "");
  std::string login_dir = get_string("login_dir", "");
  int64_t port = get_int("port", 22);
  bool compression = false;
  auto compression_it = host->find("compression");
  if (compression_it != host->end() && compression_it->is_boolean() &&
      compression_it->get<bool>()) {
    compression = true;
  } else {
    if (compression_it == host->end() || !compression_it->is_boolean() ||
        compression_it->get<bool>()) {
      (*host)["compression"] = false;
      updated = true;
    }
    compression = false;
  }

  config.request =
      ConRequst(nickname, hostname, username, static_cast<int>(port), password,
                keyfile, compression, trash_dir);

  std::string protocol_str = get_string("protocol", "sftp");
  config.protocol = ProtocolFromString(protocol_str);
  config.buffer_size = get_int("buffer_size", -1);
  config.login_dir = login_dir;

  if (updated) {
    (void)Dump();
  }

  return {Ok(), config};
}

int AMConfigManager::GetSettingInt(const Path &path, int default_value) const {
  auto status = EnsureInitialized("GetSettingInt");
  if (status.first != EC::Success)
    return default_value;
  const Json *node = FindJsonNode(
      storage_.GetJson(DocumentKind::Settings).value().get(), path);
  return GetSettingValueImpl<int>(node, default_value);
}

/**
 * @brief Resolve an integer setting by type with optional post-processing.
 */
int AMConfigManager::ResolveArg(ResolveArgType target_type,
                                int default_value) const {
  static const std::map<ResolveArgType, Path> kPaths = {
      {ResolveArgType::TimeoutMs, {"client_manager", "timeout_ms"}},
      {ResolveArgType::RefreshIntervalMs,
       {"transfer_manager", "refresh_interval_ms"}},
      {ResolveArgType::HeartbeatIntervalS,
       {"client_manager", "heartbeat_interval_s"}},
      {ResolveArgType::TraceNum, {"client_manager", "trace_num"}},
      {ResolveArgType::MaxHistoryCount, {"InternalVars", "MaxHistoryCount"}}};

  static const std::map<ResolveArgType, std::function<int(int, int)>>
      kAfterProcess = {
          {ResolveArgType::TimeoutMs,
           [](int value, int fallback) {
             if (value <= 0) {
               return fallback;
             }
             return value;
           }},
          {ResolveArgType::RefreshIntervalMs,
           [](int value, int fallback) {
             if (value <= 0) {
               value = fallback;
             }
             if (value < 30) {
               value = 30;
             }
             return value;
           }},
          {ResolveArgType::HeartbeatIntervalS,
           [](int value, int fallback) {
             (void)fallback;
             if (value < 1) {
               return value;
             }
             return value > 10 ? value : 10;
           }},
          {ResolveArgType::TraceNum,
           [](int value, int fallback) {
             if (value <= 0) {
               value = fallback;
             }
             if (value < 5) {
               value = 5;
             }
             return value;
           }},
          {ResolveArgType::MaxHistoryCount, [](int value, int fallback) {
             (void)fallback;
             if (value < 10) {
               value = 10;
             }
             return value;
           }}};

  auto path_it = kPaths.find(target_type);
  if (path_it == kPaths.end()) {
    return default_value;
  }
  int value = GetSettingInt(path_it->second, default_value);
  auto post_it = kAfterProcess.find(target_type);
  if (post_it != kAfterProcess.end()) {
    value = post_it->second(value, default_value);
  }
  return value;
}

/**
 * @brief Resolve network timeout from settings with a default fallback.
 */
int AMConfigManager::ResolveTimeoutMs(int default_timeout_ms) const {
  return ResolveArg(ResolveArgType::TimeoutMs, default_timeout_ms);
}

/**
 * @brief Resolve transfer refresh interval from settings with defaults.
 */
int AMConfigManager::ResolveRefreshIntervalMs() const {
  return ResolveArg(ResolveArgType::RefreshIntervalMs, 200);
}

/**
 * @brief Resolve heartbeat interval from settings with a default fallback.
 */
int AMConfigManager::ResolveHeartbeatInterval() const {
  return ResolveArg(ResolveArgType::HeartbeatIntervalS, 60);
}

/**
 * @brief Resolve trace buffer size from settings with sane defaults.
 */
ssize_t AMConfigManager::ResolveTraceNum() const {
  return static_cast<ssize_t>(ResolveArg(ResolveArgType::TraceNum, 10));
}

/** Return a string setting value or the provided default. */
std::string
AMConfigManager::GetSettingString(const Path &path,
                                  const std::string &default_value) const {
  auto status = EnsureInitialized("GetSettingString");
  if (status.first != EC::Success)
    return default_value;
  const Json *node = FindJsonNode(
      storage_.GetJson(DocumentKind::Settings).value().get(), path);
  return GetSettingValueImpl<std::string>(node, default_value);
}

/**
 * @brief Create a progress bar configured from style.ProgressBar settings.
 */
AMProgressBar
AMConfigManager::CreateProgressBar(int64_t total_size,
                                   const std::string &prefix) const {
  return style_data_.CreateProgressBar(total_size, prefix);
}

/**
 * @brief Create a UTF-8 table using style.Table settings.
 */
std::string AMConfigManager::FormatUtf8Table(
    const std::vector<std::string> &keys,
    const std::vector<std::vector<std::string>> &rows) const {
  return style_data_.FormatUtf8Table(keys, rows);
}

/**
 * @brief Query a UserVars entry by name.
 */
bool AMConfigManager::GetUserVar(const std::string &name,
                                 std::string *value) const {
  auto status = EnsureInitialized("GetUserVar");
  if (status.first != EC::Success)
    return false;
  if (name.empty())
    return false;

  const Json *node =
      FindJsonNode(storage_.GetJson(DocumentKind::Settings).value().get(),
                   {"UserVars", name});
  if (!node)
    return false;

  if (value) {
    if (node->is_string()) {
      *value = node->get<std::string>();
    } else {
      *value = GetSettingString({"UserVars", name}, "");
    }
  }
  return true;
}

/**
 * @brief List all UserVars entries.
 */
std::vector<std::pair<std::string, std::string>>
AMConfigManager::ListUserVars() const {
  std::vector<std::pair<std::string, std::string>> entries;
  auto status = EnsureInitialized("ListUserVars");
  if (status.first != EC::Success)
    return entries;

  const Json *node = FindJsonNode(
      storage_.GetJson(DocumentKind::Settings).value().get(), {"UserVars"});
  if (!node || !node->is_object())
    return entries;

  entries.reserve(node->size());
  for (auto it = node->begin(); it != node->end(); ++it) {
    if (it.value().is_string()) {
      entries.emplace_back(it.key(), it.value().get<std::string>());
    } else {
      entries.emplace_back(it.key(),
                           GetSettingString({"UserVars", it.key()}, ""));
    }
  }
  return entries;
}

/**
 * @brief Set a UserVars entry and optionally persist to settings.
 */
ECM AMConfigManager::SetUserVar(const std::string &name,
                                const std::string &value, bool dump_now) {
  auto status = EnsureInitialized("SetUserVar");
  if (status.first != EC::Success)
    return status;
  if (name.empty())
    return Err(EC::InvalidArg, "Empty variable name");

  SetKey(storage_.GetJson(DocumentKind::Settings).value().get(),
         {"UserVars", name}, value);
  if (dump_now) {
    return Dump();
  }
  return Ok();
}

/** Return a list of configured host nicknames. */
std::vector<std::string> AMConfigManager::ListHostnames() const {
  std::vector<std::string> names;
  auto status = EnsureInitialized("ListHostnames");
  if (status.first != EC::Success)
    return names;
  auto hosts = CollectHosts();
  names.reserve(hosts.size());
  for (const auto &item : hosts) {
    names.push_back(item.first);
  }
  return names;
}

/**
 * @brief Remove a UserVars entry and optionally persist to settings.
 */
ECM AMConfigManager::RemoveUserVar(const std::string &name, bool dump_now) {
  auto status = EnsureInitialized("RemoveUserVar");
  if (status.first != EC::Success)
    return status;
  if (name.empty())
    return Err(EC::InvalidArg, "Empty variable name");

  Json *node = nullptr;
  auto &settings_json = storage_.GetJson(DocumentKind::Settings).value().get();
  if (settings_json.contains("UserVars") &&
      settings_json["UserVars"].is_object()) {
    node = &settings_json["UserVars"];
  }

  if (!node || !node->contains(name)) {
    return Err(EC::InvalidArg, "Variable not found");
  }

  node->erase(name);
  if (dump_now) {
    return Dump();
  }
  return Ok();
}

bool AMConfigManager::QueryKey(const Json &root, const Path &path,
                               Value *value) const {
  const Json *node = FindJsonNode(root, path);
  if (!node) {
    return false;
  }
  return NodeToValue(*node, value);
}

ECM AMConfigManager::Src() const {
  auto status = EnsureInitialized("Src");
  if (status.first != EC::Success)
    return status;

  const std::string config_label = AMStr::BBCEscape("[Config]");
  const std::string settings_label = AMStr::BBCEscape("[Setting]");
  size_t width = std::max(config_label.size(), settings_label.size());

  const auto config_paths = storage_.GetDataPath(DocumentKind::Config);
  const auto settings_paths = storage_.GetDataPath(DocumentKind::Settings);
  std::string config_path =
      config_paths.first ? config_paths.first->string() : std::string();
  std::string settings_path =
      settings_paths.first ? settings_paths.first->string() : std::string();

  auto [config_rcm, config_info] = AMFS::stat(config_path, false);
  PathInfo missing_config_info;
  if (config_rcm.first != EC::Success) {
    missing_config_info.name = AMPathStr::basename(config_path);
  }
  const PathInfo *config_ptr =
      config_rcm.first == EC::Success ? &config_info : &missing_config_info;
  auto [settings_rcm, settings_info] = AMFS::stat(settings_path, false);
  PathInfo missing_settings_info;
  if (settings_rcm.first != EC::Success) {
    missing_settings_info.name = AMPathStr::basename(settings_path);
  }
  const PathInfo *settings_ptr = settings_rcm.first == EC::Success
                                     ? &settings_info
                                     : &missing_settings_info;

  std::string styled_config = Format(config_path, "dir", config_ptr);
  std::string styled_settings = Format(settings_path, "dir", settings_ptr);

  {
    std::ostringstream line;
    line << std::left << std::setw(static_cast<int>(width)) << config_label
         << " = " << styled_config;
    PrintLine(line.str());
  }
  {
    std::ostringstream line;
    line << std::left << std::setw(static_cast<int>(width)) << settings_label
         << " = " << styled_settings;
    PrintLine(line.str());
  }
  return Ok();
}

ECM AMConfigManager::Delete(const std::string &targets) {
  std::istringstream iss(targets);
  std::vector<std::string> names;
  std::string nickname;
  while (iss >> nickname) {
    names.push_back(nickname);
  }
  return Delete(names);
}

/** Delete hosts by nickname list without parsing input. */
ECM AMConfigManager::Delete(const std::vector<std::string> &targets) {
  auto status = EnsureInitialized("Delete");
  if (status.first != EC::Success)
    return status;

  std::vector<std::string> unique_targets = UniqueTargetsKeepOrder(targets);
  if (unique_targets.empty()) {
    const std::string msg = "Empty delete targets";
    prompt.ErrorFormat(ECM{EC::InvalidArg, msg});
    return Err(EC::InvalidArg, "empty delete targets");
  }

  ECM last = Ok();
  std::string msg;
  std::vector<std::string> valid_targets;
  std::vector<std::string> styled_targets;
  styled_targets.reserve(unique_targets.size());
  for (const auto &nickname : unique_targets) {
    if (nickname.empty()) {
      msg = "Invalid Empty Hostname";
      last = Err(EC::InvalidArg, msg);
      prompt.ErrorFormat(ECM{EC::InvalidArg, msg});
      continue;
    }
    if (AMStr::lowercase(nickname) == "local") {
      msg = "Unable to delete local host";
      last = Err(EC::PermissionDenied, msg);
      prompt.ErrorFormat(ECM{EC::InvalidArg, msg});
      continue;
    }
    if (!HostExists(nickname)) {
      msg =
          AMStr::amfmt("{} not found in config", Format(nickname, "nickname"));
      prompt.ErrorFormat(ECM{EC::HostConfigNotFound, msg});
      last = Err(EC::HostConfigNotFound, msg);
      continue;
    }
    valid_targets.push_back(nickname);
    styled_targets.push_back(Format(nickname, "nickname"));
  }
  if (styled_targets.empty()) {
    return last.first == EC::Success
               ? Err(EC::HostConfigNotFound, "no valid hosts to delete")
               : last;
  }

  {
    bool canceled = false;
    std::string target_line;
    for (size_t i = 0; i < styled_targets.size(); ++i) {
      if (i > 0) {
        target_line += ", ";
      }
      target_line += styled_targets[i];
    }
    const std::string question =
        AMStr::amfmt("Delete host(s): {} ? (y/N): ", target_line);
    if (!prompt.PromptYesNo(question, &canceled) || canceled) {
      PrintLine(AMStr::amfmt("🚫  {}\n", Format("Remove Canceled", "abort")));
      return Err(EC::ConfigCanceled, "delete canceled");
    }
  }

  bool changed = false;
  for (const auto &nickname : valid_targets) {
    auto rm_status = RemoveHost(nickname);
    if (rm_status.first != EC::Success) {
      last = rm_status;
      prompt.ErrorFormat(rm_status);
      continue;
    }
    changed = true;
    PrintLine(AMStr::amfmt("[#ffd460]⚠️[/]  Deleted host: {}",
                           Format(nickname, "nickname")));
  }

  if (changed) {
    auto dump_status = Dump();
    if (dump_status.first != EC::Success) {
      return dump_status;
    }
  }

  return last;
}

ECM AMConfigManager::Rename(const std::string &old_nickname,
                            const std::string &new_nickname) {
  auto status = EnsureInitialized("Rename");
  if (status.first != EC::Success)
    return status;

  if (old_nickname == new_nickname) {
    return Ok();
  }
  std::string msg = "";
  msg = AMStr::amfmt("Host {} not found", Format(old_nickname, "nickname"));
  if (!HostExists(old_nickname)) {
    prompt.ErrorFormat(ECM{EC::HostConfigNotFound, msg});
    return {EC::HostConfigNotFound, "host not found"};
  }

  if (new_nickname.empty()) {
    msg = "new nickname must contain only letters, numbers, and underscore";
    prompt.ErrorFormat(ECM{EC::InvalidArg, msg});
    return Err(EC::InvalidArg, msg);
  }
  const std::regex nickname_pattern("^[A-Za-z0-9_]+$");
  if (!std::regex_match(new_nickname, nickname_pattern)) {
    msg = "new nickname must contain only letters, numbers, and "
          "underscore";
    prompt.ErrorFormat(ECM{EC::InvalidArg, msg});
    return Err(EC::InvalidArg, msg);
  }
  if (HostExists(new_nickname)) {
    msg = "new nickname already exists";
    prompt.ErrorFormat(ECM{EC::KeyAlreadyExists, msg});
    return Err(EC::KeyAlreadyExists, msg);
  }

  Json *host = FindHostJsonMutable(
      storage_.GetJson(DocumentKind::Config).value().get(), old_nickname);
  if (!host) {
    return Err(EC::ConfigInvalid, "invalid host entry");
  }
  (*host)["nickname"] = new_nickname;
  PrintLine(AMStr::amfmt("Rename host: \x1b[9m{}\x1b[29m -> {}", old_nickname,
                         Format(new_nickname, "nickname")));

  return Ok();
}

ECM AMConfigManager::Query(const std::string &targets) const {
  std::istringstream iss(targets);
  std::vector<std::string> names;
  std::string nickname;
  while (iss >> nickname) {
    names.push_back(nickname);
  }
  return Query(names);
}

/** Query hosts by nickname list without parsing input. */
ECM AMConfigManager::Query(const std::vector<std::string> &targets) const {
  auto status = EnsureInitialized("Query");
  if (status.first != EC::Success)
    return status;

  std::vector<std::string> unique_targets = UniqueTargetsKeepOrder(targets);
  if (unique_targets.empty()) {
    auto &client_manager =
        AMClientManager::Instance(const_cast<AMConfigManager &>(*this));
    std::string current =
        client_manager.CLIENT ? client_manager.CLIENT->GetNickname() : "local";
    if (current.empty()) {
      current = "local";
    }
    unique_targets.push_back(current);
  }

  auto hosts = CollectHosts();
  ECM last = Ok();
  for (const auto &nickname : unique_targets) {
    if (nickname.empty()) {
      last = Err(EC::InvalidArg, "empty query target");
      prompt.ErrorFormat(ECM{EC::InvalidArg, "Empty query target"});
      continue;
    }
    auto it = hosts.find(nickname);
    if (it == hosts.end()) {
      std::string msg = AMStr::amfmt("Host {} not found in config",
                                     Format(nickname, "nickname"));
      prompt.ErrorFormat(ECM{EC::InvalidArg, msg});
      last = Err(EC::HostConfigNotFound, msg);
      continue;
    }
    auto rcm = PrintHost(nickname, it->second);
    if (rcm.first != EC::Success) {
      last = rcm;
    }
  }

  return last;
}

ECM AMConfigManager::Add() {
  auto status = EnsureInitialized("Add");
  if (status.first != EC::Success)
    return status;

  std::string nickname;
  HostEntry entry;
  auto prompt_status = PromptAddFields(&nickname, &entry);
  if (prompt_status.first != EC::Success)
    return prompt_status;

  bool canceled = false;
  if (!prompt.PromptYesNo("Save host? (y/N): ", &canceled) || canceled) {
    PrintLine(AMStr::amfmt("🚫  {}\n", Format("Add Canceled", "abort")));
    return Err(EC::ConfigCanceled, "add canceled");
  }

  for (const auto &field : kHostFields) {
    auto it = entry.fields.find(field);
    if (it == entry.fields.end())
      continue;
    auto up_status = UpsertHostField(nickname, it->first, it->second);
    if (up_status.first != EC::Success)
      return up_status;
  }

  PrintLine(AMStr::amfmt("✅ Add new host {}", Format(nickname, "nickname")));
  return Ok();
}

ECM AMConfigManager::Modify(const std::string &nickname) {
  auto status = EnsureInitialized("Modify");
  if (status.first != EC::Success)
    return status;

  if (!HostExists(nickname)) {
    PrintLine(AMStr::amfmt("Host not found: {}", Format(nickname, "nickname")));
    return Err(EC::HostConfigNotFound, "host not found");
  }

  HostEntry entry;
  auto prompt_status = PromptModifyFields(nickname, &entry);
  if (prompt_status.first != EC::Success)
    return prompt_status;

  bool canceled = false;
  if (!prompt.PromptYesNo("Apply changes? (y/N): ", &canceled) || canceled) {
    PrintLine(AMStr::amfmt("🚫 {}\n", Format("Modify Canceled", "abort")));
    return Err(EC::ConfigCanceled, "modify canceled");
  }

  for (const auto &field : entry.fields) {
    auto up_status = UpsertHostField(nickname, field.first, field.second);
    if (up_status.first != EC::Success)
      return up_status;
  }

  PrintLine(Format("Modified host: " + nickname, "success"));
  return Ok();
}

/**
 * @brief Parse and set a host field from config set command arguments.
 */
ECM AMConfigManager::SetHostValue(const std::string &nickname,
                                  const std::string &attrname,
                                  const std::string &value_str) {
  auto status = EnsureInitialized("SetHostValue");
  if (status.first != EC::Success) {
    prompt.ErrorFormat(status);
    return status;
  }
  std::string field = ToLowerCopy(attrname);

  if (nickname.empty()) {
    prompt.ErrorFormat(ECM{EC::InvalidArg, "empty nickname"});
    return Err(EC::InvalidArg, "empty nickname");
  }
  if (!HostExists(nickname)) {
    std::string msg = AMStr::amfmt("Host {} not found in config",
                                   Format(nickname, "nickname"));
    prompt.ErrorFormat(ECM{EC::InvalidArg, msg});
    return Err(EC::HostConfigNotFound, "host not found");
  }

  const std::vector<std::string> allowed_fields = {
      "hostname",    "username",  "port",      "password", "protocol",
      "buffer_size", "trash_dir", "login_dir", "keyfile",  "compression"};
  if (std::find(allowed_fields.begin(), allowed_fields.end(), field) ==
      allowed_fields.end()) {
    std::string msg = "unsupported property name";
    prompt.ErrorFormat(ECM{EC::InvalidArg, msg});
    return Err(EC::InvalidArg, msg);
  }

  Value value;
  if (field == "port") {
    int64_t port = 0;
    if (!ParsePositiveInt(value_str, &port)) {
      std::string msg = "invalid port value";
      prompt.ErrorFormat(ECM{EC::InvalidArg, msg});
      return Err(EC::InvalidArg, msg);
    }
    value = port;
  } else if (field == "buffer_size") {
    try {
      int64_t parsed = std::stoll(value_str);
      if (parsed == 0 || parsed < -1) {
        std::string msg = "invalid buffer_size value";
        prompt.ErrorFormat(ECM{EC::InvalidArg, msg});
        return Err(EC::InvalidArg, msg);
      }
      value = parsed;
    } catch (...) {
      std::string msg = "invalid buffer_size value";
      prompt.ErrorFormat(ECM{EC::InvalidArg, msg});
      return Err(EC::InvalidArg, msg);
    }
  } else if (field == "compression") {
    bool parsed = false;
    if (!ParseBoolToken(value_str, &parsed)) {
      std::string msg = "invalid compression value";
      prompt.ErrorFormat(ECM{EC::InvalidArg, msg});
      return Err(EC::InvalidArg, msg);
    }
    value = parsed;
  } else if (field == "protocol") {
    std::string protocol = ToLowerCopy(value_str);
    if (protocol != "sftp" && protocol != "ftp" && protocol != "local") {
      std::string msg = "invalid protocol value";
      prompt.ErrorFormat(ECM{EC::InvalidArg, msg});
      return Err(EC::InvalidArg, msg);
    }
    value = protocol;
  } else {
    value = value_str;
  }

  std::string old_value;
  auto hosts = CollectHosts();
  auto host_it = hosts.find(nickname);
  if (host_it != hosts.end()) {
    auto field_it = host_it->second.fields.find(field);
    if (field_it != host_it->second.fields.end()) {
      old_value = ValueToString(field_it->second);
    }
  }

  ECM set_status = SetHostField(nickname, field, value, true);
  if (set_status.first != EC::Success) {
    prompt.ErrorFormat(set_status);
    return set_status;
  }

  const std::string new_value = ValueToString(value);
  PrintLine(
      AMStr::amfmt("{}.{}: {} -> {}", nickname, field, old_value, new_value));
  return Ok();
}

/**
 * @brief Persist an encrypted password for a given client nickname.
 */
ECM AMConfigManager::SetClientPasswordEncrypted(
    const std::string &nickname, const std::string &encrypted_password,
    bool dump_now) {
  auto status = EnsureInitialized("SetClientPasswordEncrypted");
  if (status.first != EC::Success) {
    return status;
  }
  if (!HostExists(nickname)) {
    return Err(EC::HostConfigNotFound, "host not found");
  }

  std::string stored = encrypted_password;
  if (!stored.empty() && !AMAuth::IsEncrypted(stored)) {
    stored = AMAuth::EncryptPassword(stored);
  }

  auto up_status = UpsertHostField(nickname, "password", stored);
  if (up_status.first != EC::Success) {
    return up_status;
  }
  if (dump_now) {
    return Dump();
  }
  return Ok();
}

void AMConfigManager::OnExit() {
  try {
    (void)AMConfigManager::Instance().Dump();
    AMConfigManager::Instance().CloseHandles();
  } catch (const std::exception &e) {
    std::cerr << "❌ Toml config files dump failed: " << e.what() << "\n";
    std::terminate();
  }
}

void AMConfigManager::CloseHandles() { storage_.CloseHandles(); }

ECM AMConfigManager::EnsureInitialized(const char *caller) const {
  if (!initialized_) {
    return Err(EC::ConfigNotInitialized,
               AMStr::amfmt("{} called before Init()", caller));
  }
  return Ok();
}

ECM AMConfigManager::SetHostField(const std::string &nickname,
                                  const std::string &field, const Value &value,
                                  bool dump_now) {
  auto status = EnsureInitialized("SetHostField");
  if (status.first != EC::Success) {
    return status;
  }
  auto up_status = UpsertHostField(nickname, field, value);
  if (up_status.first != EC::Success) {
    return up_status;
  }
  if (dump_now) {
    return Dump();
  }
  return Ok();
}

std::string AMConfigManager::ValueToString(const Value &value) const {
  if (std::holds_alternative<int64_t>(value)) {
    return std::to_string(std::get<int64_t>(value));
  }
  if (std::holds_alternative<bool>(value)) {
    return std::get<bool>(value) ? "true" : "false";
  }
  if (std::holds_alternative<std::string>(value)) {
    return std::get<std::string>(value);
  }
  if (std::holds_alternative<std::vector<std::string>>(value)) {
    const auto &items = std::get<std::vector<std::string>>(value);
    std::ostringstream oss;
    for (size_t i = 0; i < items.size(); ++i) {
      if (i > 0)
        oss << ", ";
      oss << items[i];
    }
    return oss.str();
  }
  return "";
}

std::map<std::string, AMConfigManager::HostEntry>
AMConfigManager::CollectHosts() const {
  std::map<std::string, HostEntry> hosts;
  const Json *arr =
      GetHostsArray(storage_.GetJson(DocumentKind::Config).value().get());
  if (!arr)
    return hosts;
  for (const auto &node : *arr) {
    if (!node.is_object())
      continue;
    const Json &host = node;
    if (!IsHostValid(host))
      continue;
    auto nickname = GetStringField(host, "nickname");
    HostEntry entry;
    for (auto it = host.begin(); it != host.end(); ++it) {
      Value value;
      if (!NodeToValue(it.value(), &value))
        continue;
      entry.fields[it.key()] = std::move(value);
    }
    if (!entry.fields.empty())
      hosts[*nickname] = std::move(entry);
  }
  return hosts;
}

ECM AMConfigManager::PrintHost(const std::string &nickname,
                               const HostEntry &entry) const {
  PrintLine("[!pre][" + nickname + "][/pre]");
  size_t width = 0;
  for (const auto &field : kHostFields)
    width = std::max(width, field.size());

  for (const auto &field : kHostFields) {
    auto it = entry.fields.find(field);
    if (it == entry.fields.end())
      continue;
    std::string value = ValueToString(it->second);
    // abort value style in config print
    // std::string styled_value = Format(value, field);
    std::ostringstream line;
    line << std::left << std::setw(static_cast<int>(width)) << field << " :   "
         << (value.empty() ? "\"\"" : value);
    PrintLine(line.str());
  }
  return Ok();
}

bool AMConfigManager::HostExists(const std::string &nickname) const {
  return core_data_.HostExists(nickname);
}

ECM AMConfigManager::UpsertHostField(const std::string &nickname,
                                     const std::string &field, Value value) {
  Json *host = FindHostJsonMutable(
      storage_.GetJson(DocumentKind::Config).value().get(), nickname);
  if (!host) {
    Json *arr =
        EnsureHostsArray(storage_.GetJson(DocumentKind::Config).value().get());
    if (!arr)
      return Err(EC::ConfigInvalid, "invalid host list");
    Json new_host = Json::object();
    new_host["nickname"] = nickname;
    arr->push_back(std::move(new_host));
    host = FindHostJsonMutable(
        storage_.GetJson(DocumentKind::Config).value().get(), nickname);
  }
  if (!host)
    return Err(EC::ConfigInvalid, "invalid host table");

  (*host)["nickname"] = nickname;

  if (std::holds_alternative<int64_t>(value)) {
    (*host)[field] = std::get<int64_t>(value);
    return Ok();
  }
  if (std::holds_alternative<bool>(value)) {
    (*host)[field] = std::get<bool>(value);
    return Ok();
  }
  if (std::holds_alternative<std::string>(value)) {
    std::string str_value = std::get<std::string>(value);
    if (field == "password" && !str_value.empty() &&
        !AMAuth::IsEncrypted(str_value)) {
      str_value = AMAuth::EncryptPassword(str_value);
    }
    (*host)[field] = str_value;
    return Ok();
  }
  if (std::holds_alternative<std::vector<std::string>>(value)) {
    Json arr = Json::array();
    for (const auto &item : std::get<std::vector<std::string>>(value))
      arr.push_back(item);
    (*host)[field] = std::move(arr);
    return Ok();
  }
  return Ok();
}

ECM AMConfigManager::RemoveHost(const std::string &nickname) {
  std::size_t index = 0;
  if (!FindHostJson(storage_.GetJson(DocumentKind::Config).value().get(),
                    nickname, &index))
    return Ok();
  Json *arr =
      EnsureHostsArray(storage_.GetJson(DocumentKind::Config).value().get());
  if (!arr || index >= arr->size())
    return Ok();
  arr->erase(arr->begin() + static_cast<std::ptrdiff_t>(index));
  return Ok();
}

ECM AMConfigManager::PromptAddFields(std::string *nickname, HostEntry *entry) {
  std::string error;
  bool canceled = false;
  while (true) {
    if (!prompt.PromptLine("Nickname: ", nickname, "", true, &canceled)) {
      if (canceled) {
        PrintLine(AMStr::amfmt("🚫 {}\n", Format("Input Abort", "abort")));
        return Err(EC::ConfigCanceled, "add canceled");
      }
      return Err(EC::ConfigInvalid, "failed to read nickname");
    }
    error.clear();
    if (ValidateNickname(*nickname, &error))
      break;
    PrintLine(Format(error, "error"));
  }

  std::string hostname;
  while (true) {
    if (!prompt.PromptLine("Hostname: ", &hostname, "", true, &canceled)) {
      PrintLine(AMStr::amfmt("🚫 {}\n", Format("Input Abort", "abort")));
      return Err(EC::ConfigCanceled, "add canceled");
    }
    if (!hostname.empty())
      break;
    PrintLine(Format("Hostname cannot be empty.", "error"));
  }

  std::string username;
  while (true) {
    if (!prompt.PromptLine("Username: ", &username, "", true, &canceled)) {
      PrintLine(AMStr::amfmt("🚫 {}\n", Format("Input Abort", "abort")));
      return Err(EC::ConfigCanceled, "add canceled");
    }
    if (!username.empty())
      break;
    PrintLine(Format("Username cannot be empty.", "error"));
  }

  std::string port_input;
  int64_t port = 22;
  while (true) {
    if (!prompt.PromptLine("Port (default 22): ", &port_input, "", true,
                           &canceled)) {
      PrintLine(AMStr::amfmt("🚫 {}\n", Format("Input Abort", "abort")));
      return Err(EC::ConfigCanceled, "add canceled");
    }
    if (port_input.empty()) {
      PrintLine("Using default port 22.");
      break;
    }
    if (ParsePositiveInt(port_input, &port))
      break;
    PrintLine(Format("Port must be a positive integer.", "error"));
  }

  std::string password;
  while (true) {
    std::string first;
    std::string second;
    if (prompt.SecurePrompt("Password (optional): ", &first)) {
      return {EC::InvalidArg, "Password entry canceled"};
    }
    if (prompt.SecurePrompt("Confirm password: ", &second)) {
      return {EC::InvalidArg, "Password entry canceled"};
    }
    if (first == second) {
      password = std::move(first);
      AMAuth::SecureZero(second);
      break;
    }
    AMAuth::SecureZero(first);
    AMAuth::SecureZero(second);
    PrintLine(Format("Passwords do not match. Please try again.", "error"));
  }

  std::string protocol;
  while (true) {
    if (!prompt.PromptLine("Protocol (sftp/ftp): ", &protocol, "", true,
                           &canceled)) {
      PrintLine(AMStr::amfmt("🚫 {}\n", Format("Input Abort", "abort")));
      return Err(EC::ConfigCanceled, "add canceled");
    }
    if (protocol.empty()) {
      PrintLine(Format("Protocol cannot be empty.", "error"));
      continue;
    }
    protocol = ToLowerCopy(protocol);
    if (protocol == "sftp" || protocol == "ftp")
      break;
    PrintLine(Format("Protocol must be sftp or ftp.", "error"));
  }

  std::string buffer_input;
  int64_t buffer_size = 24 * AMMB;
  while (true) {
    if (!prompt.PromptLine("Buffer size(Default 24MB): ", &buffer_input, "",
                           true, &canceled)) {
      PrintLine(AMStr::amfmt("🚫 {}\n", Format("Input Abort", "abort")));
      return Err(EC::ConfigCanceled, "add canceled");
    }
    if (buffer_input.empty()) {
      break;
    }
    if (ParsePositiveInt(buffer_input, &buffer_size))
      break;
    PrintLine(Format("Buffer size must be a positive integer.", "error"));
  }

  std::string trash_dir;
  if (!prompt.PromptLine("Trash dir (optional): ", &trash_dir, "", true,
                         &canceled)) {
    PrintLine(AMStr::amfmt("🚫 {}\n", Format("Input Abort", "abort")));
    return Err(EC::ConfigCanceled, "add canceled");
  }

  std::string login_dir;
  if (!prompt.PromptLine("Login dir (optional): ", &login_dir, "", true,
                         &canceled)) {
    PrintLine(AMStr::amfmt("🚫 {}\n", Format("Input Abort", "abort")));
    return Err(EC::ConfigCanceled, "add canceled");
  }

  std::string keyfile;
  if (!prompt.PromptLine("Keyfile (optional): ", &keyfile, "", true,
                         &canceled)) {
    PrintLine(AMStr::amfmt("🚫 {}\n", Format("Input Abort", "abort")));
    return Err(EC::ConfigCanceled, "add canceled");
  }

  bool compression = false;
  compression = prompt.PromptYesNo("Enable compression? (y/N): ", &canceled);
  if (canceled) {
    PrintLine(AMStr::amfmt("🚫 {}\n", Format("Input Abort", "abort")));
    return Err(EC::ConfigCanceled, "add canceled");
  }

  entry->fields.clear();
  entry->fields["hostname"] = hostname;
  entry->fields["username"] = username;
  entry->fields["port"] = port;
  entry->fields["password"] = AMAuth::EncryptPassword(password);
  entry->fields["protocol"] = protocol;
  entry->fields["buffer_size"] = buffer_size;
  entry->fields["trash_dir"] = trash_dir;
  entry->fields["login_dir"] = login_dir;
  entry->fields["keyfile"] = keyfile;
  entry->fields["compression"] = compression;
  AMAuth::SecureZero(password);
  return Ok();
}

ECM AMConfigManager::PromptModifyFields(const std::string &nickname,
                                        HostEntry *entry) {
  auto hosts = CollectHosts();
  auto it = hosts.find(nickname);
  if (it == hosts.end())
    return Err(EC::HostConfigNotFound, "host not found");

  bool canceled = false;
  HostEntry updated = it->second;

  auto get_value = [&](const std::string &field) {
    auto fit = updated.fields.find(field);
    if (fit == updated.fields.end())
      return std::string();
    return ValueToString(fit->second);
  };

  std::string hostname = get_value("hostname");
  if (!prompt.PromptLine("Hostname: ", &hostname, hostname, false, &canceled,
                         false)) {
    PrintLine(AMStr::amfmt("🚫 {}\n", Format("Input Abort", "abort")));
    return Err(EC::ConfigCanceled, "modify canceled");
  }

  std::string username = get_value("username");
  if (!prompt.PromptLine("Username: ", &username, username, false, &canceled,
                         false)) {
    PrintLine(AMStr::amfmt("🚫 {}\n", Format("Input Abort", "abort")));
    return Err(EC::ConfigCanceled, "modify canceled");
  }

  std::string port_input = get_value("port");
  int64_t port = 22;
  if (!port_input.empty())
    ParsePositiveInt(port_input, &port);
  while (true) {
    if (!prompt.PromptLine("Port (default 22): ", &port_input, port_input, true,
                           &canceled, false)) {
      PrintLine(AMStr::amfmt("🚫 {}\n", Format("Input Abort", "abort")));
      return Err(EC::ConfigCanceled, "modify canceled");
    }
    if (port_input.empty())
      break;
    if (ParsePositiveInt(port_input, &port))
      break;
    PrintLine(Format("Port must be a positive integer.", "error"));
  }
  if (!port_input.empty())
    port = std::stoll(port_input);

  Value password_value = std::string();
  auto pw_it = updated.fields.find("password");
  if (pw_it != updated.fields.end()) {
    password_value = pw_it->second;
  }
  bool change_password =
      prompt.PromptYesNo("Change password? (y/N): ", &canceled);
  if (canceled) {
    PrintLine(AMStr::amfmt("🚫 {}\n", Format("Input Abort", "abort")));
    return Err(EC::ConfigCanceled, "modify canceled");
  }
  if (change_password) {
    std::string password;
    while (true) {
      std::string first;
      std::string second;
      if (prompt.SecurePrompt("Password (optional): ", &first)) {
        return {EC::InvalidArg, "Password entry canceled"};
      }
      if (prompt.SecurePrompt("Confirm password: ", &second)) {
        return {EC::InvalidArg, "Password entry canceled"};
      }
      if (first == second) {
        password = std::move(first);
        AMAuth::SecureZero(second);
        break;
      }
      AMAuth::SecureZero(first);
      AMAuth::SecureZero(second);
      PrintLine(Format("Passwords do not match. Please try again.", "error"));
    }
    password_value = AMAuth::EncryptPassword(password);
    AMAuth::SecureZero(password);
  }

  std::string protocol = get_value("protocol");
  while (true) {
    if (!prompt.PromptLine("Protocol (sftp/ftp): ", &protocol, protocol, false,
                           &canceled, false)) {
      PrintLine(AMStr::amfmt("🚫 {}\n", Format("Input Abort", "abort")));
      return Err(EC::ConfigCanceled, "modify canceled");
    }
    protocol = ToLowerCopy(protocol);
    if (protocol == "sftp" || protocol == "ftp")
      break;
    PrintLine(Format("Protocol must be sftp or ftp.", "error"));
  }

  std::string buffer_input = get_value("buffer_size");
  int64_t buffer_size = 24 * AMMB;
  if (!buffer_input.empty())
    ParsePositiveInt(buffer_input, &buffer_size);
  while (true) {
    if (!prompt.PromptLine("Buffer size: ", &buffer_input, buffer_input, false,
                           &canceled, false)) {
      PrintLine(AMStr::amfmt("🚫 {}\n", Format("Input Abort", "abort")));
      return Err(EC::ConfigCanceled, "modify canceled");
    }
    if (buffer_input.empty())
      break;
    if (ParsePositiveInt(buffer_input, &buffer_size))
      break;
    PrintLine(Format("Buffer size must be a positive integer.", "error"));
  }

  std::string trash_dir = get_value("trash_dir");
  if (!prompt.PromptLine("Trash dir (optional): ", &trash_dir, trash_dir, true,
                         &canceled, false)) {
    PrintLine(AMStr::amfmt("🚫 {}\n", Format("Input Abort", "abort")));
    return Err(EC::ConfigCanceled, "modify canceled");
  }

  std::string login_dir = get_value("login_dir");
  if (!prompt.PromptLine("Login dir (optional): ", &login_dir, login_dir, true,
                         &canceled, false)) {
    PrintLine(AMStr::amfmt("🚫 {}\n", Format("Input Abort", "abort")));
    return Err(EC::ConfigCanceled, "modify canceled");
  }

  std::string keyfile = get_value("keyfile");
  if (!prompt.PromptLine("Keyfile (optional): ", &keyfile, keyfile, true,
                         &canceled, false)) {
    PrintLine(AMStr::amfmt("🚫 {}\n", Format("Input Abort", "abort")));
    return Err(EC::ConfigCanceled, "modify canceled");
  }

  bool compression = false;
  bool current_compression = false;
  std::string compression_input = get_value("compression");
  if (ParseBoolToken(compression_input, &current_compression)) {
    compression_input = current_compression ? "true" : "false";
  } else {
    compression_input = "false";
  }
  while (true) {
    if (!prompt.PromptLine("Compression (true/false): ", &compression_input,
                           compression_input, true, &canceled, false)) {
      PrintLine(AMStr::amfmt("🚫 {}\n", Format("Input Abort", "abort")));
      return Err(EC::ConfigCanceled, "modify canceled");
    }
    if (ParseBoolToken(compression_input, &compression)) {
      break;
    }
    PrintLine(Format("Compression must be true or false.", "error"));
  }

  entry->fields.clear();
  entry->fields["hostname"] = hostname;
  entry->fields["username"] = username;
  entry->fields["port"] = port;
  entry->fields["password"] = password_value;
  entry->fields["protocol"] = protocol;
  entry->fields["buffer_size"] = buffer_size;
  entry->fields["trash_dir"] = trash_dir;
  entry->fields["login_dir"] = login_dir;
  entry->fields["keyfile"] = keyfile;
  entry->fields["compression"] = compression;
  return Ok();
}

bool AMConfigManager::ParsePositiveInt(const std::string &input,
                                       int64_t *value) const {
  if (input.empty())
    return false;
  for (char c : input) {
    if (!std::isdigit(static_cast<unsigned char>(c)))
      return false;
  }
  try {
    int64_t parsed = std::stoll(input);
    if (parsed <= 0)
      return false;
    if (value)
      *value = parsed;
    return true;
  } catch (...) {
    return false;
  }
}

bool AMConfigManager::ValidateNickname(const std::string &nickname,
                                       std::string *error) const {
  return core_data_.ValidateNickname(nickname, error);
}
