#pragma once
#include "AMBase/CommonTools.hpp"
#include "AMBase/DataClass.hpp"
#include "AMBase/Enum.hpp"
#include "AMBase/RustTomlRead.h"
#include "AMManager/Prompt.hpp"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <functional>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <queue>
#include <regex>
#include <string>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

/**
 * @brief Configuration document types tracked by storage.
 */
enum class DocumentKind {
  Config = 1,
  Settings = 2,
  KnownHosts = 3,
  History = 4
};

/**
 * @brief Per-document storage state for configuration data.
 */
struct DocumentState {
  std::filesystem::path path;
  std::filesystem::path schema_path;
  ConfigHandle *handle = nullptr;
  nlohmann::ordered_json json;
  mutable std::mutex mtx;
  bool dirty = false;
  std::chrono::system_clock::time_point last_modified;
};

/**
 * @brief Low-level config storage layer for raw persistence and file I/O.
 */
class AMConfigStorage {
public:
  using Path = std::vector<std::string>;
  using Value =
      std::variant<int64_t, bool, std::string, std::vector<std::string>>;
  template <class T>
  static inline constexpr bool kValueTypeSupported =
      std::is_arithmetic_v<T> || std::is_same_v<T, std::string> ||
      std::is_same_v<T, nlohmann::ordered_json *>;
  /**
   * @brief Construct a storage layer with empty state.
   */
  AMConfigStorage();

  /**
   * @brief Stop the background writer thread on destruction.
   */
  ~AMConfigStorage();

  /**
   * @brief Initialize storage paths from a project root directory.
   * @param root_dir Project root directory.
   * @return ECM success or failure.
   */
  ECM Init(const std::filesystem::path &root_dir);

  /**
   * @brief Initialize storage with explicit document paths and schemas.
   * @param root_dir Project root directory.
   * @param paths Document paths keyed by kind.
   * @param schemas Schema paths keyed by kind.
   * @return ECM success or failure.
   */
  ECM Init(
      const std::filesystem::path &root_dir,
      const std::unordered_map<DocumentKind, std::filesystem::path> &paths,
      const std::unordered_map<DocumentKind, std::filesystem::path> &schemas);

  /**
   * @brief Bind cfgffi handles used for persisting config documents.
   * @param config_handle Config handle pointer.
   * @param settings_handle Settings handle pointer.
   * @param known_hosts_handle Known hosts handle pointer.
   * @param history_handle History handle pointer.
   * @return ECM success or failure.
   */
  ECM BindHandles(ConfigHandle *config_handle, ConfigHandle *settings_handle,
                  ConfigHandle *known_hosts_handle,
                  ConfigHandle *history_handle);

  /**
   * @brief Load config, settings, and known_hosts documents from disk.
   * @return ECM success or failure.
   */
  ECM LoadAll();

  /**
   * @brief Load a document from disk by kind.
   * @param kind Document kind to load.
   * @return ECM success or failure.
   */
  ECM Load(DocumentKind kind, bool force = false);

  /**
   * @brief Close storage with a final dump and shutdown.
   * @return ECM success or failure.
   */
  ECM Close();

  /**
   * @brief Release cfgffi handles and reset pointers without dumping.
   */
  void CloseHandles();

  /**
   * @brief Snapshot a document in a thread-safe manner.
   * @param kind Document kind to snapshot.
   * @return JSON snapshot copy.
   */
  nlohmann::ordered_json Snapshot(DocumentKind kind) const;

  /**
   * @brief Report whether a document has pending changes.
   * @param kind Document kind to check.
   * @return True if the document is dirty.
   */
  bool IsDirty(DocumentKind kind) const;

  /**
   * @brief Mutate a document and optionally persist immediately.
   * @param kind Document kind to mutate.
   * @param mutator Mutation callback invoked with the JSON object.
   * @param dump_now Whether to persist immediately.
   * @return ECM success or failure.
   */
  ECM Mutate(DocumentKind kind,
             std::function<void(nlohmann::ordered_json &)> mutator,
             bool dump_now = false);

  /**
   * @brief Persist all document snapshots to disk.
   * @return ECM success or failure.
   */
  ECM DumpAll();

  /**
   * @brief Persist a single document snapshot to disk.
   * @param kind Document kind to dump.
   * @param path Override output path (empty uses document path).
   * @return ECM success or failure.
   */
  ECM Dump(DocumentKind kind, const std::string &path = "");

  /**
   * @brief Trigger backup logic when needed.
   * @return ECM success or failure.
   */
  ECM BackupIfNeeded();

  /**
   * @brief Start the background writer thread if not running.
   */
  void StartWriteThread();

  /**
   * @brief Stop the background writer thread and drain pending tasks.
   */
  void StopWriteThread();

  /**
   * @brief Submit a write task to the background queue.
   * @param task Task returning ECM to execute asynchronously.
   */
  void SubmitWriteTask(std::function<ECM()> task);

  /**
   * @brief Submit a no-arg write task to the background queue.
   * @param task Task to execute asynchronously.
   */
  void SubmitWriteTaskVoid(std::function<void()> task);

  /**
   * @brief Provide mutable access to a document JSON.
   * @return Reference to JSON object.
   */
  [[nodiscard]] std::optional<std::reference_wrapper<nlohmann::ordered_json>>
  GetJson(DocumentKind kind);

  /**
   * @brief Provide read-only access to a document JSON.
   * @return Const reference to JSON object.
   */
  [[nodiscard]]
  std::optional<std::reference_wrapper<const nlohmann::ordered_json>>
  GetJson(DocumentKind kind) const;

  /**
   * @brief Return the root directory used by the storage layer.
   * @return Root directory path.
   */
  [[nodiscard]] const std::filesystem::path &RootDir() const;

  /**
   * @brief Return the config and schema paths tracked by the storage layer.
   */
  [[nodiscard]]
  std::pair<std::optional<std::filesystem::path>,
            std::optional<std::filesystem::path>>
  GetDataPath(DocumentKind kind) const;

  template <typename T>
  bool QueryKey(const nlohmann::ordered_json &root, const Path &path,
                T *value) const {
    static_assert(kValueTypeSupported<T>, "T is not supported");
    if (!value) {
      return false;
    }
    const nlohmann::ordered_json *node = &root;
    for (const auto &seg : path) {
      if (!node->is_object()) {
        return false;
      }
      auto it = node->find(seg);
      if (it == node->end()) {
        return false;
      }
      node = &(*it);
    }
    if constexpr (std::is_same_v<T, bool>) {
      if (!node->is_boolean()) {
        return false;
      }
      *value = node->get<bool>();
      return true;
    } else if constexpr (std::is_same_v<T, std::string>) {
      if (!node->is_string()) {
        return false;
      }
      *value = node->get<std::string>();
      return true;
    } else if constexpr (std::is_floating_point_v<T>) {
      if (!node->is_number()) {
        return false;
      }
      *value = static_cast<T>(node->get<double>());
      return true;
    } else if constexpr (std::is_integral_v<T>) {
      if (!node->is_number()) {
        return false;
      }
      if (node->is_number_integer()) {
        const int64_t raw = node->get<int64_t>();
        if (raw < static_cast<int64_t>(std::numeric_limits<T>::min()) ||
            raw > static_cast<int64_t>(std::numeric_limits<T>::max())) {
          return false;
        }
        *value = static_cast<T>(raw);
        return true;
      }
      return false;
    } else if constexpr (std::is_same_v<T, nlohmann::ordered_json *>) {
      *value = const_cast<nlohmann::ordered_json *>(node);
      return true;
    } else {
      return false;
    }
  }

  /**
   * @brief Set or create a JSON value by path in a root object.
   * @param root JSON root to mutate.
   * @param path Path segments to create or update.
   * @param value Value to assign at the target node.
   * @return True when the value is set.
   */
  template <typename T>
  bool SetKey(nlohmann::ordered_json &root, const Path &path, T value) {
    static_assert(kValueTypeSupported<T>, "T is not supported");
    nlohmann::ordered_json *node = &root;
    for (size_t i = 0; i < path.size(); ++i) {
      const std::string &seg = path[i];
      if (i + 1 == path.size()) {
        (*node)[seg] = value;
        return true;
      }
      if (!node->is_object()) {
        *node = nlohmann::ordered_json::object();
      }
      if (!node->contains(seg) || !(*node)[seg].is_object()) {
        (*node)[seg] = nlohmann::ordered_json::object();
      }
      node = &(*node)[seg];
    }
    return false;
  }

  template <typename T>
  T ResolveArg(DocumentKind kind, const Path &path, const T &default_value,
               const std::function<T(T)> &post_process) {
    static_assert(kValueTypeSupported<T>, "T is not supported");
    auto json = GetJson(kind);
    if (!json.has_value()) {
      return default_value;
    }
    T value = {};
    if (!QueryKey(json->get(), path, &value)) {
      return default_value;
    }
    if (post_process) {
      return post_process(value);
    }
    return value;
  }

private:
  /**
   * @brief Locate a document state by kind.
   * @param kind Document kind.
   * @return Pointer to document state or nullptr.
   */
  DocumentState *GetDoc_(DocumentKind kind);

  /**
   * @brief Locate a document state by kind (const).
   * @param kind Document kind.
   * @return Pointer to document state or nullptr.
   */
  const DocumentState *GetDoc_(DocumentKind kind) const;

  /**
   * @brief Load a document into memory using cfgffi.
   * @param kind Document kind.
   * @param doc Document state to populate.
   * @return ECM success or failure.
   */
  ECM LoadDocument_(DocumentKind kind, DocumentState *doc);

  /**
   * @brief Write JSON content into a cfgffi handle and refresh the cache.
   * @param doc Document state to dump.
   * @param kind Document kind used in error messages.
   * @return ECM success or failure.
   */
  ECM WriteHandleJson_(DocumentState *doc, DocumentKind kind);

  /**
   * @brief Write a TOML snapshot to a target path using the given handle.
   * @param handle cfgffi handle pointer.
   * @param json JSON payload to serialize.
   * @param out_path Target file path.
   */
  void WriteSnapshotToPath_(ConfigHandle *handle, const std::string &json,
                            const std::filesystem::path &out_path) const;

  /**
   * @brief Worker loop that processes queued write tasks.
   */
  void WriteThreadLoop_();

  std::filesystem::path root_dir_;
  std::map<DocumentKind, DocumentState> docs_;
  std::mutex handle_mtx_;
  std::mutex write_mtx_;
  std::condition_variable write_cv_;
  std::queue<std::function<ECM()>> write_queue_;
  std::thread write_thread_;
  std::atomic<bool> write_running_{false};
  std::atomic<bool> shutdown_requested_{false};
  bool backup_prune_checked_ = false;
};

/**
 * @brief Data access layer for non-style configuration entities.
 */
class AMConfigCoreData {
public:
  using Path = std::vector<std::string>;
  using Value =
      std::variant<int64_t, bool, std::string, std::vector<std::string>>;

  /**
   * @brief Construct a core data layer with default rules.
   */
  AMConfigCoreData();

  /**
   * @brief Bind the storage layer used for raw config access.
   * @param storage Storage layer pointer.
   */
  void BindStorage(AMConfigStorage *storage);

  /**
   * @brief Report whether the layer has an attached storage instance.
   * @return True when storage is bound.
   */
  [[nodiscard]] bool HasStorage() const;

  /**
   * @brief Load history data into memory (in-memory only for now).
   * @return ECM success or failure.
   */
  ECM LoadHistory();

  /**
   * @brief Fetch history commands for a nickname.
   * @param nickname Host nickname.
   * @param out Output list for commands.
   * @return ECM success or failure.
   */
  ECM GetHistoryCommands(std::string nickname,
                         std::vector<std::string> *out) const;

  /**
   * @brief Store history commands for a nickname and optionally persist.
   * @param nickname Host nickname.
   * @param commands Command list to store.
   * @param dump_now Whether to persist immediately.
   * @return ECM success or failure.
   */
  ECM SetHistoryCommands(const std::string &nickname,
                         const std::vector<std::string> &commands,
                         bool dump_now = true);

  /**
   * @brief Check whether a host nickname exists in the configuration.
   * @param nickname Host nickname.
   * @return True when the nickname is present.
   */
  [[nodiscard]] bool HostExists(const std::string &nickname) const;

  /**
   * @brief Validate whether a nickname is legal and not already used.
   * @param nickname Host nickname to validate.
   * @param error Output error message on failure.
   * @return True when the nickname is valid.
   */
  bool ValidateNickname(const std::string &nickname, std::string *error) const;

private:
  AMConfigStorage *storage_ = nullptr;
  std::regex nickname_pattern_;
};

/**
 * @brief Style access layer for UI and formatting configuration.
 */
class AMConfigStyleData {
public:
  /**
   * @brief Construct a style layer with no bound storage.
   */
  AMConfigStyleData();

  /**
   * @brief Bind the storage layer used for style configuration lookups.
   * @param storage Storage layer pointer.
   */
  void BindStorage(AMConfigStorage *storage);

  /**
   * @brief Apply a named style to a string with optional path context.
   * @param ori_str Original string.
   * @param style_name Style key name.
   * @param path_info Optional path info for styling decisions.
   * @return Styled string output.
   */
  [[nodiscard]] std::string Format(const std::string &ori_str,
                                   const std::string &style_name,
                                   const PathInfo *path_info = nullptr) const;

  /**
   * @brief Create a progress bar using the current style configuration.
   * @param total_size Total bytes for the progress bar.
   * @param prefix Prefix label displayed before the bar.
   * @return Configured progress bar instance.
   */
  [[nodiscard]] AMProgressBar
  CreateProgressBar(int64_t total_size, const std::string &prefix) const;

  /**
   * @brief Format a UTF-8 table using configured style defaults.
   * @param keys Column headers.
   * @param rows Row data.
   * @return Formatted table string.
   */
  [[nodiscard]] std::string
  FormatUtf8Table(const std::vector<std::string> &keys,
                  const std::vector<std::vector<std::string>> &rows) const;

private:
  /**
   * @brief Build progress bar style from settings.
   * @return Progress bar style configuration.
   */
  AMProgressBarStyle BuildProgressBarStyle_() const;

  AMConfigStorage *storage_ = nullptr;
  mutable std::optional<AMProgressBarStyle> progress_bar_style_;
};

/**
 * @brief CLI exposure layer for configuration commands.
 */
class AMConfigCLIAdapter {
public:
  using SimpleCallback = std::function<ECM()>;
  using StringCallback = std::function<ECM(const std::string &)>;
  using StringsCallback = std::function<ECM(const std::vector<std::string> &)>;
  using RenameCallback =
      std::function<ECM(const std::string &, const std::string &)>;

  /**
   * @brief Construct an empty CLI adapter without callbacks.
   */
  AMConfigCLIAdapter();

  /**
   * @brief Bind the list callback used by CLI.
   * @param cb Callback to invoke for list.
   */
  void SetListCallback(SimpleCallback cb);

  /**
   * @brief Bind the list-name callback used by CLI.
   * @param cb Callback to invoke for list-name.
   */
  void SetListNameCallback(SimpleCallback cb);

  /**
   * @brief Bind the add callback used by CLI.
   * @param cb Callback to invoke for add.
   */
  void SetAddCallback(SimpleCallback cb);

  /**
   * @brief Bind the modify callback used by CLI.
   * @param cb Callback to invoke for modify.
   */
  void SetModifyCallback(StringCallback cb);

  /**
   * @brief Bind the delete callback used by CLI.
   * @param cb Callback to invoke for delete.
   */
  void SetDeleteCallback(StringCallback cb);

  /**
   * @brief Bind the delete-list callback used by CLI.
   * @param cb Callback to invoke for delete-list.
   */
  void SetDeleteListCallback(StringsCallback cb);

  /**
   * @brief Bind the query callback used by CLI.
   * @param cb Callback to invoke for query.
   */
  void SetQueryCallback(StringCallback cb);

  /**
   * @brief Bind the query-list callback used by CLI.
   * @param cb Callback to invoke for query-list.
   */
  void SetQueryListCallback(StringsCallback cb);

  /**
   * @brief Bind the rename callback used by CLI.
   * @param cb Callback to invoke for rename.
   */
  void SetRenameCallback(RenameCallback cb);

  /**
   * @brief Bind the src callback used by CLI.
   * @param cb Callback to invoke for src.
   */
  void SetSrcCallback(SimpleCallback cb);

  /**
   * @brief List configuration entries for CLI output.
   * @return ECM success or failure.
   */
  [[nodiscard]] ECM List() const;

  /**
   * @brief List configuration entry names for CLI output.
   * @return ECM success or failure.
   */
  [[nodiscard]] ECM ListName() const;

  /**
   * @brief Add a configuration entry for CLI output.
   * @return ECM success or failure.
   */
  [[nodiscard]] ECM Add() const;

  /**
   * @brief Modify a configuration entry.
   * @param nickname Entry nickname.
   * @return ECM success or failure.
   */
  [[nodiscard]] ECM Modify(const std::string &nickname) const;

  /**
   * @brief Delete a configuration entry.
   * @param nickname Entry nickname.
   * @return ECM success or failure.
   */
  [[nodiscard]] ECM Delete(const std::string &nickname) const;

  /**
   * @brief Delete configuration entries by list.
   * @param targets Entry nicknames.
   * @return ECM success or failure.
   */
  [[nodiscard]] ECM Delete(const std::vector<std::string> &targets) const;

  /**
   * @brief Query a configuration entry.
   * @param nickname Entry nickname.
   * @return ECM success or failure.
   */
  [[nodiscard]] ECM Query(const std::string &nickname) const;

  /**
   * @brief Query configuration entries by list.
   * @param targets Entry nicknames.
   * @return ECM success or failure.
   */
  [[nodiscard]] ECM Query(const std::vector<std::string> &targets) const;

  /**
   * @brief Rename a configuration entry.
   * @param old_nickname Current nickname.
   * @param new_nickname New nickname.
   * @return ECM success or failure.
   */
  [[nodiscard]] ECM Rename(const std::string &old_nickname,
                           const std::string &new_nickname);

  /**
   * @brief Print configuration source file locations for CLI.
   * @return ECM success or failure.
   */
  [[nodiscard]] ECM Src() const;

private:
  /**
   * @brief Build a standardized error response for missing callbacks.
   * @param action Action name being invoked.
   * @return ECM error response.
   */
  [[nodiscard]] ECM MissingCallback_(const std::string &action) const;

  SimpleCallback list_cb_;
  SimpleCallback list_name_cb_;
  SimpleCallback add_cb_;
  SimpleCallback src_cb_;
  StringCallback modify_cb_;
  StringCallback delete_cb_;
  StringsCallback delete_list_cb_;
  StringCallback query_cb_;
  StringsCallback query_list_cb_;
  RenameCallback rename_cb_;
};

class AMConfigManager {
public:
  using Path = std::vector<std::string>;
  using Value =
      std::variant<int64_t, bool, std::string, std::vector<std::string>>;
  enum class ResolveArgType {
    TimeoutMs,
    RefreshIntervalMs,
    HeartbeatIntervalS,
    TraceNum,
    MaxHistoryCount
  };

  struct ClientConfig {
    ConRequst request;
    ClientProtocol protocol = ClientProtocol::SFTP;
    int64_t buffer_size = -1;
    std::string login_dir = "";
  };

  /**
   * @brief Known host entry for SSH fingerprint verification.
   */
  struct KnownHostEntry {
    std::string nickname;
    std::string hostname;
    int port = 0;
    std::string protocol;
    std::string fingerprint;
    std::string fingerprint_sha256;
  };

  using KnownHostCallback = std::function<ECM(AMConfigManager::KnownHostEntry)>;

  static AMConfigManager &Instance();

  AMConfigManager(const AMConfigManager &) = delete;
  AMConfigManager &operator=(const AMConfigManager &) = delete;
  AMConfigManager(AMConfigManager &&) = delete;
  AMConfigManager &operator=(AMConfigManager &&) = delete;

  /** @brief Stop the background writer and release config handles. */
  ~AMConfigManager();

  ECM Init();
  ECM Dump();

  [[nodiscard]] std::string Format(const std::string &ori_str,
                                   const std::string &style_name,
                                   const PathInfo *path_info = nullptr) const;

  [[nodiscard]] ECM List() const;
  [[nodiscard]] ECM ListName() const;
  /** Return a list of configured host nicknames. */
  [[nodiscard]] std::vector<std::string> ListHostnames() const;
  [[nodiscard]] std::pair<ECM, std::vector<std::string>>
  PrivateKeys(bool print_sign = false) const;
  /**
   * @brief Find a known host entry by hostname, port, and protocol.
   */
  [[nodiscard]] std::pair<ECM, std::optional<KnownHostEntry>>
  FindKnownHost(const std::string &hostname, int port,
                const std::string &protocol) const;
  /**
   * @brief Insert or update a known host entry and optionally persist it.
   */
  ECM UpsertKnownHost(const KnownHostEntry &entry, bool dump_now = true);
  /**
   * @brief Build a known host verification callback for SFTP clients.
   */
  KnownHostCallback BuildKnownHostCallback();
  /** Return the project root directory path. */
  [[nodiscard]] std::filesystem::path ProjectRoot() const;
  [[nodiscard]] std::pair<ECM, ClientConfig>
  GetClientConfig(const std::string &nickname);
  /**
   * @brief Create a progress bar configured from style.ProgressBar settings.
   */
  [[nodiscard]] AMProgressBar
  CreateProgressBar(int64_t total_size, const std::string &prefix) const;
  /**
   * @brief Create a UTF-8 table using style.Table settings.
   */
  [[nodiscard]] std::string
  FormatUtf8Table(const std::vector<std::string> &keys,
                  const std::vector<std::vector<std::string>> &rows) const;
  [[nodiscard]] int GetSettingInt(const Path &path, int default_value) const;
  /**
   * @brief Resolve an integer setting by type with optional post-processing.
   */
  [[nodiscard]] int ResolveArg(ResolveArgType target_type,
                               int default_value) const;
  /**
   * @brief Resolve network timeout from settings with a default fallback.
   */
  [[nodiscard]] int ResolveTimeoutMs(int default_timeout_ms = 5000) const;
  /**
   * @brief Resolve transfer refresh interval from settings with defaults.
   */
  [[nodiscard]] int ResolveRefreshIntervalMs() const;
  /**
   * @brief Resolve heartbeat interval from settings with a default fallback.
   */
  [[nodiscard]] int ResolveHeartbeatInterval() const;
  /**
   * @brief Resolve trace buffer size from settings with sane defaults.
   */
  [[nodiscard]] ssize_t ResolveTraceNum() const;
  /** Return a string setting value or the provided default. */
  [[nodiscard]] std::string
  GetSettingString(const Path &path, const std::string &default_value) const;
  /**
   * @brief Query a UserVars entry by name.
   */
  bool GetUserVar(const std::string &name, std::string *value) const;
  /**
   * @brief List all UserVars entries.
   */
  [[nodiscard]] std::vector<std::pair<std::string, std::string>>
  ListUserVars() const;
  /**
   * @brief Set a UserVars entry and optionally persist to settings.
   */
  ECM SetUserVar(const std::string &name, const std::string &value,
                 bool dump_now = true);
  /**
   * @brief Remove a UserVars entry and optionally persist to settings.
   */
  ECM RemoveUserVar(const std::string &name, bool dump_now = true);
  [[nodiscard]] ECM Src() const;
  [[nodiscard]] ECM Delete(const std::string &targets);
  /**
   * @brief Delete hosts by nickname list without parsing input.
   */
  [[nodiscard]] ECM Delete(const std::vector<std::string> &targets);
  [[nodiscard]] ECM Rename(const std::string &old_nickname,
                           const std::string &new_nickname);
  [[nodiscard]] ECM Query(const std::string &targets) const;
  /**
   * @brief Query hosts by nickname list without parsing input.
   */
  [[nodiscard]] ECM Query(const std::vector<std::string> &targets) const;
  [[nodiscard]] ECM Add();
  [[nodiscard]] ECM Modify(const std::string &nickname);
  /**
   * @brief Validate whether a nickname is legal and not already used.
   */
  bool ValidateNickname(const std::string &nickname, std::string *error) const;
  /**
   * @brief Persist an encrypted password for a given client nickname.
   */
  ECM SetClientPasswordEncrypted(const std::string &nickname,
                                 const std::string &encrypted_password,
                                 bool dump_now = true);
  /** Set a host field and optionally dump config. */
  ECM SetHostField(const std::string &nickname, const std::string &field,
                   const Value &value, bool dump_now = true);

  /**
   * @brief Parse and set a host field from config set command arguments.
   */
  ECM SetHostValue(const std::string &nickname, const std::string &attrname,
                   const std::string &value);

  /**
   * @brief Load history data from .AMSFTP_History.toml into memory.
   */
  ECM LoadHistory();

  /**
   * @brief Fetch history commands for a nickname.
   */
  ECM GetHistoryCommands(const std::string &nickname,
                         std::vector<std::string> *out);

  /**
   * @brief Store history commands for a nickname and optionally persist.
   */
  ECM SetHistoryCommands(const std::string &nickname,
                         const std::vector<std::string> &commands,
                         bool dump_now = true);

  /**
   * @brief Resolve history size limit from settings with minimum 10.
   */
  [[nodiscard]] int ResolveMaxHistoryCount(int default_value = 10) const;

  /**
   * @brief Submit a no-arg write task to the background writer thread.
   */
  void SubmitWriteTask(std::function<void()> task);

  /**
   * @brief Backup config/settings/known_hosts when the interval elapses.
   */
  ECM ConfigBackupIfNeeded();

  /** Query a value at path for config/settings JSON. */
  bool QueryKey(const nlohmann::ordered_json &root, const Path &path,
                Value *value) const;
  /** Set or create a value at path for config/settings JSON. */
  template <typename T>
  bool SetKey(nlohmann::ordered_json &root, const Path &path, T value) {
    nlohmann::ordered_json *node = &root;
    for (size_t i = 0; i < path.size(); ++i) {
      const std::string &seg = path[i];
      if (i + 1 == path.size()) {
        (*node)[seg] = value;
        return true;
      }
      if (!node->is_object()) {
        *node = nlohmann::ordered_json::object();
      }
      if (!node->contains(seg) || !(*node)[seg].is_object()) {
        (*node)[seg] = nlohmann::ordered_json::object();
      }
      node = &(*node)[seg];
    }
    return false;
  }

  [[nodiscard]] bool HostExists(const std::string &nickname) const;

private:
  AMConfigManager() = default;

  struct HostEntry {
    std::map<std::string, Value> fields;
  };

  static void OnExit();
  void CloseHandles();
  ECM EnsureInitialized(const char *caller) const;
  [[nodiscard]] std::string ValueToString(const Value &value) const;
  [[nodiscard]] std::map<std::string, HostEntry> CollectHosts() const;
  [[nodiscard]] ECM PrintHost(const std::string &nickname,
                              const HostEntry &entry) const;
  ECM UpsertHostField(const std::string &nickname, const std::string &field,
                      Value value);
  ECM RemoveHost(const std::string &nickname);

  ECM PromptAddFields(std::string *nickname, HostEntry *entry);
  ECM PromptModifyFields(const std::string &nickname, HostEntry *entry);
  bool ParsePositiveInt(const std::string &input, int64_t *value) const;
  /**
   * @brief Persist in-memory history JSON to disk.
   */
  ECM DumpHistory_();

  AMConfigStorage storage_;
  AMConfigCoreData core_data_;
  AMConfigStyleData style_data_;
  AMConfigCLIAdapter cli_adapter_;
  KnownHostCallback known_host_cb_ = {};
  AMPromptManager &prompt = AMPromptManager::Instance();

  bool initialized_ = false;
  bool exit_hook_installed_ = false;
};
