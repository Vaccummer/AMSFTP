#pragma once
#include "AMBase/DataClass.hpp"
#include "AMBase/RustTomlRead.h"
#include "AMBase/tools/bar.hpp"
#include "AMBase/tools/json.hpp"
#include <condition_variable>
#include <handleapi.h>
#include <queue>
#include <thread>


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

  /**
   * @brief Return a thread-safe copy of the JSON document.
   * @return Copied JSON payload.
   */
  [[nodiscard]] nlohmann::ordered_json GetJson() const {
    std::lock_guard<std::mutex> lock(mtx);
    return json;
  }

  /**
   * @brief Return a thread-safe serialized JSON string.
   * @param indent Indent passed to nlohmann::json::dump.
   * @return Serialized JSON text.
   */
  [[nodiscard]] std::string GetJsonStr(int indent = 2) const {
    std::lock_guard<std::mutex> lock(mtx);
    return json.dump(indent);
  }

  /**
   * @brief Acquire a document mutex lock for guarded JSON access.
   * @return Unique lock holding the document mutex.
   */
  [[nodiscard]] std::unique_lock<std::mutex> LockJson() const {
    return std::unique_lock<std::mutex>(mtx);
  }

  /**
   * @brief Return a const reference to JSON without locking.
   * @return Const JSON reference. Caller must hold LockJson().
   */
  [[nodiscard]] const nlohmann::ordered_json &GetJsonConstRef() const {
    return json;
  }
};

/**
 * @brief Low-level config storage layer for raw persistence and file I/O.
 */
class AMConfigStorage {
public:
  using Path = std::vector<std::string>;
  using DumpErrorCallback = std::function<void(ECM)>;

  /**
   * @brief Construct a storage layer with empty state.
   */
  AMConfigStorage() = default;

  /**
   * @brief Stop the background writer thread on destruction.
   */
  virtual ~AMConfigStorage() { CloseHandles(); };

  /**
   * @brief Initialize storage paths from a project root directory.
   * @param root_dir Project root directory.
   * @return ECM success or failure.
   */
  ECM AMInit(const std::filesystem::path &root_dir);

  /**
   * @brief Initialize storage with explicit document paths and schemas.
   * @param root_dir Project root directory.
   * @param paths Document paths keyed by kind.
   * @param schemas Schema paths keyed by kind.
   * @return ECM success or failure.
   */
  ECM AMInit(
      const std::filesystem::path &root_dir,
      const std::unordered_map<DocumentKind, std::filesystem::path> &paths,
      const std::unordered_map<DocumentKind, std::filesystem::path> &schemas);

  /**
   * @brief Load a document from disk, or all documents when kind is nullopt.
   * @param kind Target document kind; nullopt means load all.
   * @return ECM success or failure.
   */
  ECM Load(std::optional<DocumentKind> kind = std::nullopt, bool force = false);

  /**
   * @brief Release cfgffi handles and reset pointers without dumping.
   */
  void CloseHandles();

  /**
   * @brief Report whether a document has pending changes.
   * @param kind Document kind to check.
   * @return True if the document is dirty.
   */
  bool IsDirty(DocumentKind kind) const;

  /**
   * @brief Persist all document snapshots to disk.
   * @return ECM success or failure.
   */
  ECM DumpAll(bool async = false);

  /**
   * @brief Persist a single document snapshot to disk.
   * @param kind Document kind to dump.
   * @param path Override output path (empty uses document path).
   * @return ECM success or failure.
   */
  ECM Dump(DocumentKind kind, const std::string &path = "", bool async = false);

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
   * @brief Register a callback invoked on dump errors.
   * @param cb Callback to receive error ECM.
   */
  void SetDumpErrorCallback(DumpErrorCallback cb);

  /**
   * @brief Return a thread-safe copy of a document JSON.
   * @param kind Document kind to snapshot.
   * @param value Output JSON snapshot copy.
   * @return True when the document exists and value is written.
   */
  [[nodiscard]] bool GetJson(DocumentKind kind,
                             nlohmann::ordered_json *value) const;

  /**
   * @brief Return a thread-safe serialized JSON string of a document.
   * @param kind Document kind to snapshot.
   * @param value Output JSON string snapshot.
   * @param indent Indent passed to nlohmann::json::dump.
   * @return True when the document exists and value is written.
   */
  [[nodiscard]] bool GetJsonStr(DocumentKind kind, std::string *value,
                                int indent = 2) const;

  /**
   * @brief Return the config data path tracked for a document.
   * @param kind Document kind to query.
   * @param value Output path when available.
   * @return True when the document exists and value is written.
   */
  [[nodiscard]] bool GetDataPath(DocumentKind kind,
                                 std::filesystem::path *value) const;

  /** Return the project root directory path. */
  [[nodiscard]] std::filesystem::path ProjectRoot() const;

  /**
   * @brief Backup config/settings/known_hosts when the interval elapses.
   */
  ECM ConfigBackupIfNeeded();

  /**
   * @brief Persist an encrypted password for a given client nickname.
   */
  // ECM SetClientPasswordEncrypted(const std::string &nickname,
  //                                const std::string &encrypted_password,
  //                                bool dump_now = true);
  // /** Set a host field and optionally dump config. */
  // ECM SetHostField(const std::string &nickname, const std::string &field,
  //                  const Value &value, bool dump_now = true);
  // /**
  //  * @brief Validate whether a nickname is legal and not already used.
  //  */
  // bool ValidateNickname(const std::string &nickname, std::string *error)
  // const;
  // /**
  //  * @brief Check whether a host nickname exists in the configuration.
  //  * @param nickname Host nickname.
  //  * @return True when the nickname is present.
  //  */
  // [[nodiscard]] bool HostExists(const std::string &nickname) const;

  template <typename T>
  T ResolveArg(DocumentKind kind, const Path &path, const T &default_value,
               const std::function<T(T)> &post_process) const {
    static_assert(AMJson::kValueTypeSupported<T>, "T is not supported");
    const DocumentState *doc = GetDoc_(kind);
    if (!doc) {
      return default_value;
    }
    std::lock_guard<std::mutex> lock(doc->mtx);
    T value = {};
    if (!AMJson::QueryKey(doc->GetJsonConstRef(), path, &value)) {
      return default_value;
    }
    if (post_process) {
      return post_process(value);
    }
    return value;
  }
  template <typename T>
  bool ResolveArg(DocumentKind kind, const Path &path, T *data) {
    static_assert(AMJson::kValueTypeSupported<T>, "T is not supported");
    const DocumentState *doc = GetDoc_(kind);
    std::lock_guard<std::mutex> lock(doc->mtx);
    if (!AMJson::QueryKey(doc->GetJsonConstRef(), path, data)) {
      return false;
    }
    return true;
  }

  // conduct a read-only operation on a document's JSON with a provided
  // transform in lock guard
  inline bool
  ExternaLView(DocumentKind kind,
               const std::function<void(const Json &)> &transform) const {
    const DocumentState *doc = GetDoc_(kind);
    if (!doc || !transform) {
      return false;
    }
    std::lock_guard<std::mutex> lock(doc->mtx);
    try {
      transform(doc->GetJsonConstRef());
      return true;
    } catch (...) {
      return false;
    }
  }

  template <typename T>
  bool SetArg(DocumentKind kind, const Path &path, T value) {
    static_assert(AMJson::kValueTypeSupported<T>, "T is not supported");
    DocumentState *doc = GetDoc_(kind);
    if (!doc) {
      return false;
    }
    std::lock_guard<std::mutex> lock(doc->mtx);
    if (!doc->json.is_object()) {
      doc->json = nlohmann::ordered_json::object();
    }
    if (!AMJson::SetKey(doc->json, path, value)) {
      return false;
    }
    doc->dirty = true;
    return true;
  }

  bool DelArg(DocumentKind kind, const Path &path) {
    DocumentState *doc = GetDoc_(kind);
    if (!doc) {
      return false;
    }
    std::lock_guard<std::mutex> lock(doc->mtx);
    if (!doc->json.is_object()) {
      return false;
    }
    if (!AMJson::DelKey(doc->json, path)) {
      return false;
    }
    doc->dirty = true;
    return true;
  }

protected:
  friend class AMHostManager;
  /**
   * @brief Notify any registered dump-error callback.
   * @param err Error ECM to forward.
   */
  void NotifyDumpError_(const ECM &err) const;

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
  void WriteSnapshotToPath_(ConfigHandle *handle, std::string_view json,
                            const std::filesystem::path &out_path) const;

  /**
   * @brief Worker loop that processes queued write tasks.
   */
  void WriteThreadLoop_();

  std::filesystem::path root_dir_;
  std::unordered_map<DocumentKind, DocumentState> docs_;
  std::mutex handle_mtx_;
  std::mutex write_mtx_; // shared by all write operations and the write thread
  std::mutex write_queue_mtx_; // protects the write task queue
  std::condition_variable write_cv_;
  std::queue<std::function<ECM()>> write_queue_;
  std::thread write_thread_;
  std::atomic<bool> write_running_{false};
  std::atomic<bool> shutdown_requested_{false};
  bool backup_prune_checked_ = false;
  DumpErrorCallback dump_error_cb_;
  bool initialized_ = false;
};

/**
 * @brief Style access layer for UI and formatting configuration.
 */
class AMConfigManager : public AMConfigStorage, NonCopyableNonMovable {
public:
  AMConfigManager() = default;
  static AMConfigManager &Instance() {
    static AMConfigManager instance;
    return instance;
  };
  ECM Init() override {
    std::string root_dir = "";
    if (!AMStr::GetEnv("AMSFTP_ROOT", &root_dir)) {
      return Err(EC::ProgrammInitializeFailed,
                 "Failed to get $AMSFTP_ROOT environment variable");
    }
    return AMInit(std::filesystem::path(root_dir));
  };

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
  [[nodiscard]] AMProgressBar CreateProgressBar(int64_t total_size,
                                                const std::string &prefix);

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

  mutable std::optional<AMProgressBarStyle> progress_bar_style_;
};

