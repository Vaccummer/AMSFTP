#pragma once

#include "domain/config/AsyncWriteSchedulerPort.hpp"
#include "domain/config/ConfigHandlePort.hpp"
#include "domain/config/ConfigSyncPort.hpp"
#include "domain/config/DocumentKind.hpp"
#include "foundation/DataClass.hpp"
#include "foundation/tools/json.hpp"
#include <map>
#include <mutex>
#include <optional>
#include <unordered_map>

namespace AMDomain::config {
/**
 * @brief Domain-level config manager with per-document handle orchestration.
 */
class AMConfigManager : NonCopyableNonMovable {
public:
  using Path = std::vector<std::string>;
  using DumpErrorCallback = std::function<void(ECM)>;
  using SyncPort = std::shared_ptr<AMConfigSyncPort>;

  /**
   * @brief Initializer for one managed document.
   */
  struct DocumentInitSpec {
    std::filesystem::path json_path;
    std::filesystem::path schema_path;
    std::string schema_data;
  };

  /**
   * @brief Runtime state for one managed document.
   */
  struct DocumentState {
    std::filesystem::path json_path;
    std::filesystem::path schema_path;
    std::string schema_data;
    std::shared_ptr<AMInfraConfigHandlePort> handle;
  };

  /**
   * @brief Initialize managed documents and bind async write scheduler.
   */
  ECM Init(const std::unordered_map<DocumentKind, DocumentInitSpec> &specs,
           AMDomain::writer::AMAsyncWriteSchedulerPort *writer);

  /**
   * @brief Load one or all documents from storage.
   */
  ECM Load(std::optional<DocumentKind> kind = std::nullopt, bool force = false);

  /**
   * @brief Dump one document; optional async scheduling.
   */
  ECM Dump(DocumentKind kind, const std::string &dst_path = "",
           bool async = false);

  /**
   * @brief Dump all documents; optional async scheduling.
   */
  ECM DumpAll(bool async = false);

  /**
   * @brief Close all bound handles and release runtime state.
   */
  void CloseHandles();

  /**
   * @brief Bind callback invoked on write/dump failures.
   */
  void SetDumpErrorCallback(DumpErrorCallback cb);

  /**
   * @brief Start async scheduler if available.
   */
  void StartWriteThread();

  /**
   * @brief Stop async scheduler if available.
   */
  void StopWriteThread();

  /**
   * @brief Submit one write task through scheduler, with sync fallback.
   */
  void SubmitWriteTask(std::function<ECM()> task);

  /**
   * @brief Return JSON snapshot for one document.
   */
  [[nodiscard]] bool GetJson(DocumentKind kind, Json *out) const;

  /**
   * @brief Return value by key path from one document.
   */
  [[nodiscard]] bool ReadValue(DocumentKind kind, const Path &path,
                               JsonValue *out) const;

  /**
   * @brief Write one value by key path to one document.
   */
  [[nodiscard]] bool WriteValue(DocumentKind kind, const Path &path,
                                const JsonValue &value);

  /**
   * @brief Delete one value by key path from one document.
   */
  [[nodiscard]] bool DeleteValue(DocumentKind kind, const Path &path);

  /**
   * @brief Return schema JSON string tracked by one document.
   */
  [[nodiscard]] bool GetSchemaData(DocumentKind kind, std::string *out) const;

  /**
   * @brief Return schema JSON string tracked by one document.
   */
  [[nodiscard]] bool GetSchemaJson(DocumentKind kind, std::string *out) const;

  /**
   * @brief Return parsed schema JSON tracked by one document.
   */
  [[nodiscard]] bool GetSchemaJson(DocumentKind kind, Json *out) const;

  /**
   * @brief Return document json path.
   */
  [[nodiscard]] bool GetDataPath(DocumentKind kind,
                                 std::filesystem::path *out) const;

  /**
   * @brief Return whether one document has in-memory changes.
   */
  [[nodiscard]] bool IsDirty(DocumentKind kind) const;

  /**
   * @brief Create or return one sync port for one `(kind, path)` key.
   *
   * When the key is new, this method uses load-sync mode:
   * 1) If current manager JSON contains value at `(kind, path)`, use it.
   * 2) Otherwise initialize port payload with @p fallback.
   */
  [[nodiscard]] SyncPort
  CreateOrGetSyncPort(DocumentKind kind, const Path &path,
                      const Json &fallback = Json::object());

  /**
   * @brief Return one sync port by `(kind, path)` key when registered.
   */
  [[nodiscard]] SyncPort GetSyncPort(DocumentKind kind,
                                     const Path &path) const;

  /**
   * @brief Backup config/settings/known_hosts when interval elapsed.
   */
  ECM BackupIfNeeded(const std::filesystem::path &root_dir);

  template <typename T>
  [[nodiscard]] bool Resolve(DocumentKind kind, const Path &path, T *out) const {
    static_assert(AMJson::kValueTypeSupported<T>, "T is not supported");
    if (!out) {
      return false;
    }
    JsonValue value;
    if (!ReadValue(kind, path, &value)) {
      return false;
    }
    return AMJson::JsonValueTo(value, out);
  }

  template <typename T>
  [[nodiscard]] bool Set(DocumentKind kind, const Path &path, const T &value) {
    static_assert(AMJson::kValueTypeSupported<T>, "T is not supported");
    JsonValue boxed;
    if (!AMJson::ToJsonValue(value, &boxed)) {
      return false;
    }
    return WriteValue(kind, path, boxed);
  }

private:
  void NotifyDumpError_(const ECM &err) const;
  DocumentState *GetDoc_(DocumentKind kind);
  const DocumentState *GetDoc_(DocumentKind kind) const;
  ECM LoadDocument_(DocumentKind kind, DocumentState *doc);
  ECM SyncPortsToDocument_(DocumentKind kind);
  void SyncPortsFromDocument_(DocumentKind kind);

  std::unordered_map<DocumentKind, DocumentState> docs_;
  std::map<DocumentKind, std::map<Path, SyncPort>> sync_ports_;
  mutable std::mutex sync_ports_mtx_;
  AMDomain::writer::AMAsyncWriteSchedulerPort *writer_ = nullptr;
  DumpErrorCallback dump_error_cb_;
  bool initialized_ = false;
  bool backup_prune_checked_ = false;
};
} // namespace AMDomain::config
