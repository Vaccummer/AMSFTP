#pragma once

#include "application/config/ConfigBackupUseCase.hpp"
#include "application/config/ConfigStorePort.hpp"
#include "foundation/DataClass.hpp"
#include "foundation/tools/json.hpp"
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <type_traits>
#include <vector>

namespace AMApplication::config {
/**
 * @brief Application service orchestrating config store operations.
 */
class AMConfigAppService : NonCopyable {
public:
  using Path = std::vector<std::string>;
  using DumpErrorCallback = std::function<void(ECM)>;

  /**
   * @brief Construct one app service with optional bound dependencies.
   */
  explicit AMConfigAppService(IConfigStorePort *store = nullptr,
                              AMConfigBackupUseCase *backup_use_case = nullptr);

  /**
   * @brief Bind store and use-case dependencies.
   */
  void Bind(IConfigStorePort *store, AMConfigBackupUseCase *backup_use_case);

  /**
   * @brief Load one document or all documents from store.
   */
  ECM Load(std::optional<AMDomain::config::DocumentKind> kind = std::nullopt,
           bool force = false);

  /**
   * @brief Dump one document; optional async scheduling.
   */
  ECM Dump(AMDomain::config::DocumentKind kind,
           const std::string &dst_path = "", bool async = false);

  /**
   * @brief Dump all documents; optional async scheduling.
   */
  ECM DumpAll(bool async = false);

  /**
   * @brief Close store resources and reset app state.
   */
  void CloseHandles();

  /**
   * @brief Bind callback invoked on write/dump failures.
   */
  void SetDumpErrorCallback(DumpErrorCallback cb);

  /**
   * @brief Return whether one document is dirty in store.
   */
  [[nodiscard]] bool IsDirty(AMDomain::config::DocumentKind kind) const;

  /**
   * @brief Execute auto-backup use-case.
   */
  ECM BackupIfNeeded();

  /**
   * @brief Submit one asynchronous write task.
   */
  void SubmitWriteTask(std::function<ECM()> task);

  /**
   * @brief Return one full document JSON snapshot.
   */
  [[nodiscard]] bool GetJson(AMDomain::config::DocumentKind kind,
                             Json *value) const;

  /**
   * @brief Return pretty serialized JSON for one document.
   */
  [[nodiscard]] bool GetJsonStr(AMDomain::config::DocumentKind kind,
                                std::string *value, int indent = 2) const;

  /**
   * @brief Return data file path for one document.
   */
  [[nodiscard]] bool GetDataPath(AMDomain::config::DocumentKind kind,
                                 std::filesystem::path *value) const;

  /**
   * @brief Return project root path.
   */
  [[nodiscard]] std::filesystem::path ProjectRoot() const;

  /**
   * @brief Ensure one directory exists.
   */
  ECM EnsureDirectory(const std::filesystem::path &dir);

  /**
   * @brief Prune old backups matching naming convention.
   */
  void PruneBackupFiles(const std::filesystem::path &dir,
                        const std::string &prefix, const std::string &suffix,
                        int64_t max_count);

  template <typename T>
  T ResolveArg(AMDomain::config::DocumentKind kind, const Path &path,
               const T &default_value,
               const std::function<T(T)> &post_process) const {
    static_assert(AMJson::kValueTypeSupported<T>, "T is not supported");
    T value = {};
    if (!ResolveArg(kind, path, &value)) {
      return default_value;
    }
    if (post_process) {
      return post_process(value);
    }
    return value;
  }

  template <typename T>
  bool ResolveArg(AMDomain::config::DocumentKind kind, const Path &path,
                  T *data) const {
    static_assert(AMJson::kValueTypeSupported<T>, "T is not supported");
    if (!data) {
      return false;
    }
    Json root = Json::object();
    if (!ReadDocumentJson_(kind, &root)) {
      return false;
    }
    return AMJson::QueryKey(root, path, data);
  }

  template <typename T>
  bool SetArg(AMDomain::config::DocumentKind kind, const Path &path, T value) {
    static_assert(AMJson::kValueTypeSupported<T>, "T is not supported");
    Json root = Json::object();
    if (!ReadDocumentJson_(kind, &root)) {
      return false;
    }
    if (!AMJson::SetKey(root, path, value)) {
      return false;
    }
    return WriteDocumentJson_(kind, root);
  }

  bool DelArg(AMDomain::config::DocumentKind kind, const Path &path);

  /**
   * @brief Read one typed config arg from store.
   */
  template <typename T> [[nodiscard]] bool Resolve(T *out) const {
    using ValueT = std::decay_t<T>;
    static_assert(AMDomain::arg::kSupportedArgType<ValueT>,
                  "T is not a supported config arg type");
    if (!out || !store_) {
      return false;
    }
    return store_->Read(AMDomain::arg::TypeTagOf<ValueT>::value,
                        static_cast<void *>(out));
  }

  /**
   * @brief Write one typed config arg into store.
   */
  template <typename T> [[nodiscard]] bool Set(const T &value) {
    using ValueT = std::decay_t<T>;
    static_assert(AMDomain::arg::kSupportedArgType<ValueT>,
                  "T is not a supported config arg type");
    if (!store_) {
      return false;
    }
    return store_->Write(AMDomain::arg::TypeTagOf<ValueT>::value,
                         static_cast<const void *>(&value));
  }

private:
  [[nodiscard]] bool ReadDocumentJson_(AMDomain::config::DocumentKind kind,
                                       Json *out) const;
  [[nodiscard]] bool WriteDocumentJson_(AMDomain::config::DocumentKind kind,
                                        const Json &json);

  IConfigStorePort *store_ = nullptr;
  AMConfigBackupUseCase *backup_use_case_ = nullptr;
  DumpErrorCallback dump_error_cb_;
};
} // namespace AMApplication::config
