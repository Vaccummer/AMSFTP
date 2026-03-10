#pragma once

#include "domain/arg/ArgTypes.hpp"
#include "domain/writer/AsyncWriteSchedulerPort.hpp"
#include "domain/config/ConfigHandlePort.hpp"
#include "domain/config/ConfigModel.hpp"
#include "foundation/DataClass.hpp"
#include <memory>
#include <optional>
#include <type_traits>
#include <unordered_map>

namespace AMDomain::config {
/**
 * @brief Domain-level config manager with per-document handle orchestration.
 */
class AMConfigManager : NonCopyableNonMovable {
public:
  using DumpErrorCallback = std::function<void(ECM)>;

  /**
   * @brief Initialize managed documents and bind async write scheduler.
   */
  ECM Init(const std::unordered_map<DocumentKind, HandleInitSpec> &specs,
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

  [[nodiscard]] bool GetHandleInitSpec(DocumentKind kind,
                                       HandleInitSpec *out) const;

  /**
   * @brief Return whether one document has in-memory changes.
   */
  [[nodiscard]] bool IsDirty(DocumentKind kind) const;

  template <typename T> [[nodiscard]] bool Resolve(T *out) const {
    using ValueT = std::decay_t<T>;
    static_assert(AMDomain::arg::kSupportedArgType<ValueT>,
                  "T is not a supported config arg type");
    if (!out) {
      return false;
    }
    return ReadValue(AMDomain::arg::TypeTagOf<ValueT>::value,
                     static_cast<void *>(out));
  }

  template <typename T> [[nodiscard]] bool Set(const T &value) {
    using ValueT = std::decay_t<T>;
    static_assert(AMDomain::arg::kSupportedArgType<ValueT>,
                  "T is not a supported config arg type");
    return WriteValue(AMDomain::arg::TypeTagOf<ValueT>::value,
                      static_cast<const void *>(&value));
  }

private:
  ECM BackupIfNeeded(const std::filesystem::path &root_dir);

  [[nodiscard]] bool ReadValue(AMDomain::arg::TypeTag type, void *out) const;

  [[nodiscard]] bool WriteValue(AMDomain::arg::TypeTag type, const void *in);

  void NotifyDumpError_(const ECM &err) const;
  [[nodiscard]] std::shared_ptr<AMInfraConfigHandlePort>

  GetHandle_(DocumentKind kind);
  [[nodiscard]] std::shared_ptr<const AMInfraConfigHandlePort>
  GetHandle_(DocumentKind kind) const;
  [[nodiscard]] std::shared_ptr<AMInfraConfigHandlePort>
  GetHandleByType_(AMDomain::arg::TypeTag type);
  [[nodiscard]] std::shared_ptr<const AMInfraConfigHandlePort>
  GetHandleByType_(AMDomain::arg::TypeTag type) const;
  ECM LoadDocument_(DocumentKind kind);

  std::unordered_map<DocumentKind, HandleInitSpec> init_specs_;
  std::unordered_map<DocumentKind, std::shared_ptr<AMInfraConfigHandlePort>>
      handles_;
  DumpErrorCallback dump_error_cb_;
  bool initialized_ = false;
  bool backup_prune_checked_ = false;
};
} // namespace AMDomain::config


