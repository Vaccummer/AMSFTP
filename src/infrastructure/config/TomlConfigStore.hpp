#pragma once

#include "domain/config/ConfigStorePort.hpp"
#include "foundation/core/DataClass.hpp"
#include "infrastructure/config/ConfigDocumentHandle.hpp"
#include "infrastructure/config/internal/ArgCodecRegistry.hpp"
#include "infrastructure/writer/WriteDispatcher.hpp"
#include <memory>
#include <mutex>
#include <unordered_map>

namespace AMInfra::config {
/**
 * @brief cfgffi-backed config store implementation for application service.
 */
class AMTomlConfigStore final : public AMDomain::config::IConfigStorePort {
public:
  /**
   * @brief Construct one empty store.
   */
  AMTomlConfigStore() = default;

  /**
   * @brief Stop writer and release handles on destruction.
   */
  ~AMTomlConfigStore() override { Close(); }

  /**
   * @brief Configure infrastructure layout before application operations run.
   */
  ECM Configure(const AMDomain::config::ConfigStoreInitArg &arg);

  ECM Load(std::optional<AMDomain::config::DocumentKind> kind,
           bool force) override;

  ECM Dump(AMDomain::config::DocumentKind kind,
           const std::filesystem::path &dst_path, bool async) override;

  ECM DumpAll(bool async) override;

  void Close() override;

  [[nodiscard]] bool
  IsDirty(AMDomain::config::DocumentKind kind) const override;

  [[nodiscard]] bool GetDataPath(AMDomain::config::DocumentKind kind,
                                 std::filesystem::path *out) const override;

  void SetDumpErrorCallback(DumpErrorCallback cb) override;

  void SubmitWriteTask(std::function<ECM()> task) override;

  [[nodiscard]] std::filesystem::path ProjectRoot() const override;

  ECM EnsureDirectory(const std::filesystem::path &dir) override;

  void PruneBackupFiles(const std::filesystem::path &bak_dir,
                        int64_t max_count) override;

  [[nodiscard]] bool Read(AMDomain::config::ConfigPayloadTag tag,
                          void *out) const override;

  [[nodiscard]] bool Write(AMDomain::config::ConfigPayloadTag tag,
                           const void *in) override;

  [[nodiscard]] bool Erase(AMDomain::config::ConfigPayloadTag tag,
                           const void *in) override;

private:
  [[nodiscard]] std::shared_ptr<IConfigDocumentHandle>
  GetHandle_(AMDomain::config::DocumentKind kind);
  [[nodiscard]] std::shared_ptr<const IConfigDocumentHandle>
  GetHandle_(AMDomain::config::DocumentKind kind) const;

  ECM LoadDocument_(AMDomain::config::DocumentKind kind);
  void NotifyDumpError_(const ECM &err) const;

  std::filesystem::path root_dir_;
  ConfigStoreLayout layout_;
  std::unordered_map<AMDomain::config::DocumentKind,
                     std::shared_ptr<IConfigDocumentHandle>>
      handles_;
  mutable std::mutex mtx_;
  AMInfraAsyncWriter writer_;
  ArgCodecRegistry codec_registry_ = {};
  DumpErrorCallback dump_error_cb_;
  bool initialized_ = false;
};
} // namespace AMInfra::config
