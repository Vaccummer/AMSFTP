#pragma once

#include "application/config/ConfigAppService.hpp"
#include "application/config/ConfigBackupUseCase.hpp"
#include "foundation/DataClass.hpp"
#include "infrastructure/config/ConfigDocumentHandle.hpp"
#include "infrastructure/config/TomlConfigStore.hpp"
#include <filesystem>

namespace AMInfra::config {
/**
 * @brief Infrastructure composition root for config store + app service.
 */
class AMConfigRuntime : NonCopyable {
public:
  using DumpErrorCallback = std::function<void(ECM)>;

  /**
   * @brief Construct runtime and bind app service dependencies.
   */
  AMConfigRuntime();

  /**
   * @brief Close store resources on destruction.
   */
  ~AMConfigRuntime();

  /**
   * @brief Initialize storage paths from one project root directory.
   */
  ECM Init(const std::filesystem::path &root_dir);

  /**
   * @brief Initialize with explicit infrastructure document layout.
   */
  ECM Init(const std::filesystem::path &root_dir,
           const ConfigStoreLayout &layout);

  /**
   * @brief Close config handles and stop async writer.
   */
  void Close();

  /**
   * @brief Bind callback invoked on dump/write failures.
   */
  void SetDumpErrorCallback(DumpErrorCallback cb);

  /**
   * @brief Return bound config application service.
   */
  [[nodiscard]] AMApplication::config::AMConfigAppService &AppService();

  /**
   * @brief Return bound config application service.
   */
  [[nodiscard]] const AMApplication::config::AMConfigAppService &
  AppService() const;

private:
  /**
   * @brief Forward dump errors to bound callback when present.
   */
  void NotifyDumpError_(const ECM &err) const;

  std::filesystem::path root_dir_;
  AMTomlConfigStore store_;
  AMApplication::config::AMConfigBackupUseCase backup_use_case_;
  AMApplication::config::AMConfigAppService app_service_;
  DumpErrorCallback dump_error_cb_;
  bool initialized_ = false;
};
} // namespace AMInfra::config
