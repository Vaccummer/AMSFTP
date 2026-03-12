#pragma once

#include "application/config/ConfigAppService.hpp"
#include "application/config/ConfigBackupUseCase.hpp"
#include "foundation/DataClass.hpp"
#include "infrastructure/config/ConfigDocumentHandle.hpp"
#include "infrastructure/config/TomlConfigStore.hpp"
#include "interface/style/StyleManager.hpp"
#include <filesystem>
#include <functional>

namespace AMBootstrap {
/**
 * @brief Bootstrap-owned config composition root.
 *
 * This assembly owns the concrete infrastructure store, the application
 * use-case/service objects, and the interface style service that depends on
 * loaded settings.
 */
class ConfigAssembly : NonCopyableNonMovable {
public:
  using DumpErrorCallback = std::function<void(ECM)>;

  /**
   * @brief Construct config assembly and bind app-service dependencies.
   */
  ConfigAssembly();

  /**
   * @brief Close config resources on destruction.
   */
  ~ConfigAssembly();

  /**
   * @brief Initialize config stack using default infrastructure layout.
   */
  ECM Init(const std::filesystem::path &root_dir);

  /**
   * @brief Initialize config stack using explicit document layout.
   */
  ECM Init(const std::filesystem::path &root_dir,
           const AMInfra::config::ConfigStoreLayout &layout);

  /**
   * @brief Close config handles and stop background writer.
   */
  void Close();

  /**
   * @brief Bind callback invoked on dump/write failures.
   */
  void SetDumpErrorCallback(DumpErrorCallback cb);

  /**
   * @brief Return bound config application service.
   */
  [[nodiscard]] AMApplication::config::AMConfigAppService &ConfigService();

  /**
   * @brief Return bound config application service.
   */
  [[nodiscard]] const AMApplication::config::AMConfigAppService &
  ConfigService() const;

  /**
   * @brief Return initialized interface style service.
   */
  [[nodiscard]] AMInterface::style::AMStyleService &StyleService();

  /**
   * @brief Return initialized interface style service.
   */
  [[nodiscard]] const AMInterface::style::AMStyleService &StyleService() const;

private:
  /**
   * @brief Forward dump errors to bound callback when present.
   */
  void NotifyDumpError_(const ECM &err) const;

  std::filesystem::path root_dir_;
  AMInfra::config::AMTomlConfigStore store_;
  AMApplication::config::AMConfigBackupUseCase backup_use_case_;
  AMApplication::config::AMConfigAppService app_service_;
  AMInterface::style::AMStyleService style_service_;
  DumpErrorCallback dump_error_cb_;
  bool initialized_ = false;
};
} // namespace AMBootstrap
