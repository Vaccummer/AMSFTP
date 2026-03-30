#pragma once

#include "application/config/ConfigAppService.hpp"
#include "foundation/core/DataClass.hpp"
#include "interface/style/StyleManager.hpp"
#include <filesystem>
#include <functional>

namespace AMBootstrap {
/**
 * @brief Bootstrap-owned config composition root.
 *
 * This assembly owns config store/app service objects and the style service
 * that depends on loaded settings.
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
   * @brief Initialize config stack using explicit store init payload.
   */
  ECM Init(const std::filesystem::path &root_dir,
           const AMDomain::config::ConfigStoreInitArg &init_arg);

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
  AMApplication::config::AMConfigAppService app_service_;
  AMInterface::style::AMStyleService style_service_;
  DumpErrorCallback dump_error_cb_;
  bool initialized_ = false;
};
} // namespace AMBootstrap
