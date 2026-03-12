#include "bootstrap/ConfigAssembly.hpp"

#include "foundation/tools/enum_related.hpp"
#include "infrastructure/config/ConfigStoreLayoutFactory.hpp"

namespace AMBootstrap {
/**
 * @brief Construct config assembly and pre-bind application dependencies.
 */
ConfigAssembly::ConfigAssembly() : app_service_(&store_, &backup_use_case_) {}

/**
 * @brief Release config resources on destruction.
 */
ConfigAssembly::~ConfigAssembly() { Close(); }

/**
 * @brief Initialize config stack using default infrastructure layout.
 */
ECM ConfigAssembly::Init(const std::filesystem::path &root_dir) {
  return Init(root_dir, AMInfra::config::BuildDefaultConfigStoreLayout(root_dir));
}

/**
 * @brief Initialize config stack using explicit document layout.
 */
ECM ConfigAssembly::Init(const std::filesystem::path &root_dir,
                         const AMInfra::config::ConfigStoreLayout &layout) {
  Close();
  root_dir_ = root_dir;
  app_service_.Bind(&store_, &backup_use_case_);
  app_service_.SetDumpErrorCallback(
      [this](const ECM &err) { NotifyDumpError_(err); });

  ECM rcm = store_.Configure(root_dir, layout);
  if (!isok(rcm)) {
    initialized_ = false;
    return rcm;
  }

  rcm = app_service_.Load(std::nullopt, true);
  if (!isok(rcm)) {
    Close();
    return rcm;
  }

  rcm = style_service_.Init(&app_service_);
  if (!isok(rcm)) {
    Close();
    return rcm;
  }

  initialized_ = true;
  return Ok();
}

/**
 * @brief Close config handles and stop background writer.
 */
void ConfigAssembly::Close() {
  app_service_.CloseHandles();
  root_dir_.clear();
  initialized_ = false;
}

/**
 * @brief Bind callback invoked on dump/write failures.
 */
void ConfigAssembly::SetDumpErrorCallback(DumpErrorCallback cb) {
  dump_error_cb_ = std::move(cb);
  app_service_.SetDumpErrorCallback(
      [this](const ECM &err) { NotifyDumpError_(err); });
}

/**
 * @brief Return bound config application service.
 */
AMApplication::config::AMConfigAppService &ConfigAssembly::ConfigService() {
  return app_service_;
}

/**
 * @brief Return bound config application service.
 */
const AMApplication::config::AMConfigAppService &
ConfigAssembly::ConfigService() const {
  return app_service_;
}

/**
 * @brief Return initialized interface style service.
 */
AMInterface::style::AMStyleService &ConfigAssembly::StyleService() {
  return style_service_;
}

/**
 * @brief Return initialized interface style service.
 */
const AMInterface::style::AMStyleService &ConfigAssembly::StyleService() const {
  return style_service_;
}

/**
 * @brief Forward dump errors to bound callback when present.
 */
void ConfigAssembly::NotifyDumpError_(const ECM &err) const {
  if (dump_error_cb_) {
    dump_error_cb_(err);
  }
}
} // namespace AMBootstrap
