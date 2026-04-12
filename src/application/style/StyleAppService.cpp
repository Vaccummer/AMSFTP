#include "application/style/StyleAppService.hpp"
#include "domain/style/StyleDomainService.hpp"
#include "foundation/tools/enum_related.hpp"

namespace AMApplication::style {
StyleConfigManager::StyleConfigManager(StyleConfigArg arg)
    : AMApplication::config::IConfigSyncPort(typeid(StyleConfigArg)),
      init_arg_(std::move(arg)) {}

ECM StyleConfigManager::Init() {
  auto guard = init_arg_.lock();
  AMDomain::style::services::NormalizeStyleConfigArg(&guard.get());
  return OK;
}

StyleConfigArg StyleConfigManager::GetInitArg() const {
  return init_arg_.lock().load();
}

ECM StyleConfigManager::FlushTo(
    AMApplication::config::ConfigAppService *config_service) {
  if (config_service == nullptr) {
    return Err(EC::InvalidArg, __func__, "", "config service is null");
  }
  if (!config_service->Write<StyleConfigArg>(ExportConfigSnapshot())) {
    return Err(EC::ConfigDumpFailed, __func__, "", "failed to flush style config");
  }
  return OK;
}

StyleConfigArg StyleConfigManager::ExportConfigSnapshot() const {
  return GetInitArg();
}

void StyleConfigManager::SetInitArg(StyleConfigArg arg) {
  init_arg_.lock().store(std::move(arg));
  MarkConfigDirty();
}
} // namespace AMApplication::style

