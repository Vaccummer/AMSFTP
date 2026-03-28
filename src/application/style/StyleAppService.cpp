#include "application/style/StyleAppService.hpp"

#include "domain/style/StyleDomainService.hpp"

namespace AMApplication::style {
AMStyleConfigManager::AMStyleConfigManager(StyleConfigArg arg)
    : init_arg_(std::move(arg)), config_dirty_(false) {}

ECM AMStyleConfigManager::Init() {
  auto guard = init_arg_.lock();
  AMDomain::style::services::NormalizeStyleConfigArg(&guard.get());
  return {EC::Success, ""};
}

StyleConfigArg AMStyleConfigManager::GetInitArg() const {
  return init_arg_.lock().load();
}

bool AMStyleConfigManager::IsConfigDirty() const {
  return config_dirty_.lock().load();
}

void AMStyleConfigManager::ClearConfigDirty() {
  config_dirty_.lock().store(false);
}

StyleConfigArg AMStyleConfigManager::ExportConfigSnapshot() const {
  return GetInitArg();
}

void AMStyleConfigManager::SetInitArg(StyleConfigArg arg) {
  init_arg_.lock().store(std::move(arg));
  config_dirty_.lock().store(true);
}
} // namespace AMApplication::style
