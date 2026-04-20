#include "application/style/StyleAppService.hpp"
#include "domain/style/StyleDomainService.hpp"

namespace AMApplication::style {
using AMDomain::style::service::NormalizeStyleConfigArg;

StyleConfigManager::StyleConfigManager(StyleConfigArg arg)
    : AMDomain::config::IConfigSyncPort(typeid(StyleConfigArg)),
      init_arg_(std::move(arg)) {}

ECM StyleConfigManager::Init() {
  auto guard = init_arg_.lock();
  NormalizeStyleConfigArg(&guard.get());
  return OK;
}

StyleConfigArg StyleConfigManager::GetInitArg() const {
  return init_arg_.lock().load();
}

ECM StyleConfigManager::FlushTo(AMDomain::config::IConfigStorePort *store) {
  if (store == nullptr) {
    return Err(EC::InvalidArg, "", "", "config store is null");
  }
  const StyleConfigArg snapshot = GetInitArg();
  if (!store->Write(std::type_index(typeid(StyleConfigArg)),
                    static_cast<const void *>(&snapshot))) {
    return Err(EC::ConfigDumpFailed, "", "", "failed to flush style config");
  }
  return OK;
}

void StyleConfigManager::SetInitArg(StyleConfigArg arg) {
  NormalizeStyleConfigArg(&arg);
  init_arg_.lock().store(std::move(arg));
  MarkConfigDirty();
}
} // namespace AMApplication::style
