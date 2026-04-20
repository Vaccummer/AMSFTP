#include "application/completion/CompleterAppService.hpp"

#include <utility>

namespace AMApplication::completion {

CompleterConfigManager::CompleterConfigManager(CompleterArg arg)
    : IConfigSyncPort(typeid(CompleterArg)), init_arg_(std::move(arg)) {}

ECM CompleterConfigManager::Init() {
  auto guard = init_arg_.lock();
  AMDomain::completion::NormalizeCompleterArg(&guard.get());
  return OK;
}

CompleterArg CompleterConfigManager::GetInitArg() const {
  return init_arg_.lock().load();
}

void CompleterConfigManager::SetInitArg(CompleterArg arg) {
  AMDomain::completion::NormalizeCompleterArg(&arg);
  init_arg_.lock().store(std::move(arg));
  MarkConfigDirty();
}

ECM CompleterConfigManager::FlushTo(AMDomain::config::IConfigStorePort *store) {
  if (!store) {
    return {EC::InvalidArg, "completion.flush", "", "config store is null"};
  }
  const CompleterArg snapshot = GetInitArg();
  if (!store->Write(std::type_index(typeid(CompleterArg)),
                    static_cast<const void *>(&snapshot))) {
    return {EC::ConfigDumpFailed, "completion.flush", "",
            "failed to flush completer config"};
  }
  return OK;
}

} // namespace AMApplication::completion
