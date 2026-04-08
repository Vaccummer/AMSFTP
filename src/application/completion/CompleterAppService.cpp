#include "application/completion/CompleterAppService.hpp"

#include "foundation/tools/enum_related.hpp"

#include <algorithm>
#include <limits>
#include <utility>

namespace AMApplication::completion {
namespace {
void NormalizeCompleterArg_(CompleterArg *arg) {
  if (!arg) {
    return;
  }
  arg->maxnum = std::max<int64_t>(1, arg->maxnum);
  arg->maxrows_perpage = std::max<int64_t>(1, arg->maxrows_perpage);
  arg->complete_delay_ms = std::max<int64_t>(0, arg->complete_delay_ms);
  arg->async_workers = std::max<int64_t>(1, arg->async_workers);
  if (arg->maxrows_perpage >
      static_cast<int64_t>(std::numeric_limits<long>::max())) {
    arg->maxrows_perpage = static_cast<int64_t>(std::numeric_limits<long>::max());
  }
}
} // namespace

CompleterConfigManager::CompleterConfigManager(CompleterArg arg)
    : IConfigSyncPort(typeid(CompleterArg)), init_arg_(std::move(arg)) {}

ECM CompleterConfigManager::Init() {
  auto guard = init_arg_.lock();
  NormalizeCompleterArg_(&guard.get());
  return OK;
}

CompleterArg CompleterConfigManager::GetInitArg() const {
  return init_arg_.lock().load();
}

void CompleterConfigManager::SetInitArg(CompleterArg arg) {
  NormalizeCompleterArg_(&arg);
  init_arg_.lock().store(std::move(arg));
  MarkConfigDirty();
}

ECM CompleterConfigManager::FlushTo(
    AMApplication::config::ConfigAppService *config_service) {
  if (!config_service) {
    return Err(EC::InvalidArg, __func__, "<context>", "config service is null");
  }
  if (!config_service->Write<CompleterArg>(ExportConfigSnapshot())) {
    return Err(EC::ConfigDumpFailed, __func__, "<context>", "failed to flush completer config");
  }
  return OK;
}

CompleterArg CompleterConfigManager::ExportConfigSnapshot() const {
  return GetInitArg();
}

} // namespace AMApplication::completion

