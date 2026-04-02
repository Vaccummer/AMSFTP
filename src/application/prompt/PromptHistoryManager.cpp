#include "application/prompt/PromptHistoryManager.hpp"

#include "foundation/tools/enum_related.hpp"
#include "foundation/tools/string.hpp"

namespace AMApplication::prompt {
namespace {
using EC = ErrorCode;
} // namespace

PromptHistoryManager::PromptHistoryManager(PromptHistoryArg arg)
    : AMApplication::config::IConfigSyncPort(typeid(PromptHistoryArg)),
      init_arg_(std::move(arg)) {}

ECM PromptHistoryManager::Init() { return OK; }

PromptHistoryArg PromptHistoryManager::GetInitArg() const {
  return init_arg_.lock().load();
}

ECM PromptHistoryManager::FlushTo(
    AMApplication::config::ConfigAppService *config_service) {
  if (config_service == nullptr) {
    return Err(EC::InvalidArg, "", "", "config service is null");
  }
  if (!config_service->Write<PromptHistoryArg>(ExportConfigSnapshot())) {
    return Err(EC::ConfigDumpFailed, "", "", "failed to flush prompt history config");
  }
  return OK;
}

PromptHistoryArg PromptHistoryManager::ExportConfigSnapshot() const {
  return GetInitArg();
}

void PromptHistoryManager::SetInitArg(PromptHistoryArg arg) {
  init_arg_.lock().store(std::move(arg));
  MarkConfigDirty();
}

ECMData<PromptHistoryQueryResult>
PromptHistoryManager::GetZoneHistory(const std::string &zone) const {
  auto guard = init_arg_.lock();
  const auto zone_it = guard->set.find(zone);
  if (zone_it != guard->set.end()) {
    PromptHistoryQueryResult out = {};
    out.request_zone = zone;
    out.resolved_zone = zone;
    out.from_fallback = false;
    out.history = zone_it->second;
    return {std::move(out), OK};
  }

  PromptHistoryQueryResult out = {};
  out.request_zone = zone;
  out.resolved_zone = zone;
  out.from_fallback = false;
  out.history = {};
  return {std::move(out),
          Err(EC::PathNotExist, "", "", AMStr::fmt("Prompt history not found for zone: {}", zone))};
}

ECM PromptHistoryManager::SetZoneHistory(const std::string &zone,
                                         std::vector<std::string> history) {
  auto guard = init_arg_.lock();
  guard->set[zone] = std::move(history);
  MarkConfigDirty();
  return OK;
}

ECM PromptHistoryManager::AppendZoneHistory(const std::string &zone,
                                            const std::string &entry) {
  if (entry.empty()) {
    return Err(EC::InvalidArg, "", "", "Prompt history entry is empty");
  }
  auto guard = init_arg_.lock();
  auto &bucket = guard->set[zone];
  bucket.push_back(entry);
  MarkConfigDirty();
  return OK;
}

ECM PromptHistoryManager::ClearZoneHistory(const std::string &zone) {
  auto guard = init_arg_.lock();
  auto it = guard->set.find(zone);
  if (it == guard->set.end()) {
    return Err(EC::PathNotExist, "", "", AMStr::fmt("Prompt history zone not found: {}", zone));
  }
  it->second.clear();
  MarkConfigDirty();
  return OK;
}

} // namespace AMApplication::prompt
