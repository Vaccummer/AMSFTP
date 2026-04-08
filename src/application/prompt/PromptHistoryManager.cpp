#include "application/prompt/PromptHistoryManager.hpp"
#include "foundation/tools/string.hpp"

namespace AMApplication::prompt {
namespace {
using EC = ErrorCode;

std::vector<std::string>
DedupContinuousHistory_(std::vector<std::string> history) {
  std::vector<std::string> deduped = {};
  deduped.reserve(history.size());
  for (auto &entry : history) {
    if (!deduped.empty() && deduped.back() == entry) {
      continue;
    }
    deduped.push_back(std::move(entry));
  }
  return deduped;
}

void NormalizePromptHistoryArg_(PromptHistoryArg *arg) {
  if (arg == nullptr) {
    return;
  }
  for (auto &[zone, history] : arg->set) {
    (void)zone;
    history = DedupContinuousHistory_(std::move(history));
  }
}
} // namespace

PromptHistoryManager::PromptHistoryManager(PromptHistoryArg arg)
    : AMApplication::config::IConfigSyncPort(typeid(PromptHistoryArg)),
      init_arg_([&arg]() {
        NormalizePromptHistoryArg_(&arg);
        return std::move(arg);
      }()) {}

ECM PromptHistoryManager::Init() { return OK; }

PromptHistoryArg PromptHistoryManager::GetInitArg() const {
  return init_arg_.lock().load();
}

ECM PromptHistoryManager::FlushTo(
    AMApplication::config::ConfigAppService *config_service) {
  if (config_service == nullptr) {
    return Err(EC::InvalidArg, __func__, "<context>",
               "config service is null");
  }
  if (!config_service->Write<PromptHistoryArg>(ExportConfigSnapshot())) {
    return Err(EC::ConfigDumpFailed, __func__, "<context>",
               "failed to flush prompt history config");
  }
  return OK;
}

PromptHistoryArg PromptHistoryManager::ExportConfigSnapshot() const {
  PromptHistoryArg out = GetInitArg();
  NormalizePromptHistoryArg_(&out);
  return out;
}

void PromptHistoryManager::SetInitArg(PromptHistoryArg arg) {
  NormalizePromptHistoryArg_(&arg);
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
    out.history = DedupContinuousHistory_(zone_it->second);
    return {std::move(out), OK};
  }

  PromptHistoryQueryResult out = {};
  out.request_zone = zone;
  out.resolved_zone = zone;
  out.from_fallback = false;
  out.history = {};
  return {std::move(out),
          Err(EC::PathNotExist, __func__, "<context>",
              AMStr::fmt("Prompt history not found for zone: {}", zone))};
}

ECM PromptHistoryManager::SetZoneHistory(const std::string &zone,
                                         std::vector<std::string> history) {
  history = DedupContinuousHistory_(std::move(history));
  auto guard = init_arg_.lock();
  guard->set[zone] = std::move(history);
  MarkConfigDirty();
  return OK;
}

ECM PromptHistoryManager::AppendZoneHistory(const std::string &zone,
                                            const std::string &entry) {
  if (entry.empty()) {
    return Err(EC::InvalidArg, __func__, "<context>",
               "Prompt history entry is empty");
  }
  auto guard = init_arg_.lock();
  auto &bucket = guard->set[zone];
  if (!bucket.empty() && bucket.back() == entry) {
    return OK;
  }
  bucket.push_back(entry);
  MarkConfigDirty();
  return OK;
}

ECM PromptHistoryManager::ClearZoneHistory(const std::string &zone) {
  auto guard = init_arg_.lock();
  auto it = guard->set.find(zone);
  if (it == guard->set.end()) {
    return Err(EC::PathNotExist, __func__, "<context>",
               AMStr::fmt("Prompt history zone not found: {}", zone));
  }
  it->second.clear();
  MarkConfigDirty();
  return OK;
}

} // namespace AMApplication::prompt

