#include "application/prompt/PromptHistoryManager.hpp"

#include "foundation/tools/enum_related.hpp"
#include "foundation/tools/string.hpp"

namespace AMApplication::prompt {
namespace {
using EC = ErrorCode;
} // namespace

AMPromptHistoryManager::AMPromptHistoryManager(PromptHistoryArg arg)
    : init_arg_(std::move(arg)) {}

ECM AMPromptHistoryManager::Init() {
  return Ok();
}

PromptHistoryArg AMPromptHistoryManager::GetInitArg() const {
  return init_arg_.lock().load();
}

void AMPromptHistoryManager::SetInitArg(PromptHistoryArg arg) {
  init_arg_.lock().store(std::move(arg));
}

ECMData<PromptHistoryQueryResult>
AMPromptHistoryManager::GetZoneHistory(const std::string &zone) const {
  auto guard = init_arg_.lock();
  const auto zone_it = guard->set.find(zone);
  if (zone_it != guard->set.end()) {
    PromptHistoryQueryResult out = {};
    out.request_zone = zone;
    out.resolved_zone = zone;
    out.from_fallback = false;
    out.history = zone_it->second;
    return {std::move(out), Ok()};
  }

  PromptHistoryQueryResult out = {};
  out.request_zone = zone;
  out.resolved_zone = zone;
  out.from_fallback = false;
  out.history = {};
  return {
      std::move(out),
      Err(EC::PathNotExist,
          AMStr::fmt("Prompt history not found for zone: {}", zone))};
}

ECM AMPromptHistoryManager::SetZoneHistory(const std::string &zone,
                                           std::vector<std::string> history) {
  auto guard = init_arg_.lock();
  guard->set[zone] = std::move(history);
  return Ok();
}

ECM AMPromptHistoryManager::AppendZoneHistory(const std::string &zone,
                                              const std::string &entry) {
  if (entry.empty()) {
    return Err(EC::InvalidArg, "Prompt history entry is empty");
  }
  auto guard = init_arg_.lock();
  auto &bucket = guard->set[zone];
  bucket.push_back(entry);
  return Ok();
}

ECM AMPromptHistoryManager::ClearZoneHistory(const std::string &zone) {
  auto guard = init_arg_.lock();
  auto it = guard->set.find(zone);
  if (it == guard->set.end()) {
    return Err(EC::PathNotExist,
               AMStr::fmt("Prompt history zone not found: {}", zone));
  }
  it->second.clear();
  return Ok();
}

} // namespace AMApplication::prompt
