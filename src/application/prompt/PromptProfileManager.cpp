#include "application/prompt/PromptProfileManager.hpp"
#include "domain/prompt/PromptDomainService.hpp"

#include <algorithm>

namespace AMApplication::prompt {
namespace {
std::string ResolveProfileZone_(const std::string &zone) {
  if (zone.empty()) {
    return AMDomain::prompt::kPromptProfileDefault;
  }
  return zone;
}
} // namespace

PromptProfileManager::PromptProfileManager(PromptProfileArg arg)
    : AMDomain::config::IConfigSyncPort(typeid(PromptProfileArg)),
      init_arg_(std::move(arg)) {
  auto guard = init_arg_.lock();
  AMDomain::prompt::service::NormalizePromptProfileArg(&guard.get());
}

ECM PromptProfileManager::Init() {
  auto guard = init_arg_.lock();
  AMDomain::prompt::service::NormalizePromptProfileArg(&guard.get());
  return OK;
}

PromptProfileArg PromptProfileManager::GetInitArg() const {
  return init_arg_.lock().load();
}

ECM PromptProfileManager::FlushTo(AMDomain::config::IConfigStorePort *store) {
  if (store == nullptr) {
    return Err(EC::InvalidArg, "", "", "config store is null");
  }
  const PromptProfileArg snapshot = GetInitArg();
  if (!store->Write(std::type_index(typeid(PromptProfileArg)),
                    static_cast<const void *>(&snapshot))) {
    return Err(EC::ConfigDumpFailed, "", "",
               "failed to flush prompt profile config");
  }
  return OK;
}

void PromptProfileManager::SetInitArg(PromptProfileArg arg) {
  AMDomain::prompt::service::NormalizePromptProfileArg(&arg);
  init_arg_.lock().store(std::move(arg));
  MarkConfigDirty();
}

std::vector<std::string> PromptProfileManager::ListZones() const {
  auto guard = init_arg_.lock();
  std::vector<std::string> out = {};
  out.reserve(guard->set.size());
  for (const auto &[zone, _] : guard->set) {
    (void)_;
    out.push_back(zone);
  }
  std::sort(out.begin(), out.end());
  return out;
}

std::vector<std::string>
PromptProfileManager::RemoveZones(const std::vector<std::string> &zones) {
  std::vector<std::string> removed = {};
  if (zones.empty()) {
    return removed;
  }

  auto guard = init_arg_.lock();
  auto &set = guard->set;
  removed.reserve(zones.size());
  for (const auto &zone : zones) {
    if (zone.empty() || zone == AMDomain::prompt::kPromptProfileDefault) {
      continue;
    }
    if (set.erase(zone) > 0) {
      removed.push_back(zone);
    }
  }
  if (!removed.empty()) {
    MarkConfigDirty();
  }
  return removed;
}

PromptProfileQueryResult
PromptProfileManager::GetZoneProfile(const std::string &zone) const {
  auto guard = init_arg_.lock();
  auto &set = guard->set;
  const std::string requested_zone = ResolveProfileZone_(zone);
  const auto zone_it = set.find(requested_zone);
  if (zone_it != set.end()) {
    PromptProfileQueryResult out = {};
    out.request_zone = requested_zone;
    out.resolved_zone = requested_zone;
    out.from_fallback = false;
    out.profile = zone_it->second;
    return out;
  }

  auto fallback_it = set.find(AMDomain::prompt::kPromptProfileDefault);
  if (fallback_it == set.end()) {
    PromptProfileSettings default_profile = {};
    AMDomain::prompt::service::NormalizePromptProfileSettings(&default_profile);
    fallback_it = set.emplace(AMDomain::prompt::kPromptProfileDefault,
                              std::move(default_profile))
                      .first;
  }

  PromptProfileQueryResult out = {};
  out.request_zone = requested_zone;
  out.resolved_zone = fallback_it->first;
  out.from_fallback = requested_zone != fallback_it->first;
  out.profile = fallback_it->second;
  return out;
}
} // namespace AMApplication::prompt
