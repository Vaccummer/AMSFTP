#include "application/prompt/PromptProfileManager.hpp"

#include "domain/prompt/PromptDomainService.hpp"
#include "foundation/tools/enum_related.hpp"

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
    : AMApplication::config::IConfigSyncPort(typeid(PromptProfileArg)),
      init_arg_(std::move(arg)) {
  auto guard = init_arg_.lock();
  AMDomain::prompt::services::NormalizePromptProfileArg(&guard.get());
}

ECM PromptProfileManager::Init() {
  auto guard = init_arg_.lock();
  AMDomain::prompt::services::NormalizePromptProfileArg(&guard.get());
  return OK;
}

PromptProfileArg PromptProfileManager::GetInitArg() const {
  return init_arg_.lock().load();
}

ECM PromptProfileManager::FlushTo(
    AMApplication::config::ConfigAppService *config_service) {
  if (config_service == nullptr) {
    return Err(EC::InvalidArg, "", "", "config service is null");
  }
  if (!config_service->Write<PromptProfileArg>(ExportConfigSnapshot())) {
    return Err(EC::ConfigDumpFailed, "", "", "failed to flush prompt profile config");
  }
  return OK;
}

PromptProfileArg PromptProfileManager::ExportConfigSnapshot() const {
  return GetInitArg();
}

void PromptProfileManager::SetInitArg(PromptProfileArg arg) {
  AMDomain::prompt::services::NormalizePromptProfileArg(&arg);
  init_arg_.lock().store(std::move(arg));
  MarkConfigDirty();
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
    AMDomain::prompt::services::NormalizePromptProfileSettings(
        &default_profile);
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
