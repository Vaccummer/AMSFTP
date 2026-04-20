#include "application/var/VarAppService.hpp"

namespace AMApplication::var {
namespace {
using EC = ErrorCode;
}

VarAppService::VarAppService(VarSetArg init_arg)
    : AMDomain::config::IConfigSyncPort(typeid(VarSetArg)),
      init_arg_(std::move(init_arg)), store_(VarSetArg{}) {}

ECM VarAppService::Init() {
  const VarSetArg init_arg = init_arg_.lock().load();
  store_.lock().store(init_arg);
  return OK;
}

VarSetArg VarAppService::GetInitArg() const { return init_arg_.lock().load(); }

ECM VarAppService::FlushTo(AMDomain::config::IConfigStorePort *store) {
  if (store == nullptr) {
    return Err(EC::InvalidArg, "", "", "config store is null");
  }
  const VarSetArg snapshot = store_.lock().load();
  if (!store->Write(std::type_index(typeid(VarSetArg)),
                    static_cast<const void *>(&snapshot))) {
    return Err(EC::ConfigDumpFailed, "", "", "failed to flush var config");
  }
  return OK;
}

ECMData<VarInfo> VarAppService::GetVar(const std::string &zone_name,
                                       const std::string &varname) const {
  if (zone_name.empty() || varname.empty()) {
    return {{},
            Err(EC::InvalidArg, "", "", "zone_name and varname are required")};
  }

  const auto store = store_.lock();
  const auto zone_it = store->set.find(zone_name);
  if (zone_it == store->set.end()) {
    return {{}, Err(EC::InvalidArg, "", "", "target zone not found")};
  }

  const auto var_it = zone_it->second.find(varname);
  if (var_it == zone_it->second.end()) {
    return {{},
            Err(EC::InvalidArg, "", "", "variable not found in target zone")};
  }

  return {{zone_name, varname, var_it->second}, OK};
}

ECMData<VarInfoList>
VarAppService::SearchVar(const std::string &varname) const {
  if (varname.empty()) {
    return {{}, Err(EC::InvalidArg, "", "", "varname is required")};
  }

  VarInfoList out = {};
  const auto store = store_.lock();
  for (const auto &[zone_name, zone_vars] : store->set) {
    const auto it = zone_vars.find(varname);
    if (it == zone_vars.end()) {
      continue;
    }
    out.push_back({zone_name, varname, it->second});
  }
  return {std::move(out), OK};
}

ECMData<ZoneVarInfoMap>
VarAppService::EnumerateZone(const std::string &zone_name) const {
  if (zone_name.empty()) {
    return {{}, Err(EC::InvalidArg, "", "", "zone_name is required")};
  }

  const auto store = store_.lock();
  const auto zone_it = store->set.find(zone_name);
  if (zone_it == store->set.end()) {
    return {{}, Err(EC::InvalidArg, "", "", "target zone not found")};
  }

  ZoneVarInfoMap out = {};
  for (const auto &[varname, value] : zone_it->second) {
    out[varname] = {zone_name, varname, value};
  }
  return {std::move(out), OK};
}

ECMData<AllVarInfoMap> VarAppService::GetAllVar() const {
  AllVarInfoMap out = {};
  const auto store = store_.lock();
  for (const auto &[zone_name, zone_vars] : store->set) {
    ZoneVarInfoMap per_zone = {};
    for (const auto &[varname, value] : zone_vars) {
      per_zone[varname] = {zone_name, varname, value};
    }
    out[zone_name] = std::move(per_zone);
  }
  return {std::move(out), OK};
}

ECMData<bool> VarAppService::VarExists(const std::string &zone_name,
                                       const std::string &varname) const {
  if (zone_name.empty() || varname.empty()) {
    return {false,
            Err(EC::InvalidArg, "", "", "zone_name and varname are required")};
  }

  const auto store = store_.lock();
  const auto zone_it = store->set.find(zone_name);
  if (zone_it == store->set.end()) {
    return {false, OK};
  }
  return {zone_it->second.contains(varname), OK};
}

ECM VarAppService::AddVar(const VarInfo &info) {
  if (info.domain.empty() || info.varname.empty()) {
    return Err(EC::InvalidArg, "", "", "domain and varname are required");
  }
  auto store = store_.lock();
  store->set[info.domain][info.varname] = info.varvalue;
  MarkConfigDirty();
  return OK;
}

ECM VarAppService::DelVar(const std::string &zone_name,
                          const std::string &varname) {
  if (zone_name.empty() || varname.empty()) {
    return Err(EC::InvalidArg, "", "", "zone_name and varname are required");
  }

  auto store = store_.lock();
  const auto zone_it = store->set.find(zone_name);
  if (zone_it == store->set.end()) {
    return Err(EC::InvalidArg, "", "", "target zone not found");
  }

  const auto var_it = zone_it->second.find(varname);
  if (var_it == zone_it->second.end()) {
    return Err(EC::InvalidArg, "", "", "variable not found in target zone");
  }

  zone_it->second.erase(var_it);
  MarkConfigDirty();
  return OK;
}
} // namespace AMApplication::var
