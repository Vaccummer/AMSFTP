#pragma once

#include "domain/var/VarModel.hpp"
#include "domain/config/ConfigSyncPort.hpp"
#include "foundation/core/DataClass.hpp"

#include <map>
#include <string>
#include <vector>

namespace AMApplication::var {
using VarInfo = AMDomain::var::VarInfo;
using VarSet = AMDomain::var::VarSet;
using VarSetArg = AMDomain::var::VarSetArg;
using ZoneVarMap = std::map<std::string, std::string>;
using ZoneVarInfoMap = std::map<std::string, VarInfo>;
using AllVarInfoMap = std::map<std::string, ZoneVarInfoMap>;
using VarInfoList = std::vector<VarInfo>;

class VarAppService final : public AMDomain::config::IConfigSyncPort {
public:
  explicit VarAppService(VarSetArg init_arg = {});
  ~VarAppService() override = default;

  ECM Init();
  [[nodiscard]] VarSetArg GetInitArg() const;
  ECM FlushTo(AMDomain::config::IConfigStorePort *store) override;
  [[nodiscard]] ECMData<VarInfo> GetVar(const std::string &zone_name,
                                        const std::string &varname) const;
  [[nodiscard]] ECMData<VarInfoList>
  SearchVar(const std::string &varname) const;
  [[nodiscard]] ECMData<ZoneVarInfoMap>
  EnumerateZone(const std::string &zone_name) const;
  [[nodiscard]] ECMData<AllVarInfoMap> GetAllVar() const;
  [[nodiscard]] ECMData<bool> VarExists(const std::string &zone_name,
                                        const std::string &varname) const;
  ECM AddVar(const VarInfo &info);
  ECM DelVar(const std::string &zone_name, const std::string &varname);

private:
  mutable AMAtomic<VarSetArg> init_arg_ = {};
  mutable AMAtomic<VarSetArg> store_ = {};
};
} // namespace AMApplication::var
