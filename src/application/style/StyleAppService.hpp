#pragma once

#include "domain/style/StyleDomainModel.hpp"
#include "application/config/ConfigAppService.hpp"
#include "foundation/core/DataClass.hpp"

namespace AMApplication::style {
using StyleConfigArg = AMDomain::style::StyleConfigArg;

class StyleConfigManager : public AMApplication::config::IConfigSyncPort {
public:
  explicit StyleConfigManager(StyleConfigArg arg = {});
  ~StyleConfigManager() override = default;

  virtual ECM Init();

  [[nodiscard]] StyleConfigArg GetInitArg() const;
  ECM FlushTo(AMApplication::config::ConfigAppService *config_service) override;
  [[nodiscard]] StyleConfigArg ExportConfigSnapshot() const;

  void SetInitArg(StyleConfigArg arg);

  inline AMAtomic<StyleConfigArg> &GetStyleRef() { return init_arg_; };
  inline const AMAtomic<StyleConfigArg> &GetStyleRef() const {
    return init_arg_;
  };

protected:
  mutable AMAtomic<StyleConfigArg> init_arg_ = {};
};
} // namespace AMApplication::style

