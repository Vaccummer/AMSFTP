#pragma once

#include "domain/config/ConfigSyncPort.hpp"
#include "domain/style/StyleDomainModel.hpp"
#include "foundation/core/DataClass.hpp"


namespace AMApplication::style {
using StyleConfigArg = AMDomain::style::StyleConfigArg;

class StyleConfigManager : public AMDomain::config::IConfigSyncPort {
public:
  explicit StyleConfigManager(StyleConfigArg arg = {});
  ~StyleConfigManager() override = default;

  virtual ECM Init();

  [[nodiscard]] StyleConfigArg GetInitArg() const;
  ECM FlushTo(AMDomain::config::IConfigStorePort *store) override;

  void SetInitArg(StyleConfigArg arg);

  inline AMAtomic<StyleConfigArg> &GetStyleRef() { return init_arg_; };
  inline const AMAtomic<StyleConfigArg> &GetStyleRef() const {
    return init_arg_;
  };

protected:
  mutable AMAtomic<StyleConfigArg> init_arg_ = {};
};
} // namespace AMApplication::style
