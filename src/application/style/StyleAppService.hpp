#pragma once

#include "domain/style/StyleDomainModel.hpp"
#include "foundation/core/DataClass.hpp"

namespace AMApplication::style {
using StyleConfigArg = AMDomain::style::StyleConfigArg;

class AMStyleConfigManager : public NonCopyableNonMovable {
public:
  explicit AMStyleConfigManager(StyleConfigArg arg = {});
  ~AMStyleConfigManager() override = default;

  virtual ECM Init();

  [[nodiscard]] StyleConfigArg GetInitArg() const;
  [[nodiscard]] bool IsConfigDirty() const;
  void ClearConfigDirty();
  [[nodiscard]] StyleConfigArg ExportConfigSnapshot() const;

  void SetInitArg(StyleConfigArg arg);

  inline AMAtomic<StyleConfigArg> &GetStyleRef() { return init_arg_; };
  inline const AMAtomic<StyleConfigArg> &GetStyleRef() const {
    return init_arg_;
  };

protected:
  mutable AMAtomic<StyleConfigArg> init_arg_ = {};
  mutable AMAtomic<bool> config_dirty_ = {};
};
} // namespace AMApplication::style
