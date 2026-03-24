#pragma once

#include "domain/style/StyleDomainModel.hpp"
#include "foundation/core/DataClass.hpp"

namespace AMApplication::style {
using StyleConfigArg = AMDomain::style::StyleConfigArg;

class AMStyleAppService : public NonCopyableNonMovable {
public:
  explicit AMStyleAppService(StyleConfigArg arg = {});
  ~AMStyleAppService() override = default;

  virtual ECM Init();

  [[nodiscard]] StyleConfigArg GetInitArg() const;

  void SetInitArg(StyleConfigArg arg);

  inline AMAtomic<StyleConfigArg> &GetStyleRef() { return init_arg_; };

private:
  mutable AMAtomic<StyleConfigArg> init_arg_ = {};
};
} // namespace AMApplication::style
