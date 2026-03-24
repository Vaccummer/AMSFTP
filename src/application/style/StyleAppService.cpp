#include "application/style/StyleAppService.hpp"

#include "domain/style/StyleDomainService.hpp"

namespace AMApplication::style {
AMStyleAppService::AMStyleAppService(StyleConfigArg arg)
    : init_arg_(std::move(arg)) {}

ECM AMStyleAppService::Init() {
  auto guard = init_arg_.lock();
  AMDomain::style::services::NormalizeStyleConfigArg(&guard.get());
  return {EC::Success, ""};
}

StyleConfigArg AMStyleAppService::GetInitArg() const {
  return init_arg_.lock().load();
}

void AMStyleAppService::SetInitArg(StyleConfigArg arg) {
  init_arg_.lock().store(std::move(arg));
}
} // namespace AMApplication::style
