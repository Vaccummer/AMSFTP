#pragma once

#include "interface/cli/CLIServices.hpp"

namespace AMInterface::cli::argstruct_common {

inline void SetEnterInteractive(const CliRunContext &ctx, bool value) {
  ctx.enter_interactive = value;
}

inline void SetRequestExit(const CliRunContext &ctx, bool value) {
  ctx.request_exit = value;
}

inline void SetForceExit(const CliRunContext &ctx, bool value) {
  ctx.force_exit = value;
}

} // namespace AMInterface::cli::argstruct_common
