#pragma once

#include "interface/cli/CLIServices.hpp"

namespace AMInterface::cli::argstruct_common {

inline void SetEnterInteractive(const CliRunContext &ctx, bool value) {
  ctx.enter_interactive = value;
}

inline void SetRequestExit(const CliRunContext &ctx, bool value) {
  ctx.request_exit = value;
}

inline void SetSkipLoopExitCallbacks(const CliRunContext &ctx, bool value) {
  ctx.skip_loop_exit_callbacks = value;
}

} // namespace AMInterface::cli::argstruct_common
