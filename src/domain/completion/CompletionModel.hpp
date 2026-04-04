#pragma once

#include <cstdint>

namespace AMDomain::completion {

/**
 * @brief Settings payload for `Options.Completer`.
 */
struct CompleterArg {
  int64_t maxnum = 999;
  int64_t maxrows_perpage = 5;
  bool number_pick = false;
  bool auto_fillin = false;
  int64_t complete_delay_ms = 100;
  int64_t async_workers = 2;
};

} // namespace AMDomain::completion

