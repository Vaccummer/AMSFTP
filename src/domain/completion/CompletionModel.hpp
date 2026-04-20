#pragma once

#include <algorithm>
#include <cstdint>
#include <limits>

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

inline void NormalizeCompleterArg(CompleterArg *arg) {
  if (!arg) {
    return;
  }
  arg->maxnum = std::max<int64_t>(1, arg->maxnum);
  arg->maxrows_perpage = std::max<int64_t>(1, arg->maxrows_perpage);
  arg->complete_delay_ms = std::max<int64_t>(0, arg->complete_delay_ms);
  arg->async_workers = std::max<int64_t>(1, arg->async_workers);
  if (arg->maxrows_perpage >
      static_cast<int64_t>(std::numeric_limits<long>::max())) {
    arg->maxrows_perpage =
        static_cast<int64_t>(std::numeric_limits<long>::max());
  }
}

} // namespace AMDomain::completion
