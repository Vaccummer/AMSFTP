#pragma once
#include <sstream>
#include <string>
#include <vector>

namespace {
/**
 * @brief Join strings with a separator.
 */
inline std::string JoinStrings_(const std::vector<std::string> &items,
                                const std::string &sep) {
  if (items.empty()) {
    return "";
  }

  std::ostringstream oss;
  for (size_t i = 0; i < items.size(); ++i) {
    if (i > 0) {
      oss << sep;
    }
    oss << items[i];
  }
  return oss.str();
}
} // namespace
