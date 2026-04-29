#pragma once

#include "foundation/core/DataClass.hpp"
#include <vector>

namespace AMApplication::filesystem {
[[nodiscard]] std::vector<PathInfo>
CompactMatchedPaths_(const std::vector<PathInfo> &raw);
} // namespace AMApplication::filesystem
