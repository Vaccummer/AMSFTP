#pragma once

#include "foundation/core/Enum.hpp"
#include <cstddef>

namespace AMInterface::parser::model {

/**
 * @brief Raw token produced by shell-like lexical split.
 */
struct RawToken {
  size_t start = 0;
  size_t end = 0;
  size_t content_start = 0;
  size_t content_end = 0;
  bool quoted = false;
  AMTokenType type = AMTokenType::Unset;
};

} // namespace AMInterface::parser::model
