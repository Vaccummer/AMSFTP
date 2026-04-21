#pragma once

#include <cstddef>

namespace AMInterface::input::model {

struct RawToken {
  size_t start = 0;
  size_t end = 0;
  size_t content_start = 0;
  size_t content_end = 0;
  bool quoted = false;
};

} // namespace AMInterface::input::model
