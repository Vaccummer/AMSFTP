#include "AMPromptManager.hpp"
#include <iostream>
#include <replxx.h>
#include <string>

namespace {
ReplxxActionResult EscAbortHandler(Replxx *rx, unsigned int, void *ud) {
  auto *self = static_cast<AMPromptManager *>(ud);
  if (self) {
    self->esc_pressed_ = true;
  }
  if (rx) {
    return replxx_invoke(rx, REPLXX_ACTION_ABORT_LINE, 0);
  }
  return REPLXX_ACTION_RESULT_BAIL;
}
} // namespace

AMPromptManager &AMPromptManager::Instance() {
  static AMPromptManager instance;
  return instance;
}

AMPromptManager::AMPromptManager() { replxx_ = replxx_init(); }

AMPromptManager::~AMPromptManager() {
  if (replxx_) {
    replxx_end(replxx_);
    replxx_ = nullptr;
  }
}

void AMPromptManager::Print(const std::vector<std::string> &items,
                            const std::string &sep, const std::string &end) {
  std::ostringstream oss;
  for (size_t i = 0; i < items.size(); ++i) {
    if (i > 0) {
      oss << sep;
    }
    oss << items[i];
  }
  oss << end;

  const std::string output = oss.str();
  std::lock_guard<std::mutex> lock(print_mutex_);
  std::cout << output;
  std::cout.flush();
}

bool AMPromptManager::Prompt(const std::string &prompt,
                             const std::string &placeholder,
                             std::string *out_input) {
  if (!out_input) {
    return true;
  }

  esc_pressed_ = false;

  if (!replxx_) {
    return true;
  }

  if (!placeholder.empty()) {
    replxx_set_preload_buffer(replxx_, placeholder.c_str());
  } else {
    replxx_set_preload_buffer(replxx_, "");
  }

  const char *line = replxx_input(replxx_, prompt.c_str());
  if (esc_pressed_) {
    return true;
  }
  if (!line) {
    return true;
  }
  *out_input = std::string(line);
  return esc_pressed_;
}
