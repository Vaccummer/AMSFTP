#include "Isocline/isocline.h"
#include "foundation/tools/string.hpp"
#include "interface/prompt/Prompt.hpp"
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <sys/stat.h>

namespace AMInterface::prompt {

namespace {
/**
 * @brief Bridge isocline highlight callbacks to the token analyzer.
 *
 * @param henv Highlight environment provided by isocline.
 * @param input Current input text.
 * @param arg Pointer to the token analyzer instance.
 */
// void PromptHighlighter_(ic_highlight_env_t *henv, const char *input,
//                         void *arg) {
//   if (!henv || !input || !arg) {
//     return;
//   }
//   AMInterface::parser::TokenTypeAnalyzer &analyzer = ...;
//   std::string formatted;
//   analyzer.HighlightFormatted(input, &formatted);
//   if (formatted.empty()) {
//     return;
//   }
//   ic_highlight_formatted(henv, input, formatted.c_str());
// }

/**
 * @brief No-op highlighter for prompts that should not show syntax colors.
 *
 * @param henv Highlight environment provided by isocline.
 * @param input Current input text.
 * @param arg User-provided argument (unused).
 */
void PromptNoHighlight_(ic_highlight_env_t *henv, const char *input,
                        void *arg) {
  (void)henv;
  (void)input;
  (void)arg;
}

/**
 * @brief No-op completer to silence completion during simple prompts.
 *
 * @param cenv Completion environment (unused).
 * @param prefix Current input prefix (unused).
 */
void PromptNoComplete_(ic_completion_env_t *cenv, const char *prefix) {
  (void)cenv;
  (void)prefix;
}

/**
 * @brief Query-mode prompt callback context.
 */
struct PromptValueQueryContext {
  const std::function<bool(const std::string &)> *checker = nullptr;
  const std::vector<std::pair<std::string, std::string>> *candidates = nullptr;
  std::string valid_tag;
  std::string invalid_tag;
};

void SplitPromptForReadline_(const std::string &full_prompt,
                             std::string *header, std::string *line) {
  if (header) {
    header->clear();
  }
  if (!line) {
    return;
  }
  line->clear();
  if (full_prompt.empty()) {
    return;
  }
  const size_t split = full_prompt.find_last_of('\n');
  if (split == std::string::npos) {
    *line = full_prompt;
    return;
  }
  if (header) {
    *header = full_prompt.substr(0, split);
  }
  *line = full_prompt.substr(split + 1);
}

class ScopedAtomicFlag_ {
public:
  explicit ScopedAtomicFlag_(std::atomic<bool> *flag, bool value = true)
      : flag_(flag) {
    if (flag_ != nullptr) {
      old_ = flag_->exchange(value, std::memory_order_relaxed);
      armed_ = true;
    }
  }

  ~ScopedAtomicFlag_() {
    if (armed_ && flag_ != nullptr) {
      flag_->store(old_, std::memory_order_relaxed);
    }
  }

private:
  std::atomic<bool> *flag_ = nullptr;
  bool old_ = false;
  bool armed_ = false;
};

std::shared_ptr<IsoclineProfile>
CurrentProfile_(IsoclineProfileManager &profile_manager) {
  return profile_manager.CurrentProfile();
}

/**
 * @brief Query-mode highlighter that marks valid/invalid input values.
 */
void PromptValueQueryHighlight_(ic_highlight_env_t *henv, const char *input,
                                void *arg) {
  if (!henv || !input || !arg) {
    return;
  }
  const auto *ctx = static_cast<const PromptValueQueryContext *>(arg);
  if (!ctx->checker || !(*ctx->checker)) {
    return;
  }

  const std::string text(input);
  const bool is_valid = (*ctx->checker)(text);
  const std::string &tag = is_valid ? ctx->valid_tag : ctx->invalid_tag;
  if (tag.empty()) {
    return;
  }

  std::string formatted;
  formatted.reserve(text.size() + tag.size() + 4);
  formatted.append(tag);
  formatted.append(AMStr::BBCEscape(text));
  formatted.append("[/]");
  ic_highlight_formatted(henv, input, formatted.c_str());
}

/**
 * @brief Query-mode completer that uses explicit candidate strings.
 */
void PromptValueQueryComplete_(ic_completion_env_t *cenv, const char *prefix) {
  if (!cenv) {
    return;
  }
  (void)prefix;

  auto *ctx =
      static_cast<const PromptValueQueryContext *>(ic_completion_arg(cenv));
  if (!ctx) {
    return;
  }

  long cursor = 0;
  const char *input_c = ic_completion_input(cenv, &cursor);
  if (!input_c || cursor < 0) {
    return;
  }
  std::string input(input_c);
  auto cur = static_cast<size_t>(cursor);
  if (cur > input.size()) {
    cur = input.size();
  }

  size_t token_start = cur;
  while (token_start > 0 &&
         !std::isspace(static_cast<unsigned char>(input[token_start - 1]))) {
    --token_start;
  }
  size_t token_end = cur;
  while (token_end < input.size() &&
         !std::isspace(static_cast<unsigned char>(input[token_end]))) {
    ++token_end;
  }

  const std::string token_prefix = input.substr(token_start, cur - token_start);
  const long delete_before = static_cast<long>(cur - token_start);
  const long delete_after = static_cast<long>(token_end - cur);

  if (!ctx->candidates || ctx->candidates->empty()) {
    return;
  }
  for (const auto &candidate_item : *ctx->candidates) {
    const std::string &candidate = candidate_item.first;
    if (!token_prefix.empty() && candidate.rfind(token_prefix, 0) != 0) {
      continue;
    }
    const char *help =
        candidate_item.second.empty() ? nullptr : candidate_item.second.c_str();
    ic_add_completion_prim(cenv, candidate.c_str(), nullptr, help,
                           delete_before, delete_after);
  }
}

} // namespace

void PromptIOManager::PrintRaw(const std::string &text) {
  EmitOutput_(text);
}

void PromptIOManager::Print(const std::string &text) {
  EmitOutput_(EnsureTrailingNewline_(text));
}

void PromptIOManager::PrintOperationAbort() {
  const std::string abort_style =
      isocline_profile_manager_.style_config_manager_.GetInitArg()
          .style.common.abort;
  if (abort_style.empty()) {
    Print("⚠️  " + kvars::operation_abort_text);
    return;
  }
  Print("⚠️  " + abort_style + AMStr::BBCEscape(kvars::operation_abort_text) +
        "[/]");
}

void PromptIOManager::FlushCachedOutput() {
  std::string output;
  {
    std::lock_guard<std::mutex> lock(io_state_.cached_output_mutex_);
    if (io_state_.cached_output_.empty()) {
      return;
    }
    output.swap(io_state_.cached_output_);
  }

  if (output.empty()) {
    return;
  }
  EmitOutput_(output, false);
}

void PromptIOManager::SetCacheOutputOnly(bool enabled) {
  if (enabled) {
    io_state_.cache_output_lock_depth_.fetch_add(1, std::memory_order_relaxed);
    return;
  }

  int depth = io_state_.cache_output_lock_depth_.load(std::memory_order_relaxed);
  if (depth <= 0) {
    io_state_.cache_output_lock_depth_.store(0, std::memory_order_relaxed);
    return;
  }
  while (depth > 0) {
    if (io_state_.cache_output_lock_depth_.compare_exchange_weak(
            depth, depth - 1, std::memory_order_relaxed,
            std::memory_order_relaxed)) {
      if (depth == 1) {
        FlushCachedOutput();
      }
      return;
    }
  }
  if (depth <= 0) {
    io_state_.cache_output_lock_depth_.store(0, std::memory_order_relaxed);
  }
}

bool PromptIOManager::IsCacheOutputOnly() const {
  return io_state_.cache_output_lock_depth_.load(std::memory_order_relaxed) > 0;
}

void PromptIOManager::SetRefreshDiffMode(bool enabled) {
  io_state_.refresh_diff_mode_.store(enabled, std::memory_order_relaxed);
}

bool PromptIOManager::IsRefreshDiffMode() const {
  return io_state_.refresh_diff_mode_.load(std::memory_order_relaxed);
}

std::string PromptIOManager::EnsureTrailingNewline_(const std::string &text) {
  if (!text.empty() && text.back() == '\n') {
    return text;
  }
  return text + "\n";
}

bool PromptIOManager::IsAsciiText_(const std::string &text) {
  return std::all_of(text.begin(), text.end(), [](char ch) {
    return (static_cast<unsigned char>(ch) < 128);
  });
}

namespace {
bool HasBbcodeMarkup_(const std::string &text) {
  const size_t open = text.find('[');
  if (open == std::string::npos) {
    return false;
  }
  return text.find(']', open + 1) != std::string::npos;
}
} // namespace

size_t PromptIOManager::CommonPrefixAscii_(const std::string &lhs,
                                           const std::string &rhs) {
  const size_t limit = std::min(lhs.size(), rhs.size());
  size_t i = 0;

  while (i < limit && lhs[i] == rhs[i]) {
    ++i;
  }
  return i;
}

void PromptIOManager::SetActivePromptHeader_(const std::string &header) {
  std::lock_guard<std::mutex> lock(io_state_.print_mutex_);
  io_state_.active_prompt_header_ = header;
  io_state_.has_active_prompt_header_.store(!header.empty(),
                                            std::memory_order_relaxed);
}

void PromptIOManager::ClearActivePromptHeader_() {
  std::lock_guard<std::mutex> lock(io_state_.print_mutex_);
  io_state_.active_prompt_header_.clear();
  io_state_.has_active_prompt_header_.store(false, std::memory_order_relaxed);
}

bool PromptIOManager::ShouldReplayPromptHeader_() const {
  return io_state_.prompt_active_.load(std::memory_order_relaxed) &&
         io_state_.has_active_prompt_header_.load(std::memory_order_relaxed);
}

std::string PromptIOManager::BuildReplayFrame_(const std::string &msg) {
  if (!ShouldReplayPromptHeader_()) {
    return msg;
  }

  std::string header;
  {
    std::lock_guard<std::mutex> lock(io_state_.print_mutex_);
    header = io_state_.active_prompt_header_;
  }
  if (header.empty()) {
    return msg;
  }

  std::string out = msg;
  if (!out.empty() && out.back() != '\n') {
    out.push_back('\n');
  }
  out += header;
  out.push_back('\n');
  return out;
}

bool PromptIOManager::TryCacheOutput_(const std::string &text) {
  if (!IsCacheOutputOnly()) {
    return false;
  }
  std::lock_guard<std::mutex> lock(io_state_.cached_output_mutex_);
  io_state_.cached_output_ += text;
  return true;
}

void PromptIOManager::EmitOutput_(const std::string &text, bool allow_cache) {
  if (allow_cache && TryCacheOutput_(text)) {
    return;
  }

  const bool replay_prompt_header = ShouldReplayPromptHeader_();
  std::string replay_frame;
  if (replay_prompt_header) {
    replay_frame = BuildReplayFrame_(text);
  }

  if (io_state_.refresh_occupied_lines_.load(std::memory_order_relaxed) <= 0) {
    if (!replay_prompt_header && ic_is_editline_active() &&
        ic_print_async(text.c_str())) {
      return;
    }
    std::lock_guard<std::mutex> lock(io_state_.print_mutex_);
    if (auto profile = CurrentProfile_(isocline_profile_manager_); profile) {
      (void)profile->Use();
    }
    if (replay_prompt_header) {
      PrintSyncLocked_(replay_frame);
      if (io_state_.prompt_active_.load(std::memory_order_relaxed) ||
          io_state_.secure_phase_.load(std::memory_order_relaxed)) {
        (void)ic_request_refresh_async();
      }
    } else {
      PrintSyncLocked_(text);
    }
    return;
  }

  std::lock_guard<std::mutex> lock(io_state_.print_mutex_);
  if (auto profile = CurrentProfile_(isocline_profile_manager_); profile) {
    (void)profile->Use();
  }
  PrintInsertAndRepaintLocked_(text);
  if (io_state_.prompt_active_.load(std::memory_order_relaxed) ||
      io_state_.secure_phase_.load(std::memory_order_relaxed)) {
    (void)ic_request_refresh_async();
  }
}

void PromptIOManager::AppendMoveUpRows_(std::string *frame, int rows) {
  if (frame == nullptr || rows <= 0) {
    return;
  }
  *frame += "\r\x1b[" + std::to_string(rows) + "A";
}

void PromptIOManager::AppendClearRows_(std::string *frame, int rows) {
  if (frame == nullptr || rows <= 0) {
    return;
  }
  for (int i = 0; i < rows; ++i) {
    *frame += "\x1b[2K\r";
    *frame += "\n";
  }
}

void PromptIOManager::AppendRowDiffUpdate_(std::string *frame,
                                           const std::string &old_line,
                                           const std::string &new_line) const {
  if (frame == nullptr) {
    return;
  }
  if (old_line == new_line) {
    *frame += "\x1b[1B\r";
    return;
  }

  // BBCode tags do not occupy terminal columns, so byte-based cursor
  // diffs can leave stale text. Redraw the whole row when markup exists.
  if (HasBbcodeMarkup_(old_line) || HasBbcodeMarkup_(new_line)) {
    *frame += "\x1b[2K\r";
    *frame += new_line;
    *frame += "\x1b[1B\r";
    return;
  }

  if (!IsAsciiText_(old_line) || !IsAsciiText_(new_line)) {
    *frame += "\x1b[2K\r";
    *frame += new_line;
    *frame += "\x1b[1B\r";
    return;
  }

  const size_t common_prefix = CommonPrefixAscii_(old_line, new_line);
  if (common_prefix == 0) {
    *frame += "\x1b[2K\r";
    *frame += new_line;
    *frame += "\x1b[1B\r";
    return;
  }

  *frame += "\r\x1b[" + std::to_string(common_prefix) + "C";
  *frame += "\x1b[K";
  if (common_prefix < new_line.size()) {
    *frame += new_line.substr(common_prefix);
  }
  *frame += "\x1b[1B\r";
}

void PromptIOManager::PrintSyncLocked_(const std::string &text) {
  if (TryCacheOutput_(text)) {
    return;
  }
  if (text.find('\x1b') != std::string::npos) {
    ic_term_write(text.c_str());
  } else {
    ic_print(text.c_str());
  }
  ic_term_flush();
}

void PromptIOManager::PrintSyncRefreshLocked_(const std::string &text) {
  if (TryCacheOutput_(text)) {
    return;
  }
  if (text.find('\x1b') != std::string::npos) {
    ic_term_write_bbcode(text.c_str());
  } else {
    ic_print(text.c_str());
  }
  ic_term_flush();
}

void PromptIOManager::PrintInsertAndRepaintLocked_(const std::string &msg) {
  const int old_rows = painted_refresh_rows_;
  if (old_rows <= 0) {
    PrintSyncRefreshLocked_(msg);
    return;
  }

  const int new_rows = static_cast<int>(refresh_lines_.size());
  const int total_rows = std::max(old_rows, new_rows);
  const bool diff_mode =
      io_state_.refresh_diff_mode_.load(std::memory_order_relaxed);

  std::string frame;
  AppendMoveUpRows_(&frame, old_rows);
  frame += "\x1b[2K\r";
  frame += msg;
  for (int i = 0; i < total_rows; ++i) {
    const std::string old_line =
        (i < old_rows && static_cast<size_t>(i) < painted_refresh_lines_.size())
            ? painted_refresh_lines_[static_cast<size_t>(i)]
            : std::string{};
    const std::string new_line =
        (i < new_rows) ? refresh_lines_[static_cast<size_t>(i)] : std::string{};

    if (diff_mode) {
      AppendRowDiffUpdate_(&frame, old_line, new_line);
      continue;
    }
    frame += "\x1b[2K\r";
    frame += new_line;
    frame += "\x1b[1B\r";
  }
  AppendMoveUpRows_(&frame, total_rows - new_rows);
  PrintSyncRefreshLocked_(frame);
  painted_refresh_rows_ = new_rows;
  painted_refresh_lines_ = refresh_lines_;
}

void PromptIOManager::RepaintRefreshLocked_() {
  const int new_rows = static_cast<int>(refresh_lines_.size());
  const int old_rows = painted_refresh_rows_;
  if (new_rows <= 0 && old_rows <= 0) {
    painted_refresh_rows_ = 0;
    return;
  }

  const int total_rows = std::max(old_rows, new_rows);
  const bool diff_mode =
      io_state_.refresh_diff_mode_.load(std::memory_order_relaxed);
  std::string frame;
  AppendMoveUpRows_(&frame, old_rows);
  for (int i = 0; i < total_rows; ++i) {
    const std::string old_line =
        (i < old_rows && static_cast<size_t>(i) < painted_refresh_lines_.size())
            ? painted_refresh_lines_[static_cast<size_t>(i)]
            : std::string{};
    const std::string new_line =
        (i < new_rows) ? refresh_lines_[static_cast<size_t>(i)] : std::string{};

    if (diff_mode) {
      AppendRowDiffUpdate_(&frame, old_line, new_line);
      continue;
    }
    frame += "\x1b[2K\r";
    frame += new_line;
    frame += "\x1b[1B\r";
  }
  AppendMoveUpRows_(&frame, total_rows - new_rows);
  PrintSyncRefreshLocked_(frame);
  painted_refresh_rows_ = new_rows;
  painted_refresh_lines_ = refresh_lines_;
}

void PromptIOManager::ClearRefreshLocked_() {
  if (painted_refresh_rows_ <= 0) {
    refresh_lines_.clear();
    painted_refresh_lines_.clear();
    return;
  }

  std::string frame;
  AppendMoveUpRows_(&frame, painted_refresh_rows_);
  AppendClearRows_(&frame, painted_refresh_rows_);
  PrintSyncRefreshLocked_(frame);

  painted_refresh_rows_ = 0;
  refresh_lines_.clear();
  painted_refresh_lines_.clear();
}

void PromptIOManager::RefreshBegin(int lines) {
  const int occupied = std::max(0, lines);
  std::lock_guard<std::mutex> lock(io_state_.print_mutex_);
  if (auto profile = CurrentProfile_(isocline_profile_manager_); profile) {
    (void)profile->Use();
  }
  const bool detached_mode =
      occupied > 0 && painted_refresh_rows_ <= 0 &&
      !io_state_.prompt_active_.load(std::memory_order_relaxed) &&
      !io_state_.secure_phase_.load(std::memory_order_relaxed);
  io_state_.refresh_detached_mode_.store(detached_mode,
                                         std::memory_order_relaxed);
  if (detached_mode) {
    PrintSyncLocked_("\n");
  }
  io_state_.refresh_occupied_lines_.store(occupied, std::memory_order_relaxed);
  refresh_lines_.assign(static_cast<size_t>(occupied), "");
  RepaintRefreshLocked_();
}

void PromptIOManager::RefreshRender(
    const std::vector<std::optional<std::string>> &lines) {
  std::lock_guard<std::mutex> lock(io_state_.print_mutex_);
  io_state_.refresh_occupied_lines_.store(static_cast<int>(lines.size()),
                                          std::memory_order_relaxed);

  const size_t old_size = refresh_lines_.size();
  refresh_lines_.resize(lines.size(), "");
  for (size_t i = 0; i < lines.size(); ++i) {
    if (lines[i].has_value()) {
      refresh_lines_[i] = lines[i].value();
    } else if (i >= old_size) {
      refresh_lines_[i].clear();
    }
  }
  RepaintRefreshLocked_();
  if (io_state_.prompt_active_.load(std::memory_order_relaxed) ||
      io_state_.secure_phase_.load(std::memory_order_relaxed)) {
    (void)ic_request_refresh_async();
  }
}

void PromptIOManager::RefreshEnd() {
  std::lock_guard<std::mutex> lock(io_state_.print_mutex_);
  if (auto profile = CurrentProfile_(isocline_profile_manager_); profile) {
    (void)profile->Use();
  }
  const bool detached_mode = io_state_.refresh_detached_mode_.exchange(
      false, std::memory_order_relaxed);
  const int cleared_rows = painted_refresh_rows_;
  ClearRefreshLocked_();
  if (detached_mode && cleared_rows > 0) {
    std::string frame;
    AppendMoveUpRows_(&frame, cleared_rows);
    PrintSyncLocked_(frame);
  }
  io_state_.refresh_occupied_lines_.store(0, std::memory_order_relaxed);
}

void PromptIOManager::ErrorFormat(const std::string &error_name,
                                  const std::string &error_msg, bool is_exit,
                                  int exit_code) {
  std::ostringstream body;
  if (error_name.empty()) {
    body << "❌ " << error_msg;
  } else {
    body << "❌ " << error_name << " : " << error_msg;
  }
  Print(body.str());

  if (is_exit) {
    ic_term_flush();
    std::exit(exit_code);
  }
}

void PromptIOManager::ErrorFormat(const ECM &rcm, bool is_exit) {
  std::string reason = AMStr::Strip(rcm.error);
  if (reason.empty()) {
    reason = std::string(AMStr::ToString(rcm.code));
  }
  std::string operation = AMStr::Strip(rcm.operation);
  if (operation.empty()) {
    operation = "";
  }
  std::string target = AMStr::Strip(rcm.target);
  if (target.empty()) {
    target = "";
  }
  const auto esc = [](std::string v) {
    AMStr::replace(v, "\\", "\\\\");
    AMStr::replace(v, "\"", "\\\"");
    return v;
  };

  std::ostringstream body;
  body << "\\[" << AMStr::ToString(rcm.code) << "] " << reason
       << " (operation=\"" << esc(operation) << "\", target=\"" << esc(target)
       << "\"";
  if (rcm.raw_error.has_value()) {
    body << ", cause=\"" << RawErrorSourceName(rcm.raw_error->source) << ": "
         << rcm.raw_error->code << "\"";
  }
  body << ")";
  ErrorFormat("", body.str(), is_exit, static_cast<int>(rcm.code));
}

/** Prompt for a yes/no response. */
bool PromptIOManager::PromptYesNo(const std::string &prompt, bool *canceled) {
  auto answer = LiteralPrompt(
      prompt, "", {{"y", "yes"}, {"n", "no"}, {"Y", "yes"}, {"N", "no"}});
  if (canceled) {
    *canceled = !answer.has_value();
  }
  const bool is_yes =
      answer.has_value() && AMStr::lowercase(AMStr::Strip(*answer)) == "y";
  if (!is_yes) {
    PrintOperationAbort();
  }
  return is_yes;
}

void PromptIOManager::ClearScreen(bool clear_scrollback) {
  std::string frame;
  if (clear_scrollback) {
    frame += "\x1b[3J";
  }
  frame += "\x1b[2J\x1b[H";
  EmitOutput_(frame);
}

void PromptIOManager::UseAlternateScreen(bool enable) {
  EmitOutput_(enable ? "\x1b[?1049h" : "\x1b[?1049l");
}

void PromptIOManager::SetCursorVisible(bool visible) {
  EmitOutput_(visible ? "\x1b[?25h" : "\x1b[?25l");
}

void PromptIOManager::SyncCurrentHistory() {
  isocline_profile_manager_.SyncCurrentHistory();
}

/** Prompt for a line of input with optional defaults.
bool PromptIOManager::PromptLine(const std::string &prompt, std::string *out,
                                 const std::string &default_value,
                                 bool allow_empty, bool *canceled,
                                 bool show_default) {
  if (canceled)
    *canceled = false;
  if (!out)
    return false;

  std::string display_prompt = prompt;
  if (show_default && !default_value.empty()) {
    display_prompt = AMStr::fmt("{}[!e][{}][/e] ", prompt, default_value);
  }

  std::string placeholder_value;
  if (!show_default && !default_value.empty()) {
    placeholder_value = default_value;
  }

  const bool ok = Prompt(display_prompt, placeholder_value, out);
  if (!ok) {
    if (canceled)
      *canceled = true;
    return false;
  }

  if (out->empty() && !default_value.empty()) {
    *out = default_value;
  }

  if (!allow_empty && out->empty())
    return false;
  return true;
}
*/

std::optional<std::string> PromptIOManager::Prompt(
    const std::string &prompt, const std::string &placeholder,
    const std::function<bool(const std::string &)> &checker,
    const std::vector<std::pair<std::string, std::string>> &candidates,
    const PromptReadOptions &options) {

  PromptValueQueryContext query_ctx;
  query_ctx.checker = checker ? &checker : nullptr;
  query_ctx.candidates = candidates.empty() ? nullptr : &candidates;
  if (query_ctx.checker) {
    query_ctx.valid_tag = "[" + kvars::valid_value_key + "]";
    query_ctx.invalid_tag = "[" + kvars::invalid_value_key + "]";
  }

  ic_completer_fun_t *completer = &PromptNoComplete_;
  void *completer_arg = nullptr;
  if (query_ctx.candidates) {
    completer = &PromptValueQueryComplete_;
    completer_arg = &query_ctx;
  }
  ic_highlight_fun_t *highlighter = &PromptNoHighlight_;
  void *highlighter_arg = nullptr;
  if (query_ctx.checker) {
    highlighter = &PromptValueQueryHighlight_;
    highlighter_arg = &query_ctx;
  }
  if (options.completer.has_value()) {
    completer = options.completer.value();
    completer_arg = options.completer_data.has_value()
                        ? options.completer_data.value()
                        : completer_arg;
  } else if (options.completer_data.has_value()) {
    completer_arg = options.completer_data.value();
  }
  if (options.highlighter.has_value()) {
    highlighter = options.highlighter.value();
    highlighter_arg = options.highlighter_data.has_value()
                          ? options.highlighter_data.value()
                          : highlighter_arg;
  } else if (options.highlighter_data.has_value()) {
    highlighter_arg = options.highlighter_data.value();
  }

  // ScopedPrintCacheLockGuard_ lock(*this);
  // ScopedPromptHookGuard_ hooklock;
  // ScopedPromptProcessedInputGuard_ processed_input_guard;
  // (void)processed_input_guard;
  const char *initial = placeholder.empty() ? nullptr : placeholder.c_str();
  char *line = nullptr;
  ScopedAtomicFlag_ prompt_active_guard(&io_state_.prompt_active_);
  auto profile = isocline_profile_manager_.CurrentProfile();
  if (profile && profile->Use()) {
    std::optional<ic_completer_fun_t *> completer_opt = std::nullopt;
    std::optional<void *> completer_data_opt = std::nullopt;
    if (completer != nullptr || completer_arg != nullptr) {
      completer_opt = completer;
      completer_data_opt = completer_arg;
    }
    auto completer_guard =
        profile->TemporarySetCompleter(completer_opt, completer_data_opt);
    (void)completer_guard;

    std::optional<ic_highlight_fun_t *> highlighter_opt = std::nullopt;
    std::optional<void *> highlighter_data_opt = std::nullopt;
    if (highlighter != nullptr || highlighter_arg != nullptr) {
      highlighter_opt = highlighter;
      highlighter_data_opt = highlighter_arg;
    }
    auto highlighter_guard =
        profile->TemporarySetHighlighter(highlighter_opt, highlighter_data_opt);
    (void)highlighter_guard;

    line = ic_readline_ex(prompt.c_str(), initial);
  } else {
    ic_set_default_completer(completer, completer_arg);
    ic_set_default_highlighter(highlighter, highlighter_arg);
    line = ic_readline_ex(prompt.c_str(), initial);
  }
  if (!line) {
    PrintOperationAbort();
    return std::nullopt;
  }
  // isocline_profile_manager_.RemoveLastHistoryEntry();
  std::string out = line;
  ic_free(line);
  return out;
}

/**
 * @brief Prompt for one literal value using a literal->help dictionary.
 */
std::optional<std::string> PromptIOManager::LiteralPrompt(
    const std::string &prompt, const std::string &placeholder,
    const std::vector<std::pair<std::string, std::string>> &literals) {
  std::function<bool(const std::string &)> literal_checker;
  if (!literals.empty()) {
    literal_checker = [&literals](const std::string &text) {
      const std::string normalized = AMStr::Strip(text);
      return std::any_of(
          literals.begin(), literals.end(),
          [&normalized](const auto &item) { return item.first == normalized; });
    };
  }
  return Prompt(prompt, placeholder, literal_checker, literals);
}

/**
 * @brief Prompt for a command line using the shared readline handle.
 */
std::optional<std::string>
PromptIOManager::PromptCore(const std::string &prompt) {
  std::string prompt_header;
  std::string prompt_line;
  SplitPromptForReadline_(prompt, &prompt_header, &prompt_line);
  if (!prompt_header.empty()) {
    Print(prompt_header);
  }
  SetActivePromptHeader_(prompt_header);

  // ScopedPrintCacheLockGuard_ lock(*this);
  // ScopedPromptHookGuard_ hooklock;
  char *line = nullptr;
  ScopedAtomicFlag_ prompt_active_guard(&io_state_.prompt_active_);
  auto profile = CurrentProfile_(isocline_profile_manager_);
  if (profile && profile->Use()) {
    line = ic_readline_ex(prompt_line.c_str(), nullptr);
  } else {
    line = ic_readline_ex(prompt_line.c_str(), nullptr);
  }
  if (!line) {
    ClearActivePromptHeader_();
    return std::nullopt;
  }
  // isocline_profile_manager_.RemoveLastHistoryEntry();
  std::string out = line;
  ic_free(line);
  ClearActivePromptHeader_();
  return out;
}

std::optional<std::string>
PromptIOManager::SecurePrompt(const std::string &prompt) {
  ScopedAtomicFlag_ secure_phase_guard(&io_state_.secure_phase_);

  char *line = ic_readline_secure(prompt.c_str(), nullptr);
  if (!line) {
    PrintOperationAbort();
    return std::nullopt;
  }
  std::string out = line;
  ic_free(line);
  return out;
}

} // namespace AMInterface::prompt
