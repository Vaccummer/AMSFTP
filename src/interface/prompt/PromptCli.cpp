#include "Isocline/isocline.h"
#include "foundation/tools/prompt_ui.hpp"
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
  mutable std::mutex cache_mtx;
  mutable std::string cached_input;
  mutable bool cached_result = false;
  mutable bool has_cached_result = false;
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

bool QueryCheckerCachedResult_(const PromptValueQueryContext &ctx,
                               const std::string &text) {
  if (!ctx.checker || !(*ctx.checker)) {
    return true;
  }
  {
    std::lock_guard<std::mutex> lock(ctx.cache_mtx);
    if (ctx.has_cached_result && ctx.cached_input == text) {
      return ctx.cached_result;
    }
  }
  bool evaluated = false;
  try {
    evaluated = (*ctx.checker)(text);
  } catch (...) {
    evaluated = false;
  }
  {
    std::lock_guard<std::mutex> lock(ctx.cache_mtx);
    ctx.cached_input = text;
    ctx.cached_result = evaluated;
    ctx.has_cached_result = true;
  }
  return evaluated;
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
  const bool is_valid = QueryCheckerCachedResult_(*ctx, text);
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
    if (!token_prefix.empty() && !candidate.starts_with(token_prefix)) {
      continue;
    }
    const char *help =
        candidate_item.second.empty() ? nullptr : candidate_item.second.c_str();
    ic_add_completion_prim(cenv, candidate.c_str(), nullptr, help,
                           delete_before, delete_after);
  }
}

void AppendRenderLinesToFrame_(std::string *frame,
                               const std::vector<std::string> &lines) {
  if (frame == nullptr || lines.empty()) {
    return;
  }
  for (const auto &line : lines) {
    *frame += "\x1b[2K\r";
    *frame += line;
    *frame += "\n";
  }
}

std::string BuildRepaintFrame_(int old_rows, int new_rows,
                               const std::vector<std::string> &new_lines) {
  if (old_rows <= 0 && new_rows <= 0) {
    return {};
  }

  std::string frame = {};
  AMPromptUI::AppendMoveUpRows(&frame, old_rows);
  if (old_rows > 0) {
    AMPromptUI::AppendClearRows(&frame, old_rows);
    AMPromptUI::AppendMoveUpRows(&frame, old_rows);
  }
  AppendRenderLinesToFrame_(&frame, new_lines);
  return frame;
}

std::string
BuildInsertAndRepaintFrame_(int old_rows, const std::string &msg,
                            const std::vector<std::string> &new_lines) {
  if (old_rows <= 0) {
    return msg;
  }

  std::string frame = {};
  AMPromptUI::AppendMoveUpRows(&frame, old_rows);
  AMPromptUI::AppendClearRows(&frame, old_rows);
  AMPromptUI::AppendMoveUpRows(&frame, old_rows);
  frame += msg;
  AppendRenderLinesToFrame_(&frame, new_lines);
  return frame;
}

std::string BuildClearFrame_(int old_rows) {
  if (old_rows <= 0) {
    return {};
  }
  std::string frame = {};
  AMPromptUI::AppendMoveUpRows(&frame, old_rows);
  AMPromptUI::AppendClearRows(&frame, old_rows);
  AMPromptUI::AppendMoveUpRows(&frame, old_rows);
  return frame;
}

} // namespace

void PromptIOManager::PrintRaw(const std::string &text) { EmitOutput_(text); }

void PromptIOManager::Print(const std::string &text) {
  EmitOutput_(AMPromptUI::EnsureTrailingNewline(text));
}

void PromptIOManager::StaticPrint(const std::string &text,
                                  bool ensure_newline) {
  const std::string output =
      ensure_newline ? AMPromptUI::EnsureTrailingNewline(text) : text;
  if (output.find('\x1b') != std::string::npos) {
    ic_term_write(output.c_str());
  } else {
    ic_print(output.c_str());
  }
  ic_term_flush();
}

void PromptIOManager::PrintOperationAbort() {
  const std::string abort_style = isocline_profile_manager_.AbortStyle();
  if (abort_style.empty()) {
    Print("⛔  " + kvars::operation_abort_text);
    return;
  }
  Print("⛔  " + abort_style + AMStr::BBCEscape(kvars::operation_abort_text) +
        "[/]");
}

void PromptIOManager::FlushCachedOutput() {
  if (IsCacheOutputOnly()) {
    return;
  }
  std::string output = TakeCachedOutput_();
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

  int depth =
      io_state_.cache_output_lock_depth_.load(std::memory_order_relaxed);
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

std::string PromptIOManager::TakeCachedOutput_() {
  std::lock_guard<std::mutex> lock(io_state_.cached_output_mutex_);
  if (io_state_.cached_output_.empty()) {
    return {};
  }
  std::string output = {};
  output.swap(io_state_.cached_output_);
  return output;
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

  std::string output = text;
  if (!IsCacheOutputOnly()) {
    std::string cached_output = TakeCachedOutput_();
    if (!cached_output.empty()) {
      output = std::move(cached_output) + output;
    }
  }
  if (output.empty()) {
    return;
  }

  const bool replay_prompt_header = ShouldReplayPromptHeader_();
  std::string replay_frame;
  if (replay_prompt_header) {
    replay_frame = BuildReplayFrame_(output);
  }

  if (io_state_.refresh_occupied_lines_.load(std::memory_order_relaxed) <= 0) {
    if (!replay_prompt_header && ic_is_editline_active() &&
        ic_print_async(output.c_str())) {
      return;
    }
    std::lock_guard<std::mutex> lock(io_state_.print_mutex_);
    if (auto profile = isocline_profile_manager_.CurrentProfile(); profile) {
      (void)profile->Use();
    }
    if (replay_prompt_header) {
      PrintSyncLocked_(replay_frame);
      if (io_state_.prompt_active_.load(std::memory_order_relaxed) ||
          io_state_.secure_phase_.load(std::memory_order_relaxed)) {
        (void)ic_request_refresh_async();
      }
    } else {
      PrintSyncLocked_(output);
    }
    return;
  }

  std::lock_guard<std::mutex> lock(io_state_.print_mutex_);
  if (auto profile = isocline_profile_manager_.CurrentProfile(); profile) {
    (void)profile->Use();
  }
  PrintInsertAndRepaintLocked_(output);
  if (io_state_.prompt_active_.load(std::memory_order_relaxed) ||
      io_state_.secure_phase_.load(std::memory_order_relaxed)) {
    (void)ic_request_refresh_async();
  }
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
  ic_term_write_bbcode(text.c_str());
  ic_term_flush();
}

void PromptIOManager::PrintInsertAndRepaintLocked_(const std::string &msg) {
  const int old_rows = refresh_state_.rows_painted;
  if (old_rows <= 0 || !refresh_state_.active) {
    PrintSyncRefreshLocked_(msg);
    return;
  }

  const int cols = AMPromptUI::TerminalCols();
  const int new_rows =
      AMPromptUI::ComputeWrappedRows(refresh_state_.logical_lines, cols);
  const std::string frame =
      BuildInsertAndRepaintFrame_(old_rows, msg, refresh_state_.logical_lines);
  if (!frame.empty()) {
    PrintSyncRefreshLocked_(frame);
  }

  refresh_state_.rows_painted = new_rows;
  io_state_.refresh_occupied_lines_.store(new_rows, std::memory_order_relaxed);
}

void PromptIOManager::ResetRefreshStateLocked_() {
  refresh_state_.active = false;
  refresh_state_.rows_painted = 0;
  refresh_state_.logical_lines.clear();
}

void PromptIOManager::AssignRefreshRowsFromRenderInputLocked_(
    const std::vector<std::optional<std::string>> &lines) {
  const size_t old_size = refresh_state_.logical_lines.size();
  std::vector<std::string> normalized_rows = {};
  normalized_rows.reserve(lines.size());

  for (size_t i = 0; i < lines.size(); ++i) {
    std::string value = {};
    if (lines[i].has_value()) {
      value = lines[i].value();
    } else if (i < old_size) {
      value = refresh_state_.logical_lines[i];
    }

    value = AMStr::replace_all(value, "\r\n", "\n");
    value = AMStr::replace_all(value, "\r", "\n");
    value = AMStr::replace_all(value, "\t", "   ");

    size_t start = 0;
    while (start <= value.size()) {
      const size_t pos = value.find('\n', start);
      if (pos == std::string::npos) {
        normalized_rows.push_back(value.substr(start));
        break;
      }
      normalized_rows.push_back(value.substr(start, pos - start));
      start = pos + 1;
      if (start > value.size()) {
        break;
      }
    }
  }

  refresh_state_.logical_lines = std::move(normalized_rows);
}

void PromptIOManager::RepaintRefreshLocked_() {
  const int cols = AMPromptUI::TerminalCols();
  const int old_rows = refresh_state_.rows_painted;
  const int new_rows =
      AMPromptUI::ComputeWrappedRows(refresh_state_.logical_lines, cols);

  const std::string frame =
      BuildRepaintFrame_(old_rows, new_rows, refresh_state_.logical_lines);
  if (!frame.empty()) {
    PrintSyncRefreshLocked_(frame);
  }

  refresh_state_.active = true;
  refresh_state_.rows_painted = new_rows;
  io_state_.refresh_occupied_lines_.store(new_rows, std::memory_order_relaxed);
}

void PromptIOManager::ClearRefreshLocked_() {
  const int old_rows = refresh_state_.rows_painted;
  const std::string frame = BuildClearFrame_(old_rows);
  if (!frame.empty()) {
    PrintSyncRefreshLocked_(frame);
  }
  ResetRefreshStateLocked_();
  io_state_.refresh_occupied_lines_.store(0, std::memory_order_relaxed);
}

void PromptIOManager::RefreshBegin() {
  std::lock_guard<std::mutex> lock(io_state_.print_mutex_);
  if (auto profile = isocline_profile_manager_.CurrentProfile(); profile) {
    (void)profile->Use();
  }
  ResetRefreshStateLocked_();
  refresh_state_.active = true;
  io_state_.refresh_occupied_lines_.store(0, std::memory_order_relaxed);
}

void PromptIOManager::RefreshRender(
    const std::vector<std::optional<std::string>> &lines) {
  std::lock_guard<std::mutex> lock(io_state_.print_mutex_);

  AssignRefreshRowsFromRenderInputLocked_(lines);
  RepaintRefreshLocked_();
  if (io_state_.prompt_active_.load(std::memory_order_relaxed) ||
      io_state_.secure_phase_.load(std::memory_order_relaxed)) {
    (void)ic_request_refresh_async();
  }
}

void PromptIOManager::RefreshEnd() {
  std::lock_guard<std::mutex> lock(io_state_.print_mutex_);
  if (auto profile = isocline_profile_manager_.CurrentProfile(); profile) {
    (void)profile->Use();
  }
  ClearRefreshLocked_();
  io_state_.refresh_detached_mode_.store(false, std::memory_order_relaxed);
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
  if (rcm.code == EC::ConfigCanceled) {
    PrintOperationAbort();
    return;
  }

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

void PromptIOManager::PrintTaskResult(
    const std::shared_ptr<AMDomain::transfer::TaskInfo> &task_info) {
  (void)task_info;
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

std::optional<std::string> PromptIOManager::Prompt(
    const std::string &prompt, const std::string &placeholder,
    const std::function<bool(const std::string &)> &checker,
    const std::vector<std::pair<std::string, std::string>> &candidates,
    const PromptReadOptions &options) {
  FlushCachedOutput();

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

  const char *initial = placeholder.empty() ? nullptr : placeholder.c_str();
  char *line = nullptr;
  ScopedAtomicFlag_ prompt_active_guard(&io_state_.prompt_active_);
  auto profile = isocline_profile_manager_.CurrentProfile();
  const bool using_profile = profile && profile->Use();
  if (using_profile) {
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
    return std::nullopt;
  }
  std::string out = line;
  ic_free(line);
  if (using_profile) {
    (void)profile->RemoveLastHistoryEntryIfEquals(out);
  }
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
  FlushCachedOutput();
  std::string prompt_header;
  std::string prompt_line;
  SplitPromptForReadline_(prompt, &prompt_header, &prompt_line);
  if (!prompt_header.empty()) {
    Print(prompt_header);
  }
  SetActivePromptHeader_(prompt_header);

  char *line = nullptr;
  ScopedAtomicFlag_ prompt_active_guard(&io_state_.prompt_active_);
  auto profile = isocline_profile_manager_.CurrentProfile();
  const bool using_profile = profile && profile->Use();
  if (using_profile) {
    line = ic_readline_ex(prompt_line.c_str(), nullptr);
  } else {
    line = ic_readline_ex(prompt_line.c_str(), nullptr);
  }
  if (!line) {
    ClearActivePromptHeader_();
    return std::nullopt;
  }
  std::string out = line;
  ic_free(line);
  if (using_profile) {
    const std::string nickname = isocline_profile_manager_.CurrentNickname();
    {
      std::lock_guard<std::mutex> lock(io_state_.typein_result_mutex_);
      if (io_state_.has_last_typein_result_ &&
          io_state_.last_typein_result_ == out &&
          io_state_.last_typein_nickname_ == nickname) {
        (void)profile->RemoveLastHistoryEntry();
      }
      io_state_.last_typein_result_ = out;
      io_state_.last_typein_nickname_ = nickname;
      io_state_.has_last_typein_result_ = true;
    }
  }
  isocline_profile_manager_.PersistHistoryEntry(out);
  ClearActivePromptHeader_();
  return out;
}

std::optional<std::string>
PromptIOManager::SecurePrompt(const std::string &prompt) {
  FlushCachedOutput();
  ScopedAtomicFlag_ secure_phase_guard(&io_state_.secure_phase_);

  char *line = ic_readline_secure(prompt.c_str(), nullptr);
  if (!line) {
    return std::nullopt;
  }
  std::string out = line;
  ic_free(line);
  return out;
}

} // namespace AMInterface::prompt
