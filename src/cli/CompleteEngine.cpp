#include "AMCLI/Completer.hpp"
#include "AMCLI/CompleteEngine.hpp"
#include "AMCLI/CompleteSources.hpp"
#include "AMBase/CommonTools.hpp"
#include "AMManager/Config.hpp"
#include "Isocline/isocline.h"

namespace {
/**
 * @brief Normalize a configured style into a bbcode opening tag.
 */
std::string NormalizeStyleTag_(const std::string &raw) {
  std::string trimmed = AMStr::Strip(raw);
  if (trimmed.empty()) {
    return "";
  }
  if (trimmed.find("[/") != std::string::npos) {
    return "";
  }
  if (trimmed.front() != '[') {
    trimmed.insert(trimmed.begin(), '[');
  }
  if (trimmed.back() != ']') {
    trimmed.push_back(']');
  }
  return trimmed;
}
} // namespace

/**
 * @brief Construct the completion engine.
 */
AMCompleteEngine::AMCompleteEngine()
    : config_manager_(AMConfigManager::Instance()),
      client_manager_(AMClientManage::Manager::Instance()),
      filesystem_(AMFileSystem::Instance()),
      transfer_manager_(AMTransferManager::Instance()) {
  sources_ = std::make_unique<AMCompleteSources>(this, config_manager_,
                                                 client_manager_, filesystem_,
                                                 transfer_manager_);
}

/**
 * @brief Default destructor.
 */
AMCompleteEngine::~AMCompleteEngine() = default;

/**
 * @brief Install the completer into isocline.
 */
void AMCompleteEngine::Install(void *completion_arg) {
  ic_set_default_completer(&AMCompleter::IsoclineCompleter, completion_arg);
  ic_enable_completion_sort(false);
  ic_enable_completion_preview(true);
  const int max_items = args_.complete_max_items;
  if (max_items > 0) {
    ic_set_completion_max_items(max_items);
  }
  ic_set_completion_max_rows(args_.complete_max_rows);
  ic_enable_completion_number_pick(args_.complete_number_pick);
  ic_enable_completion_auto_fill(args_.complete_auto_fill);
  const std::string &select_sign = args_.complete_select_sign;
  if (select_sign.empty()) {
    ic_set_completion_select_sign(nullptr);
  } else {
    ic_set_completion_select_sign(select_sign.c_str());
  }
}

/**
 * @brief Clear completion caches.
 */
void AMCompleteEngine::ClearCache() {
  if (sources_) {
    sources_->ClearCache();
  }
}

/**
 * @brief Handle a completion request from isocline.
 */
void AMCompleteEngine::HandleCompletion(ic_completion_env_t *cenv,
                                        const std::string &input,
                                        size_t cursor) {
  CompletionRequest request;
  request.cenv = cenv;
  request.input = input;
  request.cursor = cursor;
  request.request_id = NextRequestId_(input, cursor);

  CompletionContext ctx = BuildContext_(request);
  if (ctx.target == CompletionTarget::Disabled ||
      ctx.target == CompletionTarget::None) {
    return;
  }

  std::vector<CompletionCandidate> candidates;
  DispatchCandidates_(ctx, candidates);
  if (candidates.empty()) {
    return;
  }
  SortCandidates_(candidates);
  EmitCandidates_(cenv, ctx, candidates);
}

/**
 * @brief Load completion configuration from settings.
 */
void AMCompleteEngine::LoadConfig() {
  AMConfigManager &config = AMConfigManager::Instance();

  int max_items = config.ResolveArg<int>(DocumentKind::Settings,
                                         {"CompleteOption", "maxnum"}, -1, {});
  if (max_items <= 0) {
    max_items = -1;
  }
  args_.complete_max_items = max_items;

  int max_rows = config.ResolveArg<int>(
      DocumentKind::Settings, {"CompleteOption", "maxrows_perpage"}, 9, {});
  if (max_rows == 0) {
    max_rows = 9;
  }
  if (max_rows > 0 && max_rows < 3) {
    max_rows = 3;
  }
  args_.complete_max_rows = static_cast<long>(max_rows);

  auto read_bool = [&config](const std::vector<std::string> &path,
                             bool default_value) {
    std::string value = config.ResolveArg<std::string>(
        DocumentKind::Settings, path, default_value ? "true" : "false", {});
    value = AMStr::lowercase(AMStr::Strip(value));
    if (value == "true" || value == "1" || value == "yes" || value == "on") {
      return true;
    }
    if (value == "false" || value == "0" || value == "no" || value == "off") {
      return false;
    }
    return default_value;
  };

  args_.complete_number_pick = read_bool({"CompleteOption", "number_pick"}, true);
  args_.complete_auto_fill = read_bool({"CompleteOption", "auto_fillin"}, true);
  args_.complete_select_sign = config.ResolveArg<std::string>(
      DocumentKind::Settings, {"CompleteOption", "item_select_sign"}, "", {});

  args_.complete_delay_ms = config.ResolveArg<int>(
      DocumentKind::Settings, {"CompleteOption", "complete_delay_ms"}, 100,
      [](int v) { return v < 0 ? 0 : v; });

  args_.cache_min_items = config.ResolveArg<size_t>(
      DocumentKind::Settings, {"CompleteOption", "cache_min_items"},
      static_cast<size_t>(100), [](size_t v) { return static_cast<size_t>(v); });

  int max_entries = config.ResolveArg<int>(
      DocumentKind::Settings, {"CompleteOption", "cache_max_entries"}, 64, {});
  if (max_entries < 1) {
    max_entries = 1;
  }
  args_.cache_max_entries = static_cast<size_t>(max_entries);

  std::string command_tag = "";
  config.ResolveArg(DocumentKind::Settings,
                    {"style", "InputHighlight", "command"}, &command_tag);
  args_.input_tag_command = NormalizeStyleTag_(command_tag);

  std::string module_tag = "";
  config.ResolveArg(DocumentKind::Settings,
                    {"style", "InputHighlight", "module"}, &module_tag);
  args_.input_tag_module = NormalizeStyleTag_(module_tag);
}

/**
 * @brief Get current completion arguments.
 */
const AMCompleteEngine::Args &AMCompleteEngine::GetArgs() const {
  return args_;
}

/**
 * @brief Get mutable completion arguments.
 */
AMCompleteEngine::Args &AMCompleteEngine::MutableArgs() { return args_; }

/**
 * @brief Get the current request id.
 */
uint64_t AMCompleteEngine::CurrentRequestId() const {
  return current_request_id_.load(std::memory_order_relaxed);
}

/**
 * @brief Return true if any client nickname matches the prefix.
 */
bool AMCompleteEngine::HasClientPrefixMatch_(const std::string &prefix) const {
  if (prefix.empty()) {
    return false;
  }
  auto names = client_manager_.GetClientNames();
  for (const auto &name : names) {
    if (name.rfind(prefix, 0) == 0) {
      return true;
    }
  }
  return false;
}

/**
 * @brief Generate or reuse request ID for the input.
 */
uint64_t AMCompleteEngine::NextRequestId_(const std::string &input,
                                          size_t cursor) {
  std::lock_guard<std::mutex> lock(request_mtx_);
  if (input == last_input_ && cursor == last_cursor_) {
    return last_request_id_;
  }
  last_input_ = input;
  last_cursor_ = cursor;
  last_request_id_ =
      request_counter_.fetch_add(1, std::memory_order_relaxed) + 1;
  current_request_id_.store(last_request_id_, std::memory_order_relaxed);
  if (sources_) {
    sources_->ResetAsyncResult();
  }
  return last_request_id_;
}
