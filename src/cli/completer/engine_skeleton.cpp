#include "AMBase/CommonTools.hpp"
#include "AMCLI/Completer/Engine.hpp"
#include "AMCLI/Completer/Proxy.hpp"
#include "AMCLI/Completer/Searcher.hpp"
#include "AMManager/Config.hpp"
#include "Isocline/isocline.h"
#include <algorithm>
#include <chrono>
#include <climits>
#include <iterator>

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

/**
 * @brief Return true if completion context contains target.
 */
bool HasTarget_(const AMCompletionContext &ctx, AMCompletionTarget target) {
  return std::find(ctx.targets.begin(), ctx.targets.end(), target) !=
         ctx.targets.end();
}
} // namespace

/**
 * @brief Execute the request-specific search routine.
 */
bool AMCompletionAsyncRequest::Search(AMCompletionAsyncResult *out) const {
  if (IsInterrupted()) {
    return false;
  }
  if (!search) {
    return false;
  }
  return search(*this, out);
}

/**
 * @brief Return true when the request has been interrupted.
 */
bool AMCompletionAsyncRequest::IsInterrupted() const {
  return interrupt_flag ? interrupt_flag() : true;
}

/**
 * @brief Default cache-clear hook for engines without cache state.
 */
void AMCompletionSearchEngine::ClearCache() {}

/**
 * @brief Install the completer into isocline.
 */
void AMCompleteEngine::Install(void *completion_arg) {
  ic_set_default_completer(&AMCompleter::IsoclineCompleter, completion_arg);
  ic_enable_completion_sort(false);
  ic_enable_completion_preview(true);
  const int max_items = args_.complete_max_items;
  ic_enable_hint(true);
  if (max_items > 0) {
    ic_set_completion_max_items(max_items);
  } else {
    ic_set_completion_max_items(LONG_MAX);
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
 * @brief Clear completion caches managed by registered search engines.
 */
void AMCompleteEngine::ClearCache() {
  std::vector<std::shared_ptr<AMCompletionSearchEngine>> engines;
  {
    std::lock_guard<std::mutex> lock(engines_mtx_);
    engines = engines_;
  }
  for (const auto &engine : engines) {
    if (engine) {
      engine->ClearCache();
    }
  }
}

/**
 * @brief Handle a completion request from isocline.
 */
void AMCompleteEngine::HandleCompletion(ic_completion_env_t *cenv,
                                        const std::string &input,
                                        size_t cursor) {
  AMCompletionRequest request;
  request.cenv = cenv;
  request.input = input;
  request.cursor = cursor;
  request.request_id = NextRequestId_(input, cursor);

  AMCompletionContext ctx = BuildContext_(request);
  ic_set_completion_page_marker(nullptr);
  if (HasTarget_(ctx, AMCompletionTarget::Disabled)) {
    return;
  }

  AMCompletionCandidates candidates;
  DispatchCandidates_(ctx, candidates);
  if (candidates.items.empty()) {
    return;
  }
  EmitCandidates_(cenv, ctx, candidates);
}

/**
 * @brief Load completion configuration from settings.
 */
void AMCompleteEngine::LoadConfig() {
  AMConfigManager &config = AMConfigManager::Instance();

  int max_items = config.ResolveArg<int>(
      DocumentKind::Settings, {"Style", "CompleteMenu", "maxnum"}, -1, {});
  if (max_items <= 0) {
    max_items = -1;
  }
  args_.complete_max_items = max_items;

  int max_rows = config.ResolveArg<int>(
      DocumentKind::Settings, {"Style", "CompleteMenu", "maxrows_perpage"}, 9,
      {});
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

  args_.complete_number_pick =
      read_bool({"Style", "CompleteMenu", "number_pick"}, true);
  args_.complete_auto_fill =
      read_bool({"Style", "CompleteMenu", "auto_fillin"}, true);
  args_.complete_select_sign = config.ResolveArg<std::string>(
      DocumentKind::Settings, {"Style", "CompleteMenu", "item_select_sign"}, "",
      {});

  args_.complete_delay_ms = config.ResolveArg<int>(
      DocumentKind::Settings, {"Style", "CompleteMenu", "complete_delay_ms"},
      100, [](int v) { return v < 0 ? 0 : v; });

  int async_workers = config.ResolveArg<int>(
      DocumentKind::Settings, {"Style", "CompleteMenu", "async_workers"}, 2,
      [](int v) { return v < 1 ? 1 : v; });
  if (async_workers < 1) {
    async_workers = 1;
  }
  auto worker_count = static_cast<size_t>(async_workers);
  const bool worker_changed = args_.complete_async_workers != worker_count;
  args_.complete_async_workers = worker_count;

  std::string command_tag = "";
  config.ResolveArg(DocumentKind::Settings,
                    {"Style", "InputHighlight", "command"}, &command_tag);
  args_.input_tag_command = NormalizeStyleTag_(command_tag);

  std::string module_tag = "";
  config.ResolveArg(DocumentKind::Settings,
                    {"Style", "InputHighlight", "module"}, &module_tag);
  args_.input_tag_module = NormalizeStyleTag_(module_tag);

  if (worker_changed) {
    RestartAsyncWorkers_();
  }
}

/**
 * @brief Get the current request id.
 */
uint64_t AMCompleteEngine::CurrentRequestId() const {
  return current_request_id_.load(std::memory_order_relaxed);
}

/**
 * @brief Register a search engine for one or more completion targets.
 */
void AMCompleteEngine::RegisterSearchEngine(
    const std::vector<AMCompletionTarget> &targets,
    const std::shared_ptr<AMCompletionSearchEngine> &engine) {
  if (!engine) {
    return;
  }

  std::lock_guard<std::mutex> lock(engines_mtx_);
  auto it = std::find(engines_.begin(), engines_.end(), engine);
  if (it == engines_.end()) {
    engines_.push_back(engine);
  }

  for (const auto &target : targets) {
    engines_by_target_[target] = engine;
  }
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

  CancelPendingAsyncRequests_();
  return last_request_id_;
}

/**
 * @brief Resolve the engine for a routed completion target.
 */
std::shared_ptr<AMCompletionSearchEngine>
AMCompleteEngine::ResolveSearchEngine_(AMCompletionTarget target) {
  std::lock_guard<std::mutex> lock(engines_mtx_);
  auto it = engines_by_target_.find(target);
  if (it == engines_by_target_.end()) {
    return nullptr;
  }
  return it->second;
}

/**
 * @brief Resolve all registered engines.
 */
std::vector<std::shared_ptr<AMCompletionSearchEngine>>
AMCompleteEngine::ResolveAllEngines_() {
  std::lock_guard<std::mutex> lock(engines_mtx_);
  return engines_;
}

/**
 * @brief Start async worker threads.
 */
void AMCompleteEngine::StartAsyncWorkers_() {
  if (!async_workers_.empty()) {
    return;
  }

  async_stop_.store(false, std::memory_order_relaxed);
  const size_t count = std::max<size_t>(1, args_.complete_async_workers);
  async_workers_.reserve(count);
  for (size_t i = 0; i < count; ++i) {
    async_workers_.emplace_back([this]() { AsyncWorkerLoop_(); });
  }
}

/**
 * @brief Stop async worker threads.
 */
void AMCompleteEngine::StopAsyncWorkers_() {
  async_stop_.store(true, std::memory_order_relaxed);
  CancelPendingAsyncRequests_();
  async_queue_cv_.notify_all();

  for (auto &worker : async_workers_) {
    if (worker.joinable()) {
      worker.join();
    }
  }
  async_workers_.clear();
}

/**
 * @brief Restart async worker threads after config changes.
 */
void AMCompleteEngine::RestartAsyncWorkers_() {
  StopAsyncWorkers_();
  StartAsyncWorkers_();
}

/**
 * @brief Push an async request into the worker queue.
 */
void AMCompleteEngine::ScheduleAsyncRequest_(AMCompletionAsyncRequest request) {
  if (!request.interrupt_flag) {
    return;
  }

  if (request.interrupt_cancel) {
    std::lock_guard<std::mutex> lock(async_interrupts_mtx_);
    async_interrupts_.push_back(request.interrupt_cancel);
  }

  {
    std::lock_guard<std::mutex> lock(async_queue_mtx_);
    async_queue_.push_back(std::move(request));
  }

  async_queue_cv_.notify_one();
}

/**
 * @brief Interrupt and clear queued/inflight async requests.
 */
void AMCompleteEngine::CancelPendingAsyncRequests_() {
  {
    std::lock_guard<std::mutex> lock(async_queue_mtx_);
    async_queue_.clear();
  }

  {
    std::lock_guard<std::mutex> lock(async_interrupts_mtx_);
    for (auto &cancel : async_interrupts_) {
      if (cancel) {
        cancel();
      }
    }
    async_interrupts_.clear();
  }

  {
    std::lock_guard<std::mutex> lock(async_results_mtx_);
    async_results_.clear();
  }
}

/**
 * @brief Consume finished async results for the current context target.
 */
void AMCompleteEngine::ConsumeAsyncResults_(const AMCompletionContext &ctx,
                                            AMCompletionCandidates &out) {
  if (ctx.targets.empty()) {
    return;
  }
  std::vector<AMCompletionAsyncResult> consumed;
  {
    std::lock_guard<std::mutex> lock(async_results_mtx_);
    auto it = async_results_.find(ctx.request_id);
    if (it == async_results_.end()) {
      return;
    }

    auto &bucket = it->second;
    auto keep_it = bucket.begin();
    for (auto iter = bucket.begin(); iter != bucket.end(); ++iter) {
      if (HasTarget_(ctx, iter->target)) {
        consumed.push_back(std::move(*iter));
      } else {
        *keep_it = std::move(*iter);
        ++keep_it;
      }
    }
    bucket.erase(keep_it, bucket.end());
    if (bucket.empty()) {
      async_results_.erase(it);
    }
  }

  for (auto &result : consumed) {
    if (result.candidates.empty()) {
      continue;
    }
    out.items.insert(out.items.end(),
                     std::make_move_iterator(result.candidates.begin()),
                     std::make_move_iterator(result.candidates.end()));
  }
}

/**
 * @brief Async worker loop body.
 */
void AMCompleteEngine::AsyncWorkerLoop_() {
  while (true) {
    AMCompletionAsyncRequest request;
    {
      std::unique_lock<std::mutex> lock(async_queue_mtx_);
      async_queue_cv_.wait(lock, [this]() {
        return async_stop_.load(std::memory_order_relaxed) ||
               !async_queue_.empty();
      });
      if (async_stop_.load(std::memory_order_relaxed)) {
        return;
      }

      request = std::move(async_queue_.front());
      async_queue_.pop_front();
    }

    if (request.request_id != CurrentRequestId()) {
      continue;
    }
    if (request.IsInterrupted()) {
      continue;
    }

    if (args_.complete_delay_ms > 0) {
      std::this_thread::sleep_for(
          std::chrono::milliseconds(args_.complete_delay_ms));
      if (request.IsInterrupted()) {
        continue;
      }
    }

    AMCompletionAsyncResult result;
    result.request_id = request.request_id;
    result.target = request.target;
    result.source_engine = request.source_engine;

    if (!request.Search(&result)) {
      continue;
    }

    if (request.IsInterrupted()) {
      continue;
    }

    if (result.request_id == 0) {
      result.request_id = request.request_id;
    }
    if (result.target == AMCompletionTarget::Disabled &&
        request.target != AMCompletionTarget::Disabled) {
      result.target = request.target;
    }
    if (result.source_engine.expired()) {
      result.source_engine = request.source_engine;
    }

    if (result.request_id != CurrentRequestId()) {
      continue;
    }

    {
      std::lock_guard<std::mutex> lock(async_results_mtx_);
      async_results_[result.request_id].push_back(std::move(result));
    }
    (void)ic_request_completion_menu_async();
  }
}
