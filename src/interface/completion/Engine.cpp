#include "interface/completion/Engine.hpp"
#include "Isocline/isocline.h"
#include "application/completion/CompleterAppService.hpp"
#include "interface/style/StyleManager.hpp"
#include <algorithm>
#include <chrono>
#include <climits>
#include <exception>
#include <iterator>

namespace AMInterface::completer {
namespace {
std::atomic<uint64_t> g_completion_task_id{1};

uint64_t NextCompletionTaskId_() {
  return g_completion_task_id.fetch_add(1, std::memory_order_relaxed);
}

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
 * @brief Normalize style string for ic_style_def.
 *
 * Accept both "#RRGGBB b" and "[#RRGGBB b]" formats.
 */
std::string NormalizeStyleForIc_(const std::string &raw) {
  std::string trimmed = AMStr::Strip(raw);
  if (trimmed.empty()) {
    return "";
  }
  if (trimmed.find("[/") != std::string::npos) {
    return "";
  }
  if (trimmed.size() >= 2 && trimmed.front() == '[' && trimmed.back() == ']') {
    trimmed = AMStr::Strip(trimmed.substr(1, trimmed.size() - 2));
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

AMCompletionMode MapCompletionMode_(ic_completion_source_t source) {
  switch (source) {
  case IC_COMPLETION_SOURCE_INLINE_HINT:
    return AMCompletionMode::InlineHint;
  case IC_COMPLETION_SOURCE_TAB:
  case IC_COMPLETION_SOURCE_UNKNOWN:
  default:
    return AMCompletionMode::Complete;
  }
}

void IsoclineCompleteCallback_(ic_completion_env_t *cenv, const char *prefix) {
  (void)prefix;
  if (!cenv) {
    return;
  }
  void *raw = ic_completion_arg(cenv);
  if (!raw) {
    return;
  }
  auto *engine = static_cast<AMCompleteEngine *>(raw);
  long cursor = 0;
  const char *input = ic_completion_input(cenv, &cursor);
  if (!input || cursor < 0) {
    return;
  }
  const AMCompletionMode mode = MapCompletionMode_(ic_completion_source(cenv));
  engine->HandleCompletion(cenv, std::string(input),
                           static_cast<size_t>(cursor), mode);
}

class GenericCompletionTask final : public ICompletionTask {
public:
  GenericCompletionTask(uint64_t id, AMCompletionContext ctx,
                        AMCompletionSearchEngine *engine)
      : id_(id), ctx_(std::move(ctx)), engine_(engine) {
    if (!ctx_.control_token) {
      ctx_.control_token = CreateInterruptControl();
    }
    ctx_.async_search = true;
  }

  [[nodiscard]] uint64_t ID() const override { return id_; }

  void Run() override {
    CompletionTaskState expected = CompletionTaskState::Pending;
    if (!state_.compare_exchange_strong(expected, CompletionTaskState::Running,
                                        std::memory_order_acq_rel)) {
      return;
    }
    if (cancel_requested_.load(std::memory_order_acquire)) {
      state_.store(CompletionTaskState::Canceled, std::memory_order_release);
      return;
    }
    const std::string task_target =
        ctx_.input.empty() ? std::string("<completion-input>") : ctx_.input;
    if (engine_ == nullptr) {
      {
        std::lock_guard<std::mutex> lock(result_mtx_);
        result_.rcm = Err(EC::InvalidHandle, "completion task", task_target,
                          "search engine is null");
      }
      state_.store(CompletionTaskState::Failed, std::memory_order_release);
      return;
    }

    try {
      if (ctx_.search_delay_ms > 0 &&
          !cancel_requested_.load(std::memory_order_acquire)) {
        std::this_thread::sleep_for(
            std::chrono::milliseconds(ctx_.search_delay_ms));
      }
      if (cancel_requested_.load(std::memory_order_acquire)) {
        state_.store(CompletionTaskState::Canceled, std::memory_order_release);
        return;
      }
      AMCompletionCandidates collected = engine_->CollectCandidates(ctx_);
      if (!cancel_requested_.load(std::memory_order_acquire)) {
        engine_->SortCandidates(ctx_, collected.items);
      }
      {
        std::lock_guard<std::mutex> lock(result_mtx_);
        result_ = {std::move(collected), OK};
      }
      if (cancel_requested_.load(std::memory_order_acquire)) {
        state_.store(CompletionTaskState::Canceled, std::memory_order_release);
      } else {
        state_.store(CompletionTaskState::Done, std::memory_order_release);
      }
    } catch (const std::exception &e) {
      {
        std::lock_guard<std::mutex> lock(result_mtx_);
        result_.rcm =
            Err(EC::UnknownError, "completion task", task_target, e.what());
      }
      if (cancel_requested_.load(std::memory_order_acquire)) {
        state_.store(CompletionTaskState::Canceled, std::memory_order_release);
      } else {
        state_.store(CompletionTaskState::Failed, std::memory_order_release);
      }
    } catch (...) {
      {
        std::lock_guard<std::mutex> lock(result_mtx_);
        result_.rcm = Err(EC::UnknownError, "completion task", task_target,
                          "unknown error");
      }
      if (cancel_requested_.load(std::memory_order_acquire)) {
        state_.store(CompletionTaskState::Canceled, std::memory_order_release);
      } else {
        state_.store(CompletionTaskState::Failed, std::memory_order_release);
      }
    }
  }

  void Terminate() override {
    cancel_requested_.store(true, std::memory_order_release);
    if (ctx_.control_token) {
      ctx_.control_token->RequestInterrupt();
    }
    CompletionTaskState expected = CompletionTaskState::Pending;
    (void)state_.compare_exchange_strong(
        expected, CompletionTaskState::Canceled, std::memory_order_acq_rel);
  }

  [[nodiscard]] CompletionTaskState State() const override {
    return state_.load(std::memory_order_acquire);
  }

  [[nodiscard]] ECMData<AMCompletionCandidates> Result() const override {
    std::lock_guard<std::mutex> lock(result_mtx_);
    return result_;
  }

private:
  uint64_t id_ = 0;
  AMCompletionContext ctx_ = {};
  AMCompletionSearchEngine *engine_ = nullptr;
  std::atomic<CompletionTaskState> state_{CompletionTaskState::Pending};
  std::atomic<bool> cancel_requested_{false};
  mutable std::mutex result_mtx_;
  ECMData<AMCompletionCandidates> result_ = {};
};
} // namespace

void AMCompleteEngine::IsoclineCompleteCallback(ic_completion_env_t *cenv,
                                                const char *prefix) {
  IsoclineCompleteCallback_(cenv, prefix);
}

/**
 * @brief Default cache-clear hook for engines without cache state.
 */
std::shared_ptr<ICompletionTask>
AMCompletionSearchEngine::CreateTask(const AMCompletionContext &ctx) {
  return std::make_shared<GenericCompletionTask>(NextCompletionTaskId_(), ctx,
                                                 this);
}

void AMCompletionSearchEngine::ClearCache() {}

/**
 * @brief Install the completer into isocline.
 */
void AMCompleteEngine::Install() {
  ic_set_default_completer(&IsoclineCompleteCallback_, this);
  ic_enable_completion_sort(false);
  ic_enable_completion_preview(true);
  const std::string order_num_style = NormalizeStyleForIc_(
      args_.complete_order_num_style.empty() ? "[ansi-darkgray]"
                                             : args_.complete_order_num_style);
  const std::string help_style = NormalizeStyleForIc_(
      args_.complete_help_style.empty() ? "[ansi-darkgray]"
                                        : args_.complete_help_style);
  ic_style_def("ic-comp-order", order_num_style.c_str());
  ic_style_def("ic-comp-help", help_style.c_str());
  const int max_items = args_.complete_max_items;
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

void AMCompleteEngine::CancelPendingAsync() { CancelPendingAsyncRequests_(); }

/**
 * @brief Handle a completion request from isocline.
 */
void AMCompleteEngine::HandleCompletion(ic_completion_env_t *cenv,
                                        const std::string &input, size_t cursor,
                                        AMCompletionMode mode) {
  AMCompletionRequest request;
  request.cenv = cenv;
  request.input = input;
  request.cursor = cursor;
  request.request_id = NextRequestId_(input, cursor, mode);
  request.mode = mode;

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
  AMDomain::completion::CompleterArg completer_arg = {};
  if (completer_config_manager_ != nullptr) {
    completer_arg = completer_config_manager_->GetInitArg();
  }

  int max_items = static_cast<int>(completer_arg.maxnum);
  if (max_items <= 0) {
    max_items = -1;
  }
  args_.complete_max_items = max_items;

  int max_rows = static_cast<int>(completer_arg.maxrows_perpage);
  if (max_rows == 0) {
    max_rows = 9;
  }
  if (max_rows > 0 && max_rows < 3) {
    max_rows = 3;
  }
  args_.complete_max_rows = static_cast<long>(max_rows);

  args_.complete_number_pick = completer_arg.number_pick;
  args_.complete_auto_fill = completer_arg.auto_fillin;
  args_.complete_select_sign = ">";
  args_.complete_order_num_style = "";
  args_.complete_help_style = "";

  if (style_service_ != nullptr) {
    const auto style_cfg = style_service_->GetInitArg().style.complete_menu;
    args_.complete_select_sign = style_cfg.item_select_sign;
    args_.complete_order_num_style = style_cfg.order_num_style;
    args_.complete_help_style = style_cfg.help_style;
  }

  args_.complete_delay_ms = static_cast<int>(completer_arg.complete_delay_ms);
  if (args_.complete_delay_ms < 0) {
    args_.complete_delay_ms = 0;
  }

  int async_workers = static_cast<int>(completer_arg.async_workers);
  if (async_workers < 1) {
    async_workers = 1;
  }
  auto worker_count = static_cast<size_t>(async_workers);
  const bool worker_changed = args_.complete_async_workers != worker_count;
  args_.complete_async_workers = worker_count;

  std::string command_tag = "";
  std::string module_tag = "";
  if (style_service_ != nullptr) {
    const auto style_cfg = style_service_->GetInitArg().style;
    command_tag = style_cfg.common.command;
    module_tag = style_cfg.common.module;
  }
  args_.input_tag_command = NormalizeStyleTag_(command_tag);
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
                                          size_t cursor,
                                          AMCompletionMode mode) {
  std::lock_guard<std::mutex> lock(request_mtx_);
  if (input == last_input_ && cursor == last_cursor_ && mode == last_mode_) {
    return last_request_id_;
  }

  last_input_ = input;
  last_cursor_ = cursor;
  last_mode_ = mode;
  last_request_id_ =
      request_counter_.fetch_add(1, std::memory_order_relaxed) + 1;
  current_request_id_.store(last_request_id_, std::memory_order_relaxed);
  desired_request_id_.store(last_request_id_, std::memory_order_relaxed);

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
    async_workers_.emplace_back(
        [this](std::stop_token stop_token) { AsyncWorkerLoop_(stop_token); });
  }
}

/**
 * @brief Stop async worker threads.
 */
void AMCompleteEngine::StopAsyncWorkers_() {
  async_stop_.store(true, std::memory_order_relaxed);
  CancelPendingAsyncRequests_();
  if (!async_workers_.empty()) {
    async_queue_ready_.release(
        static_cast<std::ptrdiff_t>(async_workers_.size()));
  }

  for (auto &worker : async_workers_) {
    if (worker.joinable()) {
      worker.request_stop();
    }
  }
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
 * @brief Push an async task into the worker queue.
 */
void AMCompleteEngine::ScheduleAsyncTask_(AMCompletionAsyncTask request) {
  if (!request.task) {
    return;
  }
  {
    std::lock_guard<std::mutex> lock(async_queue_mtx_);
    async_queue_.push_back(std::move(request));
  }
  async_queue_ready_.release();
}

void AMCompleteEngine::TerminateOnAirTask_(AMCompletionTarget target) {
  std::shared_ptr<ICompletionTask> task = nullptr;
  {
    std::lock_guard<std::mutex> lock(async_on_air_mtx_);
    auto it = async_on_air_tasks_.find(target);
    if (it != async_on_air_tasks_.end()) {
      task = it->second;
    }
  }
  if (task) {
    task->Terminate();
  }
}

void AMCompleteEngine::SetOnAirTask_(
    AMCompletionTarget target, const std::shared_ptr<ICompletionTask> &task) {
  if (!task) {
    return;
  }
  std::lock_guard<std::mutex> lock(async_on_air_mtx_);
  async_on_air_tasks_[target] = task;
}

void AMCompleteEngine::ClearOnAirTask_(
    AMCompletionTarget target, const std::shared_ptr<ICompletionTask> &task) {
  std::lock_guard<std::mutex> lock(async_on_air_mtx_);
  auto it = async_on_air_tasks_.find(target);
  if (it == async_on_air_tasks_.end()) {
    return;
  }
  if (it->second == task) {
    async_on_air_tasks_.erase(it);
  }
}

/**
 * @brief Interrupt and clear queued/inflight async requests.
 */
void AMCompleteEngine::CancelPendingAsyncRequests_() {
  std::vector<std::shared_ptr<ICompletionTask>> tasks_to_cancel = {};
  {
    std::lock_guard<std::mutex> lock(async_queue_mtx_);
    tasks_to_cancel.reserve(async_queue_.size());
    for (auto &queued : async_queue_) {
      if (queued.task) {
        tasks_to_cancel.push_back(queued.task);
      }
    }
    async_queue_.clear();
  }

  {
    std::lock_guard<std::mutex> lock(async_on_air_mtx_);
    tasks_to_cancel.reserve(tasks_to_cancel.size() +
                            async_on_air_tasks_.size());
    for (const auto &entry : async_on_air_tasks_) {
      if (entry.second) {
        tasks_to_cancel.push_back(entry.second);
      }
    }
    async_on_air_tasks_.clear();
  }

  for (const auto &task : tasks_to_cancel) {
    if (task) {
      task->Terminate();
    }
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
    std::erase_if(bucket, [&](AMCompletionAsyncResult &entry) {
      if (!HasTarget_(ctx, entry.target)) {
        return false;
      }
      consumed.push_back(std::move(entry));
      return true;
    });
    if (bucket.empty()) {
      async_results_.erase(it);
    }
  }

  const AMCompletionTarget policy_target =
      HasTarget_(ctx, AMCompletionTarget::Path) ? AMCompletionTarget::Path
                                                : AMCompletionTarget::Disabled;
  const CompletionModePolicy policy = ResolveModePolicy_(ctx, policy_target);
  if (ctx.mode == AMCompletionMode::InlineHint && !policy.enabled) {
    return;
  }
  if (!policy.use_async) {
    return;
  }

  for (auto &result : consumed) {
    if (result.mode != ctx.mode) {
      continue;
    }
    if (result.candidates.empty()) {
      continue;
    }
    out.from_cache = out.from_cache || result.from_cache;
    out.items.insert(out.items.end(),
                     std::make_move_iterator(result.candidates.begin()),
                     std::make_move_iterator(result.candidates.end()));
  }
}

/**
 * @brief Async worker loop body.
 */
void AMCompleteEngine::AsyncWorkerLoop_(std::stop_token stop_token) {
  while (true) {
    async_queue_ready_.acquire();
    if (stop_token.stop_requested() ||
        async_stop_.load(std::memory_order_relaxed)) {
      return;
    }

    AMCompletionAsyncTask request;
    {
      std::lock_guard<std::mutex> lock(async_queue_mtx_);
      if (async_queue_.empty()) {
        continue;
      }
      request = std::move(async_queue_.front());
      async_queue_.pop_front();
    }

    if (!request.task) {
      continue;
    }
    SetOnAirTask_(request.target, request.task);

    if (request.request_id !=
        desired_request_id_.load(std::memory_order_acquire)) {
      request.task->Terminate();
      ClearOnAirTask_(request.target, request.task);
      continue;
    }

    request.task->Run();
    ClearOnAirTask_(request.target, request.task);

    AMCompletionAsyncResult result;
    result.request_id = request.request_id;
    result.mode = request.mode;
    result.target = request.target;
    result.source_engine = request.source_engine;
    if (result.request_id !=
        desired_request_id_.load(std::memory_order_acquire)) {
      continue;
    }

    const CompletionTaskState state = request.task->State();
    if (state == CompletionTaskState::Canceled ||
        state == CompletionTaskState::Pending ||
        state == CompletionTaskState::Running) {
      continue;
    }
    const auto task_result = request.task->Result();
    if (!(task_result.rcm) || task_result.data.items.empty()) {
      continue;
    }

    result.candidates = task_result.data.items;
    result.from_cache = task_result.data.from_cache;

    {
      std::lock_guard<std::mutex> lock(async_results_mtx_);
      async_results_[result.request_id].push_back(std::move(result));
    }
    (void)ic_request_completion_menu_async();
  }
}

} // namespace AMInterface::completer
