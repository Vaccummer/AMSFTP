#pragma once
#include "domain/client/ClientPort.hpp"
#include "interface/parser/CommandTree.hpp"
#include "interface/token_analyser/TokenTypeAnalyzer.hpp"
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <foundation/core/Enum.hpp>
#include <memory>
#include <mutex>
#include <semaphore>
#include <string>
#include <stop_token>
#include <thread>
#include <unordered_map>
#include <vector>

struct ic_completion_env_s;
using ic_completion_env_t = ic_completion_env_s;
namespace AMInterface::completion {
class ICompletionRuntime;
}
namespace AMApplication::completion {
class CompleterConfigManager;
}
namespace AMInterface::style {
class AMStyleService;
}
namespace AMInterface::completer {
using amf = AMDomain::client::amf;

/**
 * @brief Completion target classification used for search-engine routing.
 */
enum class AMCompletionTarget {
  Disabled = 0,
  TopCommand = 1,
  Subcommand = 2,
  LongOption = 3,
  ShortOption = 4,
  VariableName = 5,
  ClientName = 6,
  PoolName = 7,
  HostNickname = 8,
  HostAttr = 9,
  TaskId = 10,
  Path = 11,
  VarZone = 12,
  TerminalName = 13,
  ChannelTargetExisting = 14,
  ChannelTargetNew = 15,
  SshChannelTarget = 16,
};

/**
 * @brief Candidate kind metadata.
 */
enum class AMCompletionKind {
  Module,
  Command,
  Option,
  VariableName,
  VarZone,
  ClientName,
  HostNickname,
  TerminalName,
  ChannelName,
  HostAttr,
  TaskId,
  PathLocal,
  PathRemote,
};

enum class AMCompletionMode { Complete = 0, InlineHint = 1 };

/**
 * @brief Single completion candidate.
 */
struct AMCompletionCandidate {
  std::string insert_text;
  std::string display;
  AMCompletionKind kind = AMCompletionKind::Command;
  std::string help;
  int score = 0;
  std::unordered_map<std::string, std::string> metadata;
  PathType path_type = PathType::Unknown;
};

/**
 * @brief Completion candidate container with response metadata.
 */
struct AMCompletionCandidates {
  std::vector<AMCompletionCandidate> items;
  bool from_cache = false;
};

/**
 * @brief Runtime/completion arguments loaded from settings.
 */
struct AMCompletionArgs {
  int complete_max_items = -1;
  long complete_max_rows = 9;
  bool complete_number_pick = true;
  bool complete_auto_fill = true;
  std::string complete_select_sign;
  std::string complete_order_num_style;
  std::string complete_help_style;
  int complete_delay_ms = 100;
  size_t complete_async_workers = 2;
  std::string input_tag_command;
  std::string input_tag_module;
};

/**
 * @brief Parsed completion context shared with search engines.
 */
struct AMCompletionContext {
  std::string input;
  size_t cursor = 0;
  uint64_t request_id = 0;
  AMCompletionMode mode = AMCompletionMode::Complete;
  std::vector<AMInterface::parser::TokenTypeAnalyzer::AMToken> tokens;
  size_t token_index = 0;
  bool has_token = false;
  bool cursor_in_token = false;
  AMInterface::parser::TokenTypeAnalyzer::AMToken token;
  std::string token_raw;
  std::string token_text;
  std::string token_prefix_raw;
  std::string token_prefix;
  std::string token_postfix_raw;
  std::string token_postfix;
  bool token_quoted = false;
  std::string module;
  std::string cmd;
  std::vector<std::string> options;
  std::vector<std::string> args;
  std::vector<AMCompletionTarget> targets;
  bool forbid_cache = false;
  int timeout_ms = 0;
  int search_delay_ms = 0;
  amf control_token = nullptr;
  bool async_search = false;
  const AMInterface::parser::CommandNode *command_tree = nullptr;
  const AMCompletionArgs *completion_args = nullptr;
};

class AMCompletionSearchEngine;

enum class CompletionTaskState {
  Pending = 0,
  Running = 1,
  Done = 2,
  Canceled = 3,
  Failed = 4,
};

class ICompletionTask {
public:
  virtual ~ICompletionTask() = default;
  [[nodiscard]] virtual uint64_t ID() const = 0;
  virtual void Run() = 0;
  virtual void Terminate() = 0;
  [[nodiscard]] virtual CompletionTaskState State() const = 0;
  [[nodiscard]] virtual ECMData<AMCompletionCandidates> Result() const = 0;
};

struct AMCompletionAsyncResult {
  uint64_t request_id = 0;
  AMCompletionMode mode = AMCompletionMode::Complete;
  AMCompletionTarget target = AMCompletionTarget::Disabled;
  std::vector<AMCompletionCandidate> candidates;
  bool from_cache = false;
  std::weak_ptr<AMCompletionSearchEngine> source_engine;
};

struct AMCompletionAsyncTask {
  uint64_t request_id = 0;
  AMCompletionMode mode = AMCompletionMode::Complete;
  AMCompletionTarget target = AMCompletionTarget::Disabled;
  std::shared_ptr<ICompletionTask> task = nullptr;
  std::weak_ptr<AMCompletionSearchEngine> source_engine;
};

/**
 * @brief Search engine abstraction for pluggable completion providers.
 */
class AMCompletionSearchEngine {
public:
  /**
   * @brief Virtual destructor for polymorphic deletion.
   */
  virtual ~AMCompletionSearchEngine() = default;

  /**
   * @brief Collect completion candidates for a request context.
   *
   * @param ctx Completion request context.
   * @return Candidate payload.
   */
  virtual AMCompletionCandidates
  CollectCandidates(const AMCompletionContext &ctx) = 0;

  /**
   * @brief Sort candidates owned by this search engine.
   *
   * @param ctx Completion request context.
   * @param items Candidate container to sort in-place.
   */
  virtual void SortCandidates(const AMCompletionContext &ctx,
                              std::vector<AMCompletionCandidate> &items) = 0;

  /**
   * @brief Create async completion task for this engine.
   *
   * Default implementation wraps CollectCandidates() in a task.
   *
   * @param ctx Completion request context.
   * @return Async task handle; nullptr means caller should fallback to sync.
   */
  [[nodiscard]] virtual std::shared_ptr<ICompletionTask>
  CreateTask(const AMCompletionContext &ctx);

  /**
   * @brief Clear internal search-engine cache state.
   */
  virtual void ClearCache();
};

/**
 * @brief Standardized completion request.
 */
struct AMCompletionRequest {
  ic_completion_env_t *cenv = nullptr;
  std::string input;
  size_t cursor = 0;
  uint64_t request_id = 0;
  AMCompletionMode mode = AMCompletionMode::Complete;
};

/**
 * @brief Registration tuple used to bind targets to search engines.
 */
struct AMSearchEngineRegistration {
  std::vector<AMCompletionTarget> targets;
  std::shared_ptr<AMCompletionSearchEngine> engine;
};

/**
 * @brief Build the default completion search-engine registration set.
 */
std::vector<AMSearchEngineRegistration> AMBuildDefaultSearchEngineRegistrations(
    std::shared_ptr<AMInterface::completion::ICompletionRuntime> runtime);

/**
 * @brief Core completion engine that orchestrates parsing, dispatch, and async
 * execution.
 */
class AMCompleteEngine {
public:
  AMCompleteEngine(
      const AMInterface::parser::CommandNode *command_tree,
      AMInterface::parser::TokenTypeAnalyzer *token_type_analyzer,
      std::shared_ptr<AMInterface::completion::ICompletionRuntime> runtime,
      AMApplication::completion::CompleterConfigManager
          *completer_config_manager = nullptr,
      AMInterface::style::AMStyleService *style_service = nullptr)
      : command_tree_(command_tree), token_type_analyzer_(token_type_analyzer),
        runtime_(std::move(runtime)),
        completer_config_manager_(completer_config_manager),
        style_service_(style_service) {
    StartAsyncWorkers_();
    Init();
  }

  /**
   * @brief Register built-in search engines.
   */
  void Init() {
    {
      std::lock_guard<std::mutex> lock(engines_mtx_);
      engines_.clear();
      engines_by_target_.clear();
    }
    for (const auto &registration :
         AMBuildDefaultSearchEngineRegistrations(runtime_)) {
      RegisterSearchEngine(registration.targets, registration.engine);
    }
  }

  /**
   * @brief Stop async workers and release resources.
   */
  ~AMCompleteEngine() { StopAsyncWorkers_(); }

  /**
   * @brief Static isocline callback entry used for persistent profile binding.
   */
  static void IsoclineCompleteCallback(ic_completion_env_t *cenv,
                                       const char *prefix);

  /**
   * @brief Install the completer into isocline.
   */
  void Install();

  /**
   * @brief Clear completion caches managed by registered search engines.
   */
  void ClearCache();
  void CancelPendingAsync();

  /**
   * @brief Handle a completion request from isocline.
   *
   * @param cenv Isocline completion environment.
   * @param input Input line.
   * @param cursor Cursor position.
   */
  void HandleCompletion(ic_completion_env_t *cenv, const std::string &input,
                        size_t cursor, AMCompletionMode mode);

  /**
   * @brief Load completion configuration from settings.
   */
  void LoadConfig();

  /**
   * @brief Get the current request id.
   */
  uint64_t CurrentRequestId() const;

  /**
   * @brief Register a search engine for one or more completion targets.
   *
   * Each target keeps exactly one engine; later registrations replace earlier
   * bindings for the same target.
   *
   * @param targets Target list routed to this engine.
   * @param engine Search engine instance.
   */
  void
  RegisterSearchEngine(const std::vector<AMCompletionTarget> &targets,
                       const std::shared_ptr<AMCompletionSearchEngine> &engine);

private:
  /**
   * @brief Generate or reuse request ID for the input.
   */
  uint64_t NextRequestId_(const std::string &input, size_t cursor,
                          AMCompletionMode mode);

  /**
   * @brief Find the token that owns the cursor.
   */
  bool FindTokenAtCursor_(
      const std::vector<AMInterface::parser::TokenTypeAnalyzer::AMToken>
          &tokens,
      size_t cursor, AMInterface::parser::TokenTypeAnalyzer::AMToken *out,
      size_t *out_index) const;

  /**
   * @brief Build the completion context for the current input.
   */
  AMCompletionContext BuildContext_(const AMCompletionRequest &request) const;

  /**
   * @brief Dispatch completion requests to registered search engines.
   */
  void DispatchCandidates_(const AMCompletionContext &ctx,
                           AMCompletionCandidates &out);

  struct CompletionModePolicy {
    bool enabled = true;
    bool use_async = false;
    int timeout_ms = 0;
    int search_delay_ms = 0;
  };

  [[nodiscard]] CompletionModePolicy
  ResolveModePolicy_(const AMCompletionContext &ctx,
                     AMCompletionTarget target) const;
  [[nodiscard]] std::string
  ResolvePolicyNickname_(const AMCompletionContext &ctx) const;
  void FinalizeCandidates_(const AMCompletionContext &ctx,
                           AMCompletionCandidates *out) const;

  /**
   * @brief Emit candidates to isocline with delete ranges.
   */
  void EmitCandidates_(ic_completion_env_t *cenv,
                       const AMCompletionContext &ctx,
                       const AMCompletionCandidates &items);

  /**
   * @brief Start async worker threads.
   */
  void StartAsyncWorkers_();

  /**
   * @brief Stop async worker threads.
   */
  void StopAsyncWorkers_();

  /**
   * @brief Restart async worker threads after config changes.
   */
  void RestartAsyncWorkers_();

  /**
   * @brief Async worker loop body.
   */
  void AsyncWorkerLoop_(std::stop_token stop_token);

  /**
   * @brief Push an async task into the worker queue.
   */
  void ScheduleAsyncTask_(AMCompletionAsyncTask request);

  /**
   * @brief Terminate currently on-air task for one target.
   */
  void TerminateOnAirTask_(AMCompletionTarget target);

  /**
   * @brief Mark one task as on-air for target.
   */
  void SetOnAirTask_(AMCompletionTarget target,
                     const std::shared_ptr<ICompletionTask> &task);

  /**
   * @brief Clear one on-air task for target only when handle matches.
   */
  void ClearOnAirTask_(AMCompletionTarget target,
                       const std::shared_ptr<ICompletionTask> &task);

  /**
   * @brief Interrupt and clear queued/inflight async requests.
   */
  void CancelPendingAsyncRequests_();

  /**
   * @brief Consume finished async results for the current context target.
   */
  void ConsumeAsyncResults_(const AMCompletionContext &ctx,
                            AMCompletionCandidates &out);

  /**
   * @brief Resolve the engine for a routed completion target.
   */
  std::shared_ptr<AMCompletionSearchEngine>
  ResolveSearchEngine_(AMCompletionTarget target);

  /**
   * @brief Resolve all registered engines.
   */
  std::vector<std::shared_ptr<AMCompletionSearchEngine>> ResolveAllEngines_();

  AMCompletionArgs args_{};
  std::atomic<uint64_t> request_counter_{0};
  std::atomic<uint64_t> current_request_id_{0};
  std::atomic<uint64_t> desired_request_id_{0};
  std::mutex request_mtx_;
  std::string last_input_;
  size_t last_cursor_ = 0;
  uint64_t last_request_id_ = 0;
  AMCompletionMode last_mode_ = AMCompletionMode::Complete;

  std::mutex engines_mtx_;
  std::unordered_map<AMCompletionTarget,
                     std::shared_ptr<AMCompletionSearchEngine>>
      engines_by_target_;
  std::vector<std::shared_ptr<AMCompletionSearchEngine>> engines_;

  std::atomic<bool> async_stop_{false};
  std::mutex async_queue_mtx_;
  std::deque<AMCompletionAsyncTask> async_queue_;
  std::counting_semaphore<> async_queue_ready_{0};
  std::vector<std::jthread> async_workers_;

  const AMInterface::parser::CommandNode *command_tree_ = nullptr;
  AMInterface::parser::TokenTypeAnalyzer *token_type_analyzer_ = nullptr;
  std::shared_ptr<AMInterface::completion::ICompletionRuntime> runtime_ =
      nullptr;
  AMApplication::completion::CompleterConfigManager *completer_config_manager_ =
      nullptr;
  AMInterface::style::AMStyleService *style_service_ = nullptr;

  std::mutex async_results_mtx_;
  std::unordered_map<uint64_t, std::vector<AMCompletionAsyncResult>>
      async_results_;

  std::mutex async_on_air_mtx_;
  std::unordered_map<AMCompletionTarget, std::shared_ptr<ICompletionTask>>
      async_on_air_tasks_;
};

} // namespace AMInterface::completer
