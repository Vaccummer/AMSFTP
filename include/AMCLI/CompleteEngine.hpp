#pragma once
#include "AMBase/Path.hpp"
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

struct ic_completion_env_s;
using ic_completion_env_t = ic_completion_env_s;

class AMCompleteSources;

/**
 * @brief Core completion engine that owns parsing and dispatch.
 */
class AMCompleteEngine {
public:
  /**
   * @brief Completion target classification.
   */
  enum class CompletionTarget {
    None,
    Disabled,
    TopCommand,
    Subcommand,
    LongOption,
    ShortOption,
    VariableName,
    ClientName,
    HostNickname,
    HostAttr,
    TaskId,
    Path,
  };

  /**
   * @brief Candidate kind metadata.
   */
  enum class CompletionKind {
    Module,
    Command,
    Option,
    VariableName,
    ClientName,
    HostNickname,
    HostAttr,
    TaskId,
    PathLocal,
    PathRemote,
  };

  /**
   * @brief Single completion candidate.
   */
  struct CompletionCandidate {
    std::string insert_text;
    std::string display;
    CompletionKind kind = CompletionKind::Command;
    std::string help;
    int score = 0;
    std::unordered_map<std::string, std::string> metadata;
    PathType path_type = PathType::Unknown;
  };

  /**
   * @brief Standardized completion request.
   */
  struct CompletionRequest {
    ic_completion_env_t *cenv = nullptr;
    std::string input;
    size_t cursor = 0;
    uint64_t request_id = 0;
  };

  /**
   * @brief Async completion result payload.
   */
  struct AsyncResult {
    uint64_t request_id = 0;
    std::string nickname;
    std::string dir;
    std::string base;
    std::string leaf_prefix;
    char sep = '/';
    bool remote = false;
    std::vector<PathInfo> items;
    std::vector<CompletionCandidate> candidates;
  };

  /**
   * @brief Async completion request.
   */
  struct AsyncRequest {
    uint64_t request_id = 0;
    int priority = 0;
    std::vector<CompletionCandidate> candidates;
    std::function<bool(AsyncResult *out)> search;
    std::shared_ptr<std::atomic<bool>> cancel_token;
  };

  /**
   * @brief Runtime/completion arguments loaded from settings.
   */
  struct Args {
    int complete_max_items = -1;
    long complete_max_rows = 9;
    bool complete_number_pick = true;
    bool complete_auto_fill = true;
    std::string complete_select_sign;
    int complete_delay_ms = 100;
    size_t cache_min_items = 100;
    size_t cache_max_entries = 64;
    std::string input_tag_command;
    std::string input_tag_module;
  };

  /**
   * @brief Token span for completion parsing.
   */
  struct CompletionToken {
    size_t start = 0;
    size_t end = 0;
    size_t content_start = 0;
    size_t content_end = 0;
    bool quoted = false;
  };

  /**
   * @brief Parsed path completion context.
   */
  struct PathContext {
    bool valid = false;
    bool remote = false;
    std::string nickname;
    std::string header;
    std::string raw_path;
    std::string dir_raw;
    std::string leaf_prefix;
    std::string base;
    std::string dir_abs;
    char sep = '/';
    bool trailing_sep = false;
  };

  /**
   * @brief Command tree node for completion.
   */
  struct CommandNode {
    std::unordered_map<std::string, std::string> subcommands;
    std::unordered_map<std::string, std::string> long_options;
    std::unordered_map<char, std::string> short_options;
  };

  /**
   * @brief Parsed completion context.
   */
  struct CompletionContext {
    std::string input;
    size_t cursor = 0;
    uint64_t request_id = 0;
    bool has_token = false;
    CompletionToken token;
    std::string token_raw;
    std::string token_text;
    std::string token_prefix_raw;
    std::string token_prefix;
    bool token_quoted = false;
    std::string command_path;
    size_t command_tokens = 0;
    size_t arg_index = 0;
    const CommandNode *command_node = nullptr;
    CompletionTarget target = CompletionTarget::None;
    PathContext path;
  };

  /**
   * @brief Construct the completion engine.
   */
  AMCompleteEngine();

  /**
   * @brief Default destructor.
   */
  ~AMCompleteEngine();

  /**
   * @brief Install the completer into isocline.
   */
  void Install(void *completion_arg);

  /**
   * @brief Clear completion caches.
   */
  void ClearCache();

  /**
   * @brief Handle a completion request from isocline.
   */
  void HandleCompletion(ic_completion_env_t *cenv, const std::string &input,
                        size_t cursor);

  /**
   * @brief Load completion configuration from settings.
   */
  void LoadConfig();

  /**
   * @brief Get current completion arguments.
   */
  const Args &GetArgs() const;

  /**
   * @brief Get mutable completion arguments.
   */
  Args &MutableArgs();

  /**
   * @brief Get the current request id.
   */
  uint64_t CurrentRequestId() const;

private:
  /**
   * @brief Return true if any client nickname matches the prefix.
   */
  bool HasClientPrefixMatch_(const std::string &prefix) const;

  /**
   * @brief Generate or reuse request ID for the input.
   */
  uint64_t NextRequestId_(const std::string &input, size_t cursor);

  /**
   * @brief Tokenize input into completion tokens.
   */
  std::vector<CompletionToken> TokenizeInput_(const std::string &input) const;

  /**
   * @brief Find the token that owns the cursor.
   */
  bool FindTokenAtCursor_(const std::vector<CompletionToken> &tokens,
                          size_t cursor, CompletionToken *out,
                          size_t *out_index) const;

  /**
   * @brief Parse the command path from tokens before the cursor.
   */
  void ParseCommandPath_(const std::vector<CompletionToken> &tokens,
                         const std::string &input, size_t current_index,
                         std::string *out_path, const CommandNode **out_node,
                         size_t *out_consumed) const;

  /**
   * @brief Compute positional argument index for the current token.
   */
  size_t ComputeArgIndex_(const std::vector<CompletionToken> &tokens,
                          const std::string &input, size_t command_tokens,
                          size_t current_index) const;

  /**
   * @brief Build the completion context for the current input.
   */
  CompletionContext BuildContext_(const CompletionRequest &request) const;

  /**
   * @brief Build path-specific context from the token.
   */
  PathContext BuildPathContext_(const CompletionContext &ctx,
                                bool force_path) const;

  /**
   * @brief Dispatch completion requests to their sources.
   */
  void DispatchCandidates_(const CompletionContext &ctx,
                           std::vector<CompletionCandidate> &out);

  /**
   * @brief Sort candidates by prefix and path type rules.
   */
  void SortCandidates_(std::vector<CompletionCandidate> &items);

  /**
   * @brief Emit candidates to isocline with delete ranges.
   */
  void EmitCandidates_(ic_completion_env_t *cenv, const CompletionContext &ctx,
                       const std::vector<CompletionCandidate> &items);

  std::unique_ptr<AMCompleteSources> sources_;
  Args args_{};

  std::atomic<uint64_t> request_counter_{0};
  std::atomic<uint64_t> current_request_id_{0};
  std::mutex request_mtx_;
  std::string last_input_;
  size_t last_cursor_ = 0;
  uint64_t last_request_id_ = 0;
};
