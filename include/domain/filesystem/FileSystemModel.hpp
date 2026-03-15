#pragma once
#include "domain/client/ClientPort.hpp"
#include "foundation/DataClass.hpp"
#include <memory>
#include <string>

namespace AMDomain::filesystem {
/**
 * @brief Explicit confirmation policy passed from interface into application.
 */
enum class ConfirmPolicy {
  /**
   * @brief Caller requires interactive confirmation before execution.
   */
  RequireConfirm = 0,

  /**
   * @brief Caller already approved operation (force/yes mode).
   */
  AutoApprove = 1,

  /**
   * @brief Caller runs in non-interactive mode and denies risky operations.
   */
  DenyIfConfirmNeeded = 2,
};

/**
 * @brief Generic filesystem result contract carrying status and typed payload.
 */
template <typename T> struct Result {
  /**
   * @brief Result status code and detail message.
   */
  ECM rcm = {EC::Success, ""};

  /**
   * @brief Typed result payload data.
   */
  T data = {};

  /**
   * @brief Return true when status is success.
   */
  [[nodiscard]] bool ok() const { return rcm.first == EC::Success; }
};

/**
 * @brief Empty payload used by status-oriented operations.
 */
struct EmptyPayload {};

/**
 * @brief Client handle alias used by filesystem domain contracts.
 */
using ClientHandle = std::shared_ptr<AMDomain::client::IClientPort>;

/**
 * @brief Parsed path target containing optional client nickname prefix.
 */
struct PathTarget {
  /**
   * @brief Raw token before parsing.
   */
  std::string raw = "";

  /**
   * @brief Optional nickname parsed from `nickname@path` syntax.
   *
   * Empty value means current/local client resolution should be used.
   */
  std::string nickname = "";

  /**
   * @brief Path segment parsed from input token.
   */
  std::string path = "";

  /**
   * @brief True when input explicitly carries nickname prefix.
   */
  bool has_explicit_nickname = false;
};

/**
 * @brief Path-resolution policy flags for filesystem operations.
 */
struct PathResolveOptions {
  /**
   * @brief Require non-empty path text after parsing.
   */
  bool require_non_empty_path = false;

  /**
   * @brief Allow empty nickname to resolve through current/local fallback.
   */
  bool allow_empty_nickname = true;

  /**
   * @brief Normalize resolved absolute path separator to `/`.
   */
  bool normalize_path_separator = true;
};

/**
 * @brief Result payload for resolving one command path token.
 */
struct PathResolveResult {
  /**
   * @brief Resolution status code and detail.
   */
  ECM rcm = {EC::Success, ""};

  /**
   * @brief Parsed target data.
   */
  PathTarget target = {};

  /**
   * @brief Resolved client handle for the target.
   */
  ClientHandle client = nullptr;

  /**
   * @brief Final absolute path used by client operation.
   */
  std::string abs_path = "";
};

/**
 * @brief Parsed target for protocol connect commands.
 */
struct ProtocolConnectTarget {
  /**
   * @brief Optional nickname that persists connection profile.
   */
  std::string nickname = "";

  /**
   * @brief Required `user@host` literal.
   */
  std::string user_at_host = "";
};

/**
 * @brief Remove operation flags independent from CLI representation.
 */
struct RemovePolicy {
  /**
   * @brief Use permanent remove instead of safe-remove/trash behavior.
   */
  bool permanent = false;

  /**
   * @brief Skip confirmation prompt when true.
   */
  bool force = false;

  /**
   * @brief Suppress per-item error output when true.
   */
  bool quiet = false;
};

/**
 * @brief Remove request contract with explicit confirmation policy.
 */
struct RemoveRequest {
  /**
   * @brief Raw input paths passed from caller.
   */
  std::vector<std::string> paths = {};

  /**
   * @brief Use permanent remove instead of saferm/trash.
   */
  bool permanent = false;

  /**
   * @brief Explicit confirmation policy for non-interactive compatibility.
   */
  ConfirmPolicy confirm_policy = ConfirmPolicy::RequireConfirm;

  /**
   * @brief Suppress per-item error output when true.
   */
  bool quiet = false;

  /**
   * @brief IO timeout in milliseconds, `-1` means unlimited/default.
   */
  int timeout_ms = -1;
};

/**
 * @brief Walk operation filtering policy.
 */
struct WalkPolicy {
  /**
   * @brief Return only files.
   */
  bool only_file = false;

  /**
   * @brief Return only directories.
   */
  bool only_dir = false;

  /**
   * @brief Include hidden entries.
   */
  bool show_all = false;

  /**
   * @brief Ignore special files while traversing tree.
   */
  bool ignore_special_file = true;

  /**
   * @brief Suppress formatted output when true.
   */
  bool quiet = false;
};

/**
 * @brief Tree rendering policy for filesystem tree output.
 */
struct TreePolicy {
  /**
   * @brief Maximum depth limit, `-1` means unlimited.
   */
  int max_depth = -1;

  /**
   * @brief Print only directories.
   */
  bool only_dir = false;

  /**
   * @brief Include hidden entries.
   */
  bool show_all = false;

  /**
   * @brief Ignore special files.
   */
  bool ignore_special_file = true;

  /**
   * @brief Suppress formatted output when true.
   */
  bool quiet = false;
};

/**
 * @brief One size query record for a resolved path.
 */
struct SizeEntry {
  /**
   * @brief Original input token.
   */
  std::string raw = "";

  /**
   * @brief Resolved absolute path used in backend execution.
   */
  std::string abs_path = "";

  /**
   * @brief Computed recursive size.
   */
  int64_t size = 0;
};

/**
 * @brief One realpath resolution record.
 */
struct RealpathEntry {
  /**
   * @brief Original input token.
   */
  std::string raw = "";

  /**
   * @brief Resolved absolute path.
   */
  std::string abs_path = "";
};

/**
 * @brief List path payload containing target stat and optional child entries.
 */
struct ListPathPayload {
  /**
   * @brief Target path metadata returned by stat.
   */
  PathInfo target = {};

  /**
   * @brief Child entries returned when target is directory.
   */
  std::vector<PathInfo> entries = {};
};

/**
 * @brief Walk/tree query payload with partial data and per-path errors.
 */
struct WalkPayload {
  /**
   * @brief Flattened path records returned by walk query.
   */
  std::vector<PathInfo> items = {};

  /**
   * @brief Per-path walk errors from backend walk execution.
   */
  std::vector<std::pair<std::string, ECM>> errors = {};
};

/**
 * @brief Typed result alias for status-oriented remove operation.
 */
using RemoveResult = Result<EmptyPayload>;

/**
 * @brief Typed result alias for stat query.
 */
using StatPathsResult = Result<std::vector<PathInfo>>;

/**
 * @brief Typed result alias for list query.
 */
using ListPathResult = Result<ListPathPayload>;

/**
 * @brief Typed result alias for size query.
 */
using GetSizeResult = Result<std::vector<SizeEntry>>;

/**
 * @brief Typed result alias for find query.
 */
using FindResult = Result<std::vector<PathInfo>>;

/**
 * @brief Typed result alias for walk query.
 */
using WalkQueryResult = Result<WalkPayload>;

/**
 * @brief Typed result alias for tree query.
 */
using TreeQueryResult = Result<WalkPayload>;

/**
 * @brief Typed result alias for realpath query.
 */
using RealpathQueryResult = Result<RealpathEntry>;
} // namespace AMDomain::filesystem
