#pragma once
#include "domain/client/ClientPort.hpp"
#include "foundation/DataClass.hpp"
#include <memory>
#include <string>

namespace AMDomain::filesystem {
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
} // namespace AMDomain::filesystem
