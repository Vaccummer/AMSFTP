#pragma once
#include "domain/filesystem/FileSystemModel.hpp"
#include "foundation/DataClass.hpp"
#include <string>
#include <vector>

namespace AMDomain::filesystem {
/**
 * @brief Domain service that centralizes filesystem command validation rules.
 *
 * This service is intentionally side-effect free and can be reused by
 * application workflows and interface adapters.
 */
class FileSystemDomainService {
public:
  /**
   * @brief Split one whitespace-delimited argument string into tokens.
   */
  [[nodiscard]] static std::vector<std::string>
  SplitTargets(const std::string &input);

  /**
   * @brief Return unique tokens while preserving first-seen order.
   */
  [[nodiscard]] static std::vector<std::string>
  DedupTargetsKeepOrder(const std::vector<std::string> &targets);

  /**
   * @brief Return true when nickname should map to local profile.
   */
  [[nodiscard]] static bool IsLocalNickname(const std::string &nickname);

  /**
   * @brief Validate protocol-connect target payload from positional tokens.
   *
   * Accepted formats are `[user@host]` or `[nickname user@host]`.
   */
  [[nodiscard]] static ECM
  ValidateProtocolConnectTarget(const std::vector<std::string> &targets,
                                const std::string &protocol_name,
                                ProtocolConnectTarget *out_target);

  /**
   * @brief Validate one parsed path target with resolution policy.
   */
  [[nodiscard]] static ECM
  ValidatePathTarget(const PathTarget &target,
                     const PathResolveOptions &options);

  /**
   * @brief Build final shell command text from prefix/wrap policy.
   */
  [[nodiscard]] static std::string
  BuildShellCommand(const std::string &command, const std::string &cmd_prefix,
                    bool wrap_cmd);

  /**
   * @brief Merge operation status by preferring the latest failure.
   */
  [[nodiscard]] static ECM MergeStatus(const ECM &current, const ECM &next);
};
} // namespace AMDomain::filesystem
