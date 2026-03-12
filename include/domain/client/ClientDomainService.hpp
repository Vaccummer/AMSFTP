#pragma once
#include "domain/client/ClientModel.hpp"
#include <string>

namespace AMDomain::client {
/**
 * @brief Domain service for client nickname/path/workdir business rules.
 */
class ClientDomainService {
public:
  /**
   * @brief Minimum legal heartbeat timeout in milliseconds.
   */
  static constexpr int kHeartbeatTimeoutMinMs = 10;

  /**
   * @brief Maximum legal heartbeat timeout in milliseconds.
   */
  static constexpr int kHeartbeatTimeoutMaxMs = 10000;

  /**
   * @brief Clamp heartbeat timeout to legal range.
   */
  [[nodiscard]] static int ClampHeartbeatTimeoutMs(int timeout_ms);

  /**
   * @brief Return true when nickname maps to local client.
   */
  [[nodiscard]] static bool IsLocalNickname(const std::string &nickname);

  /**
   * @brief Normalize user-provided nickname for comparisons.
   */
  [[nodiscard]] static std::string
  NormalizeNickname(const std::string &nickname);

  /**
   * @brief Parse one user path token into scoped nickname/path form.
   *
   * Supported forms:
   * - `@path` => local path
   * - `nickname@path` => explicit remote/local nickname path
   * - `path` => implicit current-client path
   */
  [[nodiscard]] static ScopedPath
  ParseScopedPath(const std::string &input,
                  const std::string &current_nickname);

  /**
   * @brief Validate one parsed scoped path.
   */
  [[nodiscard]] static ECM ValidateScopedPath(const ScopedPath &scoped_path);

  /**
   * @brief Resolve effective workdir from client state snapshot.
   */
  [[nodiscard]] static std::string
  ResolveWorkdir(const ClientWorkdirState &state,
                 const std::string &path_sep = "/");

  /**
   * @brief Resolve one input path into absolute path using workdir state.
   */
  [[nodiscard]] static std::string
  ResolveAbsolutePath(const std::string &path, const ClientWorkdirState &state,
                      const std::string &path_sep = "/");

  /**
   * @brief Validate connect request at domain boundary.
   */
  [[nodiscard]] static ECM
  ValidateConnectRequest(const AMDomain::host::ConRequest &request,
                         bool allow_local_protocol = false);
};
} // namespace AMDomain::client
