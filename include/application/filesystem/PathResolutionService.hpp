#pragma once

#include "domain/client/ClientPort.hpp"
#include "domain/filesystem/FileSystemModel.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

namespace AMApplication::filesystem {
/**
 * @brief Shared application-side resolver for client-qualified path tokens.
 *
 * This service centralizes the path/client preparation logic that was
 * previously duplicated in filesystem and transfer workflows.
 */
class PathResolutionService {
public:
  using ECM = std::pair<ErrorCode, std::string>;
  using ClientHandle = AMDomain::client::ClientHandle;
  using PathResolveResult = AMDomain::filesystem::PathResolveResult;

  /**
   * @brief Parse one raw token into nickname/path/client form using runtime
   * ports.
   */
  [[nodiscard]] static PathResolveResult
  ParsePathTarget(const std::string &input,
                  AMDomain::client::IClientRuntimePort &runtime_port,
                  AMDomain::client::IClientPathPort &path_port,
                  amf interrupt_flag = nullptr);

  /**
   * @brief Resolve one ready client for command planning/execution.
   */
  [[nodiscard]] static std::pair<ECM, ClientHandle>
  ResolveReadyClient(AMDomain::client::IClientRuntimePort &runtime_port,
                     AMDomain::client::IClientLifecyclePort &lifecycle_port,
                     const std::string &nickname,
                     std::shared_ptr<TaskControlToken> control_token = nullptr,
                     int timeout_ms = -1, int64_t start_time = -1);

  /**
   * @brief Parse one raw token, ensure its client is ready, and build the
   * absolute path for downstream IO planning.
   */
  [[nodiscard]] static PathResolveResult
  ResolveReadyPath(const std::string &input,
                   AMDomain::client::IClientRuntimePort &runtime_port,
                   AMDomain::client::IClientLifecyclePort &lifecycle_port,
                   AMDomain::client::IClientPathPort &path_port,
                   std::shared_ptr<TaskControlToken> control_token = nullptr,
                   int timeout_ms = -1, int64_t start_time = -1);
};
} // namespace AMApplication::filesystem
