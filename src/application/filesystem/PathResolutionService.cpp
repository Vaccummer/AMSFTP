#include "application/filesystem/PathResolutionService.hpp"

#include "domain/client/ClientDomainService.hpp"
#include "foundation/tools/enum_related.hpp"
#include "domain/host/HostDomainService.hpp"

namespace AMApplication::filesystem {
namespace {
/**
 * @brief Return one normalized nickname for runtime resolution.
 */
std::string NormalizePathNickname_(const std::string &nickname) {
  return AMDomain::client::ClientDomainService::NormalizeNickname(nickname);
}
} // namespace

/**
 * @brief Parse one raw token into nickname/path/client form using runtime
 * ports.
 */
PathResolutionService::PathResolveResult PathResolutionService::ParsePathTarget(
    const std::string &input, AMDomain::client::IClientRuntimePort &runtime_port,
    AMDomain::client::IClientPathPort &path_port,
    AMDomain::client::amf interrupt_flag) {
  PathResolveResult result{};

  const auto scoped = AMDomain::client::ClientDomainService::ParseScopedPath(
      input, runtime_port.CurrentNickname());
  result.target.nickname = NormalizePathNickname_(scoped.nickname);
  result.target.path = scoped.path;

  auto [nickname, path, client, rcm] =
      path_port.ParseScopedPath(input, interrupt_flag);
  (void)nickname;
  (void)path;
  result.client = client;
  result.rcm = rcm;
  return result;
}

/**
 * @brief Resolve one ready client for command planning/execution.
 */
std::pair<PathResolutionService::ECM, PathResolutionService::ClientHandle>
PathResolutionService::ResolveReadyClient(
    AMDomain::client::IClientRuntimePort &runtime_port,
    AMDomain::client::IClientLifecyclePort &lifecycle_port,
    const std::string &nickname, AMDomain::client::amf control_token,
    int timeout_ms, int64_t start_time) {
  using ClientStatus = AMDomain::client::ClientStatus;

  if (control_token && control_token->IsInterrupted()) {
    return {ECM{ErrorCode::Terminate, "Interrupted during client preparation"},
            nullptr};
  }

  const std::string normalized = NormalizePathNickname_(nickname);
  ClientHandle client = nullptr;
  ECM rcm = {ErrorCode::Success, ""};
  if (AMDomain::host::HostManagerService::IsLocalNickname(normalized)) {
    client = runtime_port.GetLocalClient();
    if (!client) {
      return {ECM{ErrorCode::ClientNotFound, "Local client not found"},
              nullptr};
    }
  } else {
    auto ensured = lifecycle_port.EnsureClient(normalized, control_token);
    rcm = ensured.first;
    client = ensured.second;
    if (!isok(rcm) || !client) {
      return {rcm, nullptr};
    }
  }

  const auto state = client->ConfigPort().GetState();
  rcm = state.rcm;
  if (state.status != ClientStatus::OK || rcm.first != ErrorCode::Success) {
    rcm = client->IOPort().Check({AMDomain::client::MakeClientIOControlArgs(
        control_token, timeout_ms, start_time)});
  }
  return {rcm, client};
}

/**
 * @brief Parse one raw token, ensure its client is ready, and build the
 * absolute path for downstream IO planning.
 */
PathResolutionService::PathResolveResult PathResolutionService::ResolveReadyPath(
    const std::string &input, AMDomain::client::IClientRuntimePort &runtime_port,
    AMDomain::client::IClientLifecyclePort &lifecycle_port,
    AMDomain::client::IClientPathPort &path_port,
    AMDomain::client::amf control_token, int timeout_ms, int64_t start_time) {
  PathResolveResult result =
      ParsePathTarget(input, runtime_port, path_port, control_token);
  if (!isok(result.rcm)) {
    return result;
  }

  auto [ready_rcm, client] =
      ResolveReadyClient(runtime_port, lifecycle_port, result.target.nickname,
                         std::move(control_token), timeout_ms, start_time);
  result.rcm = ready_rcm;
  if (!isok(result.rcm) || !client) {
    result.client = nullptr;
    result.abs_path.clear();
    return result;
  }

  result.client = client;
  result.abs_path = path_port.BuildAbsolutePath(client, result.target.path);
  return result;
}
} // namespace AMApplication::filesystem




