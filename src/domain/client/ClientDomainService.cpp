#include "domain/client/ClientDomainService.hpp"
#include "domain/host/HostDomainService.hpp"
#include "foundation/core/Path.hpp"
#include "foundation/tools/time.hpp"
#include "foundation/tools/string.hpp"

namespace AMDomain::client {
namespace {
/**
 * @brief Normalize path separators to one canonical separator.
 */
std::string NormalizePath_(const std::string &value,
                           const std::string &path_sep) {
  return AMPathStr::UnifyPathSep(value, path_sep);
}
} // namespace

float ResolveTimeoutBudgetMs(int timeout_ms, int64_t start_time) {
  if (timeout_ms <= 0) {
    return static_cast<float>(timeout_ms);
  }
  if (start_time < 0) {
    return static_cast<float>(timeout_ms);
  }
  const float remain = static_cast<float>(timeout_ms) -
                       static_cast<float>(AMTime::miliseconds() - start_time);
  return remain > 0.0f ? remain : 0.0f;
}

ClientControlComponent MakeClientControlComponent(amf interrupt_flag,
                                                  int timeout_ms,
                                                  int64_t start_time) {
  timeoutf timeout_port = CreateClientTimeoutPort();
  if (timeout_port) {
    timeout_port->SetTimeout(ResolveTimeoutBudgetMs(timeout_ms, start_time));
  }
  return ClientControlComponent(std::move(interrupt_flag),
                                std::move(timeout_port));
}

ClientControlComponent MakeClientIOControlArgs(amf interrupt_flag, int timeout_ms,
                                               int64_t start_time) {
  return MakeClientControlComponent(std::move(interrupt_flag), timeout_ms,
                                    start_time);
}

/**
 * @brief Clamp heartbeat timeout to legal range.
 */
int ClientDomainService::ClampHeartbeatTimeoutMs(int timeout_ms) {
  if (timeout_ms < kHeartbeatTimeoutMinMs) {
    return kHeartbeatTimeoutMinMs;
  }
  if (timeout_ms > kHeartbeatTimeoutMaxMs) {
    return kHeartbeatTimeoutMaxMs;
  }
  return timeout_ms;
}

/**
 * @brief Return true when nickname maps to local client.
 */
bool ClientDomainService::IsLocalNickname(const std::string &nickname) {
  const std::string normalized =
      AMStr::lowercase(AMStr::Strip(nickname));
  return normalized.empty() || normalized == "local";
}

/**
 * @brief Normalize user-provided nickname for comparisons.
 */
std::string ClientDomainService::NormalizeNickname(
    const std::string &nickname) {
  const std::string normalized = AMStr::Strip(nickname);
  return IsLocalNickname(normalized) ? std::string("local") : normalized;
}

/**
 * @brief Parse one user path token into scoped nickname/path form.
 */
ScopedPath ClientDomainService::ParseScopedPath(
    const std::string &input, const std::string &current_nickname) {
  ScopedPath scoped;
  if (!input.empty() && input.front() == '@') {
    scoped.explicit_client = true;
    scoped.nickname = "local";
    scoped.path = input.substr(1);
    return scoped;
  }

  const auto pos = input.find('@');
  if (pos == std::string::npos) {
    scoped.explicit_client = false;
    scoped.nickname = NormalizeNickname(current_nickname);
    scoped.path = input;
    return scoped;
  }

  scoped.explicit_client = true;
  scoped.nickname = NormalizeNickname(input.substr(0, pos));
  scoped.path = input.substr(pos + 1);
  return scoped;
}

/**
 * @brief Validate one parsed scoped path.
 */
ECM ClientDomainService::ValidateScopedPath(const ScopedPath &scoped_path) {
  if (scoped_path.nickname.empty()) {
    return Err(EC::InvalidArg, "empty client nickname");
  }
  return Ok();
}

/**
 * @brief Resolve effective workdir from client state snapshot.
 */
std::string ClientDomainService::ResolveWorkdir(
    const ClientWorkdirState &state, const std::string &path_sep) {
  const std::string home_dir = NormalizePath_(state.home_dir, path_sep);
  std::string workdir = NormalizePath_(state.cwd, path_sep);
  if (workdir.empty()) {
    workdir = NormalizePath_(state.login_dir, path_sep);
  }
  if (workdir.empty()) {
    workdir = home_dir;
  }
  if (workdir.empty()) {
    return {};
  }
  if (AMPathStr::IsAbs(workdir, path_sep)) {
    return workdir;
  }
  const std::string base = home_dir.empty() ? workdir : home_dir;
  return AMFS::abspath(workdir, true, home_dir, base, path_sep);
}

/**
 * @brief Resolve one input path into absolute path using workdir state.
 */
std::string ClientDomainService::ResolveAbsolutePath(
    const std::string &path, const ClientWorkdirState &state,
    const std::string &path_sep) {
  if (path.empty()) {
    return ResolveWorkdir(state, path_sep);
  }
  const std::string home_dir = NormalizePath_(state.home_dir, path_sep);
  const std::string workdir = ResolveWorkdir(state, path_sep);
  return AMFS::abspath(path, true, home_dir, workdir, path_sep);
}

/**
 * @brief Validate connect request at domain boundary.
 */
ECM ClientDomainService::ValidateConnectRequest(
    const AMDomain::host::ConRequest &request, bool allow_local_protocol) {
  if (!allow_local_protocol &&
      request.protocol == AMDomain::host::ClientProtocol::LOCAL) {
    return Err(EC::InvalidArg, "local protocol is not allowed here");
  }
  ECM validate_rcm = AMDomain::host::HostService::ValidateConfig(request);
  if (!isok(validate_rcm)) {
    return Err(EC::InvalidArg, validate_rcm.second.empty()
                                   ? std::string("invalid connect request")
                                   : validate_rcm.second);
  }
  return Ok();
}
} // namespace AMDomain::client
