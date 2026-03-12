#include "application/client/ClientSessionWorkflows.hpp"
#include "foundation/tools/enum_related.hpp"
#include "foundation/tools/string.hpp"

namespace AMApplication::ClientWorkflow {
using ClientProtocol = AMDomain::host::ClientProtocol;

namespace {
/**
 * @brief Return protocol display name for diagnostics.
 */
[[nodiscard]] std::string ProtocolDisplayName_(ClientProtocol protocol) {
  switch (protocol) {
  case ClientProtocol::SFTP:
    return "sftp";
  case ClientProtocol::FTP:
    return "ftp";
  default:
    return "protocol";
  }
}
} // namespace

/**
 * @brief Return true when caller should run interactive-only path.
 */
bool IsInteractiveMode(const SessionMode &mode) {
  return mode.enforce_interactive || mode.current_interactive;
}

/**
 * @brief Parse protocol targets from `[user@host]` or `[nickname user@host]`.
 */
ECM ResolveProtocolTarget(const std::vector<std::string> &targets,
                          const std::string &protocol_name,
                          ProtocolConnectTarget *out_target) {
  if (!out_target) {
    return Err(EC::InvalidArg, "null output target");
  }
  out_target->nickname.clear();
  out_target->user_at_host.clear();

  if (targets.size() == 1) {
    out_target->user_at_host = targets.front();
  } else if (targets.size() == 2) {
    out_target->nickname = targets.front();
    out_target->user_at_host = targets.back();
  } else {
    const std::string name =
        protocol_name.empty() ? std::string("connect") : protocol_name;
    return Err(EC::InvalidArg, AMStr::fmt("{} requires user@host", name));
  }

  if (out_target->user_at_host.find('@') == std::string::npos) {
    return Err(EC::InvalidArg, "Invalid user@host format");
  }
  return Ok();
}

/**
 * @brief Run `sftp`/`ftp` style connect workflow.
 */
SessionWorkflowResult
ConnectProtocolClient(IClientSessionGateway &gateway, ClientProtocol protocol,
                      const std::vector<std::string> &targets, int64_t port,
                      const std::string &password, const std::string &keyfile,
                      amf interrupt_flag) {
  ProtocolConnectTarget resolved;
  SessionWorkflowResult out = {};
  const std::string name = ProtocolDisplayName_(protocol);
  out.rcm = ResolveProtocolTarget(targets, name, &resolved);
  if (!isok(out.rcm)) {
    return out;
  }

  switch (protocol) {
  case ClientProtocol::SFTP:
    out.rcm = gateway.ConnectSftp(resolved.nickname, resolved.user_at_host,
                                  port, password, keyfile, interrupt_flag);
    break;
  case ClientProtocol::FTP:
    out.rcm = gateway.ConnectFtp(resolved.nickname, resolved.user_at_host, port,
                                 password, keyfile, interrupt_flag);
    break;
  default:
    out.rcm = Err(EC::InvalidArg, "Unsupported protocol");
    break;
  }
  out.enter_interactive = isok(out.rcm);
  return out;
}

/**
 * @brief Run `ch` style workflow with interactive/non-interactive behavior.
 */
SessionWorkflowResult ChangeClient(IClientSessionGateway &gateway,
                                   const std::string &nickname,
                                   const SessionMode &mode,
                                   amf interrupt_flag) {
  SessionWorkflowResult out = {};
  if (IsInteractiveMode(mode)) {
    out.rcm = gateway.ChangeCurrentClient(nickname, interrupt_flag);
    return out;
  }

  out.rcm = gateway.ConnectNickname(nickname, false, true, interrupt_flag);
  out.enter_interactive = isok(out.rcm);
  return out;
}

/**
 * @brief Run multi-target `connect` orchestration.
 */
SessionWorkflowResult
ConnectNicknames(IClientSessionGateway &gateway,
                 const std::vector<std::string> &nicknames, bool force,
                 const SessionMode &mode, amf interrupt_flag) {
  SessionWorkflowResult out = {};
  const std::vector<std::string> targets =
      AMStr::UniqueTargetsKeepOrder(nicknames);
  if (targets.empty()) {
    out.rcm = Err(EC::InvalidArg, "connect requires at least one nickname");
    return out;
  }

  bool any_success = false;
  ECM last = Ok();
  for (const auto &nickname : targets) {
    if (nickname.empty()) {
      last = Err(EC::InvalidArg, "Empty nickname");
      continue;
    }

    ECM rcm = gateway.ConnectNickname(nickname, force, false, interrupt_flag);
    if (!isok(rcm)) {
      last = rcm;
      continue;
    }
    any_success = true;
  }

  if (!IsInteractiveMode(mode) && any_success) {
    ECM switch_local = gateway.ChangeCurrentClient("local", interrupt_flag);
    if (!isok(switch_local) && isok(last)) {
      last = switch_local;
    }
    out.enter_interactive = isok(switch_local);
  }

  out.rcm = last;
  return out;
}

/**
 * @brief Execute client-list workflow.
 */
ECM ExecuteClientList(IClientSessionGateway &gateway, bool detail,
                      amf interrupt_flag) {
  return gateway.ListClients(detail, interrupt_flag);
}

/**
 * @brief Execute client-disconnect workflow.
 */
ECM ExecuteClientDisconnect(IClientSessionGateway &gateway,
                            const std::vector<std::string> &nicknames) {
  return gateway.DisconnectClients(nicknames);
}

/**
 * @brief Execute path-stat workflow.
 */
ECM ExecuteStatPaths(IClientSessionGateway &gateway,
                     const std::vector<std::string> &paths,
                     amf interrupt_flag) {
  return gateway.StatPaths(paths, interrupt_flag);
}

/**
 * @brief Execute path-list workflow.
 */
ECM ExecuteListPath(IClientSessionGateway &gateway, const std::string &path,
                    bool list_like, bool show_all, amf interrupt_flag) {
  return gateway.ListPath(path, list_like, show_all, interrupt_flag);
}
} // namespace AMApplication::ClientWorkflow
