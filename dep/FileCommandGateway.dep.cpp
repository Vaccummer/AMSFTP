#include "interface/adapters/FileCommandGateway.dep.hpp"

#include "infrastructure/controller/ClientControlTokenAdapter.hpp"

namespace AMInterface::ApplicationAdapters {
namespace {
ECM DeprecatedUnsupported_() {
  return Err(EC::OperationUnsupported,
             "Deprecated gateway: use FileSystemCliAdapter");
}

ECM MergeStatus_(const ECM &current, const ECM &next) {
  return isok(next) ? current : next;
}
} // namespace

/**
 * @brief Construct deprecated gateway from client app service.
 */
FileCommandGateway::FileCommandGateway(
    AMApplication::client::ClientAppService &client_service)
    : client_service_(client_service) {}

ECM FileCommandGateway::CheckClients(const std::vector<std::string> &nicknames,
                                     bool detail, amf interrupt_flag) {
  const AMDomain::client::amf client_interrupt =
      AMInfra::controller::AdaptClientInterruptFlag(interrupt_flag);
  std::vector<std::string> targets = nicknames;
  if (targets.empty()) {
    targets = client_service_.GetClientNames();
  }
  if (targets.empty()) {
    return Err(EC::ClientNotFound, "No client to check");
  }
  ECM status = Ok();
  for (const auto &name : targets) {
    auto [rcm, _client] =
        client_service_.CheckClient(name, detail, client_interrupt, -1, -1);
    status = MergeStatus_(status, rcm);
  }
  return status;
}

ECM FileCommandGateway::ListClients(bool detail, amf interrupt_flag) {
  return CheckClients({}, detail, interrupt_flag);
}

ECM FileCommandGateway::DisconnectClients(
    const std::vector<std::string> &nicknames) {
  ECM status = Ok();
  for (const auto &name : nicknames) {
    status = MergeStatus_(status, client_service_.RemoveClient(name));
  }
  return status;
}

ECM FileCommandGateway::StatPaths(const std::vector<std::string> &paths,
                                  amf interrupt_flag, int timeout_ms) {
  (void)paths;
  (void)interrupt_flag;
  (void)timeout_ms;
  return DeprecatedUnsupported_();
}

ECM FileCommandGateway::ListPath(const std::string &path, bool list_like,
                                 bool show_all, amf interrupt_flag,
                                 int timeout_ms) {
  (void)path;
  (void)list_like;
  (void)show_all;
  (void)interrupt_flag;
  (void)timeout_ms;
  return DeprecatedUnsupported_();
}

ECM FileCommandGateway::GetSize(const std::vector<std::string> &paths,
                                amf interrupt_flag, int timeout_ms) {
  (void)paths;
  (void)interrupt_flag;
  (void)timeout_ms;
  return DeprecatedUnsupported_();
}

ECM FileCommandGateway::Find(const std::string &path, SearchType type,
                             amf interrupt_flag, int timeout_ms) {
  (void)path;
  (void)type;
  (void)interrupt_flag;
  (void)timeout_ms;
  return DeprecatedUnsupported_();
}

ECM FileCommandGateway::Mkdir(const std::vector<std::string> &paths,
                              amf interrupt_flag, int timeout_ms) {
  (void)paths;
  (void)interrupt_flag;
  (void)timeout_ms;
  return DeprecatedUnsupported_();
}

ECM FileCommandGateway::Remove(const std::vector<std::string> &paths,
                               bool permanent, bool force, bool quiet,
                               amf interrupt_flag, int timeout_ms) {
  (void)paths;
  (void)permanent;
  (void)force;
  (void)quiet;
  (void)interrupt_flag;
  (void)timeout_ms;
  return DeprecatedUnsupported_();
}

ECM FileCommandGateway::Walk(const std::string &path, bool only_file,
                             bool only_dir, bool show_all,
                             bool ignore_special_file, bool quiet,
                             amf interrupt_flag, int timeout_ms) {
  (void)path;
  (void)only_file;
  (void)only_dir;
  (void)show_all;
  (void)ignore_special_file;
  (void)quiet;
  (void)interrupt_flag;
  (void)timeout_ms;
  return DeprecatedUnsupported_();
}

ECM FileCommandGateway::Tree(const std::string &path, int max_depth,
                             bool only_dir, bool show_all,
                             bool ignore_special_file, bool quiet,
                             amf interrupt_flag, int timeout_ms) {
  (void)path;
  (void)max_depth;
  (void)only_dir;
  (void)show_all;
  (void)ignore_special_file;
  (void)quiet;
  (void)interrupt_flag;
  (void)timeout_ms;
  return DeprecatedUnsupported_();
}

ECM FileCommandGateway::Realpath(const std::string &path, amf interrupt_flag,
                                 int timeout_ms) {
  (void)path;
  (void)interrupt_flag;
  (void)timeout_ms;
  return DeprecatedUnsupported_();
}

ECM FileCommandGateway::TestRtt(int times, amf interrupt_flag) {
  (void)times;
  (void)interrupt_flag;
  return DeprecatedUnsupported_();
}

ECM FileCommandGateway::Cd(const std::string &path, amf interrupt_flag,
                           bool from_history) {
  (void)path;
  (void)interrupt_flag;
  (void)from_history;
  return DeprecatedUnsupported_();
}

std::pair<ECM, std::pair<std::string, int>>
FileCommandGateway::ShellRun(const std::string &cmd, int max_time_ms,
                             amf interrupt_flag) {
  (void)cmd;
  (void)max_time_ms;
  (void)interrupt_flag;
  return {DeprecatedUnsupported_(), {"", -1}};
}
} // namespace AMInterface::ApplicationAdapters
