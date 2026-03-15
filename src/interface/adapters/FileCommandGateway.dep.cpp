#include "interface/adapters/FileCommandGateway.dep.hpp"

namespace AMInterface::ApplicationAdapters {
/**
 * @brief Construct filesystem command gateway from filesystem app service.
 */
FileCommandGateway::FileCommandGateway(
    AMApplication::filesystem::FileSystemAppService &filesystem_service)
    : filesystem_service_(filesystem_service) {}

/**
 * @brief Check clients by nickname list.
 */
ECM FileCommandGateway::CheckClients(const std::vector<std::string> &nicknames,
                                     bool detail, amf interrupt_flag) {
  return filesystem_service_.CheckClients(nicknames, detail, interrupt_flag);
}

/**
 * @brief Print current clients.
 */
ECM FileCommandGateway::ListClients(bool detail, amf interrupt_flag) {
  return filesystem_service_.ListClients(detail, interrupt_flag);
}

/**
 * @brief Disconnect clients by nickname list.
 */
ECM FileCommandGateway::DisconnectClients(
    const std::vector<std::string> &nicknames) {
  return filesystem_service_.DisconnectClients(nicknames);
}

/**
 * @brief Print stat for one or more paths.
 */
ECM FileCommandGateway::StatPaths(const std::vector<std::string> &paths,
                                  amf interrupt_flag, int timeout_ms) {
  return filesystem_service_
      .QueryStatPaths(paths, interrupt_flag, timeout_ms)
      .rcm;
}

/**
 * @brief List one path.
 */
ECM FileCommandGateway::ListPath(const std::string &path, bool list_like,
                                 bool show_all, amf interrupt_flag,
                                 int timeout_ms) {
  return filesystem_service_
      .QueryListPath(path, list_like, show_all, interrupt_flag, timeout_ms)
      .rcm;
}

/**
 * @brief Print size for one or more paths.
 */
ECM FileCommandGateway::GetSize(const std::vector<std::string> &paths,
                                amf interrupt_flag, int timeout_ms) {
  return filesystem_service_
      .QueryGetSize(paths, interrupt_flag, timeout_ms)
      .rcm;
}

/**
 * @brief Run find on one path.
 */
ECM FileCommandGateway::Find(const std::string &path, SearchType type,
                             amf interrupt_flag, int timeout_ms) {
  return filesystem_service_
      .QueryFind(path, type, interrupt_flag, timeout_ms)
      .rcm;
}

/**
 * @brief Create directories for one or more paths.
 */
ECM FileCommandGateway::Mkdir(const std::vector<std::string> &paths,
                              amf interrupt_flag, int timeout_ms) {
  return filesystem_service_.Mkdir(paths, interrupt_flag, timeout_ms);
}

/**
 * @brief Remove one or more paths.
 */
ECM FileCommandGateway::Remove(const std::vector<std::string> &paths,
                               bool permanent, bool force, bool quiet,
                               amf interrupt_flag, int timeout_ms) {
  AMDomain::filesystem::RemoveRequest request = {};
  request.paths = paths;
  request.permanent = permanent;
  request.confirm_policy = force ? AMDomain::filesystem::ConfirmPolicy::AutoApprove
                                 : AMDomain::filesystem::ConfirmPolicy::RequireConfirm;
  request.quiet = quiet;
  request.timeout_ms = timeout_ms;
  return filesystem_service_.ExecuteRemove(request, interrupt_flag).rcm;
}

/**
 * @brief Walk one path.
 */
ECM FileCommandGateway::Walk(const std::string &path, bool only_file,
                             bool only_dir, bool show_all,
                             bool ignore_special_file, bool quiet,
                             amf interrupt_flag, int timeout_ms) {
  return filesystem_service_
      .QueryWalk(path, only_file, only_dir, show_all, ignore_special_file,
                 quiet, interrupt_flag, timeout_ms)
      .rcm;
}

/**
 * @brief Print one path tree.
 */
ECM FileCommandGateway::Tree(const std::string &path, int max_depth,
                             bool only_dir, bool show_all,
                             bool ignore_special_file, bool quiet,
                             amf interrupt_flag, int timeout_ms) {
  return filesystem_service_
      .QueryTree(path, max_depth, only_dir, show_all, ignore_special_file,
                 quiet, interrupt_flag, timeout_ms)
      .rcm;
}

/**
 * @brief Resolve one real path.
 */
ECM FileCommandGateway::Realpath(const std::string &path, amf interrupt_flag,
                                 int timeout_ms) {
  return filesystem_service_
      .QueryRealpath(path, interrupt_flag, timeout_ms)
      .rcm;
}

/**
 * @brief Measure RTT for current client.
 */
ECM FileCommandGateway::TestRtt(int times, amf interrupt_flag) {
  return filesystem_service_.TestRtt(times, interrupt_flag);
}

/**
 * @brief Change current workdir.
 */
ECM FileCommandGateway::Cd(const std::string &path, amf interrupt_flag,
                           bool from_history) {
  return filesystem_service_.Cd(path, interrupt_flag, from_history);
}

/**
 * @brief Run one shell command.
 */
std::pair<ECM, std::pair<std::string, int>>
FileCommandGateway::ShellRun(const std::string &cmd, int max_time_ms,
                             amf interrupt_flag) {
  return filesystem_service_.ShellRun(cmd, max_time_ms, interrupt_flag);
}
} // namespace AMInterface::ApplicationAdapters
