#include "interface/adapters/FileSystemAdapter.hpp"

#include "interface/prompt/Prompt.hpp"
#include "foundation/tools/string.hpp"

namespace AMInterface::ApplicationAdapters {
/**
 * @brief Construct direct CLI adapter from app service and prompt manager.
 */
FileSystemCliAdapter::FileSystemCliAdapter(
    AMApplication::filesystem::FileSystemAppService &filesystem_service,
    AMPromptManager &prompt_manager)
    : filesystem_service_(filesystem_service), prompt_manager_(prompt_manager) {}

/**
 * @brief Check clients by nickname list.
 */
ECM FileSystemCliAdapter::CheckClients(const std::vector<std::string> &nicknames,
                                       bool detail,
                                       amf interrupt_flag) const {
  return filesystem_service_.CheckClients(nicknames, detail, interrupt_flag);
}

/**
 * @brief List clients.
 */
ECM FileSystemCliAdapter::ListClients(bool detail, amf interrupt_flag) const {
  return filesystem_service_.ListClients(detail, interrupt_flag);
}

/**
 * @brief Disconnect clients by nickname list.
 */
ECM FileSystemCliAdapter::DisconnectClients(
    const std::vector<std::string> &nicknames) const {
  return filesystem_service_.DisconnectClients(nicknames);
}

/**
 * @brief Query stat results for one or more paths.
 */
ECM FileSystemCliAdapter::StatPaths(const std::vector<std::string> &paths,
                                    amf interrupt_flag,
                                    int timeout_ms) const {
  return filesystem_service_.QueryStatPaths(paths, interrupt_flag, timeout_ms).rcm;
}

/**
 * @brief Query list results for one path.
 */
ECM FileSystemCliAdapter::ListPath(const std::string &path, bool list_like,
                                   bool show_all, amf interrupt_flag,
                                   int timeout_ms) const {
  return filesystem_service_
      .QueryListPath(path, list_like, show_all, interrupt_flag, timeout_ms)
      .rcm;
}

/**
 * @brief Query size results for one or more paths.
 */
ECM FileSystemCliAdapter::GetSize(const std::vector<std::string> &paths,
                                  amf interrupt_flag, int timeout_ms) const {
  return filesystem_service_.QueryGetSize(paths, interrupt_flag, timeout_ms).rcm;
}

/**
 * @brief Query find results for one path.
 */
ECM FileSystemCliAdapter::Find(const std::string &path, SearchType type,
                               amf interrupt_flag, int timeout_ms) const {
  return filesystem_service_.QueryFind(path, type, interrupt_flag, timeout_ms).rcm;
}

/**
 * @brief Create directories for one or more paths.
 */
ECM FileSystemCliAdapter::Mkdir(const std::vector<std::string> &paths,
                                amf interrupt_flag, int timeout_ms) const {
  return filesystem_service_.Mkdir(paths, interrupt_flag, timeout_ms);
}

/**
 * @brief Remove paths with interface-owned confirmation behavior.
 */
ECM FileSystemCliAdapter::Remove(const std::vector<std::string> &paths,
                                 bool permanent, bool quiet,
                                 amf interrupt_flag, int timeout_ms) const {
  if (paths.empty()) {
    return Err(EC::InvalidArg, "No path is given");
  }

  AMDomain::filesystem::ConfirmPolicy policy =
      AMDomain::filesystem::ConfirmPolicy::RequireConfirm;
  if (quiet) {
    policy = AMDomain::filesystem::ConfirmPolicy::AutoApprove;
  } else {
    bool canceled = false;
    const bool confirmed = prompt_manager_.PromptYesNo(
        AMStr::fmt("Remove {} path(s)? (y/N): ", paths.size()), &canceled);
    if (canceled || !confirmed) {
      return Err(EC::ConfigCanceled, "remove canceled");
    }
    policy = AMDomain::filesystem::ConfirmPolicy::AutoApprove;
  }

  AMDomain::filesystem::RemoveRequest request = {};
  request.paths = paths;
  request.permanent = permanent;
  request.confirm_policy = policy;
  request.quiet = quiet;
  request.timeout_ms = timeout_ms;
  return filesystem_service_.ExecuteRemove(request, interrupt_flag).rcm;
}

/**
 * @brief Query walk results.
 */
ECM FileSystemCliAdapter::Walk(const std::string &path, bool only_file,
                               bool only_dir, bool show_all,
                               bool ignore_special_file, bool quiet,
                               amf interrupt_flag, int timeout_ms) const {
  return filesystem_service_
      .QueryWalk(path, only_file, only_dir, show_all, ignore_special_file,
                 quiet, interrupt_flag, timeout_ms)
      .rcm;
}

/**
 * @brief Query tree results.
 */
ECM FileSystemCliAdapter::Tree(const std::string &path, int max_depth,
                               bool only_dir, bool show_all,
                               bool ignore_special_file, bool quiet,
                               amf interrupt_flag, int timeout_ms) const {
  return filesystem_service_
      .QueryTree(path, max_depth, only_dir, show_all, ignore_special_file,
                 quiet, interrupt_flag, timeout_ms)
      .rcm;
}

/**
 * @brief Query realpath result.
 */
ECM FileSystemCliAdapter::Realpath(const std::string &path, amf interrupt_flag,
                                   int timeout_ms) const {
  return filesystem_service_.QueryRealpath(path, interrupt_flag, timeout_ms).rcm;
}

/**
 * @brief Measure RTT for current client.
 */
ECM FileSystemCliAdapter::TestRtt(int times, amf interrupt_flag) const {
  return filesystem_service_.TestRtt(times, interrupt_flag);
}

/**
 * @brief Change current workdir.
 */
ECM FileSystemCliAdapter::Cd(const std::string &path, amf interrupt_flag,
                             bool from_history) const {
  return filesystem_service_.Cd(path, interrupt_flag, from_history);
}

/**
 * @brief Execute one shell command and return output + code.
 */
std::pair<ECM, std::pair<std::string, int>>
FileSystemCliAdapter::ShellRun(const std::string &cmd, int max_time_ms,
                               amf interrupt_flag) const {
  return filesystem_service_.ShellRun(cmd, max_time_ms, interrupt_flag);
}
} // namespace AMInterface::ApplicationAdapters
