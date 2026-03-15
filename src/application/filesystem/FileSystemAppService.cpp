#include "application/filesystem/FileSystemAppService.hpp"
#include "foundation/tools/enum_related.hpp"

namespace AMApplication::filesystem {
/**
 * @brief Construct from filesystem backend port.
 */
FileSystemAppService::FileSystemAppService(std::shared_ptr<Backend> backend)
    : backend_(std::move(backend)) {}

/**
 * @brief Return true when backend is available.
 */
bool FileSystemAppService::HasBackend() const {
  return static_cast<bool>(backend_);
}

ECM FileSystemAppService::EnsureBackend_() const {
  if (!backend_) {
    return Err(EC::InvalidHandle, "filesystem backend is null");
  }
  return Ok();
}

ECM FileSystemAppService::CheckClients(const std::vector<std::string> &nicknames,
                                       bool detail, amf interrupt_flag) const {
  ECM rcm = EnsureBackend_();
  return isok(rcm) ? backend_->CheckClients(nicknames, detail, interrupt_flag)
                   : rcm;
}

ECM FileSystemAppService::ListClients(bool detail, amf interrupt_flag) const {
  ECM rcm = EnsureBackend_();
  return isok(rcm) ? backend_->ListClients(detail, interrupt_flag) : rcm;
}

ECM FileSystemAppService::DisconnectClients(
    const std::vector<std::string> &nicknames) const {
  ECM rcm = EnsureBackend_();
  return isok(rcm) ? backend_->DisconnectClients(nicknames) : rcm;
}

/* {ori_code}
ECM FileSystemAppService::StatPaths(const std::vector<std::string> &paths,
                                    amf interrupt_flag, int timeout_ms) const {
  ECM rcm = EnsureBackend_();
  return isok(rcm) ? backend_->StatPaths(paths, interrupt_flag, timeout_ms)
                   : rcm;
}

ECM FileSystemAppService::ListPath(const std::string &path, bool list_like,
                                   bool show_all, amf interrupt_flag,
                                   int timeout_ms) const {
  ECM rcm = EnsureBackend_();
  return isok(rcm)
             ? backend_->ListPath(path, list_like, show_all, interrupt_flag,
                                  timeout_ms)
             : rcm;
}

ECM FileSystemAppService::GetSize(const std::vector<std::string> &paths,
                                  amf interrupt_flag, int timeout_ms) const {
  ECM rcm = EnsureBackend_();
  return isok(rcm) ? backend_->GetSize(paths, interrupt_flag, timeout_ms)
                   : rcm;
}

ECM FileSystemAppService::Find(const std::string &path, SearchType type,
                               amf interrupt_flag, int timeout_ms) const {
  ECM rcm = EnsureBackend_();
  return isok(rcm) ? backend_->Find(path, type, interrupt_flag, timeout_ms)
                   : rcm;
}
*/
ECM FileSystemAppService::Mkdir(const std::vector<std::string> &paths,
                                amf interrupt_flag, int timeout_ms) const {
  ECM rcm = EnsureBackend_();
  return isok(rcm) ? backend_->Mkdir(paths, interrupt_flag, timeout_ms) : rcm;
}

/* {ori_code}
ECM FileSystemAppService::Remove(const std::vector<std::string> &paths,
                                 bool permanent, bool force, bool quiet,
                                 amf interrupt_flag, int timeout_ms) const {
  ECM rcm = EnsureBackend_();
  return isok(rcm)
             ? backend_->Remove(paths, permanent, force, quiet, interrupt_flag,
                                timeout_ms)
             : rcm;
}
*/
/**
 * @brief Execute remove request with explicit confirmation policy.
 */
FileSystemAppService::RemoveResult
FileSystemAppService::ExecuteRemove(const RemoveRequest &request,
                                    amf interrupt_flag) const {
  ECM rcm = EnsureBackend_();
  if (!isok(rcm)) {
    return {rcm, {}};
  }
  return backend_->ExecuteRemove(request, interrupt_flag);
}

ECM FileSystemAppService::Walk(const std::string &path, bool only_file,
                               bool only_dir, bool show_all,
                               bool ignore_special_file, bool quiet,
                               amf interrupt_flag, int timeout_ms) const {
  ECM rcm = EnsureBackend_();
  return isok(rcm)
             ? backend_->Walk(path, only_file, only_dir, show_all,
                              ignore_special_file, quiet, interrupt_flag,
                              timeout_ms)
             : rcm;
}

ECM FileSystemAppService::Tree(const std::string &path, int max_depth,
                               bool only_dir, bool show_all,
                               bool ignore_special_file, bool quiet,
                               amf interrupt_flag, int timeout_ms) const {
  ECM rcm = EnsureBackend_();
  return isok(rcm)
             ? backend_->Tree(path, max_depth, only_dir, show_all,
                              ignore_special_file, quiet, interrupt_flag,
                              timeout_ms)
             : rcm;
}

ECM FileSystemAppService::Realpath(const std::string &path, amf interrupt_flag,
                                   int timeout_ms) const {
  ECM rcm = EnsureBackend_();
  return isok(rcm) ? backend_->Realpath(path, interrupt_flag, timeout_ms) : rcm;
}
*/

/**
 * @brief Query stat records with typed payload contract.
 */
FileSystemAppService::StatPathsResult
FileSystemAppService::QueryStatPaths(const std::vector<std::string> &paths,
                                     amf interrupt_flag, int timeout_ms) const {
  ECM rcm = EnsureBackend_();
  if (!isok(rcm)) {
    return {rcm, {}};
  }
  return backend_->QueryStatPaths(paths, interrupt_flag, timeout_ms);
}

/**
 * @brief Query list payload with target metadata and children.
 */
FileSystemAppService::ListPathResult
FileSystemAppService::QueryListPath(const std::string &path, bool list_like,
                                    bool show_all, amf interrupt_flag,
                                    int timeout_ms) const {
  ECM rcm = EnsureBackend_();
  if (!isok(rcm)) {
    return {rcm, {}};
  }
  return backend_->QueryListPath(path, list_like, show_all, interrupt_flag,
                                 timeout_ms);
}

/**
 * @brief Query path sizes with typed payload contract.
 */
FileSystemAppService::GetSizeResult
FileSystemAppService::QueryGetSize(const std::vector<std::string> &paths,
                                   amf interrupt_flag, int timeout_ms) const {
  ECM rcm = EnsureBackend_();
  if (!isok(rcm)) {
    return {rcm, {}};
  }
  return backend_->QueryGetSize(paths, interrupt_flag, timeout_ms);
}

/**
 * @brief Query find records with typed payload contract.
 */
FileSystemAppService::FindResult
FileSystemAppService::QueryFind(const std::string &path, SearchType type,
                                amf interrupt_flag, int timeout_ms) const {
  ECM rcm = EnsureBackend_();
  if (!isok(rcm)) {
    return {rcm, {}};
  }
  return backend_->QueryFind(path, type, interrupt_flag, timeout_ms);
}

/**
 * @brief Query walk records with typed payload contract.
 */
FileSystemAppService::WalkQueryResult
FileSystemAppService::QueryWalk(const std::string &path, bool only_file,
                                bool only_dir, bool show_all,
                                bool ignore_special_file, bool quiet,
                                amf interrupt_flag, int timeout_ms) const {
  ECM rcm = EnsureBackend_();
  if (!isok(rcm)) {
    return {rcm, {}};
  }
  return backend_->QueryWalk(path, only_file, only_dir, show_all,
                             ignore_special_file, quiet, interrupt_flag,
                             timeout_ms);
}

/**
 * @brief Query tree records with typed payload contract.
 */
FileSystemAppService::TreeQueryResult
FileSystemAppService::QueryTree(const std::string &path, int max_depth,
                                bool only_dir, bool show_all,
                                bool ignore_special_file, bool quiet,
                                amf interrupt_flag, int timeout_ms) const {
  ECM rcm = EnsureBackend_();
  if (!isok(rcm)) {
    return {rcm, {}};
  }
  return backend_->QueryTree(path, max_depth, only_dir, show_all,
                             ignore_special_file, quiet, interrupt_flag,
                             timeout_ms);
}

/**
 * @brief Query one realpath record with typed payload contract.
 */
FileSystemAppService::RealpathQueryResult
FileSystemAppService::QueryRealpath(const std::string &path,
                                    amf interrupt_flag, int timeout_ms) const {
  ECM rcm = EnsureBackend_();
  if (!isok(rcm)) {
    return {rcm, {}};
  }
  return backend_->QueryRealpath(path, interrupt_flag, timeout_ms);
}

ECM FileSystemAppService::TestRtt(int times, amf interrupt_flag) const {
  ECM rcm = EnsureBackend_();
  return isok(rcm) ? backend_->TestRtt(times, interrupt_flag) : rcm;
}

ECM FileSystemAppService::Cd(const std::string &path, amf interrupt_flag,
                             bool from_history) const {
  ECM rcm = EnsureBackend_();
  return isok(rcm) ? backend_->Cd(path, interrupt_flag, from_history) : rcm;
}

std::pair<ECM, std::pair<std::string, int>>
FileSystemAppService::ShellRun(const std::string &cmd, int max_time_ms,
                               amf interrupt_flag) const {
  ECM rcm = EnsureBackend_();
  if (!isok(rcm)) {
    return {rcm, {"", -1}};
  }
  return backend_->ShellRun(cmd, max_time_ms, interrupt_flag);
}
} // namespace AMApplication::filesystem
