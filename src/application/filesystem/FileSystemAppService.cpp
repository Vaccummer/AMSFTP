#include "application/filesystem/FileSystemAppService.hpp"

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

/* {ori_code}
ECM FileSystemAppService::CheckClients(const std::vector<std::string> &nicknames,
                                       bool detail, amf interrupt_flag) const;
ECM FileSystemAppService::ListClients(bool detail, amf interrupt_flag) const;
ECM FileSystemAppService::DisconnectClients(
    const std::vector<std::string> &nicknames) const;
StatPathsResult FileSystemAppService::QueryStatPaths(
    const std::vector<std::string> &paths, amf interrupt_flag, int timeout_ms) const;
GetSizeResult FileSystemAppService::QueryGetSize(
    const std::vector<std::string> &paths, amf interrupt_flag, int timeout_ms) const;
TreeQueryResult FileSystemAppService::QueryTree(
    const std::string &path, int max_depth, bool only_dir, bool show_all,
    bool ignore_special_file, bool quiet, amf interrupt_flag, int timeout_ms) const;
ECM FileSystemAppService::TestRtt(int times, amf interrupt_flag) const;
ECM FileSystemAppService::Mkdir(const std::string &nickname,
                                const std::string &path, amf interrupt_flag,
                                int timeout_ms) const;
FileSystemAppService::RemoveResult
FileSystemAppService::ExecuteRemove(const std::string &nickname,
                                    const std::string &path, bool permanent,
                                    bool quiet, amf interrupt_flag,
                                    int timeout_ms) const;
FileSystemAppService::StatPathResult
FileSystemAppService::QueryStatPath(const std::string &nickname,
                                    const std::string &path,
                                    amf interrupt_flag, int timeout_ms) const;
FileSystemAppService::ListPathResult
FileSystemAppService::QueryListPath(const std::string &nickname,
                                    const std::string &path, bool list_like,
                                    bool show_all, amf interrupt_flag,
                                    int timeout_ms) const;
FileSystemAppService::GetSizeEntryResult
FileSystemAppService::QueryGetSize(const std::string &nickname,
                                   const std::string &path, amf interrupt_flag,
                                   int timeout_ms) const;
FileSystemAppService::FindResult
FileSystemAppService::QueryFind(const std::string &nickname,
                                const std::string &path, SearchType type,
                                amf interrupt_flag, int timeout_ms) const;
FileSystemAppService::WalkQueryResult
FileSystemAppService::QueryWalk(const std::string &nickname,
                                const std::string &path, bool only_file,
                                bool only_dir, bool show_all,
                                bool ignore_special_file, bool quiet,
                                amf interrupt_flag, int timeout_ms) const;
FileSystemAppService::RealpathQueryResult
FileSystemAppService::QueryRealpath(const std::string &nickname,
                                    const std::string &path,
                                    amf interrupt_flag, int timeout_ms) const;
FileSystemAppService::RttQueryResult
FileSystemAppService::QueryRtt(int times, amf interrupt_flag) const;
ECM FileSystemAppService::Cd(const std::string &nickname,
                             const std::string &path, amf interrupt_flag,
                             bool from_history) const;
std::pair<ECM, std::pair<std::string, int>>
FileSystemAppService::ShellRun(const std::string &cmd, int max_time_ms,
                               amf interrupt_flag) const;
*/

/**
 * @brief Return bound filesystem backend for interface orchestration.
 */
std::shared_ptr<FileSystemAppService::Backend>
FileSystemAppService::BackendPort() const {
  return backend_;
}
} // namespace AMApplication::filesystem


