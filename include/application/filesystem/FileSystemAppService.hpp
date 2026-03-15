#pragma once

#include "application/filesystem/FileSystemBackendPort.hpp"
#include "foundation/DataClass.hpp"
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace AMApplication::filesystem {
/**
 * @brief Application facade for filesystem command orchestration.
 *
 * This facade delegates filesystem runtime execution to a backend port.
 */
class FileSystemAppService {
public:
  using Backend = runtime::IFileSystemBackendPort;
  using RemoveRequest = AMDomain::filesystem::RemoveRequest;
  using RemoveResult = AMDomain::filesystem::RemoveResult;
  using StatPathsResult = AMDomain::filesystem::StatPathsResult;
  using ListPathResult = AMDomain::filesystem::ListPathResult;
  using GetSizeResult = AMDomain::filesystem::GetSizeResult;
  using FindResult = AMDomain::filesystem::FindResult;
  using WalkQueryResult = AMDomain::filesystem::WalkQueryResult;
  using TreeQueryResult = AMDomain::filesystem::TreeQueryResult;
  using RealpathQueryResult = AMDomain::filesystem::RealpathQueryResult;

  /**
   * @brief Construct from filesystem backend port.
   */
  explicit FileSystemAppService(std::shared_ptr<Backend> backend);

  /**
   * @brief Return true when backend is available.
   */
  [[nodiscard]] bool HasBackend() const;

  ECM CheckClients(const std::vector<std::string> &nicknames, bool detail,
                   amf interrupt_flag = nullptr) const;
  ECM ListClients(bool detail, amf interrupt_flag = nullptr) const;
  ECM DisconnectClients(const std::vector<std::string> &nicknames) const;
  /* {ori_code}
  ECM StatPaths(const std::vector<std::string> &paths,
                amf interrupt_flag = nullptr, int timeout_ms = -1) const;
  ECM ListPath(const std::string &path, bool list_like, bool show_all,
               amf interrupt_flag = nullptr, int timeout_ms = -1) const;
  ECM GetSize(const std::vector<std::string> &paths,
              amf interrupt_flag = nullptr, int timeout_ms = -1) const;
  ECM Find(const std::string &path, SearchType type = SearchType::All,
           amf interrupt_flag = nullptr, int timeout_ms = -1) const;
  */
  ECM Mkdir(const std::vector<std::string> &paths, amf interrupt_flag = nullptr,
            int timeout_ms = -1) const;
  /* {ori_code}
  ECM Remove(const std::vector<std::string> &paths, bool permanent, bool force,
             bool quiet = false, amf interrupt_flag = nullptr,
             int timeout_ms = -1) const;
  */
  /**
   * @brief Execute remove request using explicit confirmation policy.
   */
  RemoveResult ExecuteRemove(const RemoveRequest &request,
                             amf interrupt_flag = nullptr) const;
  /* {ori_code}
  ECM Walk(const std::string &path, bool only_file = false,
           bool only_dir = false, bool show_all = false,
           bool ignore_special_file = true, bool quiet = false,
           amf interrupt_flag = nullptr, int timeout_ms = -1) const;
  ECM Tree(const std::string &path, int max_depth = -1, bool only_dir = false,
           bool show_all = false, bool ignore_special_file = true,
           bool quiet = false, amf interrupt_flag = nullptr,
           int timeout_ms = -1) const;
  ECM Realpath(const std::string &path, amf interrupt_flag = nullptr,
               int timeout_ms = -1) const;
  */
  /**
   * @brief Query stat records with typed payload contract.
   */
  StatPathsResult QueryStatPaths(const std::vector<std::string> &paths,
                                 amf interrupt_flag = nullptr,
                                 int timeout_ms = -1) const;
  /**
   * @brief Query list payload with target metadata and children.
   */
  ListPathResult QueryListPath(const std::string &path, bool list_like,
                               bool show_all, amf interrupt_flag = nullptr,
                               int timeout_ms = -1) const;
  /**
   * @brief Query path sizes with typed payload contract.
   */
  GetSizeResult QueryGetSize(const std::vector<std::string> &paths,
                             amf interrupt_flag = nullptr,
                             int timeout_ms = -1) const;
  /**
   * @brief Query find records with typed payload contract.
   */
  FindResult QueryFind(const std::string &path,
                       SearchType type = SearchType::All,
                       amf interrupt_flag = nullptr, int timeout_ms = -1) const;
  /**
   * @brief Query walk records with typed payload contract.
   */
  WalkQueryResult QueryWalk(const std::string &path, bool only_file = false,
                            bool only_dir = false, bool show_all = false,
                            bool ignore_special_file = true, bool quiet = false,
                            amf interrupt_flag = nullptr,
                            int timeout_ms = -1) const;
  /**
   * @brief Query tree records with typed payload contract.
   */
  TreeQueryResult QueryTree(const std::string &path, int max_depth = -1,
                            bool only_dir = false, bool show_all = false,
                            bool ignore_special_file = true, bool quiet = false,
                            amf interrupt_flag = nullptr,
                            int timeout_ms = -1) const;
  /**
   * @brief Query one realpath record with typed payload contract.
   */
  RealpathQueryResult QueryRealpath(const std::string &path,
                                    amf interrupt_flag = nullptr,
                                    int timeout_ms = -1) const;
  ECM TestRtt(int times = 1, amf interrupt_flag = nullptr) const;
  ECM Cd(const std::string &path, amf interrupt_flag = nullptr,
         bool from_history = false) const;
  std::pair<ECM, std::pair<std::string, int>>
  ShellRun(const std::string &cmd, int max_time_ms = -1,
           amf interrupt_flag = nullptr) const;

private:
  [[nodiscard]] ECM EnsureBackend_() const;

  std::shared_ptr<Backend> backend_;
};
} // namespace AMApplication::filesystem
