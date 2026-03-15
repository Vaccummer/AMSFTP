#pragma once

#include "domain/filesystem/FileSystemModel.hpp"
#include "foundation/DataClass.hpp"
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace AMDomain::client {
class IClientRuntimePort;
class IClientLifecyclePort;
class IClientPathPort;
}

namespace AMApplication::filesystem::runtime {
/**
 * @brief Runtime backend port for filesystem command execution.
 */
class IFileSystemBackendPort {
public:
  using ConfirmPolicy = AMDomain::filesystem::ConfirmPolicy;
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
   * @brief Virtual destructor for polymorphic backend.
   */
  virtual ~IFileSystemBackendPort() = default;

  /**
   * @brief Check clients by nickname list.
   */
  virtual ECM CheckClients(const std::vector<std::string> &nicknames,
                           bool detail, amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Print current clients.
   */
  virtual ECM ListClients(bool detail, amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Disconnect clients by nickname list.
   */
  virtual ECM DisconnectClients(const std::vector<std::string> &nicknames) = 0;

  /**
   * @brief Print stat for one or more paths.
   */
  virtual ECM StatPaths(const std::vector<std::string> &paths,
                        amf interrupt_flag = nullptr, int timeout_ms = -1) = 0;

  /**
   * @brief List one path.
   */
  virtual ECM ListPath(const std::string &path, bool list_like, bool show_all,
                       amf interrupt_flag = nullptr,
                       int timeout_ms = -1) = 0;

  /**
   * @brief Print size for one or more paths.
   */
  virtual ECM GetSize(const std::vector<std::string> &paths,
                      amf interrupt_flag = nullptr, int timeout_ms = -1) = 0;

  /**
   * @brief Run find on one path.
   */
  virtual ECM Find(const std::string &path, SearchType type = SearchType::All,
                   amf interrupt_flag = nullptr, int timeout_ms = -1) = 0;

  /**
   * @brief Create directories for one or more paths.
   */
  virtual ECM Mkdir(const std::vector<std::string> &paths,
                    amf interrupt_flag = nullptr, int timeout_ms = -1) = 0;

  /**
   * @brief Remove one or more paths.
   */
  virtual ECM Remove(const std::vector<std::string> &paths, bool permanent,
                     bool force, bool quiet = false,
                     amf interrupt_flag = nullptr, int timeout_ms = -1) = 0;

  /**
   * @brief Remove request with explicit confirmation policy contract.
   */
  virtual RemoveResult
  ExecuteRemove(const RemoveRequest &request,
                amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Walk one path.
   */
  virtual ECM Walk(const std::string &path, bool only_file = false,
                   bool only_dir = false, bool show_all = false,
                   bool ignore_special_file = true, bool quiet = false,
                   amf interrupt_flag = nullptr, int timeout_ms = -1) = 0;

  /**
   * @brief Print one path tree.
   */
  virtual ECM Tree(const std::string &path, int max_depth = -1,
                   bool only_dir = false, bool show_all = false,
                   bool ignore_special_file = true, bool quiet = false,
                   amf interrupt_flag = nullptr, int timeout_ms = -1) = 0;

  /**
   * @brief Resolve one real path.
   */
  virtual ECM Realpath(const std::string &path, amf interrupt_flag = nullptr,
                       int timeout_ms = -1) = 0;

  /**
   * @brief Query stat records using typed result contract.
   */
  virtual StatPathsResult
  QueryStatPaths(const std::vector<std::string> &paths,
                 amf interrupt_flag = nullptr, int timeout_ms = -1) = 0;

  /**
   * @brief Query list payload using typed result contract.
   */
  virtual ListPathResult
  QueryListPath(const std::string &path, bool list_like, bool show_all,
                amf interrupt_flag = nullptr, int timeout_ms = -1) = 0;

  /**
   * @brief Query path sizes using typed result contract.
   */
  virtual GetSizeResult
  QueryGetSize(const std::vector<std::string> &paths,
               amf interrupt_flag = nullptr, int timeout_ms = -1) = 0;

  /**
   * @brief Query find records using typed result contract.
   */
  virtual FindResult QueryFind(const std::string &path,
                               SearchType type = SearchType::All,
                               amf interrupt_flag = nullptr,
                               int timeout_ms = -1) = 0;

  /**
   * @brief Query walk records using typed result contract.
   */
  virtual WalkQueryResult
  QueryWalk(const std::string &path, bool only_file = false,
            bool only_dir = false, bool show_all = false,
            bool ignore_special_file = true, bool quiet = false,
            amf interrupt_flag = nullptr, int timeout_ms = -1) = 0;

  /**
   * @brief Query tree records using typed result contract.
   */
  virtual TreeQueryResult
  QueryTree(const std::string &path, int max_depth = -1,
            bool only_dir = false, bool show_all = false,
            bool ignore_special_file = true, bool quiet = false,
            amf interrupt_flag = nullptr, int timeout_ms = -1) = 0;

  /**
   * @brief Query realpath using typed result contract.
   */
  virtual RealpathQueryResult
  QueryRealpath(const std::string &path, amf interrupt_flag = nullptr,
                int timeout_ms = -1) = 0;

  /**
   * @brief Measure RTT for current client.
   */
  virtual ECM TestRtt(int times = 1, amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Change current workdir.
   */
  virtual ECM Cd(const std::string &path, amf interrupt_flag = nullptr,
                 bool from_history = false) = 0;

  /**
   * @brief Run one shell command.
   */
  virtual std::pair<ECM, std::pair<std::string, int>>
  ShellRun(const std::string &cmd, int max_time_ms = -1,
           amf interrupt_flag = nullptr) = 0;

};

/**
 * @brief Create default filesystem backend for application wiring.
 */
std::shared_ptr<IFileSystemBackendPort> CreateDefaultFileSystemBackend(
    AMDomain::client::IClientRuntimePort &runtime_port,
    AMDomain::client::IClientLifecyclePort &lifecycle_port,
    AMDomain::client::IClientPathPort &path_port);
} // namespace AMApplication::filesystem::runtime
