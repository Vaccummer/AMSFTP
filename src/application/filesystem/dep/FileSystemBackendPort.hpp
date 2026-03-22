#pragma once

#include "domain/filesystem/FileSystemModel.hpp"
#include "foundation/core/DataClass.hpp"
#include <memory>
#include <string>
#include <utility>

namespace AMDomain::client {
class IClientRuntimePort;
class IClientPathPort;
} // namespace AMDomain::client

namespace AMApplication::filesystem {
using amf = AMDomain::client::amf;
}

namespace AMApplication::filesystem::runtime {
/**
 * @brief Runtime backend port for filesystem command execution.
 */
class IFileSystemBackendPort {
public:
  using RemoveResult = AMDomain::filesystem::RemoveResult;
  using StatPathResult = AMDomain::filesystem::StatPathResult;
  using ListPathResult = AMDomain::filesystem::ListPathResult;
  using GetSizeEntryResult = AMDomain::filesystem::GetSizeEntryResult;
  using FindResult = AMDomain::filesystem::FindResult;
  using WalkQueryResult = AMDomain::filesystem::WalkQueryResult;
  using RealpathQueryResult = AMDomain::filesystem::RealpathQueryResult;
  using RttQueryResult = AMDomain::filesystem::RttQueryResult;

  /**
   * @brief Virtual destructor for polymorphic backend.
   */
  virtual ~IFileSystemBackendPort() = default;

  /**
   * @brief Query RTT for current client.
   */
  virtual RttQueryResult QueryRtt(int times = 1,
                                  amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Create directory for explicit client target.
   */
  virtual ECM MkdirForClient(const std::string &nickname,
                             const std::string &path,
                             amf interrupt_flag = nullptr,
                             int timeout_ms = -1) = 0;

  /**
   * @brief Remove one path for explicit client target.
   */
  virtual RemoveResult
  ExecuteRemoveForClient(const std::string &nickname, const std::string &path,
                         bool permanent, bool quiet = false,
                         amf interrupt_flag = nullptr, int timeout_ms = -1) = 0;

  /**
   * @brief Query stat for explicit client target.
   */
  virtual StatPathResult QueryStatPath(const std::string &nickname,
                                       const std::string &path,
                                       amf interrupt_flag = nullptr,
                                       int timeout_ms = -1) = 0;

  /**
   * @brief Query list payload for explicit client target.
   */
  virtual ListPathResult QueryListPathForClient(const std::string &nickname,
                                                const std::string &path,
                                                bool list_like, bool show_all,
                                                amf interrupt_flag = nullptr,
                                                int timeout_ms = -1) = 0;

  /**
   * @brief Query size for explicit client target.
   */
  virtual GetSizeEntryResult QueryGetSizeForClient(const std::string &nickname,
                                                   const std::string &path,
                                                   amf interrupt_flag = nullptr,
                                                   int timeout_ms = -1) = 0;

  /**
   * @brief Query find for explicit client target.
   */
  virtual FindResult QueryFindForClient(const std::string &nickname,
                                        const std::string &path,
                                        SearchType type = SearchType::All,
                                        amf interrupt_flag = nullptr,
                                        int timeout_ms = -1) = 0;

  /**
   * @brief Query walk for explicit client target.
   */
  virtual WalkQueryResult
  QueryWalkForClient(const std::string &nickname, const std::string &path,
                     bool only_file = false, bool only_dir = false,
                     bool show_all = false, bool ignore_special_file = true,
                     bool quiet = false, amf interrupt_flag = nullptr,
                     int timeout_ms = -1) = 0;

  /**
   * @brief Query realpath for explicit client target.
   */
  virtual RealpathQueryResult
  QueryRealpathForClient(const std::string &nickname, const std::string &path,
                         amf interrupt_flag = nullptr, int timeout_ms = -1) = 0;

  /**
   * @brief Change workdir for explicit client target.
   */
  virtual ECM CdForClient(const std::string &nickname, const std::string &path,
                          amf interrupt_flag = nullptr,
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
    AMDomain::client::IClientPathPort &path_port);
} // namespace AMApplication::filesystem::runtime
