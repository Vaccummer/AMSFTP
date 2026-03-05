#pragma once

#include "foundation/DataClass.hpp"
#include <string>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

namespace AMApplication::ClientPort {
using RemoveErrors = std::vector<std::pair<std::string, ECM>>;
using StatResult = std::pair<ECM, PathInfo>;
using ListResult = std::pair<ECM, std::vector<PathInfo>>;
using IWalkResult = std::pair<ECM, AMFS::WRI>;
using WalkResult = std::pair<ECM, std::pair<AMFS::WRD, AMFS::WER>>;
using ChmodResult = std::pair<ECM, std::unordered_map<std::string, ECM>>;
using CommandResult = std::pair<ECM, std::pair<std::string, int>>;

/**
 * @brief Application-level client capability port.
 *
 * Infrastructure client adapters implement this interface.
 */
class IClientPort {
public:
  /**
   * @brief Virtual destructor for polymorphic use.
   */
  virtual ~IClientPort() = default;

  /**
   * @brief Return runtime client UID.
   */
  virtual std::string GetUID() = 0;

  /**
   * @brief Return configured nickname.
   */
  [[nodiscard]] virtual const std::string &GetNickname() const = 0;

  /**
   * @brief Return request payload used to build this client.
   */
  [[nodiscard]] virtual const ConRequest &GetRequest() const = 0;

  /**
   * @brief Return protocol kind.
   */
  [[nodiscard]] virtual ClientProtocol GetProtocol() const = 0;

  /**
   * @brief Return metadata snapshot.
   */
  [[nodiscard]] virtual ClientMetaData GetClientMetaData() const = 0;

  /**
   * @brief Replace metadata snapshot.
   */
  virtual void SetClientMetaData(const ClientMetaData &metadata) = 0;

  /**
   * @brief Return current working directory.
   */
  [[nodiscard]] virtual std::string GetCwd() const = 0;

  /**
   * @brief Update current working directory.
   */
  virtual void SetCwd(const std::string &cwd) = 0;

  /**
   * @brief Return configured login directory.
   */
  [[nodiscard]] virtual std::string GetLoginDir() const = 0;

  /**
   * @brief Update configured login directory.
   */
  virtual void SetLoginDir(const std::string &login_dir) = 0;

  /**
   * @brief Validate connection health.
   */
  virtual ECM Check(amf interrupt_flag = nullptr, int timeout_ms = -1,
                    int64_t start_time = -1) = 0;

  /**
   * @brief Return cached state from last check/connect action.
   */
  [[nodiscard]] virtual ECM GetState() const = 0;

  /**
   * @brief Connect or reconnect this client.
   */
  virtual ECM Connect(bool force = false, amf interrupt_flag = nullptr,
                      int timeout_ms = -1, int64_t start_time = -1) = 0;

  /**
   * @brief Return remote/local OS type.
   */
  virtual OS_TYPE GetOSType(bool update = false) = 0;

  /**
   * @brief Measure round trip time when supported.
   */
  virtual double GetRTT(ssize_t times = 5, amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Execute command and return output + exit code when supported.
   */
  virtual CommandResult ConductCmd(const std::string &cmd,
                                   int max_time_ms = 3000,
                                   amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Return home directory.
   */
  virtual std::string GetHomeDir() = 0;

  /**
   * @brief Resolve path to real absolute path when supported.
   */
  virtual std::pair<ECM, std::string> realpath(const std::string &path,
                                               amf interrupt_flag = nullptr,
                                               int timeout_ms = -1,
                                               int64_t start_time = -1) = 0;

  /**
   * @brief Change mode for path(s) when supported.
   */
  virtual ChmodResult chmod(const std::string &path,
                            std::variant<std::string, size_t> mode,
                            bool recursive = false,
                            amf interrupt_flag = nullptr, int timeout_ms = -1,
                            int64_t start_time = -1) = 0;

  /**
   * @brief Query path metadata.
   */
  virtual StatResult stat(const std::string &path, bool trace_link = false,
                          amf interrupt_flag = nullptr, int timeout_ms = -1,
                          int64_t start_time = -1) = 0;

  /**
   * @brief List one directory.
   */
  virtual ListResult listdir(const std::string &path,
                             amf interrupt_flag = nullptr, int timeout_ms = -1,
                             int64_t start_time = -1) = 0;

  /**
   * @brief Compute recursive total size for a path.
   */
  virtual int64_t getsize(const std::string &path,
                          bool ignore_special_file = true,
                          amf interrupt_flag = nullptr, int timeout_ms = -1,
                          int64_t start_time = -1) = 0;

  /**
   * @brief Find entries by wildcard path pattern.
   */
  virtual std::vector<PathInfo> find(const std::string &path,
                                     SearchType type = SearchType::All,
                                     amf interrupt_flag = nullptr,
                                     int timeout_ms = -1,
                                     int64_t start_time = -1) = 0;

  /**
   * @brief Create one directory.
   */
  virtual ECM mkdir(const std::string &path, amf interrupt_flag = nullptr,
                    int timeout_ms = -1, int64_t start_time = -1) = 0;

  /**
   * @brief Create directory tree.
   */
  virtual ECM mkdirs(const std::string &path, amf interrupt_flag = nullptr,
                     int timeout_ms = -1, int64_t start_time = -1) = 0;

  /**
   * @brief Remove one directory.
   */
  virtual ECM rmdir(const std::string &path, amf interrupt_flag = nullptr,
                    int timeout_ms = -1, int64_t start_time = -1) = 0;

  /**
   * @brief Remove one file.
   */
  virtual ECM rmfile(const std::string &path, amf interrupt_flag = nullptr,
                     int timeout_ms = -1, int64_t start_time = -1) = 0;

  /**
   * @brief Rename or move one path.
   */
  virtual ECM rename(const std::string &src, const std::string &dst,
                     bool mkdir = true, bool overwrite = false,
                     amf interrupt_flag = nullptr, int timeout_ms = -1,
                     int64_t start_time = -1) = 0;

  /**
   * @brief Remove one path recursively.
   */
  virtual std::pair<ECM, RemoveErrors>
  remove(const std::string &path,
         AMFS::WalkErrorCallback error_callback = nullptr,
         amf interrupt_flag = nullptr, int timeout_ms = -1,
         int64_t start_time = -1) = 0;

  /**
   * @brief Safe-remove one path.
   */
  virtual ECM saferm(const std::string &path, amf interrupt_flag = nullptr,
                     int timeout_ms = -1, int64_t start_time = -1) = 0;

  /**
   * @brief Copy one path in-host when supported.
   */
  virtual ECM copy(const std::string &src, const std::string &dst,
                   bool need_mkdir = false, int timeout_ms = -1,
                   amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Walk and return flattened leaf-oriented view.
   */
  virtual IWalkResult iwalk(const std::string &path, bool show_all = false,
                            bool ignore_special_file = true,
                            AMFS::WalkErrorCallback error_callback = nullptr,
                            amf interrupt_flag = nullptr, int timeout_ms = -1,
                            int64_t start_time = -1) = 0;

  /**
   * @brief Walk and return tree-oriented view.
   */
  virtual WalkResult walk(const std::string &path, int max_depth = -1,
                          bool show_all = false,
                          bool ignore_special_file = false,
                          AMFS::WalkErrorCallback error_callback = nullptr,
                          amf interrupt_flag = nullptr, int timeout_ms = -1,
                          int64_t start_time = -1) = 0;
};
} // namespace AMApplication::ClientPort
