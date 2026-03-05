#pragma once
#include "foundation/DataClass.hpp"
#include <string>
#include <utility>
#include <vector>

namespace AMDomain::filesystem {
/**
 * @brief Read-only filesystem query port.
 */
class IFileSystemQueryPort {
public:
  virtual ~IFileSystemQueryPort() = default;

  /**
   * @brief Query one path stat result.
   */
  virtual std::pair<ECM, PathInfo> Stat(const std::string &path,
                                        amf interrupt_flag = nullptr,
                                        int timeout_ms = -1) = 0;

  /**
   * @brief List entries under one directory path.
   */
  virtual std::pair<ECM, std::vector<PathInfo>>
  List(const std::string &path, bool show_all = false,
       amf interrupt_flag = nullptr, int timeout_ms = -1) = 0;

  /**
   * @brief Walk one path tree.
   */
  virtual std::pair<ECM, std::vector<PathInfo>>
  Walk(const std::string &path, bool only_file = false, bool only_dir = false,
       bool show_all = false, bool ignore_special_file = true,
       amf interrupt_flag = nullptr, int timeout_ms = -1) = 0;
};

/**
 * @brief Mutating filesystem operation port.
 */
class IFileSystemMutationPort {
public:
  virtual ~IFileSystemMutationPort() = default;

  /**
   * @brief Create directory recursively.
   */
  virtual ECM Mkdir(const std::string &path, amf interrupt_flag = nullptr,
                    int timeout_ms = -1) = 0;

  /**
   * @brief Remove one path.
   */
  virtual ECM Remove(const std::string &path, bool permanent = false,
                     bool force = false, amf interrupt_flag = nullptr,
                     int timeout_ms = -1) = 0;

  /**
   * @brief Move or rename path.
   */
  virtual ECM Move(const std::string &src, const std::string &dst,
                   bool mkdir = false, bool overwrite = false,
                   amf interrupt_flag = nullptr, int timeout_ms = -1) = 0;
};
} // namespace AMDomain::filesystem
