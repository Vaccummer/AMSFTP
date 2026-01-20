#pragma once
// 标准库
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <ctime>
#include <fcntl.h>
#include <filesystem>
#include <memory>
#include <pybind11/pytypes.h>
#include <string>
#include <vector>

// 标准库

// 自身依赖
#include "AMBaseClient.hpp"
#include "AMDataClass.hpp"
#include "AMEnum.hpp"
#include "AMPath.hpp"
// 自身依赖

// 第三方库
#include <curl/curl.h>
#include <fmt/core.h>
#include <libssh2.h>
#include <libssh2_sftp.h>
#include <magic_enum/magic_enum.hpp>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <pybind11/functional.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

// 第三方库

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#define SOCKET int
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define closesocket close
#endif

// Wait result for non-blocking socket operations
class AMLocalClient : public BaseClient {
public:
  AMLocalClient(ConRequst request, size_t buffer_capacity = 10,
                const py::object &trace_cb = py::none())
      : BaseClient(request, buffer_capacity, trace_cb) {
    this->PROTOCOL = ClientProtocol::LOCAL;
  }

  ECM Check(amf interrupt_flag = nullptr, int timeout_ms = -1,
            std::chrono::steady_clock::time_point start_time =
                std::chrono::steady_clock::now()) override {
    return {EC::Success, ""};
  }

  ECM Connect(bool force = false, amf interrupt_flag = nullptr,
              int timeout_ms = -1,
              std::chrono::steady_clock::time_point start_time =
                  std::chrono::steady_clock::now()) override {
    return {EC::Success, ""};
  }

  OS_TYPE GetOSType(bool update = false) override {
    if (!update && this->os_type != OS_TYPE::Uncertain) {
      return this->os_type;
    }

#ifdef _WIN32
    this->os_type = OS_TYPE::Windows;
#elif defined(_WIN64)
    this->os_type = OS_TYPE::Windows;
#elif defined(__linux__) || defined(__gnu_linux__)
    this->os_type = OS_TYPE::Linux;
#elif defined(__APPLE__) && defined(__MACH__)
    this->os_type = OS_TYPE::MacOS;
#elif defined(__FreeBSD__)
    this->os_type = OS_TYPE::FreeBSD;
#else
    this->os_type = OS_TYPE::Unknown;
#endif
    return this->os_type;
  }

  std::string GetHomeDir() override {
    if (!this->home_dir.empty()) {
      return this->home_dir;
    }
    this->home_dir = AMFS::HomePath();
    return this->home_dir;
  }

  SR stat(const std::string &path, bool trace_link = false,
          amf interrupt_flag = nullptr, int timeout_ms = -1,
          std::chrono::steady_clock::time_point start_time =
              std::chrono::steady_clock::now()) override {
    if (path.empty()) {
      return {ECM{EC::InvalidArg, "Invalid empty path"}, PathInfo()};
    }
    PathInfo info;
    std::string pathf = path;
    fs::path p(pathf);
    info.name = p.filename().string();
    info.path = pathf;
    info.dir = p.parent_path().string();
    fs::file_status status;
    std::error_code ec;
    if (trace_link) {
      status = fs::status(p, ec);
    } else {
      status = fs::symlink_status(p, ec);
    }
    if (ec) {
      auto rcm =
          ECM{fec(ec), fmt::format("Stat {} failed: {}", pathf, ec.message())};
      trace(TraceLevel::Debug, rcm.first, pathf, "stat", rcm.second);
      return {rcm, info};
    }
    info.type = cast_fs_type(status.type());

    auto size_f = fs::file_size(p, ec);
    if (!ec) {
      info.size = size_f;
    }

#ifdef _WIN32
    if (AMFS::is_readonly(AMStr::wstr(pathf))) {
      info.mode_int = 0333;
      info.mode_str = "r-xr-xr-x";
    } else {
      info.mode_int = 0666;
      info.mode_str = "rwxrwxrwx";
    }

    auto [create_time, access_time, modify_time] =
        AMFS::GetTime(AMStr::wstr(path));
    info.create_time = create_time;
    info.access_time = access_time;
    info.modify_time = modify_time;
    info.owner = AMFS::GetFileOwner(AMStr::wstr(path));
#else
    struct stat file_stat;
    // 调用 stat 获取文件元数据（支持符号链接，若需跟随链接用 stat 而非
    // lstat）
    if (stat(path.c_str(), &file_stat) == -1) {
      return std::make_pair(
          "Fail to stat file: " + std::string(strerror(errno)), info);
    }

    // 1. 拥有者和组（通过 UID/GID 转换）
    struct passwd *pw = getpwuid(file_stat.st_uid); // UID -> 用户名
    info.owner = pw ? pw->pw_name : std::to_string(file_stat.st_uid);

    // 2. 八进制权限（0777格式）
    info.mode_int = file_stat.st_mode & 0777;
    info.mode_str = ModeTrans(info.mode_int);

    // 3. 访问时间（access time）和修改时间（modify time）
    // 使用 struct timespec 成员（包含秒和纳秒，POSIX 标准）
    info.access_time =
        timespec_to_double(file_stat.st_atim); // st_atim 是 timespec 类型
    info.modify_time =
        timespec_to_double(file_stat.st_mtim); // st_mtim 是 timespec 类型
#endif
#ifdef __APPLE__
    info.create_time = timespec_to_double(file_stat.st_birthtimespec);
#endif
    return {{EC::Success, ""}, info};
  }

  std::pair<ECM, PathType>
  get_path_type(const std::string &path, amf interrupt_flag = nullptr,
                int timeout_ms = -1,
                std::chrono::steady_clock::time_point start_time =
                    std::chrono::steady_clock::now()) override {
    if (path.empty()) {
      return {ECM{EC::InvalidArg, "Invalid empty path"}, PathType::Unknown};
    }
    std::string pathf = path;
    fs::path p(pathf);
    fs::file_status status;
    std::error_code ec;
    status = fs::status(p, ec);
    if (ec) {
      return {ECM{fec(ec), fmt::format("Get path type {} failed: {}", pathf,
                                       ec.message())},
              PathType::Unknown};
    }
    return {ECM{EC::Success, ""}, cast_fs_type(status.type())};
  }

  std::pair<ECM, bool> exists(const std::string &path,
                              amf interrupt_flag = nullptr, int timeout_ms = -1,
                              std::chrono::steady_clock::time_point start_time =
                                  std::chrono::steady_clock::now()) override {
    if (path.empty()) {
      return {ECM{EC::InvalidArg, "Invalid empty path"}, false};
    }
    return {ECM{EC::Success, ""}, fs::exists(fs::path(path))};
  }
  std::pair<ECM, bool>
  is_regular(const std::string &path, amf interrupt_flag = nullptr,
             int timeout_ms = -1,
             std::chrono::steady_clock::time_point start_time =
                 std::chrono::steady_clock::now()) override {
    if (path.empty()) {
      return {ECM{EC::InvalidArg, "Invalid empty path"}, false};
    }
    return {ECM{EC::Success, ""}, fs::is_regular_file(fs::path(path))};
  }
  std::pair<ECM, bool> is_dir(const std::string &path,
                              amf interrupt_flag = nullptr, int timeout_ms = -1,
                              std::chrono::steady_clock::time_point start_time =
                                  std::chrono::steady_clock::now()) override {
    if (path.empty()) {
      return {ECM{EC::InvalidArg, "Invalid empty path"}, false};
    }
    return {ECM{EC::Success, ""}, fs::is_directory(fs::path(path))};
  }

  std::pair<ECM, bool>
  is_symlink(const std::string &path, amf interrupt_flag = nullptr,
             int timeout_ms = -1,
             std::chrono::steady_clock::time_point start_time =
                 std::chrono::steady_clock::now()) override {
    if (path.empty()) {
      return {ECM{EC::InvalidArg, "Invalid empty path"}, false};
    }
    return {ECM{EC::Success, ""}, fs::is_symlink(fs::path(path))};
  }

  std::pair<ECM, std::vector<PathInfo>>
  listdir(const std::string &path, amf interrupt_flag = nullptr,
          int timeout_ms = -1,
          std::chrono::steady_clock::time_point start_time =
              std::chrono::steady_clock::now()) override {
    std::string pathf = path;
    std::vector<PathInfo> result = {};
    fs::path p(pathf);
    if (!fs::exists(p)) {
      auto rcm =
          ECM{EC::PathNotExist, fmt::format("Path not found: {}", pathf)};
      trace(TraceLevel::Debug, EC::PathNotExist, pathf, "listdir", rcm.second);
      return {rcm, result};
    }
    if (!fs::is_directory(p)) {
      auto rcm = ECM{EC::NotADirectory,
                     fmt::format("Path is not a directory: {}", pathf)};
      trace(TraceLevel::Debug, EC::NotADirectory, pathf, "listdir", rcm.second);
      return {rcm, result};
    }
    std::variant<PathInfo, std::pair<std::string, std::exception>> sr;
    std::vector<std::string> dir_paths = {};
    std::error_code ec;
    auto dir_iter = fs::directory_iterator(p, ec);
    if (ec) {
      return {ECM{fec(ec),
                  fmt::format("Listdir {} failed: {}", pathf, ec.message())},
              result};
    }
    for (const auto &entry : dir_iter) {
      if (interrupt_flag && interrupt_flag->check()) {
        return {ECM{EC::Terminate, "Listdir interrupted by user"}, result};
      }
      if (timeout_ms > 0 && std::chrono::steady_clock::now() - start_time >
                                std::chrono::milliseconds(timeout_ms)) {
        return {ECM{EC::OperationTimeout, "Listdir timeout"}, result};
      }
      auto [error, info] = stat(entry.path().string(), false);
      if (error.first != EC::Success) {
        continue;
      }
      result.push_back(info);
    }
    return {ECM{EC::Success, ""}, result};
  }

  inline void _iwalk(const std::string &path, std::vector<PathInfo> &result,
                     bool ignore_sepcial_file, amf interrupt_flag = nullptr,
                     int timeout_ms = -1,
                     std::chrono::steady_clock::time_point start_time =
                         std::chrono::steady_clock::now()) {
    std::error_code ec;
    auto iter = fs::directory_iterator(path, ec);
    if (ec) {
      return;
    }
    bool end_dir = true;
    PathType type = PathType::Unknown;
    for (const auto &entry : iter) {
      if (interrupt_flag && interrupt_flag->check()) {
        return;
      }
      if (timeout_ms > 0 && std::chrono::steady_clock::now() - start_time >
                                std::chrono::milliseconds(timeout_ms)) {
        return;
      }
      type = cast_fs_type(entry.status().type());
      if (type == PathType::DIR) {
        end_dir = false;
        _iwalk(entry.path().string(), result, ignore_sepcial_file,
               interrupt_flag, timeout_ms, start_time);
      }
      if (ignore_sepcial_file && type != PathType::FILE) {
        continue;
      }
      auto [error, info] = stat(entry.path().string(), false);
      if (error.first != EC::Success) {
        continue;
      }
      result.push_back(info);
    }
    if (end_dir) {
      auto [error2, info2] = stat(path, false);
      if (error2.first != EC::Success) {
        return;
      }
      result.push_back(info2);
    }
  }

  inline std::pair<ECM, std::vector<PathInfo>>
  iwalk(const std::string &path, bool ignore_sepcial_file = true,
        amf interrupt_flag = nullptr, int timeout_ms = -1,
        std::chrono::steady_clock::time_point start_time =
            std::chrono::steady_clock::now()) override {
    std::vector<PathInfo> result = {};
    auto [error, info] = stat(path);
    if (error.first != EC::Success) {
      return {error, result};
    }
    if (info.type != PathType::DIR) {
      trace(TraceLevel::Debug, EC::NotADirectory, path, "iwalk",
            fmt::format("Path is not a directory: {}", path));
      return {ECM{EC::NotADirectory,
                  fmt::format("Path is not a directory: {}", path)},
              result};
    }
    _iwalk(path, result, ignore_sepcial_file, interrupt_flag, timeout_ms,
           start_time);
    return {ECM{EC::Success, ""}, result};
  }

  inline void _walk(std::vector<std::string> parts, WRD &result, int cur_depth,
                    int max_depth, bool ignore_sepcial_file = true,
                    amf interrupt_flag = nullptr, int timeout_ms = -1,
                    std::chrono::steady_clock::time_point start_time =
                        std::chrono::steady_clock::now()) {
    if (max_depth > 0 && cur_depth > max_depth) {
      return;
    }
    std::string pathf = AMPathStr::join(parts);
    std::vector<PathInfo> files_info = {};
    bool empty_dir = true;
    auto [error, info] = listdir(pathf, interrupt_flag, timeout_ms, start_time);
    if (error.first != EC::Success) {
      return;
    }
    for (const auto &entry : info) {
      empty_dir = false;
      if (entry.type == PathType::DIR) {
        auto n_parts = parts;
        n_parts.push_back(entry.name);
        _walk(n_parts, result, cur_depth + 1, max_depth, ignore_sepcial_file);
      } else if (static_cast<int>(entry.type) < 0 && ignore_sepcial_file) {
        continue;
      } else {
        files_info.push_back(entry);
      }
    }
    if (!empty_dir && files_info.empty()) {
      return;
    }
    result.push_back(std::make_pair(parts, files_info));
  }

  inline std::pair<ECM, WRD>
  walk(const std::string &path, int max_depth, bool ignore_sepcial_file = true,
       amf interrupt_flag = nullptr, int timeout_ms = -1,
       std::chrono::steady_clock::time_point start_time =
           std::chrono::steady_clock::now()) override {
    WRD result = {};
    auto [error, info] = stat(path);
    if (error.first != EC::Success) {
      return {error, result};
    } else if (info.type != PathType::DIR) {
      trace(TraceLevel::Debug, EC::NotADirectory, path, "walk",
            fmt::format("Path is not a directory: {}", path));
      return {ECM{EC::NotADirectory,
                  fmt::format("Path is not a directory: {}", path)},
              result};
    }

    _walk({path}, result, 0, max_depth, ignore_sepcial_file, interrupt_flag,
          timeout_ms, start_time);

    return {{EC::Success, ""}, result};
  }
  ECM mkdir(const std::string &path, amf interrupt_flag = nullptr,
            int timeout_ms = -1,
            std::chrono::steady_clock::time_point start_time =
                std::chrono::steady_clock::now()) override {
    if (path.empty()) {
      return ECM{EC::InvalidArg, "Invalid empty path"};
    }
    std::error_code ec;
    fs::create_directory(fs::path(path), ec);
    if (ec) {
      ECM rcm =
          ECM{fec(ec), fmt::format("mkdir {} failed: {}", path, ec.message())};
      trace(TraceLevel::Debug, rcm.first, path, "mkdir", rcm.second);
      return rcm;
    }
    return ECM{EC::Success, ""};
  }

  ECM mkdirs(const std::string &path, amf interrupt_flag = nullptr,
             int timeout_ms = -1,
             std::chrono::steady_clock::time_point start_time =
                 std::chrono::steady_clock::now()) override {
    if (path.empty()) {
      return ECM{EC::InvalidArg, "Invalid empty path"};
    }
    std::error_code ec;
    fs::create_directories(fs::path(path), ec);
    if (ec) {
      ECM rcm =
          ECM{fec(ec), fmt::format("mkdirs {} failed: {}", path, ec.message())};
      trace(TraceLevel::Debug, rcm.first, path, "mkdir", rcm.second);
      return rcm;
    }
    return ECM{EC::Success, ""};
  }

  ECM rename(const std::string &src, const std::string &dst, bool mkdir = true,
             bool overwrite = false, amf interrupt_flag = nullptr,
             int timeout_ms = -1,
             std::chrono::steady_clock::time_point start_time =
                 std::chrono::steady_clock::now()) override {
    if (src.empty() || dst.empty()) {
      return ECM{EC::InvalidArg, "Invalid empty path"};
    }
    std::error_code ec;
    auto [error, info] = stat(src);
    auto [error1, info1] = stat(dst);
    if (error.first != EC::Success) {
      return ECM{error.first, fmt::format("src {} not exist", src)};
    } else if (error1.first == EC::Success) {
      if ((info.type == PathType::DIR && info1.type != PathType::DIR) ||
          (info.type != PathType::DIR && info1.type == PathType::DIR)) {
        return ECM{EC::NotADirectory, "src and dst are not the same type"};
      } else if (!overwrite) {
        return ECM{EC::PathAlreadyExists,
                   fmt::format("dst {} already exists", dst)};
      }
    }

    if (mkdir) {
      mkdirs(AMPathStr::dirname(dst));
    }

    fs::rename(fs::path(src), fs::path(dst), ec);
    if (ec == std::errc::cross_device_link) {
      // 跨文件系统：复制 + 删除
      ec.clear();
      if (fs::is_directory(src, ec)) {
        fs::copy(src, dst,
                 fs::copy_options::recursive |
                     fs::copy_options::overwrite_existing,
                 ec);
        if (!ec) {
          fs::remove_all(src, ec);
        }
      } else {
        fs::copy_file(src, dst, fs::copy_options::overwrite_existing, ec);
        if (!ec) {
          fs::remove(src, ec);
        }
      }
    }
    if (ec) {
      return ECM{fec(ec), fmt::format("rename {} to {} failed: {}", src, dst,
                                      ec.message())};
    }
    return ECM{EC::Success, ""};
  }

  ECM rmdir(const std::string &path, amf interrupt_flag = nullptr,
            int timeout_ms = -1,
            std::chrono::steady_clock::time_point start_time =
                std::chrono::steady_clock::now()) override {
    if (path.empty()) {
      return ECM{EC::InvalidArg, "Invalid empty path"};
    }
    auto [error, info] = stat(path);
    if (error.first != EC::Success) {
      return error;
    }
    if (info.type != PathType::DIR) {
      return ECM{EC::NotADirectory, "Path is not a directory"};
    }
    std::error_code ec;
    fs::remove(fs::path(path), ec);
    if (ec) {
      return ECM{fec(ec),
                 fmt::format("rmdir {} failed: {}", path, ec.message())};
    }
    return ECM{EC::Success, ""};
  }

  ECM rmfile(const std::string &path, amf interrupt_flag = nullptr,
             int timeout_ms = -1,
             std::chrono::steady_clock::time_point start_time =
                 std::chrono::steady_clock::now()) override {
    if (path.empty()) {
      return ECM{EC::InvalidArg, "Invalid empty path"};
    }
    auto [error, info] = stat(path);
    if (error.first != EC::Success) {
      return error;
    }
    if (info.type == PathType::DIR) {
      return ECM{EC::NotAFile, "Path is a directory"};
    }
    std::error_code ec;
    fs::remove(fs::path(path), ec);
    if (ec) {
      return ECM{fec(ec),
                 fmt::format("rmdir {} failed: {}", path, ec.message())};
    }
    return ECM{EC::Success, ""};
  }

  void _remove(const std::string &path, RMR &errors,
               amf interrupt_flag = nullptr, int timeout_ms = -1,
               std::chrono::steady_clock::time_point start_time =
                   std::chrono::steady_clock::now()) {
    std::error_code ec;
    auto [error, listing] =
        listdir(path, interrupt_flag, timeout_ms, start_time);
    if (error.first != EC::Success) {
      errors.emplace_back(path, error);
      return;
    }
    for (const auto &entry : listing) {
      if (entry.type == PathType::DIR) {
        _remove(entry.path, errors, interrupt_flag, timeout_ms, start_time);
      } else {
        fs::remove(entry.path, ec);
        if (ec) {
          errors.emplace_back(
              entry.path, ECM{fec(ec), fmt::format("remove {} failed: {}",
                                                   entry.path, ec.message())});
        }
      }
    }
    fs::remove(fs::path(path), ec);
    if (ec) {
      errors.emplace_back(path, ECM{fec(ec), fmt::format("remove {} failed: {}",
                                                         path, ec.message())});
    }
  }
  std::pair<ECM, RMR> remove(const std::string &path,
                             amf interrupt_flag = nullptr, int timeout_ms = -1,
                             std::chrono::steady_clock::time_point start_time =
                                 std::chrono::steady_clock::now()) override {
    if (path.empty()) {
      return {ECM{EC::InvalidArg, "Invalid empty path"}, RMR{}};
    }
    auto [error, info] = stat(path);
    if (error.first != EC::Success) {
      return {error, RMR{}};
    }
    RMR errors = {};
    std::error_code ec;
    if (info.type == PathType::DIR) {
      _remove(path, errors, interrupt_flag, timeout_ms, start_time);
    } else {
      fs::remove(fs::path(path), ec);
      if (ec) {
        return {ECM{fec(ec),
                    fmt::format("remove {} failed: {}", path, ec.message())},
                errors};
      }
    }
    return {ECM{EC::Success, ""}, errors};
  }

  ECM saferm(const std::string &path, amf interrupt_flag = nullptr,
             int timeout_ms = -1,
             std::chrono::steady_clock::time_point start_time =
                 std::chrono::steady_clock::now()) override {
    if (path.empty()) {
      return ECM{EC::InvalidArg, "Invalid empty path"};
    }
    if (this->trash_dir.empty()) {
      return ECM{EC::PathNotExist, "Trash directory is not set"};
    }
    auto [error, info] = stat(path);
    if (error.first != EC::Success) {
      return error;
    }
    std::string base = AMPathStr::basename(path);
    std::string base_name = base;
    std::string base_ext = "";
    std::string target_path;

    if (info.type != PathType::DIR) {
      auto base_info = AMPathStr::split_basename(base);
      base_name = base_info.first;
      base_ext = base_info.second;
    }

    // 获取当前时间，以2026-01-01-19-06格式
    std::string current_time =
        FormatTime(std::time(nullptr), "%Y-%m-%d-%H-%M-%S");

    target_path =
        AMPathStr::join(trash_dir, current_time, base_name + "." + base_ext);
    size_t i = 1;
    std::string base_name_tmp = base_name;

    while (true) {
      auto [rcm, br] = exists(target_path);
      if (rcm.first != EC::Success) {
        return rcm;
      }
      if (!br) {
        break;
      }
      base_name_tmp = base_name + "(" + std::to_string(i) + ")";
      target_path = AMPathStr::join(trash_dir, current_time,
                                    (base_name_tmp + ".") += base_ext);
      i++;
    }

    ECM rcm0 = mkdirs(AMPathStr::join(trash_dir, current_time), interrupt_flag,
                      timeout_ms, start_time);
    if (rcm0.first != EC::Success) {
      return rcm0;
    }

    return rename(path, target_path, false, false, interrupt_flag, timeout_ms,
                  start_time);
  }
};