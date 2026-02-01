#pragma once
#include <filesystem>
#include <unordered_set>

// 自身依赖
#include "AMClient/Base.hpp"
// 自身依赖

// 第三方库
#include <curl/curl.h>
#include <libssh2.h>
#include <libssh2_sftp.h>
#include <magic_enum/magic_enum.hpp>
#include <openssl/pem.h>
#include <openssl/rsa.h>

// Wait result for non-blocking socket operations
class AMLocalClient : public BaseClient {
public:
  AMLocalClient(ConRequst request, int buffer_capacity = 10,
                TraceCallback trace_cb = {})
      : BaseClient(request, buffer_capacity, std::move(trace_cb)) {
    this->PROTOCOL = ClientProtocol::LOCAL;
  }

  ECM Check([[maybe_unused]] amf interrupt_flag = nullptr,
            [[maybe_unused]] int timeout_ms = -1,
            [[maybe_unused]] int64_t start_time = -1) override {
    return {EC::Success, ""};
  }

  ECM Connect([[maybe_unused]] bool force = false,
              [[maybe_unused]] amf interrupt_flag = nullptr,
              [[maybe_unused]] int timeout_ms = -1,
              [[maybe_unused]] int64_t start_time = -1) override {
    return {EC::Success, ""};
  }

  OS_TYPE GetOSType(bool update = false) override {
    std::lock_guard<std::recursive_mutex> lock(this->mtx);
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
    std::lock_guard<std::recursive_mutex> lock(this->mtx);
    if (!this->home_dir.empty()) {
      return this->home_dir;
    }
    this->home_dir = AMFS::HomePath();
    return this->home_dir;
  }

  SR stat(const std::string &path, bool trace_link = false,
          [[maybe_unused]] amf interrupt_flag = nullptr,
          [[maybe_unused]] int timeout_ms = -1,
          [[maybe_unused]] int64_t start_time = -1) override {

    if (path.empty()) {
      return {ECM{EC::InvalidArg, "Invalid empty path"}, PathInfo()};
    }
    if (!fs::exists(fs::path(path))) {
      return {ECM{EC::PathNotExist, "Path not found: " + path}, PathInfo()};
    }

    PathInfo info;
    std::string pathf = path;
#ifdef _WIN32
    std::string real_path = ResolveRealCasePath_(path, trace_link);
    if (!real_path.empty()) {
      pathf = std::move(real_path);
    }
#endif
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
          ECM{fec(ec), AMStr::amfmt("Stat {} failed: {}", pathf, ec.message())};
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
        AMFS::GetTime(AMStr::wstr(pathf));
    info.create_time = create_time;
    info.access_time = access_time;
    info.modify_time = modify_time;
    info.owner = AMFS::GetFileOwner(AMStr::wstr(pathf));
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

  std::pair<ECM, std::vector<PathInfo>>
  listdir(const std::string &path, amf interrupt_flag = nullptr,
          int timeout_ms = -1, int64_t start_time = -1) override {
    std::string pathf = path;
    std::vector<PathInfo> result = {};
    fs::path p(pathf);
    if (!fs::exists(p)) {
      auto rcm =
          ECM{EC::PathNotExist, AMStr::amfmt("Path not found: {}", pathf)};
      trace(TraceLevel::Debug, EC::PathNotExist, pathf, "listdir", rcm.second);
      return {rcm, result};
    }
    if (!fs::is_directory(p)) {
      auto rcm = ECM{EC::NotADirectory,
                     AMStr::amfmt("Path is not a directory: {}", pathf)};
      trace(TraceLevel::Debug, EC::NotADirectory, pathf, "listdir", rcm.second);
      return {rcm, result};
    }
    std::variant<PathInfo, std::pair<std::string, std::exception>> sr;
    std::vector<std::string> dir_paths = {};
    std::error_code ec;

    for (const auto &entry : fs::directory_iterator(p, ec)) {
      if (interrupt_flag && interrupt_flag->check()) {
        return {ECM{EC::Terminate, "Listdir interrupted by user"}, result};
      }
      if (timeout_ms > 0 && am_ms() - start_time > timeout_ms) {
        return {ECM{EC::OperationTimeout, "Listdir timeout"}, result};
      }
      // 如果出现错误，则跳过当前文件
      if (ec) {
        ec.clear();
        continue;
      }

      auto [error, info] = stat(entry.path().string(), false);
      if (error.first != EC::Success) {
        continue;
      }
      result.push_back(info);
    }
    return {ECM{EC::Success, ""}, result};
  }

  inline std::pair<ECM, std::vector<PathInfo>>
  iwalk(const std::string &path, bool ignore_sepcial_file = true,
        amf interrupt_flag = nullptr, int timeout_ms = -1,
        int64_t start_time = -1) override {
    std::vector<PathInfo> result = {};
    auto [error, info] = stat(path);
    if (error.first != EC::Success) {
      return {error, result};
    }
    if (info.type != PathType::DIR) {
      return {error, {info}};
    }
    std::unordered_set<std::string> all_dirs;   // 存储所有目录
    std::unordered_set<std::string> has_subdir; // 存储有子目录的目录（非末级）
    std::error_code ec;
    // 取消其追踪symlink
    for (const auto &entry : fs::recursive_directory_iterator(path, ec)) {
      if (interrupt_flag && interrupt_flag->check()) {
        return {ECM{EC::Terminate, "iwalk interrupted by user"}, result};
      }
      if (timeout_ms > 0 && am_ms() - start_time > timeout_ms) {
        return {ECM{EC::OperationTimeout, "iwalk timeout"}, result};
      }
      if (ec) {
        ec.clear();
        continue;
      }
      if (entry.is_regular_file()) {
        auto [error, info] = stat(entry.path().string(), false);
        if (error.first == EC::Success) {
          result.push_back(info);
        }
        continue;
      }
      if (!entry.is_directory() && ignore_sepcial_file) {
        continue;
      }
      all_dirs.insert(entry.path().string());
      if (entry.path().parent_path() != entry.path()) {
        has_subdir.insert(entry.path().parent_path().string());
      }
    }
    result.reserve(result.size() + all_dirs.size() - has_subdir.size());
    for (const auto &dir : all_dirs) {
      if (has_subdir.find(dir) == has_subdir.end()) {
        auto [error, info] = stat(dir, false);
        if (error.first == EC::Success) {
          result.push_back(info);
        }
      }
    }
    return {ECM{EC::Success, ""}, result};
  }

  inline void _walk(std::vector<std::string> parts, WRD &result, int cur_depth,
                    int max_depth, bool ignore_sepcial_file = true,
                    amf interrupt_flag = nullptr, int timeout_ms = -1,
                    int64_t start_time = -1) {
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

  inline std::pair<ECM, WRD> walk(const std::string &path, int max_depth,
                                  bool ignore_sepcial_file = true,
                                  amf interrupt_flag = nullptr,
                                  int timeout_ms = -1,
                                  int64_t start_time = -1) override {
    WRD result = {};
    auto [error, info] = stat(path);
    if (error.first != EC::Success) {
      return {error, result};
    } else if (info.type != PathType::DIR) {
      trace(TraceLevel::Debug, EC::NotADirectory, path, "walk",
            AMStr::amfmt("Path is not a directory: {}", path));
      return {ECM{EC::NotADirectory,
                  AMStr::amfmt("Path is not a directory: {}", path)},
              result};
    }

    _walk({path}, result, 0, max_depth, ignore_sepcial_file, interrupt_flag,
          timeout_ms, start_time);

    return {{EC::Success, ""}, result};
  }

  ECM mkdir(const std::string &path,
            [[maybe_unused]] amf interrupt_flag = nullptr,
            [[maybe_unused]] int timeout_ms = -1,
            [[maybe_unused]] int64_t start_time = -1) override {
    if (path.empty()) {
      return ECM{EC::InvalidArg, "Invalid empty path"};
    }
    std::error_code ec;
    fs::create_directory(fs::path(path), ec);
    if (ec) {
      ECM rcm =
          ECM{fec(ec), AMStr::amfmt("mkdir {} failed: {}", path, ec.message())};
      trace(TraceLevel::Debug, rcm.first, path, "mkdir", rcm.second);
      return rcm;
    }
    return ECM{EC::Success, ""};
  }

  ECM mkdirs(const std::string &path,
             [[maybe_unused]] amf interrupt_flag = nullptr,
             [[maybe_unused]] int timeout_ms = -1,
             [[maybe_unused]] int64_t start_time = -1) override {
    if (path.empty()) {
      return ECM{EC::InvalidArg, "Invalid empty path"};
    }
    std::error_code ec;
    fs::create_directories(fs::path(path), ec);
    if (ec) {
      ECM rcm = ECM{fec(ec),
                    AMStr::amfmt("mkdirs {} failed: {}", path, ec.message())};
      trace(TraceLevel::Debug, rcm.first, path, "mkdir", rcm.second);
      return rcm;
    }
    return ECM{EC::Success, ""};
  }

  ECM rename(const std::string &src, const std::string &dst, bool mkdir = true,
             bool overwrite = false,
             [[maybe_unused]] amf interrupt_flag = nullptr,
             [[maybe_unused]] int timeout_ms = -1,
             [[maybe_unused]] int64_t start_time = -1) override {
    if (src.empty() || dst.empty()) {
      return ECM{EC::InvalidArg, "Invalid empty path"};
    }
    std::error_code ec;
    auto [error, info] = stat(src);
    auto [error1, info1] = stat(dst);
    if (error.first != EC::Success) {
      return ECM{error.first, AMStr::amfmt("src {} not exist", src)};
    } else if (error1.first == EC::Success) {
      if ((info.type == PathType::DIR && info1.type != PathType::DIR) ||
          (info.type != PathType::DIR && info1.type == PathType::DIR)) {
        return ECM{EC::NotADirectory, "src and dst are not the same type"};
      } else if (!overwrite) {
        return ECM{EC::PathAlreadyExists,
                   AMStr::amfmt("dst {} already exists", dst)};
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
      return ECM{fec(ec), AMStr::amfmt("rename {} to {} failed: {}", src, dst,
                                       ec.message())};
    }
    return ECM{EC::Success, ""};
  }

  ECM rmdir(const std::string &path,
            [[maybe_unused]] amf interrupt_flag = nullptr,
            [[maybe_unused]] int timeout_ms = -1,
            [[maybe_unused]] int64_t start_time = -1) override {
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
                 AMStr::amfmt("rmdir {} failed: {}", path, ec.message())};
    }
    return ECM{EC::Success, ""};
  }

  ECM rmfile(const std::string &path,
             [[maybe_unused]] amf interrupt_flag = nullptr,
             [[maybe_unused]] int timeout_ms = -1,
             [[maybe_unused]] int64_t start_time = -1) override {
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
                 AMStr::amfmt("rmdir {} failed: {}", path, ec.message())};
    }
    return ECM{EC::Success, ""};
  }

  void _remove(const std::string &path, RMR &errors,
               amf interrupt_flag = nullptr, int timeout_ms = -1,
               int64_t start_time = -1) {
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
              entry.path, ECM{fec(ec), AMStr::amfmt("remove {} failed: {}",
                                                    entry.path, ec.message())});
        }
      }
    }
    fs::remove(fs::path(path), ec);
    if (ec) {
      errors.emplace_back(
          path, ECM{fec(ec),
                    AMStr::amfmt("remove {} failed: {}", path, ec.message())});
    }
  }
  std::pair<ECM, RMR> remove(const std::string &path,
                             amf interrupt_flag = nullptr, int timeout_ms = -1,
                             int64_t start_time = -1) override {
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
                    AMStr::amfmt("remove {} failed: {}", path, ec.message())},
                errors};
      }
    }
    return {ECM{EC::Success, ""}, errors};
  }

  ECM saferm(const std::string &path, amf interrupt_flag = nullptr,
             int timeout_ms = -1, int64_t start_time = -1) override {
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

private:
#ifdef _WIN32
  /**
   * @brief Resolve a Windows path with the real on-disk casing.
   * @param path Input path that may have incorrect character casing.
   * @param follow_links Whether to follow reparse points (true) or keep the link
   * itself (false).
   * @return Resolved path with real casing, or empty when resolution fails.
   */
  std::string ResolveRealCasePath_(const std::string &path,
                                   bool follow_links) const {
    if (path.empty()) {
      return "";
    }
    std::wstring wpath = AMStr::wstr(path);
    DWORD flags = FILE_FLAG_BACKUP_SEMANTICS;
    if (!follow_links) {
      flags |= FILE_FLAG_OPEN_REPARSE_POINT;
    }
    HANDLE handle = CreateFileW(wpath.c_str(), FILE_READ_ATTRIBUTES,
                                FILE_SHARE_READ | FILE_SHARE_WRITE |
                                    FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING, flags, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
      return "";
    }
    DWORD size = GetFinalPathNameByHandleW(
        handle, nullptr, 0, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (size == 0) {
      CloseHandle(handle);
      return "";
    }
    std::wstring buffer(size, L'\0');
    DWORD written = GetFinalPathNameByHandleW(
        handle, buffer.data(), size, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    CloseHandle(handle);
    if (written == 0) {
      return "";
    }
    buffer.resize(written);
    std::wstring result = buffer;
    const std::wstring prefix = L"\\\\?\\";
    const std::wstring unc_prefix = L"\\\\?\\UNC\\";
    if (result.rfind(unc_prefix, 0) == 0) {
      result = L"\\\\" + result.substr(unc_prefix.size());
    } else if (result.rfind(prefix, 0) == 0) {
      result = result.substr(prefix.size());
    }
    return AMStr::wstr(result);
  }
#endif
};
