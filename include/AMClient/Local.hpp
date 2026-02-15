#pragma once
#include <array>
#include <filesystem>
#include <unordered_map>
#include <unordered_set>

// 自身依赖
#include "AMBase/CommonTools.hpp"
#include "AMClient/Base.hpp"
// 自身依赖

// 第三方库
#include <curl/curl.h>
#include <libssh2.h>
#include <libssh2_sftp.h>
#include <magic_enum/magic_enum.hpp>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#ifdef _WIN32
#include <windows.h>
#endif

#ifndef _WIN32
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

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

  /**
   * @brief Execute a local shell command using fork/exec/pipe.
   * @param cmd Command string passed to /bin/sh -c.
   * @param max_time_ms Max execution time in milliseconds; <=0 means no limit.
   * @param interrupt_flag Optional interrupt flag to abort execution.
   * @return ECM status and pair of output string with exit status.
   */
  CR ConductCmd(const std::string &cmd, int max_time_ms = -1,
                amf interrupt_flag = nullptr) override {
#ifdef _WIN32
    amf flag = interrupt_flag ? interrupt_flag : this->ClientInterruptFlag;
    if (flag && flag->check()) {
      return {ECM{EC::Terminate, "Operation aborted before command sent"},
              {"", -1}};
    }

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = nullptr;
    sa.bInheritHandle = TRUE;

    HANDLE read_pipe = nullptr;
    HANDLE write_pipe = nullptr;
    if (!CreatePipe(&read_pipe, &write_pipe, &sa, 0)) {
      return {ECM{EC::UnknownError, "CreatePipe failed"}, {"", -1}};
    }
    SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = write_pipe;
    si.hStdError = write_pipe;

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    std::string cmdline = "cmd /c " + cmd;
    std::vector<char> cmd_buf(cmdline.begin(), cmdline.end());
    cmd_buf.push_back('\0');

    BOOL created =
        CreateProcessA(nullptr, cmd_buf.data(), nullptr, nullptr, TRUE,
                       CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(write_pipe);

    if (!created) {
      CloseHandle(read_pipe);
      return {ECM{EC::UnknownError, "CreateProcess failed"}, {"", -1}};
    }

    std::string output;
    std::array<char, 4096> buffer;
    int exit_status = -1;
    bool finished = false;
    int64_t start_time = am_ms();

    while (true) {
      if (flag && flag->check()) {
        TerminateProcess(pi.hProcess, 1);
        finished = true;
        break;
      }
      if (max_time_ms > 0 && am_ms() - start_time >= max_time_ms) {
        TerminateProcess(pi.hProcess, 1);
        finished = true;
        break;
      }

      DWORD available = 0;
      if (PeekNamedPipe(read_pipe, nullptr, 0, nullptr, &available, nullptr) &&
          available > 0) {
        DWORD read_bytes = 0;
        if (ReadFile(read_pipe, buffer.data(),
                     static_cast<DWORD>(buffer.size()), &read_bytes, nullptr) &&
            read_bytes > 0) {
          output.append(buffer.data(), static_cast<size_t>(read_bytes));
        }
      }

      DWORD wait = WaitForSingleObject(pi.hProcess, 10);
      if (wait == WAIT_OBJECT_0) {
        finished = true;
        break;
      }
    }

    if (finished) {
      DWORD code = 0;
      if (GetExitCodeProcess(pi.hProcess, &code)) {
        exit_status = static_cast<int>(code);
      }
      // Drain remaining output
      DWORD read_bytes = 0;
      while (ReadFile(read_pipe, buffer.data(),
                      static_cast<DWORD>(buffer.size()), &read_bytes,
                      nullptr) &&
             read_bytes > 0) {
        output.append(buffer.data(), static_cast<size_t>(read_bytes));
      }
    }

    CloseHandle(read_pipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return {ECM{EC::Success, ""}, { output, exit_status }};
#else
    amf flag = interrupt_flag ? interrupt_flag : this->ClientInterruptFlag;
    if (flag && flag->check()) {
      return {ECM{EC::Terminate, "Operation aborted before command sent"},
              {"", -1}};
    }

    int pipefd[2] = {-1, -1};
    if (pipe(pipefd) != 0) {
      return {ECM{fec(std::error_code(errno, std::generic_category())),
                  "pipe failed"},
              {"", -1}};
    }

    pid_t pid = fork();
    if (pid < 0) {
      close(pipefd[0]);
      close(pipefd[1]);
      return {ECM{fec(std::error_code(errno, std::generic_category())),
                  "fork failed"},
              {"", -1}};
    }

    if (pid == 0) {
      dup2(pipefd[1], STDOUT_FILENO);
      dup2(pipefd[1], STDERR_FILENO);
      close(pipefd[0]);
      close(pipefd[1]);
      execl("/bin/sh", "sh", "-c", cmd.c_str(), (char *)nullptr);
      _exit(127);
    }

    close(pipefd[1]);
    int flags = fcntl(pipefd[0], F_GETFL, 0);
    if (flags != -1) {
      fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);
    }

    std::string output;
    std::array<char, 4096> buffer;
    int exit_status = -1;
    bool child_exited = false;
    int64_t start_time = am_ms();

    auto kill_child = [&](int sig) {
      if (!child_exited) {
        kill(pid, sig);
      }
    };

    while (true) {
      if (flag && flag->check()) {
        kill_child(SIGKILL);
        break;
      }
      if (max_time_ms > 0 && am_ms() - start_time >= max_time_ms) {
        kill_child(SIGKILL);
        break;
      }

      bool read_any = false;
      while (true) {
        ssize_t n = read(pipefd[0], buffer.data(), buffer.size());
        if (n > 0) {
          output.append(buffer.data(), static_cast<size_t>(n));
          read_any = true;
          continue;
        }
        if (n == 0) {
          child_exited = true;
          break;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          break;
        }
        break;
      }

      int status = 0;
      pid_t w = waitpid(pid, &status, WNOHANG);
      if (w == pid) {
        child_exited = true;
        if (WIFEXITED(status)) {
          exit_status = WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
          exit_status = 128 + WTERMSIG(status);
        }
      }

      if (child_exited) {
        while (true) {
          ssize_t n = read(pipefd[0], buffer.data(), buffer.size());
          if (n > 0) {
            output.append(buffer.data(), static_cast<size_t>(n));
            continue;
          }
          break;
        }
        break;
      }

      if (!read_any) {
        usleep(10000);
      }
    }

    close(pipefd[0]);

    return {ECM{EC::Success, ""}, { output, exit_status }};
#endif
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
      info.mode_int = 0300;
      info.mode_str = "r--------";
    } else {
      info.mode_int = 0600;
      info.mode_str = "rwx------";
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
        print("Interrupted_ls");
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

  inline std::pair<ECM, WRI>
  iwalk(const std::string &path, bool show_all = false,
        bool ignore_sepcial_file = true,
        AMFS::WalkErrorCallback error_callback = nullptr,
        amf interrupt_flag = nullptr, int timeout_ms = -1,
        int64_t start_time = -1) override {
    std::vector<PathInfo> result = {};
    RMR errors = {};
    auto [error, info] = stat(path);
    if (error.first != EC::Success) {
      if (error_callback && *error_callback) {
        (*error_callback)(path, error);
      }
      errors.emplace_back(path, error);
      return {error, {result, errors}};
    }
    if (info.type != PathType::DIR) {
      return {error, {WRV{info}, errors}};
    }
    std::unordered_set<std::string> all_dirs;   // 存储所有目录
    std::unordered_set<std::string> has_subdir; // 存储有子目录的目录（非末级）
    const bool filter_hidden = !show_all;
    const bool filter_special = !show_all && ignore_sepcial_file;
    const auto is_hidden_name = [](const std::string &name) {
      return !name.empty() && name[0] == '.';
    };
    std::error_code ec;
    fs::recursive_directory_iterator it(path, ec);
    fs::recursive_directory_iterator end;
    for (; it != end; it.increment(ec)) {
      if (interrupt_flag && interrupt_flag->check()) {
        ECM out = {EC::Terminate, "iwalk interrupted by user"};
        if (error_callback && *error_callback) {
          (*error_callback)(path, out);
        }
        return {out, {result, errors}};
      }
      if (timeout_ms > 0 && am_ms() - start_time > timeout_ms) {
        ECM out = {EC::OperationTimeout, "iwalk timeout"};
        if (error_callback && *error_callback) {
          (*error_callback)(path, out);
        }
        return {out, {result, errors}};
      }
      if (ec) {
        ECM out = {fec(ec), ec.message()};
        if (error_callback && *error_callback) {
          (*error_callback)(it->path().string(), out);
        }
        errors.emplace_back(it->path().string(), out);
        ec.clear();
        continue;
      }
      const fs::path entry_path = it->path();
      const std::string base_name = entry_path.filename().string();
      if (filter_hidden && is_hidden_name(base_name)) {
        std::error_code ec_dir;
        if (it->is_directory(ec_dir)) {
          it.disable_recursion_pending();
        }
        if (ec_dir) {
          ec_dir.clear();
        }
        continue;
      }
      std::error_code ec_type;
      const bool is_file = it->is_regular_file(ec_type);
      if (ec_type) {
        ECM out = {fec(ec_type), ec_type.message()};
        if (error_callback && *error_callback) {
          (*error_callback)(entry_path.string(), out);
        }
        errors.emplace_back(entry_path.string(), out);
        ec_type.clear();
        continue;
      }
      if (is_file) {
        auto [error, info] = stat(entry_path.string(), false);
        if (error.first == EC::Success) {
          result.push_back(info);
        } else {
          if (error_callback && *error_callback) {
            (*error_callback)(entry_path.string(), error);
          }
          errors.emplace_back(entry_path.string(), error);
        }
        continue;
      }
      std::error_code ec_dir;
      const bool is_dir = it->is_directory(ec_dir);
      if (ec_dir) {
        ECM out = {fec(ec_dir), ec_dir.message()};
        if (error_callback && *error_callback) {
          (*error_callback)(entry_path.string(), out);
        }
        errors.emplace_back(entry_path.string(), out);
        ec_dir.clear();
        continue;
      }
      if (!is_dir && filter_special) {
        continue;
      }
      all_dirs.insert(entry_path.string());
      if (entry_path.parent_path() != entry_path) {
        has_subdir.insert(entry_path.parent_path().string());
      }
    }
    result.reserve(result.size() + all_dirs.size() - has_subdir.size());
    for (const auto &dir : all_dirs) {
      if (has_subdir.find(dir) == has_subdir.end()) {
        auto [error, info] = stat(dir, false);
        if (error.first == EC::Success) {
          result.push_back(info);
        } else {
          if (error_callback && *error_callback) {
            (*error_callback)(dir, error);
          }
          errors.emplace_back(dir, error);
        }
      }
    }
    return {ECM{EC::Success, ""}, {result, errors}};
  }

  inline void _walk(std::vector<std::string> parts, WRD &result, RMR &errors,
                    int cur_depth, int max_depth, bool show_all = false,
                    bool ignore_sepcial_file = true,
                    AMFS::WalkErrorCallback error_callback = nullptr,
                    amf interrupt_flag = nullptr, int timeout_ms = -1,
                    int64_t start_time = -1) {
    if (max_depth > 0 && cur_depth > max_depth) {
      return;
    }
    std::string pathf = AMPathStr::join(parts);
    std::vector<PathInfo> files_info = {};
    bool empty_dir = true;
    if (interrupt_flag && interrupt_flag->check()) {
      ECM out = {EC::Terminate, "walk interrupted by user"};
      if (error_callback && *error_callback) {
        (*error_callback)(pathf, out);
      }
      errors.emplace_back(pathf, out);
      return;
    }
    auto [error, info] = listdir(pathf, interrupt_flag, timeout_ms, start_time);
    if (error.first != EC::Success) {
      if (error_callback && *error_callback) {
        (*error_callback)(pathf, error);
      }
      errors.emplace_back(pathf, error);
      return;
    }
    const bool filter_hidden = !show_all;
    const bool filter_special = !show_all && ignore_sepcial_file;
    const auto is_hidden_name = [](const std::string &name) {
      return !name.empty() && name[0] == '.';
    };
    for (const auto &entry : info) {
      if (interrupt_flag && interrupt_flag->check()) {
        ECM out = {EC::Terminate, "walk interrupted by user"};
        if (error_callback && *error_callback) {
          (*error_callback)(pathf, out);
        }
        errors.emplace_back(pathf, out);
        return;
      }
      empty_dir = false;
      if (filter_hidden && is_hidden_name(entry.name)) {
        continue;
      }
      if (entry.type == PathType::DIR) {
        auto n_parts = parts;
        n_parts.push_back(entry.name);
        _walk(n_parts, result, errors, cur_depth + 1, max_depth, show_all,
              ignore_sepcial_file, error_callback);
      } else if (static_cast<int>(entry.type) < 0 && filter_special) {
        continue;
      } else {
        files_info.push_back(entry);
      }
    }
    if (!empty_dir && files_info.empty()) {
      return;
    }
    result.emplace_back(parts, files_info);
  }

  inline std::pair<ECM, WRDR>
  walk(const std::string &path, int max_depth, bool show_all = false,
       bool ignore_sepcial_file = true,
       AMFS::WalkErrorCallback error_callback = nullptr,
       amf interrupt_flag = nullptr, int timeout_ms = -1,
       int64_t start_time = -1) override {
    WRD result = {};
    RMR errors = {};
    auto [error, info] = stat(path);
    if (error.first != EC::Success) {
      if (error_callback && *error_callback) {
        (*error_callback)(path, error);
      }
      errors.emplace_back(path, error);
      return {error, {result, errors}};
    } else if (info.type != PathType::DIR) {
      trace(TraceLevel::Debug, EC::NotADirectory, path, "walk",
            AMStr::amfmt("Path is not a directory: {}", path));
      ECM out = {EC::NotADirectory,
                 AMStr::amfmt("Path is not a directory: {}", path)};
      if (error_callback && *error_callback) {
        (*error_callback)(path, out);
      }
      errors.emplace_back(path, out);
      return {out, {result, errors}};
    }

    struct DirState {
      bool has_entry = false;
      bool has_file = false;
      std::vector<PathInfo> files = {};
    };

    const fs::path root_norm =
        fs::path(info.path.empty() ? path : info.path).lexically_normal();
    const std::string root_display = path;

    auto normalize_key = [&](const std::string &value) {
      std::string key = fs::path(value).lexically_normal().string();
#ifdef _WIN32
      key = AMStr::lowercase(key);
#endif
      return key;
    };

    const std::string root_key = normalize_key(root_norm.string());

    std::unordered_map<std::string, DirState> dir_states;
    std::unordered_map<std::string, std::string> dir_display;
    std::unordered_set<std::string> seen_dirs;
    std::vector<std::string> dir_order;

    auto ensure_dir = [&](const std::string &dir_key,
                          const std::string &display_path) {
      if (seen_dirs.insert(dir_key).second) {
        dir_order.push_back(dir_key);
      }
      if (dir_display.find(dir_key) == dir_display.end()) {
        dir_display[dir_key] = display_path;
      }
      (void)dir_states[dir_key];
    };

    ensure_dir(root_key, root_norm.string());

    std::error_code ec;
    fs::recursive_directory_iterator it(root_norm, ec);
    fs::recursive_directory_iterator end;
    for (; it != end; it.increment(ec)) {
      if (interrupt_flag && interrupt_flag->check()) {
        ECM out = {EC::Terminate, "Interrupted by user, no action conducted"};
        if (error_callback && *error_callback) {
          (*error_callback)(path, out);
        }
        errors.emplace_back(path, out);
        return {out, {result, errors}};
      }
      if (timeout_ms > 0 && am_ms() - start_time > timeout_ms) {
        ECM out = {EC::OperationTimeout, "walk timeout"};
        if (error_callback && *error_callback) {
          (*error_callback)(path, out);
        }
        errors.emplace_back(path, out);
        return {out, {result, errors}};
      }
      if (ec) {
        ECM out = {fec(ec), ec.message()};
        if (error_callback && *error_callback) {
          (*error_callback)(it->path().string(), out);
        }
        errors.emplace_back(it->path().string(), out);
        ec.clear();
        continue;
      }

      const fs::path entry_path = it->path();
      const std::string base_name = entry_path.filename().string();
      if (!show_all && !base_name.empty() && base_name[0] == '.') {
        std::error_code ec_dir;
        if (it->is_directory(ec_dir)) {
          it.disable_recursion_pending();
        }
        if (ec_dir) {
          ec_dir.clear();
        }
        continue;
      }
      auto [stat_ecm, entry_info] = stat(entry_path.string(), false);
      if (stat_ecm.first != EC::Success) {
        const std::string parent_key =
            normalize_key(entry_path.parent_path().lexically_normal().string());
        dir_states[parent_key].has_entry = true;
        if (error_callback && *error_callback) {
          (*error_callback)(entry_path.string(), stat_ecm);
        }
      } else {
        const std::string entry_display = entry_info.path;
        const std::string entry_key = normalize_key(entry_display);
        const std::string parent_key =
            normalize_key(fs::path(entry_display).parent_path().string());

        dir_states[parent_key].has_entry = true;

        if (entry_info.type == PathType::DIR) {
          ensure_dir(entry_key, entry_display);
        } else {
          if (!show_all && static_cast<int>(entry_info.type) < 0 &&
              ignore_sepcial_file) {
            continue;
          }
          dir_states[parent_key].has_file = true;
          dir_states[parent_key].files.push_back(std::move(entry_info));
        }
      }

      if (max_depth > 0 && it.depth() >= max_depth) {
        it.disable_recursion_pending();
      }
    }

    auto build_parts = [&](const std::string &dir_key) {
      std::vector<std::string> parts;
      parts.reserve(4);
      parts.push_back(root_display);
      auto it_display = dir_display.find(dir_key);
      if (it_display == dir_display.end()) {
        return parts;
      }
      fs::path dir_norm = fs::path(it_display->second).lexically_normal();
      if (dir_norm != root_norm) {
        fs::path rel = dir_norm.lexically_relative(root_norm);
        if (!rel.empty() && rel != ".") {
          for (const auto &part : rel) {
            if (part == ".") {
              continue;
            }
            parts.push_back(part.string());
          }
        }
      }
      return parts;
    };

    for (const auto &dir_key : dir_order) {
      auto it_state = dir_states.find(dir_key);
      DirState empty_state;
      DirState *state =
          it_state == dir_states.end() ? &empty_state : &it_state->second;
      if (state->has_entry && !state->has_file) {
        continue;
      }
      std::vector<PathInfo> files;
      if (it_state != dir_states.end()) {
        files = std::move(it_state->second.files);
      }
      result.emplace_back(build_parts(dir_key), std::move(files));
    }

    return {{EC::Success, ""}, {result, errors}};
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
               AMFS::WalkErrorCallback error_callback = nullptr,
               amf interrupt_flag = nullptr, int timeout_ms = -1,
               int64_t start_time = -1) {
    std::error_code ec;
    auto [error, listing] =
        listdir(path, interrupt_flag, timeout_ms, start_time);
    if (error.first != EC::Success) {
      if (error_callback && *error_callback) {
        (*error_callback)(path, error);
      }
      errors.emplace_back(path, error);
      return;
    }
    for (const auto &entry : listing) {
      if (entry.type == PathType::DIR) {
        _remove(entry.path, errors, error_callback, interrupt_flag, timeout_ms,
                start_time);
      } else {
        fs::remove(entry.path, ec);
        if (ec) {
          ECM out = {fec(ec), AMStr::amfmt("remove {} failed: {}", entry.path,
                                           ec.message())};
          if (error_callback && *error_callback) {
            (*error_callback)(entry.path, out);
          }
          errors.emplace_back(entry.path, out);
        }
      }
    }
    fs::remove(fs::path(path), ec);
    if (ec) {
      ECM out = {fec(ec),
                 AMStr::amfmt("remove {} failed: {}", path, ec.message())};
      if (error_callback && *error_callback) {
        (*error_callback)(path, out);
      }
      errors.emplace_back(path, out);
    }
  }
  std::pair<ECM, RMR> remove(const std::string &path,
                             AMFS::WalkErrorCallback error_callback = nullptr,
                             amf interrupt_flag = nullptr, int timeout_ms = -1,
                             int64_t start_time = -1) override {
    if (path.empty()) {
      return {ECM{EC::InvalidArg, "Invalid empty path"}, RMR{}};
    }
    auto [error, info] = stat(path);
    if (error.first != EC::Success) {
      if (error_callback && *error_callback) {
        (*error_callback)(path, error);
      }
      return {error, RMR{}};
    }
    RMR errors = {};
    std::error_code ec;
    if (info.type == PathType::DIR) {
      _remove(path, errors, error_callback, interrupt_flag, timeout_ms,
              start_time);
    } else {
      fs::remove(fs::path(path), ec);
      if (ec) {
        ECM out = {fec(ec),
                   AMStr::amfmt("remove {} failed: {}", path, ec.message())};
        if (error_callback && *error_callback) {
          (*error_callback)(path, out);
        }
        return {out, errors};
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
   * @param follow_links Whether to follow reparse points (true) or keep the
   * link itself (false).
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
    HANDLE handle =
        CreateFileW(wpath.c_str(), FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
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
