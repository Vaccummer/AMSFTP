#pragma once

#include <array>
#include <filesystem>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>

// Internal dependencies
#include "infrastructure/client/common/Base.hpp"

#ifdef _WIN32
#include <windows.h>
#endif

#ifndef _WIN32
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

class AMLocalIOCore : public ClientIOBase, BasePathMatch {
private:
  AMAtomic<ConRequest> &request_atomic_;

  [[nodiscard]] int64_t NormalizeStartTime_(int64_t start_time) const {
    return start_time == -1 ? AMTime::miliseconds() : start_time;
  }

  [[nodiscard]] bool IsTimedOut_(int timeout_ms, int64_t start_time) const {
    return timeout_ms > 0 && AMTime::miliseconds() - start_time >= timeout_ms;
  }

  void SetState_(const AMDomain::client::ClientState &state) {
    if (config_part_) {
      config_part_->SetState(state);
    }
  }

  [[nodiscard]] std::string GetHomeDir_() {
    std::string home_dir = config_part_ ? config_part_->GetHomeDir() : "";
    if (home_dir.empty()) {
      home_dir = AMFS::HomePath();
      if (config_part_) {
        config_part_->SetHomeDir(home_dir);
      }
    }
    return home_dir;
  }

  void trace(AMDomain::client::TraceLevel level, EC error_code,
             const std::string &target = "", const std::string &action = "",
             const std::string &msg = "") const {
    if (!config_part_) {
      return;
    }
    ClientIOBase::trace(TraceInfo(
        level, error_code, config_part_->GetNickname(), target, action, msg,
        config_part_->GetRequest(), AMDomain::client::TraceSource::Client));
  }

  static fs::perms ToFsPerms_(size_t mode_int) {
    fs::perms perms = fs::perms::none;
    if ((mode_int & 0400U) != 0U) {
      perms |= fs::perms::owner_read;
    }
    if ((mode_int & 0200U) != 0U) {
      perms |= fs::perms::owner_write;
    }
    if ((mode_int & 0100U) != 0U) {
      perms |= fs::perms::owner_exec;
    }
    if ((mode_int & 0040U) != 0U) {
      perms |= fs::perms::group_read;
    }
    if ((mode_int & 0020U) != 0U) {
      perms |= fs::perms::group_write;
    }
    if ((mode_int & 0010U) != 0U) {
      perms |= fs::perms::group_exec;
    }
    if ((mode_int & 0004U) != 0U) {
      perms |= fs::perms::others_read;
    }
    if ((mode_int & 0002U) != 0U) {
      perms |= fs::perms::others_write;
    }
    if ((mode_int & 0001U) != 0U) {
      perms |= fs::perms::others_exec;
    }
    return perms;
  }

  void _remove(const std::string &path, RMR &errors,
               AMFS::WalkErrorCallback error_callback = nullptr,
               int timeout_ms = -1, int64_t start_time = -1,
               amf interrupt_flag = nullptr) {
    if ((interrupt_flag && interrupt_flag->IsInterrupted())) {
      ECM out = {EC::Terminate, "Interrupted by user"};
      if (error_callback && *error_callback) {
        (*error_callback)(path, out);
      }
      errors.emplace_back(path, out);
      return;
    }
    if (IsTimedOut_(timeout_ms, start_time)) {
      ECM out = {EC::OperationTimeout, "remove timeout"};
      if (error_callback && *error_callback) {
        (*error_callback)(path, out);
      }
      errors.emplace_back(path, out);
      return;
    }

    std::error_code ec;
    auto [error, listing] =
        listdir(path, timeout_ms, start_time, interrupt_flag);
    if (error.first != EC::Success) {
      if (error_callback && *error_callback) {
        (*error_callback)(path, error);
      }
      errors.emplace_back(path, error);
      return;
    }

    for (const auto &entry : listing) {
      if ((interrupt_flag && interrupt_flag->IsInterrupted())) {
        ECM out = {EC::Terminate, "Interrupted by user"};
        if (error_callback && *error_callback) {
          (*error_callback)(entry.path, out);
        }
        errors.emplace_back(entry.path, out);
        return;
      }
      if (IsTimedOut_(timeout_ms, start_time)) {
        ECM out = {EC::OperationTimeout, "remove timeout"};
        if (error_callback && *error_callback) {
          (*error_callback)(entry.path, out);
        }
        errors.emplace_back(entry.path, out);
        return;
      }
      if (entry.type == PathType::DIR) {
        _remove(entry.path, errors, error_callback, timeout_ms, start_time,
                interrupt_flag);
      } else {
        fs::remove(entry.path, ec);
        if (ec) {
          ECM out = {fec(ec), AMStr::fmt("remove {} failed: {}", entry.path,
                                         ec.message())};
          if (error_callback && *error_callback) {
            (*error_callback)(entry.path, out);
          }
          errors.emplace_back(entry.path, out);
          ec.clear();
        }
      }
    }

    fs::remove(fs::path(path), ec);
    if (ec) {
      ECM out = {fec(ec),
                 AMStr::fmt("remove {} failed: {}", path, ec.message())};
      if (error_callback && *error_callback) {
        (*error_callback)(path, out);
      }
      errors.emplace_back(path, out);
    }
  }

#ifdef _WIN32
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

public:
  AMLocalIOCore(AMDomain::client::IClientConfigPort *config_port,
                AMDomain::client::IClientTaskControlPort *control_port,
                TraceCallback trace_cb = {}, AuthCallback auth_cb = {})
      : ClientIOBase(config_port, control_port),
        request_atomic_((config_port != nullptr)
                            ? config_port->RequestAtomic()
                            : throw std::invalid_argument(
                                  "AMLocalIOCore requires non-null config "
                                  "port")) {
    if (control_port == nullptr) {
      throw std::invalid_argument(
          "AMLocalIOCore requires non-null task control port");
    }
    if (request_atomic_.lock()->protocol != ClientProtocol::LOCAL) {
      throw std::invalid_argument(
          "AMLocalIOCore requires LOCAL protocol request");
    }
    RegisterTraceCallback(std::move(trace_cb));
    RegisterAuthCallback(std::move(auth_cb));
    if (config_part_ && config_part_->GetHomeDir().empty()) {
      config_part_->SetHomeDir(AMFS::HomePath());
    }
    (void)UpdateOSType();
    SetState_({AMDomain::client::ClientStatus::NotInitialized,
               {EC::NotInitialized, "Client Not Initialized"}});
  }

  ~AMLocalIOCore() override = default;
  OS_TYPE UpdateOSType([[maybe_unused]] int timeout_ms = -1,
                       [[maybe_unused]] int64_t start_time = -1,
                       [[maybe_unused]] amf interrupt_flag = nullptr) override {
#ifdef _WIN32
    OS_TYPE out = OS_TYPE::Windows;
#elif defined(_WIN64)
    OS_TYPE out = OS_TYPE::Windows;
#elif defined(__linux__) || defined(__gnu_linux__)
    OS_TYPE out = OS_TYPE::Linux;
#elif defined(__APPLE__) && defined(__MACH__)
    OS_TYPE out = OS_TYPE::MacOS;
#elif defined(__FreeBSD__)
    OS_TYPE out = OS_TYPE::FreeBSD;
#else
    OS_TYPE out = OS_TYPE::Unknown;
#endif
    if (config_part_) {
      config_part_->SetOSType(out);
    }
    return out;
  }

  std::string
  UpdateHomeDir([[maybe_unused]] int timeout_ms = -1,
                [[maybe_unused]] int64_t start_time = -1,
                [[maybe_unused]] amf interrupt_flag = nullptr) override {
    const std::string home_dir = AMFS::HomePath();
    if (config_part_) {
      config_part_->SetHomeDir(home_dir);
    }
    return home_dir;
  }

  ECM Check(int timeout_ms = -1, int64_t start_time = -1,
            amf interrupt_flag = nullptr) override {
    start_time = NormalizeStartTime_(start_time);
    if ((interrupt_flag && interrupt_flag->IsInterrupted())) {
      ECM out = {EC::Terminate, "Check interrupted by user"};
      SetState_({AMDomain::client::ClientStatus::ConnectionBroken, out});
      return out;
    }
    if (IsTimedOut_(timeout_ms, start_time)) {
      ECM out = {EC::OperationTimeout, "check timeout"};
      SetState_({AMDomain::client::ClientStatus::ConnectionBroken, out});
      return out;
    }
    SetState_({AMDomain::client::ClientStatus::OK, {EC::Success, ""}});
    return {EC::Success, ""};
  }

  ECM Connect(bool force = false, int timeout_ms = -1, int64_t start_time = -1,
              amf interrupt_flag = nullptr) override {
    start_time = NormalizeStartTime_(start_time);
    if (!force) {
      ECM rcm = Check(timeout_ms, start_time, interrupt_flag);
      if (rcm.first == EC::Success) {
        (void)UpdateOSType(timeout_ms, start_time, interrupt_flag);
        (void)UpdateHomeDir(timeout_ms, start_time, interrupt_flag);
        return rcm;
      }
    }

    ECM rcm = Check(timeout_ms, start_time, interrupt_flag);
    if (rcm.first == EC::Success) {
      (void)UpdateOSType(timeout_ms, start_time, interrupt_flag);
      (void)UpdateHomeDir(timeout_ms, start_time, interrupt_flag);
      SetState_({AMDomain::client::ClientStatus::OK, {EC::Success, ""}});
      return {EC::Success, ""};
    }

    AMDomain::client::ClientStatus status =
        rcm.first == EC::NoConnection || rcm.first == EC::ConnectionLost
            ? AMDomain::client::ClientStatus::NoConnection
            : AMDomain::client::ClientStatus::ConnectionBroken;
    SetState_({status, rcm});
    return rcm;
  }

  double GetRTT([[maybe_unused]] ssize_t times = 5) override { return 0.0; }

  CR ConductCmd(const std::string &cmd, int max_time_ms = 3000,
                amf interrupt_flag = nullptr) override {
    int64_t start_time = AMTime::miliseconds();
    if ((interrupt_flag && interrupt_flag->IsInterrupted())) {
      return {ECM{EC::Terminate, "Operation aborted before command sent"},
              {"", -1}};
    }

#ifdef _WIN32
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

    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = write_pipe;
    si.hStdError = write_pipe;

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    std::wstring wcmd = AMStr::wstr(cmd);
    std::vector<wchar_t> cmd_buf(wcmd.begin(), wcmd.end());
    cmd_buf.push_back(L'\0');

    BOOL created =
        CreateProcessW(nullptr, cmd_buf.data(), nullptr, nullptr, TRUE,
                       CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(write_pipe);

    if (!created) {
      CloseHandle(read_pipe);
      return {ECM{EC::UnknownError, "CreateProcess failed"}, {"", -1}};
    }

    HANDLE job_handle = CreateJobObjectW(nullptr, nullptr);
    if (job_handle != nullptr) {
      JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_limits{};
      job_limits.BasicLimitInformation.LimitFlags =
          JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
      const bool configured =
          SetInformationJobObject(job_handle, JobObjectExtendedLimitInformation,
                                  &job_limits, sizeof(job_limits)) != 0;
      const bool assigned =
          configured && AssignProcessToJobObject(job_handle, pi.hProcess) != 0;
      if (!assigned) {
        CloseHandle(job_handle);
        job_handle = nullptr;
      }
    }

    std::string output;
    std::array<char, 4096> buffer;
    int exit_status = -1;
    bool finished = false;
    bool interrupted = false;
    bool timed_out = false;

    while (true) {
      if ((interrupt_flag && interrupt_flag->IsInterrupted())) {
        if (job_handle) {
          (void)TerminateJobObject(job_handle, 1);
        } else {
          (void)TerminateProcess(pi.hProcess, 1);
        }
        interrupted = true;
        finished = true;
        break;
      }
      if (max_time_ms > 0 &&
          AMTime::miliseconds() - start_time >= max_time_ms) {
        if (job_handle) {
          (void)TerminateJobObject(job_handle, 1);
        } else {
          (void)TerminateProcess(pi.hProcess, 1);
        }
        timed_out = true;
        finished = true;
        break;
      }

      DWORD available = 0;
      if (PeekNamedPipe(read_pipe, nullptr, 0, nullptr, &available, nullptr) &&
          available > 0) {
        const DWORD chunk_size = available < static_cast<DWORD>(buffer.size())
                                     ? available
                                     : static_cast<DWORD>(buffer.size());
        DWORD read_bytes = 0;
        if (ReadFile(read_pipe, buffer.data(), chunk_size, &read_bytes,
                     nullptr) &&
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

      while (true) {
        DWORD available = 0;
        if (!PeekNamedPipe(read_pipe, nullptr, 0, nullptr, &available,
                           nullptr) ||
            available == 0) {
          break;
        }
        const DWORD chunk_size = available < static_cast<DWORD>(buffer.size())
                                     ? available
                                     : static_cast<DWORD>(buffer.size());
        DWORD read_bytes = 0;
        if (!ReadFile(read_pipe, buffer.data(), chunk_size, &read_bytes,
                      nullptr) ||
            read_bytes == 0) {
          break;
        }
        output.append(buffer.data(), static_cast<size_t>(read_bytes));
      }
    }

    CloseHandle(read_pipe);
    if (job_handle) {
      CloseHandle(job_handle);
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (interrupted) {
      return {ECM{EC::Terminate, "Command interrupted"},
              { output,
                exit_status }};
    }
    if (timed_out) {
      return {ECM{EC::OperationTimeout, "Command timed out"},
              { output,
                exit_status }};
    }
    return {ECM{EC::Success, ""}, { output, exit_status }};
#else
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
    bool interrupted = false;
    bool timed_out = false;

    auto kill_child = [&](int sig) {
      if (!child_exited) {
        (void)kill(pid, sig);
      }
    };

    while (true) {
      if ((interrupt_flag && interrupt_flag->IsInterrupted())) {
        kill_child(SIGKILL);
        interrupted = true;
        break;
      }
      if (max_time_ms > 0 &&
          AMTime::miliseconds() - start_time >= max_time_ms) {
        kill_child(SIGKILL);
        timed_out = true;
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

    if (!child_exited) {
      int status = 0;
      if (waitpid(pid, &status, 0) == pid) {
        child_exited = true;
        if (WIFEXITED(status)) {
          exit_status = WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
          exit_status = 128 + WTERMSIG(status);
        }
      }
    }

    if (interrupted) {
      return {ECM{EC::Terminate, "Command interrupted"},
              { output,
                exit_status }};
    }
    if (timed_out) {
      return {ECM{EC::OperationTimeout, "Command timed out"},
              { output,
                exit_status }};
    }

    return {ECM{EC::Success, ""}, { output, exit_status }};
#endif
  }

  std::pair<ECM, std::string> realpath(const std::string &path,
                                       int timeout_ms = -1,
                                       int64_t start_time = -1,
                                       amf interrupt_flag = nullptr) override {
    start_time = NormalizeStartTime_(start_time);
    if (path.empty()) {
      return {{EC::InvalidArg, "Invalid empty path"}, ""};
    }
    if ((interrupt_flag && interrupt_flag->IsInterrupted())) {
      return {{EC::Terminate, "Interrupted by user"}, ""};
    }
    if (IsTimedOut_(timeout_ms, start_time)) {
      return {{EC::OperationTimeout, "realpath timeout"}, ""};
    }

    std::error_code ec;
    fs::path p(path);
    if (!fs::exists(p, ec)) {
      if (ec) {
        return {{fec(ec), ec.message()}, ""};
      }
      return {{EC::PathNotExist, AMStr::fmt("Path not found: {}", path)}, ""};
    }

    fs::path resolved = fs::canonical(p, ec);
    if (ec) {
      ec.clear();
      resolved = fs::absolute(p, ec);
      if (ec) {
        return {{fec(ec), ec.message()}, ""};
      }
      resolved = resolved.lexically_normal();
    }

    return {{EC::Success, ""}, resolved.string()};
  }

  AMDomain::client::ChmodResult
  chmod(const std::string &path, std::variant<std::string, size_t> mode,
        bool recursive = false, int timeout_ms = -1, int64_t start_time = -1,
        amf interrupt_flag = nullptr) override {
    start_time = NormalizeStartTime_(start_time);
    std::unordered_map<std::string, ECM> results = {};
    if (path.empty()) {
      return {{EC::InvalidArg, "Invalid empty path"}, results};
    }
    if ((interrupt_flag && interrupt_flag->IsInterrupted())) {
      return {{EC::Terminate, "Interrupted by user"}, results};
    }
    if (IsTimedOut_(timeout_ms, start_time)) {
      return {{EC::OperationTimeout, "chmod timeout"}, results};
    }

    size_t mode_int = 0;
    if (std::holds_alternative<std::string>(mode)) {
      mode_int = AMStr::ModeTrans(std::get<std::string>(mode));
    } else {
      mode_int = std::get<size_t>(mode);
    }

    const fs::perms perms = ToFsPerms_(mode_int);
    bool has_fail = false;

    auto apply_one = [&](const fs::path &target) {
      std::error_code ec;
      fs::permissions(target, perms, fs::perm_options::replace, ec);
      if (ec) {
        has_fail = true;
        results[target.string()] =
            ECM{fec(ec), AMStr::fmt("chmod {} failed: {}", target.string(),
                                    ec.message())};
      } else {
        results[target.string()] = ECM{EC::Success, ""};
      }
    };

    apply_one(fs::path(path));

    if (recursive) {
      std::error_code ec;
      fs::recursive_directory_iterator it(path, ec);
      fs::recursive_directory_iterator end;
      if (ec) {
        return {
            {fec(ec), AMStr::fmt("chmod {} failed: {}", path, ec.message())},
            results};
      }
      for (; it != end; it.increment(ec)) {
        if ((interrupt_flag && interrupt_flag->IsInterrupted())) {
          return {{EC::Terminate, "Interrupted by user"}, results};
        }
        if (IsTimedOut_(timeout_ms, start_time)) {
          return {{EC::OperationTimeout, "chmod timeout"}, results};
        }
        if (ec) {
          has_fail = true;
          results[it->path().string()] = ECM{fec(ec), ec.message()};
          ec.clear();
          continue;
        }
        apply_one(it->path());
      }
    }

    if (has_fail) {
      return {
          {EC::CommonFailure,
           AMStr::fmt("chmod partially failed on {} entries", results.size())},
          results};
    }
    return {{EC::Success, ""}, results};
  }

  SR stat(const std::string &path, bool trace_link = false, int timeout_ms = -1,
          int64_t start_time = -1, amf interrupt_flag = nullptr) override {
    start_time = NormalizeStartTime_(start_time);
    if (path.empty()) {
      return {ECM{EC::InvalidArg, "Invalid empty path"}, PathInfo()};
    }
    if ((interrupt_flag && interrupt_flag->IsInterrupted())) {
      return {ECM{EC::Terminate, "Interrupted by user"}, PathInfo()};
    }
    if (IsTimedOut_(timeout_ms, start_time)) {
      return {ECM{EC::OperationTimeout, "stat timeout"}, PathInfo()};
    }

    std::error_code ec;
    if (!fs::exists(fs::path(path), ec)) {
      if (ec) {
        return {
            ECM{fec(ec), AMStr::fmt("stat {} failed: {}", path, ec.message())},
            PathInfo()};
      }
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
    if (trace_link) {
      status = fs::status(p, ec);
    } else {
      status = fs::symlink_status(p, ec);
    }

    if (ec) {
      ECM rcm = {fec(ec),
                 AMStr::fmt("Stat {} failed: {}", pathf, ec.message())};
      trace(AMDomain::client::TraceLevel::Error, rcm.first, pathf, "stat",
            rcm.second);
      return {rcm, info};
    }

    info.type = cast_fs_type(status.type());

    const auto size_f = fs::file_size(p, ec);
    if (!ec) {
      info.size = size_f;
    } else {
      ec.clear();
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
    if (::stat(path.c_str(), &file_stat) == -1) {
      return {ECM{fec(std::error_code(errno, std::generic_category())),
                  "Fail to stat file: " + std::string(strerror(errno))},
              info};
    }

    struct passwd *pw = getpwuid(file_stat.st_uid);
    info.owner = pw ? pw->pw_name : std::to_string(file_stat.st_uid);

    info.mode_int = static_cast<size_t>(file_stat.st_mode) & 0777U;
    info.mode_str = AMStr::ModeTrans(info.mode_int);

    info.access_time = timespec_to_double(file_stat.st_atim);
    info.modify_time = timespec_to_double(file_stat.st_mtim);
#ifdef __APPLE__
    info.create_time = timespec_to_double(file_stat.st_birthtimespec);
#endif
#endif

    return {{EC::Success, ""}, info};
  }

  std::pair<ECM, std::vector<PathInfo>>
  listdir(const std::string &path, int timeout_ms = -1, int64_t start_time = -1,
          amf interrupt_flag = nullptr) override {
    start_time = NormalizeStartTime_(start_time);
    std::vector<PathInfo> result = {};
    if (path.empty()) {
      return {ECM{EC::InvalidArg, "Invalid empty path"}, result};
    }

    fs::path p(path);
    if (!fs::exists(p)) {
      ECM rcm = {EC::PathNotExist, AMStr::fmt("Path not found: {}", path)};
      trace(AMDomain::client::TraceLevel::Error, EC::PathNotExist, path,
            "listdir", rcm.second);
      return {rcm, result};
    }
    if (!fs::is_directory(p)) {
      ECM rcm = {EC::NotADirectory,
                 AMStr::fmt("Path is not a directory: {}", path)};
      trace(AMDomain::client::TraceLevel::Error, EC::NotADirectory, path,
            "listdir", rcm.second);
      return {rcm, result};
    }

    std::error_code ec;
    fs::directory_iterator it(p, ec);
    if (ec) {
      ECM rcm = {fec(ec),
                 AMStr::fmt("listdir {} failed: {}", path, ec.message())};
      trace(AMDomain::client::TraceLevel::Error, rcm.first, path, "listdir",
            rcm.second);
      return {rcm, result};
    }

    for (const auto &entry : it) {
      if ((interrupt_flag && interrupt_flag->IsInterrupted())) {
        return {ECM{EC::Terminate, "Listdir interrupted by user"}, result};
      }
      if (IsTimedOut_(timeout_ms, start_time)) {
        return {ECM{EC::OperationTimeout, "Listdir timeout"}, result};
      }
      auto [error, info] = stat(entry.path().string(), false, timeout_ms,
                                start_time, interrupt_flag);
      if (error.first != EC::Success) {
        continue;
      }
      result.push_back(info);
    }

    return {ECM{EC::Success, ""}, result};
  }

  [[nodiscard]] std::pair<ECM, WRV>
  listdir(const std::string &path, int timeout_ms = -1, int64_t start_time = -1,
          amf interrupt_flag = nullptr) const override {
    return const_cast<AMLocalIOCore *>(this)->listdir(
        path, timeout_ms, start_time, std::move(interrupt_flag));
  }
  std::pair<ECM, WRI> iwalk(const std::string &path, bool show_all = false,
                            bool ignore_special_file = true,
                            AMFS::WalkErrorCallback error_callback = nullptr,
                            int timeout_ms = -1, int64_t start_time = -1,
                            amf interrupt_flag = nullptr) override {
    start_time = NormalizeStartTime_(start_time);
    std::vector<PathInfo> result = {};
    RMR errors = {};

    auto [error, info] =
        stat(path, false, timeout_ms, start_time, interrupt_flag);
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

    std::unordered_set<std::string> all_dirs;
    std::unordered_set<std::string> has_subdir;
    const bool filter_hidden = !show_all;
    const bool filter_special = !show_all && ignore_special_file;
    const auto is_hidden_name = [](const std::string &name) {
      return !name.empty() && name[0] == '.';
    };

    std::error_code ec;
    fs::recursive_directory_iterator it(path, ec);
    fs::recursive_directory_iterator end;
    for (; it != end; it.increment(ec)) {
      if ((interrupt_flag && interrupt_flag->IsInterrupted())) {
        ECM out = {EC::Terminate, "iwalk interrupted by user"};
        if (error_callback && *error_callback) {
          (*error_callback)(path, out);
        }
        return {out, {result, errors}};
      }
      if (IsTimedOut_(timeout_ms, start_time)) {
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
        auto [stat_err, stat_info] = stat(
            entry_path.string(), false, timeout_ms, start_time, interrupt_flag);
        if (stat_err.first == EC::Success) {
          result.push_back(stat_info);
        } else {
          if (error_callback && *error_callback) {
            (*error_callback)(entry_path.string(), stat_err);
          }
          errors.emplace_back(entry_path.string(), stat_err);
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

    if (all_dirs.size() > has_subdir.size()) {
      result.reserve(result.size() + all_dirs.size() - has_subdir.size());
    }
    for (const auto &dir : all_dirs) {
      if (has_subdir.find(dir) == has_subdir.end()) {
        auto [stat_err, stat_info] =
            stat(dir, false, timeout_ms, start_time, interrupt_flag);
        if (stat_err.first == EC::Success) {
          result.push_back(stat_info);
        } else {
          if (error_callback && *error_callback) {
            (*error_callback)(dir, stat_err);
          }
          errors.emplace_back(dir, stat_err);
        }
      }
    }

    return {ECM{EC::Success, ""}, {result, errors}};
  }

  [[nodiscard]] std::pair<ECM, WRI>
  iwalk(const std::string &path, bool show_all = false,
        bool ignore_special_file = true,
        AMFS::WalkErrorCallback error_callback = nullptr, int timeout_ms = -1,
        int64_t start_time = -1, amf interrupt_flag = nullptr) const override {
    return const_cast<AMLocalIOCore *>(this)->iwalk(
        path, show_all, ignore_special_file, error_callback, timeout_ms,
        start_time, std::move(interrupt_flag));
  }

  std::pair<ECM, WRDR> walk(const std::string &path, int max_depth = -1,
                            bool show_all = false,
                            bool ignore_special_file = false,
                            AMFS::WalkErrorCallback error_callback = nullptr,
                            int timeout_ms = -1, int64_t start_time = -1,
                            amf interrupt_flag = nullptr) override {
    start_time = NormalizeStartTime_(start_time);
    WRD result = {};
    RMR errors = {};

    auto [error, info] =
        stat(path, false, timeout_ms, start_time, interrupt_flag);
    if (error.first != EC::Success) {
      if (error_callback && *error_callback) {
        (*error_callback)(path, error);
      }
      errors.emplace_back(path, error);
      return {error, {result, errors}};
    }
    if (info.type != PathType::DIR) {
      trace(AMDomain::client::TraceLevel::Error, EC::NotADirectory, path,
            "walk", AMStr::fmt("Path is not a directory: {}", path));
      ECM out = {EC::NotADirectory,
                 AMStr::fmt("Path is not a directory: {}", path)};
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
      if ((interrupt_flag && interrupt_flag->IsInterrupted())) {
        ECM out = {EC::Terminate, "Interrupted by user, no action conducted"};
        if (error_callback && *error_callback) {
          (*error_callback)(path, out);
        }
        errors.emplace_back(path, out);
        return {out, {result, errors}};
      }
      if (IsTimedOut_(timeout_ms, start_time)) {
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

      auto [stat_ecm, entry_info] = stat(entry_path.string(), false, timeout_ms,
                                         start_time, interrupt_flag);
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
              ignore_special_file) {
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
  int64_t getsize(const std::string &path, bool ignore_special_file = true,
                  int timeout_ms = -1, int64_t start_time = -1,
                  amf interrupt_flag = nullptr) override {
    start_time = NormalizeStartTime_(start_time);
    auto [rcm, info] =
        stat(path, false, timeout_ms, start_time, interrupt_flag);
    if (rcm.first != EC::Success) {
      return -1;
    }
    if (info.type != PathType::DIR) {
      return static_cast<int64_t>(info.size);
    }

    auto [walk_rcm, pack] = iwalk(path, true, ignore_special_file, nullptr,
                                  timeout_ms, start_time, interrupt_flag);
    if (walk_rcm.first != EC::Success ||
        (interrupt_flag && interrupt_flag->IsInterrupted())) {
      return -1;
    }

    int64_t size = 0;
    for (const auto &item : pack.first) {
      size += static_cast<int64_t>(item.size);
    }
    return size;
  }

  std::vector<PathInfo> find(const std::string &path,
                             SearchType type = SearchType::All,
                             int timeout_ms = -1, int64_t start_time = -1,
                             amf interrupt_flag = nullptr) override {
    if ((interrupt_flag && interrupt_flag->IsInterrupted())) {
      return {};
    }
    return BasePathMatch::find(path, type, timeout_ms, start_time,
                               std::move(interrupt_flag));
  }

  ECM mkdir(const std::string &path, int timeout_ms = -1,
            int64_t start_time = -1, amf interrupt_flag = nullptr) override {
    start_time = NormalizeStartTime_(start_time);
    if (path.empty()) {
      return {EC::InvalidArg, "Invalid empty path"};
    }
    if ((interrupt_flag && interrupt_flag->IsInterrupted())) {
      return {EC::Terminate, "Interrupted by user"};
    }
    if (IsTimedOut_(timeout_ms, start_time)) {
      return {EC::OperationTimeout, "mkdir timeout"};
    }

    std::error_code ec;
    fs::create_directory(fs::path(path), ec);
    if (ec) {
      ECM rcm = {fec(ec),
                 AMStr::fmt("mkdir {} failed: {}", path, ec.message())};
      trace(AMDomain::client::TraceLevel::Error, rcm.first, path, "mkdir",
            rcm.second);
      return rcm;
    }
    return {EC::Success, ""};
  }

  ECM mkdirs(const std::string &path, int timeout_ms = -1,
             int64_t start_time = -1, amf interrupt_flag = nullptr) override {
    start_time = NormalizeStartTime_(start_time);
    if (path.empty()) {
      return {EC::InvalidArg, "Invalid empty path"};
    }
    if ((interrupt_flag && interrupt_flag->IsInterrupted())) {
      return {EC::Terminate, "Interrupted by user"};
    }
    if (IsTimedOut_(timeout_ms, start_time)) {
      return {EC::OperationTimeout, "mkdirs timeout"};
    }

    std::error_code ec;
    fs::create_directories(fs::path(path), ec);
    if (ec) {
      ECM rcm = {fec(ec),
                 AMStr::fmt("mkdirs {} failed: {}", path, ec.message())};
      trace(AMDomain::client::TraceLevel::Error, rcm.first, path, "mkdirs",
            rcm.second);
      return rcm;
    }
    return {EC::Success, ""};
  }

  ECM rename(const std::string &src, const std::string &dst,
             bool mkdir_parent = true, bool overwrite = false,
             int timeout_ms = -1, int64_t start_time = -1,
             amf interrupt_flag = nullptr) override {
    start_time = NormalizeStartTime_(start_time);
    if (src.empty() || dst.empty()) {
      return {EC::InvalidArg, "Invalid empty path"};
    }
    if ((interrupt_flag && interrupt_flag->IsInterrupted())) {
      return {EC::Terminate, "Interrupted by user"};
    }
    if (IsTimedOut_(timeout_ms, start_time)) {
      return {EC::OperationTimeout, "rename timeout"};
    }

    std::error_code ec;
    auto [src_ecm, src_info] =
        stat(src, false, timeout_ms, start_time, interrupt_flag);
    auto [dst_ecm, dst_info] =
        stat(dst, false, timeout_ms, start_time, interrupt_flag);
    if (src_ecm.first != EC::Success) {
      return {src_ecm.first, AMStr::fmt("src {} not exist", src)};
    }
    if (dst_ecm.first == EC::Success) {
      if ((src_info.type == PathType::DIR && dst_info.type != PathType::DIR) ||
          (src_info.type != PathType::DIR && dst_info.type == PathType::DIR)) {
        return {EC::NotADirectory, "src and dst are not the same type"};
      }
      if (!overwrite) {
        return {EC::PathAlreadyExists,
                AMStr::fmt("dst {} already exists", dst)};
      }
    }

    if (mkdir_parent) {
      ECM mk_rcm = mkdirs(AMPathStr::dirname(dst), timeout_ms, start_time,
                          interrupt_flag);
      if (mk_rcm.first != EC::Success) {
        return mk_rcm;
      }
    }

    fs::rename(fs::path(src), fs::path(dst), ec);
    if (ec == std::errc::cross_device_link) {
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
      return {fec(ec),
              AMStr::fmt("rename {} to {} failed: {}", src, dst, ec.message())};
    }
    return {EC::Success, ""};
  }

  ECM rmdir(const std::string &path, int timeout_ms = -1,
            int64_t start_time = -1, amf interrupt_flag = nullptr) override {
    start_time = NormalizeStartTime_(start_time);
    if (path.empty()) {
      return {EC::InvalidArg, "Invalid empty path"};
    }
    auto [error, info] =
        stat(path, false, timeout_ms, start_time, interrupt_flag);
    if (error.first != EC::Success) {
      return error;
    }
    if (info.type != PathType::DIR) {
      return {EC::NotADirectory, "Path is not a directory"};
    }

    std::error_code ec;
    fs::remove(fs::path(path), ec);
    if (ec) {
      return {fec(ec), AMStr::fmt("rmdir {} failed: {}", path, ec.message())};
    }
    return {EC::Success, ""};
  }

  ECM rmfile(const std::string &path, int timeout_ms = -1,
             int64_t start_time = -1, amf interrupt_flag = nullptr) override {
    start_time = NormalizeStartTime_(start_time);
    if (path.empty()) {
      return {EC::InvalidArg, "Invalid empty path"};
    }
    auto [error, info] =
        stat(path, false, timeout_ms, start_time, interrupt_flag);
    if (error.first != EC::Success) {
      return error;
    }
    if (info.type == PathType::DIR) {
      return {EC::NotAFile, "Path is a directory"};
    }

    std::error_code ec;
    fs::remove(fs::path(path), ec);
    if (ec) {
      return {fec(ec), AMStr::fmt("rmfile {} failed: {}", path, ec.message())};
    }
    return {EC::Success, ""};
  }

  std::pair<ECM, RMR> remove(const std::string &path,
                             AMFS::WalkErrorCallback error_callback = nullptr,
                             int timeout_ms = -1, int64_t start_time = -1,
                             amf interrupt_flag = nullptr) override {
    start_time = NormalizeStartTime_(start_time);
    if (path.empty()) {
      return {ECM{EC::InvalidArg, "Invalid empty path"}, RMR{}};
    }

    auto [error, info] =
        stat(path, false, timeout_ms, start_time, interrupt_flag);
    if (error.first != EC::Success) {
      if (error_callback && *error_callback) {
        (*error_callback)(path, error);
      }
      return {error, RMR{}};
    }

    RMR errors = {};
    std::error_code ec;
    if (info.type == PathType::DIR) {
      _remove(path, errors, error_callback, timeout_ms, start_time,
              interrupt_flag);
    } else {
      fs::remove(fs::path(path), ec);
      if (ec) {
        ECM out = {fec(ec),
                   AMStr::fmt("remove {} failed: {}", path, ec.message())};
        if (error_callback && *error_callback) {
          (*error_callback)(path, out);
        }
        return {out, errors};
      }
    }

    if ((interrupt_flag && interrupt_flag->IsInterrupted())) {
      return {{EC::Terminate, "Interrupted by user"}, errors};
    }
    if (IsTimedOut_(timeout_ms, start_time)) {
      return {{EC::OperationTimeout, "remove timeout"}, errors};
    }

    return {ECM{EC::Success, ""}, errors};
  }

  ECM saferm(const std::string &path, int timeout_ms = -1,
             int64_t start_time = -1, amf interrupt_flag = nullptr) override {
    start_time = NormalizeStartTime_(start_time);
    if (path.empty()) {
      return {EC::InvalidArg, "Invalid empty path"};
    }
    if ((interrupt_flag && interrupt_flag->IsInterrupted())) {
      return {EC::Terminate, "Interrupted by user"};
    }
    if (IsTimedOut_(timeout_ms, start_time)) {
      return {EC::OperationTimeout, "saferm timeout"};
    }

    const ConRequest request = request_atomic_.lock().load();
    if (request.trash_dir.empty()) {
      return {EC::PathNotExist, "Trash directory is not set"};
    }

    auto [error, info] =
        stat(path, false, timeout_ms, start_time, interrupt_flag);
    if (error.first != EC::Success) {
      return error;
    }

    std::string base = AMPathStr::basename(path);
    std::string base_name = base;
    std::string base_ext = "";

    if (info.type != PathType::DIR) {
      auto base_info = AMPathStr::split_basename(base);
      base_name = base_info.first;
      base_ext = base_info.second;
    }

    const std::string current_time =
        FormatTime(std::time(nullptr), "%Y-%m-%d-%H-%M-%S");

    auto build_target_name = [&](const std::string &name) {
      return base_ext.empty() ? name : (name + "." + base_ext);
    };

    std::string target_path = AMPathStr::join(request.trash_dir, current_time,
                                              build_target_name(base_name));

    size_t i = 1;
    while (true) {
      std::error_code ec;
      const bool exists = fs::exists(target_path, ec);
      if (ec) {
        return {fec(ec), AMStr::fmt("saferm check {} failed: {}", target_path,
                                    ec.message())};
      }
      if (!exists) {
        break;
      }
      std::string base_name_tmp = base_name + "(" + std::to_string(i) + ")";
      target_path = AMPathStr::join(request.trash_dir, current_time,
                                    build_target_name(base_name_tmp));
      ++i;
    }

    ECM mk_rcm = mkdirs(AMPathStr::join(request.trash_dir, current_time),
                        timeout_ms, start_time, interrupt_flag);
    if (mk_rcm.first != EC::Success) {
      return mk_rcm;
    }

    return rename(path, target_path, false, false, timeout_ms, start_time,
                  interrupt_flag);
  }

  ECM copy(const std::string &src, const std::string &dst,
           bool need_mkdir = false, int timeout_ms = -1,
           amf interrupt_flag = nullptr) override {
    int64_t start_time = AMTime::miliseconds();
    if (src.empty() || dst.empty()) {
      return {EC::InvalidArg, "Invalid empty path"};
    }
    if ((interrupt_flag && interrupt_flag->IsInterrupted())) {
      return {EC::Terminate, "Interrupted by user"};
    }
    if (IsTimedOut_(timeout_ms, start_time)) {
      return {EC::OperationTimeout, "copy timeout"};
    }

    auto [src_ecm, src_info] =
        stat(src, false, timeout_ms, start_time, interrupt_flag);
    if (src_ecm.first != EC::Success) {
      return src_ecm;
    }

    if (need_mkdir) {
      ECM mk_rcm = mkdirs(AMPathStr::dirname(dst), timeout_ms, start_time,
                          interrupt_flag);
      if (mk_rcm.first != EC::Success) {
        return mk_rcm;
      }
    }

    std::error_code ec;
    if (src_info.type == PathType::DIR) {
      fs::copy(src, dst,
               fs::copy_options::recursive |
                   fs::copy_options::overwrite_existing,
               ec);
    } else {
      fs::copy_file(src, dst, fs::copy_options::overwrite_existing, ec);
    }

    if (ec) {
      return {fec(ec),
              AMStr::fmt("copy {} to {} failed: {}", src, dst, ec.message())};
    }
    return {EC::Success, ""};
  }
};

