#pragma once
#include <array>
#include <filesystem>
#include <stdexcept>

#ifndef _WIN32
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif
// Internal dependencies
#include "infrastructure/client/common/Base.hpp"
#ifdef _WIN32
#include <windows.h>
#endif

namespace AMInfra::client::LOCAL {
class AMLocalIOCore : public ClientIOBase {
private:
  void SetState_(const ECMData<AMDomain::filesystem::CheckResult> &state) {
    if (config_part_) {
      config_part_->SetState(state);
    }
  }

  [[nodiscard]] AMDomain::client::ClientStatus CurrentStatus_() const {
    if (!config_part_) {
      return AMDomain::client::ClientStatus::NotInitialized;
    }
    return config_part_->GetState().data.status;
  }

  [[nodiscard]] std::string GetHomeDir_() {
    std::string home_dir = config_part_ ? config_part_->GetHomeDir() : "";
    if (home_dir.empty()) {
      home_dir = AMPath::HomePath();
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

  [[nodiscard]] static ECM BuildFsError_(EC code, const std::string &operation,
                                         const std::string &target,
                                         const std::error_code &ec) {
    ECM out = {code, operation, target, ec.message()};
    if (ec) {
      out.raw_error = RawError{RawErrorSource::Filesystem, ec.value()};
    }
    return out;
  }

  [[nodiscard]] static ECM BuildFsError_(const std::string &operation,
                                         const std::string &target,
                                         const std::error_code &ec) {
    return BuildFsError_(fec(ec), operation, target, ec);
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

#ifdef _WIN32
  ECMData<AMFSI::RunResult> ConductCmdWindowsBackend_(
      const AMFSI::ConductCmdArgs &args,
      const AMDomain::client::ClientControlComponent &control) {
    ECMData<AMFSI::RunResult> out = {};

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = nullptr;
    sa.bInheritHandle = TRUE;

    HANDLE read_pipe = nullptr;
    HANDLE write_pipe = nullptr;
    if (!CreatePipe(&read_pipe, &write_pipe, &sa, 0)) {
      out.rcm = {EC::UnknownError, "unspecified", "<unknown>", "CreatePipe failed"};
      out.data.output = "";
      out.data.exit_code = -1;
      return out;
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
    std::wstring wcmd = AMStr::wstr(args.cmd);
    std::vector<wchar_t> cmd_buf(wcmd.begin(), wcmd.end());
    cmd_buf.push_back(L'\0');

    BOOL created =
        CreateProcessW(nullptr, cmd_buf.data(), nullptr, nullptr, TRUE,
                       CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(write_pipe);

    if (!created) {
      CloseHandle(read_pipe);
      out.rcm = {EC::UnknownError, "unspecified", "<unknown>", "CreateProcess failed"};
      out.data.output = "";
      out.data.exit_code = -1;
      return out;
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
    enum class WinOutEncoding { Unknown, Utf16Le, Oem };
    WinOutEncoding encoding = WinOutEncoding::Unknown;
    bool utf16_bom_checked = false;
    std::string probe;
    std::string utf16_pending;

    const auto detect_utf16le = [&](const std::string &bytes) {
      if (bytes.size() >= 2 && static_cast<unsigned char>(bytes[0]) == 0xFF &&
          static_cast<unsigned char>(bytes[1]) == 0xFE) {
        return true;
      }
      size_t pair_count = 0;
      size_t odd_zero = 0;
      size_t even_zero = 0;
      for (size_t i = 0; i + 1 < bytes.size() && pair_count < 8; i += 2) {
        ++pair_count;
        if (static_cast<unsigned char>(bytes[i]) == 0U) {
          ++even_zero;
        }
        if (static_cast<unsigned char>(bytes[i + 1]) == 0U) {
          ++odd_zero;
        }
      }
      return pair_count >= 2 && odd_zero >= pair_count - 1 && even_zero == 0;
    };

    const auto decode_utf16le_bytes = [&](std::string &raw_bytes) {
      if (!utf16_bom_checked) {
        utf16_bom_checked = true;
        if (raw_bytes.size() >= 2 &&
            static_cast<unsigned char>(raw_bytes[0]) == 0xFF &&
            static_cast<unsigned char>(raw_bytes[1]) == 0xFE) {
          raw_bytes.erase(0, 2);
        }
      }

      const size_t even_size = raw_bytes.size() & ~static_cast<size_t>(1);
      if (even_size == 0) {
        return std::string{};
      }
      std::wstring ws;
      ws.reserve(even_size / 2);
      for (size_t i = 0; i < even_size; i += 2) {
        const auto lo = static_cast<unsigned char>(raw_bytes[i]);
        const auto hi = static_cast<unsigned char>(raw_bytes[i + 1]);
        const wchar_t ch =
            static_cast<wchar_t>(static_cast<unsigned int>(lo) |
                                 (static_cast<unsigned int>(hi) << 8U));
        ws.push_back(ch);
      }
      raw_bytes.erase(0, even_size);
      return AMStr::wstr(ws);
    };

    const auto emit_chunk = [&](const char *data, size_t size) {
      if (size == 0) {
        return;
      }
      std::string current(data, size);
      if (encoding == WinOutEncoding::Unknown) {
        probe.append(current);
        if (probe.size() < 4) {
          return;
        }
        encoding = detect_utf16le(probe) ? WinOutEncoding::Utf16Le
                                         : WinOutEncoding::Oem;
        current.swap(probe);
        probe.clear();
      }

      std::string text_utf8;
      if (encoding == WinOutEncoding::Utf16Le) {
        utf16_pending.append(current);
        text_utf8 = decode_utf16le_bytes(utf16_pending);
      } else {
        text_utf8 = std::move(current);
      }

      if (text_utf8.empty()) {
        return;
      }
      output.append(text_utf8);
      if (args.processor) {
        args.processor(text_utf8);
      }
    };

    while (true) {
      if (control.IsInterrupted()) {
        if (job_handle) {
          (void)TerminateJobObject(job_handle, 1);
        } else {
          (void)TerminateProcess(pi.hProcess, 1);
        }
        interrupted = true;
        finished = true;
        break;
      }
      if (control.IsTimeout()) {
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
          emit_chunk(buffer.data(), static_cast<size_t>(read_bytes));
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
        emit_chunk(buffer.data(), static_cast<size_t>(read_bytes));
      }
    }

    CloseHandle(read_pipe);
    if (job_handle) {
      CloseHandle(job_handle);
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (encoding == WinOutEncoding::Unknown && !probe.empty()) {
      std::string tail = std::move(probe);
      if (!tail.empty()) {
        output.append(tail);
        if (args.processor) {
          args.processor(tail);
        }
      }
      probe.clear();
    } else if (encoding == WinOutEncoding::Utf16Le && !utf16_pending.empty()) {
      std::string tail = decode_utf16le_bytes(utf16_pending);
      if (!tail.empty()) {
        output.append(tail);
        if (args.processor) {
          args.processor(tail);
        }
      }
    }

    if (interrupted) {
      out.rcm = {EC::Terminate, "unspecified", "<unknown>", "Command interrupted"};
      out.data.output = std::move(output);
      out.data.exit_code = exit_status;
      return out;
    }
    if (timed_out) {
      out.rcm = {EC::OperationTimeout, "unspecified", "<unknown>", "Command timed out"};
      out.data.output = std::move(output);
      out.data.exit_code = exit_status;
      return out;
    }
    out.rcm = OK;
    out.data.output = std::move(output);
    out.data.exit_code = exit_status;
    return out;
  }
#else
  ECMData<AMFSI::RunResult> ConductCmdPosixBackend_(
      const AMFSI::ConductCmdArgs &args,
      const AMDomain::client::ClientControlComponent &control) {
    ECMData<AMFSI::RunResult> out = {};

    int pipefd[2] = {-1, -1};
    if (pipe(pipefd) != 0) {
      out.rcm = {fec(std::error_code(errno, std::generic_category())),
                 "pipe failed"};
      out.data.output = "";
      out.data.exit_code = -1;
      return out;
    }

    pid_t pid = fork();
    if (pid < 0) {
      close(pipefd[0]);
      close(pipefd[1]);
      out.rcm = {fec(std::error_code(errno, std::generic_category())),
                 "fork failed"};
      out.data.output = "";
      out.data.exit_code = -1;
      return out;
    }

    if (pid == 0) {
      dup2(pipefd[1], STDOUT_FILENO);
      dup2(pipefd[1], STDERR_FILENO);
      close(pipefd[0]);
      close(pipefd[1]);
      execl("/bin/sh", "sh", "-c", args.cmd.c_str(), (char *)nullptr);
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
    const auto emit_chunk = [&](const char *data, size_t size) {
      output.append(data, size);
      if (args.processor) {
        args.processor(std::string_view(data, size));
      }
    };

    auto kill_child = [&](int sig) {
      if (!child_exited) {
        (void)kill(pid, sig);
      }
    };

    while (true) {
      if (control.IsInterrupted()) {
        kill_child(SIGKILL);
        interrupted = true;
        break;
      }
      if (control.IsTimeout()) {
        kill_child(SIGKILL);
        timed_out = true;
        break;
      }

      pollfd pfd;
      pfd.fd = pipefd[0];
      pfd.events = POLLIN | POLLHUP;
      pfd.revents = 0;
      int pr = poll(&pfd, 1, 10);
      if (pr > 0 && (pfd.revents & (POLLIN | POLLHUP)) != 0) {
        while (true) {
          ssize_t n = read(pipefd[0], buffer.data(), buffer.size());
          if (n > 0) {
            emit_chunk(buffer.data(), static_cast<size_t>(n));
            continue;
          }
          if (n == 0) {
            child_exited = true;
            break;
          }
          if (errno == EAGAIN || errno == EWOULDBLOCK) {
            break;
          }
          child_exited = true;
          break;
        }
      } else if (pr < 0 && errno != EINTR) {
        child_exited = true;
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
            emit_chunk(buffer.data(), static_cast<size_t>(n));
            continue;
          }
          break;
        }
        break;
      }
    }

    close(pipefd[0]);

    if (!child_exited) {
      int status = 0;
      if (waitpid(pid, &status, 0) == pid) {
        if (WIFEXITED(status)) {
          exit_status = WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
          exit_status = 128 + WTERMSIG(status);
        }
      }
    }

    if (interrupted) {
      out.rcm = {EC::Terminate, "unspecified", "<unknown>", "Command interrupted"};
      out.data.output = std::move(output);
      out.data.exit_code = exit_status;
      return out;
    }
    if (timed_out) {
      out.rcm = {EC::OperationTimeout, "unspecified", "<unknown>", "Command timed out"};
      out.data.output = std::move(output);
      out.data.exit_code = exit_status;
      return out;
    }
    out.rcm = OK;
    out.data.output = std::move(output);
    out.data.exit_code = exit_status;
    return out;
  }
#endif

public:
  AMLocalIOCore(AMDomain::client::IClientConfigPort *config_port,
                AMDomain::client::IClientControlToken *control_port,
                TraceCallback trace_cb = {}, AuthCallback auth_cb = {})
      : ClientIOBase(config_port, control_port) {
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
      config_part_->SetHomeDir(AMPath::HomePath());
    }
    (void)UpdateOSType({}, {});
    SetState_({OK, AMDomain::client::ClientStatus::OK});
  }

  ~AMLocalIOCore() override = default;
  ECMData<AMFSI::UpdateOSTypeResult> UpdateOSType(
      const AMFSI::UpdateOSTypeArgs &args,
      const AMDomain::client::ClientControlComponent &control) override {
    (void)args;
    ECMData<AMFSI::UpdateOSTypeResult> out = {};
#ifdef _WIN32
    out.data.os_type = OS_TYPE::Windows;
#elif defined(_WIN64)
    out.data.os_type = OS_TYPE::Windows;
#elif defined(__linux__) || defined(__gnu_linux__)
    out.data.os_type = OS_TYPE::Linux;
#elif defined(__APPLE__) && defined(__MACH__)
    out.data.os_type = OS_TYPE::MacOS;
#elif defined(__FreeBSD__)
    out.data.os_type = OS_TYPE::FreeBSD;
#else
    out.data.os_type = OS_TYPE::Unknown;
#endif
    if (config_part_) {
      config_part_->SetOSType(out.data.os_type);
    }
    out.rcm = OK;
    return out;
  }

  ECMData<AMFSI::UpdateHomeDirResult> UpdateHomeDir(
      const AMFSI::UpdateHomeDirArgs &args,
      const AMDomain::client::ClientControlComponent &control) override {
    (void)args;
    ECMData<AMFSI::UpdateHomeDirResult> out = {};
    if (control.IsTimeout()) {
      out.rcm = ECM{EC::OperationTimeout, "unspecified", "<unknown>", "Operation timed out"};
      out.data.home_dir = "";
      return out;
    }
    out.data.home_dir = AMPath::HomePath();
    if (config_part_) {
      config_part_->SetHomeDir(out.data.home_dir);
    }
    out.rcm = OK;
    return out;
  }

  ECMData<AMFSI::CheckResult>
  Check(const AMFSI::CheckArgs &args,
        const AMDomain::client::ClientControlComponent &control) override {
    (void)args;
    ECMData<AMFSI::CheckResult> out = {};
    out.data.status = CurrentStatus_();
    if (control.IsTimeout()) {
      out.rcm = {EC::OperationTimeout, "unspecified", "<unknown>", "Operation timed out"};
      return out;
    }
    if (control.IsInterrupted()) {
      out.rcm = {EC::Terminate, "unspecified", "<unknown>", "Interrupted by user"};
      return out;
    }
    out.rcm = OK;
    out.data.status = AMDomain::client::ClientStatus::OK;
    SetState_({out.rcm, out.data.status});
    return out;
  }

  ECMData<AMFSI::ConnectResult>
  Connect(const AMFSI::ConnectArgs &args,
          const AMDomain::client::ClientControlComponent &control) override {
    (void)args;
    ECMData<AMFSI::ConnectResult> out = {};
    out.data.status = CurrentStatus_();
    if (control.IsTimeout()) {
      out.rcm = {EC::OperationTimeout, "unspecified", "<unknown>", "Operation timed out"};
      return out;
    }
    if (control.IsInterrupted()) {
      out.rcm = {EC::Terminate, "unspecified", "<unknown>", "Interrupted by user"};
      return out;
    }
    out.rcm = OK;
    out.data.status = AMDomain::client::ClientStatus::OK;
    SetState_({out.rcm, out.data.status});
    return out;
  }

  ECMData<AMFSI::RTTResult>
  GetRTT(const AMFSI::GetRTTArgs &args,
         const AMDomain::client::ClientControlComponent &control) override {
    (void)args;
    (void)control;
    ECMData<AMFSI::RTTResult> out = {};
    out.data.rtt_ms = 0.0;
    out.rcm = {EC::UnImplentedMethod, "unspecified", "<unknown>", "GetRTT is not supported for local client"};
    return out;
  }

  ECMData<AMFSI::RunResult>
  ConductCmd(const AMFSI::ConductCmdArgs &args,
             const AMDomain::client::ClientControlComponent &control) override {
    ECMData<AMFSI::RunResult> out = {};
    if (control.IsTimeout()) {
      out.rcm = {EC::OperationTimeout, "unspecified", "<unknown>", "Operation timed out"};
      out.data.output = "";
      out.data.exit_code = -1;
      return out;
    }
    if (control.IsInterrupted()) {
      out.rcm = {EC::Terminate, "unspecified", "<unknown>", "Interrupted by user"};
      out.data.output = "";
      out.data.exit_code = -1;
      return out;
    }
#ifdef _WIN32
    return ConductCmdWindowsBackend_(args, control);
#else
    return ConductCmdPosixBackend_(args, control);
#endif
  }

  ECMData<AMFSI::StatResult>
  stat(const AMFSI::StatArgs &args,
       const AMDomain::client::ClientControlComponent &control) override {
    ECMData<AMFSI::StatResult> out = {};
    if (args.path.empty()) {
      out.rcm = {EC::InvalidArg, "stat", "<empty>", "Invalid empty path"};
      out.data.info = {};
      return out;
    }
    std::error_code ec;
    if (!fs::exists(fs::path(args.path), ec)) {
      if (ec) {
        out.rcm = BuildFsError_("stat", args.path, ec);
      } else {
        out.rcm = {EC::PathNotExist, "stat", args.path, "Path not found"};
      }
      out.data.info = {};
      return out;
    }

    PathInfo info;
    std::string pathf = args.path;
#ifdef _WIN32
    std::string real_path = ResolveRealCasePath_(args.path, args.trace_link);
    if (!real_path.empty()) {
      pathf = std::move(real_path);
    }
#endif

    fs::path p(pathf);
    info.name = p.filename().string();
    info.path = pathf;
    info.dir = p.parent_path().string();

    fs::file_status status;
    if (args.trace_link) {
      status = fs::status(p, ec);
    } else {
      status = fs::symlink_status(p, ec);
    }

    if (ec) {
      out.rcm = BuildFsError_("stat", pathf, ec);
      trace(AMDomain::client::TraceLevel::Error, out.rcm.code, pathf, "stat",
            out.rcm.error);
      out.data.info = info;
      return out;
    }

    info.type = cast_fs_type(status.type());

    const auto size_f = fs::file_size(p, ec);
    if (!ec) {
      info.size = size_f;
    } else {
      ec.clear();
    }

#ifdef _WIN32
    if (AMPath::is_readonly(AMStr::wstr(pathf))) {
      info.mode_int = 0300;
      info.mode_str = "r--------";
    } else {
      info.mode_int = 0600;
      info.mode_str = "rwx------";
    }

    auto [create_time, access_time, modify_time] =
        AMPath::GetTime(AMStr::wstr(pathf));
    info.create_time = create_time;
    info.access_time = access_time;
    info.modify_time = modify_time;
    info.owner = AMPath::GetFileOwner(AMStr::wstr(pathf));
#else
    struct stat file_stat;
    if (::stat(args.path.c_str(), &file_stat) == -1) {
      const std::error_code sec(errno, std::generic_category());
      out.rcm = BuildFsError_("stat", args.path, sec);
      out.data.info = info;
      return out;
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

    out.rcm = OK;
    out.data.info = info;
    return out;
  }

  ECMData<AMFSI::ListResult>
  listdir(const AMFSI::ListdirArgs &args,
          const AMDomain::client::ClientControlComponent &control) override {
    ECMData<AMFSI::ListResult> out = {};
    if (args.path.empty()) {
      out.rcm = {EC::InvalidArg, "listdir", "<empty>", "Invalid empty path"};
      out.data.entries = {};
      return out;
    }
    std::error_code ec;
    if (!fs::exists(fs::path(args.path), ec)) {
      if (ec) {
        out.rcm.code = fec(ec);
        out.rcm.error = ec.message();
        out.rcm.target = args.path;
        out.rcm.operation = "listdir";
        out.rcm.raw_error = {RawErrorSource::Filesystem, ec.value()};
      } else {
        out.rcm.code = EC::PathNotExist;
        out.rcm.error = "Path not found";
        out.rcm.target = args.path;
        out.rcm.operation = "listdir";
      }
      trace(AMDomain::client::TraceLevel::Error, out.rcm.code, args.path,
            "listdir", out.rcm.error);
      return out;
    } else if (!fs::is_directory(fs::path(args.path), ec)) {
      if (ec) {
        out.rcm.code = fec(ec);
        out.rcm.error = ec.message();
        out.rcm.target = args.path;
        out.rcm.operation = "listdir";
        out.rcm.raw_error = {RawErrorSource::Filesystem, ec.value()};
      } else {
        out.rcm.code = EC::NotADirectory;
        out.rcm.error = "Path is not a directory";
        out.rcm.target = args.path;
        out.rcm.operation = "listdir";
      }
      trace(AMDomain::client::TraceLevel::Error, out.rcm.code, args.path,
            "listdir", out.rcm.error);
      return out;
    }
    std::vector<PathInfo> entries = {};

    fs::directory_iterator it(args.path, ec);

    if (ec) {
      out.rcm.code = fec(ec);
      out.rcm.error = ec.message();
      out.rcm.target = args.path;
      out.rcm.operation = "listdir";
      out.rcm.raw_error = {RawErrorSource::Filesystem, ec.value()};
      trace(AMDomain::client::TraceLevel::Error, out.rcm.code, args.path,
            "listdir", out.rcm.error);
      out.data.entries = {};
      return out;
    }

    for (const auto &entry : it) {
      if (control.IsInterrupted()) {
        out.rcm = {EC::Terminate, "listdir", args.path,
                   "Interrupted by user"};
        out.data.entries = std::move(entries);
        return out;
      }
      if (control.IsTimeout()) {
        out.rcm = {EC::OperationTimeout, "listdir", args.path,
                   "Operation timed out"};
        out.data.entries = std::move(entries);
        return out;
      }

      auto stat_res =
          stat(AMFSI::StatArgs{entry.path().string(), false}, control);
      if (stat_res.rcm.code != EC::Success) {
        continue;
      }
      entries.push_back(std::move(stat_res.data.info));
    }
    out.rcm = OK;
    out.data.entries = std::move(entries);
    return out;
  }

  ECMData<AMFSI::ListNamesResult>
  listnames(const AMFSI::ListNamesArgs &args,
            const AMDomain::client::ClientControlComponent &control) override {
    ECMData<AMFSI::ListNamesResult> out = {};
    if (args.path.empty()) {
      out.rcm = {EC::InvalidArg, "listnames", "<empty>", "Invalid empty path"};
      out.data.names = {};
      return out;
    }
    std::error_code ec;
    fs::directory_iterator it(args.path, ec);
    if (ec) {
      out.rcm = BuildFsError_("listnames", args.path, ec);
      trace(AMDomain::client::TraceLevel::Error, out.rcm.code, args.path,
            "listnames", out.rcm.error);
      out.data.names = {};
      return out;
    }

    std::vector<std::string> names = {};
    for (const auto &entry : it) {
      if (control.IsInterrupted()) {
        out.rcm = {EC::Terminate, "listnames", args.path,
                   "Interrupted by user"};
        out.data.names = std::move(names);
        return out;
      }
      if (control.IsTimeout()) {
        out.rcm = {EC::OperationTimeout, "listnames", args.path,
                   "Operation timed out"};
        out.data.names = std::move(names);
        return out;
      }
      names.push_back(entry.path().filename().string());
    }
    out.rcm = OK;
    out.data.names = std::move(names);
    return out;
  }

  ECMData<AMFSI::MkdirResult>
  mkdir(const AMFSI::MkdirArgs &args,
        const AMDomain::client::ClientControlComponent &control) override {
    ECMData<AMFSI::MkdirResult> out = {};
    if (args.path.empty()) {
      out.rcm = {EC::InvalidArg, "mkdir", "<empty>", "Invalid empty path"};
      return out;
    }
    if (fs::exists(fs::path(args.path))) {
      if (!fs::is_directory(fs::path(args.path))) {
        out.rcm.code = EC::PathAlreadyExists;
        out.rcm.error = "Path already exists and is not a directory";
        out.rcm.target = args.path;
        out.rcm.operation = "mkdir";
        return out;
      } else {
        return out;
      }
    }
    std::error_code ec;
    fs::create_directory(fs::path(args.path), ec);
    if (ec) {
      ECM rcm = BuildFsError_("mkdir", args.path, ec);
      trace(AMDomain::client::TraceLevel::Error, rcm.code, args.path, "mkdir",
            rcm.error);
      out.rcm = rcm;
      return out;
    }
    out.rcm = OK;
    return out;
  }

  ECMData<AMFSI::MkdirsResult>
  mkdirs(const AMFSI::MkdirsArgs &args,
         const AMDomain::client::ClientControlComponent &control) override {
    ECMData<AMFSI::MkdirsResult> out = {};
    const std::string raw_path = AMStr::Strip(args.path);
    if (raw_path.empty()) {
      out.rcm = {EC::InvalidArg, "mkdirs", "<empty>", "Invalid empty path"};
      return out;
    }
    if (control.IsInterrupted()) {
      out.rcm = {EC::Terminate, "mkdirs", raw_path, "Interrupted by user"};
      return out;
    }
    if (control.IsTimeout()) {
      out.rcm = {EC::OperationTimeout, "mkdirs", raw_path,
                 "Operation timed out"};
      return out;
    }

    const std::vector<std::string> parts = AMPath::split(raw_path);
    if (parts.empty()) {
      out.rcm =
          Err(EC::InvalidArg, "mkdirs", raw_path, "Invalid path for mkdirs");
      return out;
    }

    std::string current = "";
    for (const auto &part : parts) {
      if (control.IsInterrupted()) {
        out.rcm = {EC::Terminate, "mkdirs", current, "Interrupted by user"};
        return out;
      }
      if (control.IsTimeout()) {
        out.rcm = {EC::OperationTimeout, "mkdirs", current,
                   "Operation timed out"};
        return out;
      }

      current = current.empty() ? part : AMPath::join(current, part);
      auto mkdir_result = mkdir({current}, control);
      if (!(mkdir_result.rcm)) {
        out.rcm = mkdir_result.rcm;
        return out;
      }
    }
    out.rcm = OK;
    return out;
  }

  ECMData<AMFSI::RMResult>
  rmdir(const AMFSI::RmdirArgs &args,
        const AMDomain::client::ClientControlComponent &control) override {
    ECMData<AMFSI::RMResult> out = {};
    std::error_code ec;
    fs::remove(fs::path(args.path), ec);
    if (ec) {
      out.rcm = BuildFsError_("rmdir", args.path, ec);
      return out;
    }
    out.rcm = OK;
    return out;
  }

  ECMData<AMFSI::RMResult>
  rmfile(const AMFSI::RmfileArgs &args,
         const AMDomain::client::ClientControlComponent &control) override {
    ECMData<AMFSI::RMResult> out = {};
    if (control.IsTimeout()) {
      out.rcm = {EC::OperationTimeout, "rmfile", args.path,
                 "Operation timed out"};
      return out;
    }
    std::error_code ec;
    fs::remove(fs::path(args.path), ec);
    if (ec) {
      out.rcm = BuildFsError_("rmfile", args.path, ec);
      return out;
    }
    out.rcm = OK;
    return out;
  }

  ECMData<AMFSI::MoveResult>
  rename(const AMFSI::RenameArgs &args,
         const AMDomain::client::ClientControlComponent &control) override {
    ECMData<AMFSI::MoveResult> out = {};
    std::error_code ec;
    fs::rename(fs::path(args.src), fs::path(args.dst), ec);
    if (ec == std::errc::cross_device_link) {
      out.rcm = {EC::OperationUnsupported, "rename",
                 AMStr::fmt("{} -> {}", args.src, args.dst),
                 "cross-device link"};
      return out;
    }
    if (ec) {
      out.rcm = BuildFsError_("rename", AMStr::fmt("{} -> {}", args.src, args.dst),
                              ec);
      return out;
    }
    out.rcm = OK;
    return out;
  }

  // legacy functions, will be moved to application layer in the future
  /*
  _remove(const std::string &path, RMR &errors, ...)
  iwalk(const std::string &path, bool show_all, bool ignore_special_file, ...)
  walk(const std::string &path, int max_depth, bool show_all, ...)
  getsize(const std::string &path, bool ignore_special_file, ...)
  find(const std::string &path, SearchType type, ...)
  mkdirs(const std::string &path, ...)
  remove(const std::string &path, AMPath::WalkErrorCallback error_callback, ...)
  saferm(const std::string &path, ...)
  copy(const std::string &src, const std::string &dst, ...)

  void _remove(const std::string &path, RMR &errors,
               AMPath::WalkErrorCallback error_callback = nullptr,
               int timeout_ms = -1, int64_t start_time = -1,
               amf interrupt_flag = nullptr) {
    if (((interrupt_flag && interrupt_flag->IsInterrupted()))) {
      ECM out = {EC::Terminate, "unspecified", "<unknown>", "Interrupted by user"};
      if (error_callback && *error_callback) {
        (*error_callback)(path, out);
      }
      errors.emplace_back(path, out);
      return;
    }
    if (IsTimedOut_(timeout_ms, start_time)) {
      ECM out = {EC::OperationTimeout, "unspecified", "<unknown>", "remove timeout"};
      if (error_callback && *error_callback) {
        (*error_callback)(path, out);
      }
      errors.emplace_back(path, out);
      return;
    }

    std::error_code ec;
    auto [error, listing] =
        ListdirPath_(path, timeout_ms, start_time, interrupt_flag);
    if (error.code != EC::Success) {
      if (error_callback && *error_callback) {
        (*error_callback)(path, error);
      }
      errors.emplace_back(path, error);
      return;
    }

    for (const auto &entry : listing) {
      if (((interrupt_flag && interrupt_flag->IsInterrupted()))) {
        ECM out = {EC::Terminate, "unspecified", "<unknown>", "Interrupted by user"};
        if (error_callback && *error_callback) {
          (*error_callback)(entry.path, out);
        }
        errors.emplace_back(entry.path, out);
        return;
      }
      if (IsTimedOut_(timeout_ms, start_time)) {
        ECM out = {EC::OperationTimeout, "unspecified", "<unknown>", "remove timeout"};
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
          ECM out = BuildFsError_("remove", entry.path, ec);
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
      ECM out = BuildFsError_("remove", path, ec);
      if (error_callback && *error_callback) {
        (*error_callback)(path, out);
      }
      errors.emplace_back(path, out);
    }
  }
  std::pair<ECM, WRI> iwalk(const std::string &path, bool show_all = false,
                            bool ignore_special_file = true,
                            AMPath::WalkErrorCallback error_callback = nullptr,
                            int timeout_ms = -1, int64_t start_time = -1,
                            amf interrupt_flag = nullptr) {
    start_time = NormalizeStartTime_(start_time);
    std::vector<PathInfo> result = {};
    RMR errors = {};

    auto [error, info] =
        StatPath_(path, false, timeout_ms, start_time, interrupt_flag);
    if (error.code != EC::Success) {
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
      if (((interrupt_flag && interrupt_flag->IsInterrupted()))) {
        ECM out = {EC::Terminate, "unspecified", "<unknown>", "iwalk interrupted by user"};
        if (error_callback && *error_callback) {
          (*error_callback)(path, out);
        }
        return {out, {result, errors}};
      }
      if (IsTimedOut_(timeout_ms, start_time)) {
        ECM out = {EC::OperationTimeout, "unspecified", "<unknown>", "iwalk timeout"};
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
        if (stat_err.code == EC::Success) {
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
            StatPath_(dir, false, timeout_ms, start_time, interrupt_flag);
        if (stat_err.code == EC::Success) {
          result.push_back(stat_info);
        } else {
          if (error_callback && *error_callback) {
            (*error_callback)(dir, stat_err);
          }
          errors.emplace_back(dir, stat_err);
        }
      }
    }

    return {ECMOK, {result, errors}};
  }

  [[nodiscard]] std::pair<ECM, WRI>
  iwalk(const std::string &path, bool show_all = false,
        bool ignore_special_file = true,
        AMPath::WalkErrorCallback error_callback = nullptr, int timeout_ms = -1,
        int64_t start_time = -1, amf interrupt_flag = nullptr) const {
    return const_cast<AMLocalIOCore *>(this)->iwalk(
        path, show_all, ignore_special_file, error_callback, timeout_ms,
        start_time, interrupt_flag);
  }

  std::pair<ECM, WRDR> walk(const std::string &path, int max_depth = -1,
                            bool show_all = false,
                            bool ignore_special_file = false,
                            AMPath::WalkErrorCallback error_callback = nullptr,
                            int timeout_ms = -1, int64_t start_time = -1,
                            amf interrupt_flag = nullptr) {
    start_time = NormalizeStartTime_(start_time);
    WRD result = {};
    RMR errors = {};

    auto [error, info] =
        StatPath_(path, false, timeout_ms, start_time, interrupt_flag);
    if (error.code != EC::Success) {
      if (error_callback && *error_callback) {
        (*error_callback)(path, error);
      }
      errors.emplace_back(path, error);
      return {error, {result, errors}};
    }
    if (info.type != PathType::DIR) {
      trace(AMDomain::client::TraceLevel::Error, EC::NotADirectory, path,
            "walk", "Path is not a directory");
      ECM out = {EC::NotADirectory, "walk", path, "Path is not a directory"};
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
      if (((interrupt_flag && interrupt_flag->IsInterrupted()))) {
        ECM out = {EC::Terminate, "unspecified", "<unknown>", "Interrupted by user, no action conducted"};
        if (error_callback && *error_callback) {
          (*error_callback)(path, out);
        }
        errors.emplace_back(path, out);
        return {out, {result, errors}};
      }
      if (IsTimedOut_(timeout_ms, start_time)) {
        ECM out = {EC::OperationTimeout, "unspecified", "<unknown>", "walk timeout"};
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

      auto [stat_ecm, entry_info] = StatPath_(
          entry_path.string(), false, timeout_ms, start_time, interrupt_flag);
      if (stat_ecm.code != EC::Success) {
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

    return {OK, {result, errors}};
  }
  int64_t getsize(const std::string &path, bool ignore_special_file = true,
                  int timeout_ms = -1, int64_t start_time = -1,
                  amf interrupt_flag = nullptr) {
    start_time = NormalizeStartTime_(start_time);
    auto [rcm, info] =
        StatPath_(path, false, timeout_ms, start_time, interrupt_flag);
    if (rcm.code != EC::Success) {
      return -1;
    }
    if (info.type != PathType::DIR) {
      return static_cast<int64_t>(info.size);
    }

    auto [walk_rcm, pack] = iwalk(path, true, ignore_special_file, nullptr,
                                  timeout_ms, start_time, interrupt_flag);
    if (walk_rcm.code != EC::Success ||
        ((interrupt_flag && interrupt_flag->IsInterrupted()))) {
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
                             amf interrupt_flag = nullptr) {
    if (((interrupt_flag && interrupt_flag->IsInterrupted()))) {
      return {};
    }
    return BasePathMatch::find(path, type, timeout_ms, start_time,
                               interrupt_flag);
  }

  ECM mkdirs(const std::string &path, int timeout_ms = -1,
             int64_t start_time = -1, amf interrupt_flag = nullptr) {
    start_time = NormalizeStartTime_(start_time);
    if (path.empty()) {
      return {EC::InvalidArg, "unspecified", "<unknown>", "Invalid empty path"};
    }
    if (((interrupt_flag && interrupt_flag->IsInterrupted()))) {
      return {EC::Terminate, "unspecified", "<unknown>", "Interrupted by user"};
    }
    if (IsTimedOut_(timeout_ms, start_time)) {
      return {EC::OperationTimeout, "unspecified", "<unknown>", "mkdirs timeout"};
    }

    std::error_code ec;
    fs::create_directories(fs::path(path), ec);
    if (ec) {
      ECM rcm = BuildFsError_("mkdirs", path, ec);
      trace(AMDomain::client::TraceLevel::Error, rcm.code, path, "mkdirs",
            rcm.error);
      return rcm;
    }
    return OK;
  }

  std::pair<ECM, RMR> remove(const std::string &path,
                             AMPath::WalkErrorCallback error_callback = nullptr,
                             int timeout_ms = -1, int64_t start_time = -1,
                             amf interrupt_flag = nullptr) {
    start_time = NormalizeStartTime_(start_time);
    if (path.empty()) {
      return {ECM{EC::InvalidArg, "unspecified", "<unknown>", "Invalid empty path"}, RMR{}};
    }

    auto [error, info] =
        StatPath_(path, false, timeout_ms, start_time, interrupt_flag);
    if (error.code != EC::Success) {
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
        ECM out = BuildFsError_("remove", path, ec);
        if (error_callback && *error_callback) {
          (*error_callback)(path, out);
        }
        return {out, errors};
      }
    }

    if (((interrupt_flag && interrupt_flag->IsInterrupted()))) {
      return {{EC::Terminate, "unspecified", "<unknown>", "Interrupted by user"}, errors};
    }
    if (IsTimedOut_(timeout_ms, start_time)) {
      return {{EC::OperationTimeout, "unspecified", "<unknown>", "remove timeout"}, errors};
    }

    return {ECMOK, errors};
  }

  ECM saferm(const std::string &path, int timeout_ms = -1,
             int64_t start_time = -1, amf interrupt_flag = nullptr) {
    start_time = NormalizeStartTime_(start_time);
    if (path.empty()) {
      return {EC::InvalidArg, "unspecified", "<unknown>", "Invalid empty path"};
    }
    if (((interrupt_flag && interrupt_flag->IsInterrupted()))) {
      return {EC::Terminate, "unspecified", "<unknown>", "Interrupted by user"};
    }
    if (IsTimedOut_(timeout_ms, start_time)) {
      return {EC::OperationTimeout, "unspecified", "<unknown>", "saferm timeout"};
    }

    const ConRequest request = request_atomic_.lock().load();
    if (request.trash_dir.empty()) {
      return {EC::PathNotExist, "unspecified", "<unknown>", "Trash directory is not set"};
    }

    auto [error, info] =
        StatPath_(path, false, timeout_ms, start_time, interrupt_flag);
    if (error.code != EC::Success) {
      return error;
    }

    std::string base = AMPath::basename(path);
    std::string base_name = base;
    std::string base_ext = "";

    if (info.type != PathType::DIR) {
      auto base_info = AMPath::split_basename(base);
      base_name = base_info.first;
      base_ext = base_info.second;
    }

    const std::string current_time =
        FormatTime(std::time(nullptr), "%Y-%m-%d-%H-%M-%S");

    auto build_target_name = [&](const std::string &name) {
      return base_ext.empty() ? name : (name + "." + base_ext);
    };

    std::string target_path = AMPath::join(request.trash_dir, current_time,
                                              build_target_name(base_name));

    size_t i = 1;
    while (true) {
      std::error_code ec;
      const bool exists = fs::exists(target_path, ec);
      if (ec) {
        return BuildFsError_("saferm.check", target_path, ec);
      }
      if (!exists) {
        break;
      }
      std::string base_name_tmp = base_name + "(" + std::to_string(i) + ")";
      target_path = AMPath::join(request.trash_dir, current_time,
                                    build_target_name(base_name_tmp));
      ++i;
    }

    ECM mk_rcm = mkdirs(AMPath::join(request.trash_dir, current_time),
                        timeout_ms, start_time, interrupt_flag);
    if (mk_rcm.code != EC::Success) {
      return mk_rcm;
    }

    return rename(AMFSI::RenameArgs{path, target_path, false, false},
                  AMDomain::client::ClientControlComponent(
                      std::move(interrupt_flag), timeout_ms));
  }*/
};
} // namespace AMInfra::client::LOCAL
