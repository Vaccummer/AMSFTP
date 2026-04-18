#pragma once
// Internal dependencies
#include "infrastructure/client/common/Base.hpp"

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
#ifdef _WIN32
#include <windows.h>
#endif

namespace AMInfra::client::LOCAL {
class AMLocalIOCore : public ClientIOBase {
private:
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

  [[nodiscard]] static std::optional<ECM>
  BuildStopRCM_(const ControlComponent &control, const std::string &operation,
                const std::string &target) {
    if (auto stop_rcm = control.BuildECM(operation, target);
        stop_rcm.has_value()) {
      return stop_rcm;
    }
    return control.BuildRequestECM(operation, target);
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
    if (result.starts_with(unc_prefix)) {
      result = L"\\\\" + result.substr(unc_prefix.size());
    } else if (result.starts_with(prefix)) {
      result = result.substr(prefix.size());
    }
    return AMStr::wstr(result);
  }
#endif

#ifdef _WIN32
  ECMData<AMFSI::RunResult>
  ConductCmdWindowsBackend_(const AMFSI::ConductCmdArgs &args,
                            const ControlComponent &control) {
    ECMData<AMFSI::RunResult> out = {};
    const std::string target = args.cmd.empty() ? "<empty>" : args.cmd;

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = nullptr;
    sa.bInheritHandle = TRUE;

    HANDLE read_pipe = nullptr;
    HANDLE write_pipe = nullptr;
    if (!CreatePipe(&read_pipe, &write_pipe, &sa, 0)) {
      out.rcm = {EC::UnknownError, "", "", "CreatePipe failed"};
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
      out.rcm = {EC::UnknownError, "", "", "CreateProcess failed"};
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
    std::optional<ECM> stop_rcm = std::nullopt;
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
      stop_rcm = BuildStopRCM_(control, "ConductCmd", target);
      if (stop_rcm.has_value()) {
        if (job_handle) {
          (void)TerminateJobObject(job_handle, 1);
        } else {
          (void)TerminateProcess(pi.hProcess, 1);
        }
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

    if (stop_rcm.has_value()) {
      out.rcm = std::move(*stop_rcm);
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
  ECMData<AMFSI::RunResult>
  ConductCmdPosixBackend_(const AMFSI::ConductCmdArgs &args,
                          const ControlComponent &control) {
    ECMData<AMFSI::RunResult> out = {};
    const std::string target = args.cmd.empty() ? "<empty>" : args.cmd;

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
    std::optional<ECM> stop_rcm = std::nullopt;
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
      stop_rcm = BuildStopRCM_(control, "ConductCmd", target);
      if (stop_rcm.has_value()) {
        kill_child(SIGKILL);
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

    if (stop_rcm.has_value()) {
      out.rcm = std::move(*stop_rcm);
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
                InterruptControl *control_port, TraceCallback trace_cb = {},
                AuthCallback auth_cb = {})
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
    config_part_->SetState({OK, AMDomain::client::ClientStatus::OK});
  }

  ~AMLocalIOCore() override = default;
  ECMData<AMFSI::UpdateOSTypeResult>
  UpdateOSType(const AMFSI::UpdateOSTypeArgs &args,
               const ControlComponent &control) override {
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

  ECMData<AMFSI::UpdateHomeDirResult>
  UpdateHomeDir(const AMFSI::UpdateHomeDirArgs &args,
                const ControlComponent &control) override {
    (void)args;
    ECMData<AMFSI::UpdateHomeDirResult> out = {};
    const std::string target =
        config_part_ ? config_part_->GetNickname() : std::string{"local"};
    if (auto stop_rcm = BuildStopRCM_(control, "UpdateHomeDir", target);
        stop_rcm.has_value()) {
      out.rcm = std::move(*stop_rcm);
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

  ECMData<AMFSI::CheckResult> Check(const AMFSI::CheckArgs &args,
                                    const ControlComponent &control) override {
    (void)args;
    ECMData<AMFSI::CheckResult> out = {};
    out.data.status = config_part_->GetState().data.status;
    if (auto stop_rcm = BuildStopRCM_(control, "Check", ".");
        stop_rcm.has_value()) {
      out.rcm = std::move(*stop_rcm);
      return out;
    }
    out.rcm = OK;
    out.data.status = AMDomain::client::ClientStatus::OK;
    config_part_->SetState({out.rcm, out.data.status});
    return out;
  }

  ECMData<AMFSI::ConnectResult>
  Connect(const AMFSI::ConnectArgs &args,
          const ControlComponent &control) override {
    (void)args;
    ECMData<AMFSI::ConnectResult> out = {};
    out.data.status = config_part_->GetState().data.status;
    const auto request = config_part_->GetRequest();
    const std::string connect_target =
        AMStr::fmt("{}@{}", request.nickname, request.hostname);
    if (auto stop_rcm = BuildStopRCM_(control, "Connect", connect_target);
        stop_rcm.has_value()) {
      out.rcm = std::move(*stop_rcm);
      return out;
    }
    connect_state("initialize local client", connect_target);
    out.rcm = OK;
    out.data.status = AMDomain::client::ClientStatus::OK;
    config_part_->SetState({out.rcm, out.data.status});
    connect_state("local client ready", connect_target);
    return out;
  }

  ECMData<AMFSI::RTTResult> GetRTT(const AMFSI::GetRTTArgs &args,
                                   const ControlComponent &control) override {
    (void)args;
    ECMData<AMFSI::RTTResult> out = {};
    out.data.rtt_ms = 0.0;
    out.rcm = {EC::UnImplentedMethod, "", "",
               "GetRTT is not supported for local client"};
    return out;
  }

  ECMData<AMFSI::RunResult>
  ConductCmd(const AMFSI::ConductCmdArgs &args,
             const ControlComponent &control) override {
    ECMData<AMFSI::RunResult> out = {};
    const std::string target = args.cmd.empty() ? "<empty>" : args.cmd;
    if (auto stop_rcm = BuildStopRCM_(control, "ConductCmd", target);
        stop_rcm.has_value()) {
      out.rcm = std::move(*stop_rcm);
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

  ECMData<AMFSI::StatResult> stat(const AMFSI::StatArgs &args,
                                  const ControlComponent &control) override {
    ECMData<AMFSI::StatResult> out = {};
    if (args.path.empty()) {
      out.rcm = {EC::InvalidArg, "stat", "<empty>", "Invalid empty path"};
      out.data.info = {};
      return out;
    }
    if (auto stop_rcm = BuildStopRCM_(control, "stat", args.path);
        stop_rcm.has_value()) {
      out.rcm = std::move(*stop_rcm);
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

  ECMData<AMFSI::ListResult> listdir(const AMFSI::ListdirArgs &args,
                                     const ControlComponent &control) override {
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
    if (auto stop_rcm = BuildStopRCM_(control, "listdir", args.path);
        stop_rcm.has_value()) {
      out.rcm = std::move(*stop_rcm);
      out.data.entries = {};
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
      if (auto stop_rcm = BuildStopRCM_(control, "listdir", args.path);
          stop_rcm.has_value()) {
        out.rcm = std::move(*stop_rcm);
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
            const ControlComponent &control) override {
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
    if (auto stop_rcm = BuildStopRCM_(control, "listnames", args.path);
        stop_rcm.has_value()) {
      out.rcm = std::move(*stop_rcm);
      out.data.names = {};
      return out;
    }

    std::vector<std::string> names = {};
    for (const auto &entry : it) {
      if (auto stop_rcm = BuildStopRCM_(control, "listnames", args.path);
          stop_rcm.has_value()) {
        out.rcm = std::move(*stop_rcm);
        out.data.names = std::move(names);
        return out;
      }
      names.push_back(entry.path().filename().string());
    }
    out.rcm = OK;
    out.data.names = std::move(names);
    return out;
  }

  ECMData<AMFSI::MkdirResult> mkdir(const AMFSI::MkdirArgs &args,
                                    const ControlComponent &control) override {
    ECMData<AMFSI::MkdirResult> out = {};
    if (args.path.empty()) {
      out.rcm = {EC::InvalidArg, "mkdir", "<empty>", "Invalid empty path"};
      return out;
    }
    if (auto stop_rcm = BuildStopRCM_(control, "mkdir", args.path);
        stop_rcm.has_value()) {
      out.rcm = std::move(*stop_rcm);
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
         const ControlComponent &control) override {
    ECMData<AMFSI::MkdirsResult> out = {};
    const std::string raw_path = AMStr::Strip(args.path);
    if (raw_path.empty()) {
      out.rcm = {EC::InvalidArg, "mkdirs", "<empty>", "Invalid empty path"};
      return out;
    }
    if (auto stop_rcm = BuildStopRCM_(control, "mkdirs", raw_path);
        stop_rcm.has_value()) {
      out.rcm = std::move(*stop_rcm);
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
      const std::string stop_target = current.empty() ? raw_path : current;
      if (auto stop_rcm = BuildStopRCM_(control, "mkdirs", stop_target);
          stop_rcm.has_value()) {
        out.rcm = std::move(*stop_rcm);
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

  ECMData<AMFSI::RMResult> rmdir(const AMFSI::RmdirArgs &args,
                                 const ControlComponent &control) override {
    ECMData<AMFSI::RMResult> out = {};
    if (auto stop_rcm = BuildStopRCM_(control, "rmdir", args.path);
        stop_rcm.has_value()) {
      out.rcm = std::move(*stop_rcm);
      return out;
    }
    std::error_code ec;
    fs::remove(fs::path(args.path), ec);
    if (ec) {
      out.rcm = BuildFsError_("rmdir", args.path, ec);
      return out;
    }
    out.rcm = OK;
    return out;
  }

  ECMData<AMFSI::RMResult> rmfile(const AMFSI::RmfileArgs &args,
                                  const ControlComponent &control) override {
    ECMData<AMFSI::RMResult> out = {};
    if (auto stop_rcm = BuildStopRCM_(control, "rmfile", args.path);
        stop_rcm.has_value()) {
      out.rcm = std::move(*stop_rcm);
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

  ECMData<AMFSI::MoveResult> rename(const AMFSI::RenameArgs &args,
                                    const ControlComponent &control) override {
    ECMData<AMFSI::MoveResult> out = {};
    const std::string rename_target =
        AMStr::fmt("{} -> {}", args.src, args.dst);
    if (auto stop_rcm = BuildStopRCM_(control, "rename", rename_target);
        stop_rcm.has_value()) {
      out.rcm = std::move(*stop_rcm);
      return out;
    }
    std::error_code ec;
    fs::rename(fs::path(args.src), fs::path(args.dst), ec);
    if (ec == std::errc::cross_device_link) {
      out.rcm = {EC::OperationUnsupported, "rename", rename_target,
                 "cross-device link"};
      return out;
    }
    if (ec) {
      out.rcm = BuildFsError_("rename", rename_target, ec);
      return out;
    }
    out.rcm = OK;
    return out;
  }
};
} // namespace AMInfra::client::LOCAL
