#include "domain/client/ClientModel.hpp"
#include "domain/transfer/TransferDomainModel.hpp"
#include "foundation/core/DataClass.hpp"
#include "foundation/tools/string.hpp"
#include "foundation/tools/time.hpp"
#include "infrastructure/client/ftp/FTP.hpp"
#include "infrastructure/client/http/HTTP.hpp"
#include "infrastructure/client/sftp/SFTP.hpp"
#include "infrastructure/transfer/RuntimeProgress.hpp"
#include "infrastructure/transfer/engine/TransferExecutionDetail.hpp"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <curl/curl.h>
#include <mutex>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#endif

// TransferRuntimeProgress
namespace AMInfra::transfer {

using AMDomain::transfer::TransferControl;

TransferRuntimeProgress::TransferRuntimeProgress(TaskHandle task)
    : task_info(std::move(task)) {}

void TransferRuntimeProgress::CallInnerCallback(bool force) {
  if (!task_info || !task_info->Set.callback.need_progress_cb) {
    return;
  }

  auto cur_task = task_info->GetCurrentTaskSnapshot();
  if (!cur_task.has_value()) {
    return;
  }

  const double now = AMTime::seconds();
  if (!force && ((now - cb_time) <= task_info->Set.callback.cb_interval_s)) {
    return;
  }
  cb_time = now;

  ECM cb_error = {ErrorCode::Success, ""};
  auto ctrl_opt = task_info->Set.callback.CallProgress(
      ProgressCBInfo(
          cur_task->src, cur_task->dst, cur_task->src_host, cur_task->dst_host,
          cur_task->transferred, cur_task->size,
          task_info->Size.transferred.load(std::memory_order_relaxed),
          task_info->Size.total.load(std::memory_order_relaxed)),
      &cb_error);

  if (cb_error.code != ErrorCode::Success &&
      task_info->Set.callback.need_error_cb) {
    task_info->Set.callback.CallError(
        ErrorCBInfo(cb_error, cur_task->src, cur_task->dst, cur_task->src_host,
                    cur_task->dst_host));
  }

  if (!ctrl_opt.has_value()) {
    return;
  }

  switch (*ctrl_opt) {
  case TransferControl::Running:
    if (!task_info->IsTerminateRequested()) {
      task_info->SetRunningIntent();
      task_info->ClearInterrupt();
    }
    break;
  case TransferControl::Pause:
    task_info->RequestPause();
    break;
  case TransferControl::Terminate:
    task_info->RequestInterrupt();
    break;
  default:
    break;
  }
}

void TransferRuntimeProgress::UpdateSize(size_t delta) const {
  if (!task_info || delta == 0) {
    return;
  }
  const size_t current = task_info->Size.cur_task_transferred.fetch_add(
                             delta, std::memory_order_relaxed) +
                         delta;
  task_info->Size.transferred.fetch_add(delta, std::memory_order_relaxed);
  auto cur_guard = task_info->Core.cur_task.lock();
  auto *cur_task = cur_guard.load();
  if (cur_task != nullptr) {
    cur_task->transferred = current;
  }
}

TransferTask *TransferRuntimeProgress::GetCurrentTask() const {
  if (!task_info) {
    return nullptr;
  }
  return task_info->GetCurrentTask();
}

} // namespace AMInfra::transfer

namespace {
using ECM = ECM;
using EC = ErrorCode;
using ClientHandle = AMInfra::transfer::ClientHandle;
using RuntimeProgress = AMInfra::transfer::TransferRuntimeProgress;
using TaskInfo = AMDomain::transfer::TaskInfo;
using TaskHandle = AMInfra::transfer::TaskHandle;
using ClientProtocol = AMDomain::client::ClientProtocol;
using AMSFTPIOCore = AMInfra::client::SFTP::AMSFTPIOCore;
using AMFTPIOCore = AMInfra::client::FTP::AMFTPIOCore;
using AMHTTPIOCore = AMInfra::client::HTTP::AMHTTPIOCore;
using TransferTask = AMDomain::transfer::TransferTask;
using TaskStatus = AMDomain::transfer::TaskStatus;
using AMDomain::transfer::TaskID;
using TaskRegistry = AMAtomic<std::unordered_map<TaskID, TaskHandle>>;
using TransferClientContainer = AMDomain::transfer::TransferClientContainer;
using TransferBufferPolicy = AMInfra::transfer::TransferBufferPolicy;
using SftpWriteStats = AMInfra::transfer::SftpWriteStats;
constexpr const char *kHttpUserAgent = "amsftp-wget/1.0";
constexpr const char *kHttpProxyKey = "http.proxy";
constexpr const char *kHttpMaxRedirectTimesKey = "http.max_redirect_times";
constexpr const char *kHttpBearerTokenKey = "http.bear_token";

void NoteSftpWriteRequest_(RuntimeProgress *pd, size_t request_size) {
  if (pd == nullptr || pd->sftp_write_stats == nullptr || request_size == 0) {
    return;
  }
  auto &stats = *pd->sftp_write_stats;
  ++stats.write_requests;
  stats.logical_requested_bytes += static_cast<uint64_t>(request_size);
  stats.max_request_bytes =
      std::max<uint64_t>(stats.max_request_bytes, request_size);
}

void NoteSftpWriteAttempt_(RuntimeProgress *pd, size_t request_size,
                           ssize_t rc) {
  if (pd == nullptr || pd->sftp_write_stats == nullptr || request_size == 0) {
    return;
  }

  auto &stats = *pd->sftp_write_stats;
  const double now = AMTime::seconds();
  if (stats.libssh2_calls == 0) {
    stats.first_call_time = now;
  }
  stats.last_call_time = now;

  ++stats.libssh2_calls;
  stats.attempted_bytes += static_cast<uint64_t>(request_size);

  if (rc == LIBSSH2_ERROR_EAGAIN) {
    ++stats.eagain_retries;
    return;
  }
  if (rc < 0) {
    ++stats.fatal_errors;
    return;
  }

  ++stats.success_calls;
  if (rc == 0) {
    ++stats.zero_writes;
    return;
  }

  const auto written = static_cast<uint64_t>(rc);
  stats.written_bytes += written;
  stats.max_written_bytes = std::max(stats.max_written_bytes, written);
  if (written < request_size) {
    ++stats.short_writes;
  }
}

struct HttpTransferRuntime {
  std::string proxy = {};
  std::string bear_token = {};
  std::string username = {};
  std::string password = {};
  int max_redirect_times = 0;
};

HttpTransferRuntime LoadHttpTransferRuntime_(const ClientHandle &client) {
  HttpTransferRuntime runtime = {};
  if (!client) {
    return runtime;
  }

  bool proxy_found = false;
  bool redirect_found = false;
  bool token_found = false;

  const auto proxy_q =
      client->MetaDataPort().QueryNamedValue<std::string>(kHttpProxyKey);
  if (proxy_q.name_found && proxy_q.type_match && proxy_q.value.has_value()) {
    runtime.proxy = AMStr::Strip(*proxy_q.value);
    proxy_found = true;
  }

  const auto redirect_q =
      client->MetaDataPort().QueryNamedValue<int>(kHttpMaxRedirectTimesKey);
  if (redirect_q.name_found && redirect_q.type_match &&
      redirect_q.value.has_value()) {
    runtime.max_redirect_times = std::max(0, *redirect_q.value);
    redirect_found = true;
  }

  const auto token_q =
      client->MetaDataPort().QueryNamedValue<std::string>(kHttpBearerTokenKey);
  if (token_q.name_found && token_q.type_match && token_q.value.has_value()) {
    runtime.bear_token = AMStr::Strip(*token_q.value);
    token_found = true;
  }

  if (auto *http_io = dynamic_cast<AMHTTPIOCore *>(&client->IOPort());
      http_io != nullptr) {
    if (!proxy_found) {
      runtime.proxy = AMStr::Strip(http_io->Proxy());
    }
    if (!redirect_found) {
      runtime.max_redirect_times = std::max(0, http_io->MaxRedirectTimes());
    }
    if (!token_found) {
      runtime.bear_token = AMStr::Strip(http_io->BearerToken());
    }
  }
  const auto request = client->ConfigPort().GetRequest();
  runtime.username = AMStr::Strip(request.username);
  runtime.password = request.password;

  runtime.proxy = AMStr::Strip(runtime.proxy);
  runtime.bear_token = AMStr::Strip(runtime.bear_token);
  if (runtime.max_redirect_times < 0) {
    runtime.max_redirect_times = 0;
  }
  return runtime;
}

[[nodiscard]] ECM ContextualizeTransferRCM_(ECM rcm, std::string operation,
                                            const std::string &target) {
  rcm.operation = std::move(operation);
  rcm.target = target;
  return rcm;
}

[[nodiscard]] ECM EnsureTransferClientReady_(const ClientHandle &client,
                                             const char *operation) {
  if (!client) {
    return Err(EC::InvalidHandle, operation ? operation : "transfer_guard",
               "<client>", "Client handle is null");
  }

  bool terminal_active = false;
  bool type_mismatch = false;
  client->MetaDataPort().MutateNamedValue<bool>(
      "terminal.lease", [&](bool *leased, bool name_found, bool type_match) {
        if (!name_found) {
          terminal_active = false;
          return;
        }
        if (!type_match || !leased) {
          type_mismatch = true;
          return;
        }
        terminal_active = *leased;
      });

  if (type_mismatch) {
    return Err(EC::CommonFailure, operation ? operation : "transfer_guard",
               "<client>", "terminal.lease metadata type is invalid");
  }
  if (!terminal_active) {
    return OK;
  }
  return Err(EC::PathUsingByOthers, operation ? operation : "transfer_guard",
             client->ConfigPort().GetNickname(), "Client terminal is active");
}

bool IsTaskHardInterrupted_(const TaskHandle &task_info) {
  if (!task_info) {
    return false;
  }
  if (task_info->Core.control.IsTimeout()) {
    return true;
  }
  const auto token = task_info->Core.control.ControlToken();
  return token && token->IsInterrupt();
}

bool IsTaskInterrupted_(const RuntimeProgress &pd) {
  return pd.io_abort.load(std::memory_order_relaxed) ||
         IsTaskHardInterrupted_(pd.task_info);
}

int ResolveRingBufferWaitMs_(const RuntimeProgress &pd) {
  if (!pd.task_info) {
    return -1;
  }
  const auto remain_ms = pd.task_info->Core.control.RemainingTimeMs();
  if (!remain_ms.has_value()) {
    return -1;
  }
  return static_cast<int>(std::min<size_t>(*remain_ms, size_t{60 * 1000}));
}

void SignalTaskIoAbort_(RuntimeProgress &pd) {
  pd.io_abort.store(true, std::memory_order_relaxed);
  if (pd.ring_buffer) {
    pd.ring_buffer->NotifyAll();
  }
}

bool IsTaskIDUsedHelper(const TaskID &task_id, TaskRegistry &task_registry,
                        std::mutex &conducting_mtx,
                        const std::unordered_set<TaskID> &conducting_tasks) {
  {
    auto registry = task_registry.lock();
    if (registry->contains(task_id)) {
      return true;
    }
  }
  std::lock_guard<std::mutex> lock(conducting_mtx);
  return conducting_tasks.contains(task_id);
}

bool ShouldSkipTaskHelper(const TaskHandle &task_info) {
  if (!task_info) {
    return false;
  }
  if (task_info->IsPauseRequested()) {
    task_info->SetResult({EC::Success, "", "", "Task paused"});
    task_info->SetStatus(TaskStatus::Paused);
    task_info->Time.finish.store(AMTime::seconds(), std::memory_order_relaxed);
    return true;
  }
  if (IsTaskHardInterrupted_(task_info) && !task_info->IsPauseRequested()) {
    task_info->SetResult(
        {EC::Terminate, "", "", "Task terminated before start"});
    task_info->SetStatus(TaskStatus::Finished);
    task_info->Time.finish.store(AMTime::seconds(), std::memory_order_relaxed);
    return true;
  }
  return false;
}

void MarkUnfinishedTransferEntries_(
    const TaskHandle &task_info, ECM entry_rcm,
    const std::function<void(const std::optional<ECM> &)> &on_mark = {}) {
  if (!task_info) {
    return;
  }
  auto mark_one = [&](auto *tasks_atomic) {
    if (!tasks_atomic) {
      return;
    }
    auto tasks = tasks_atomic->lock();
    for (auto &task : *tasks) {
      if (task.IsFinished) {
        continue;
      }
      task.rcm = entry_rcm;
      task.IsFinished = true;
      if (on_mark) {
        on_mark(task.rcm);
      }
    }
  };
  mark_one(&task_info->Core.dir_tasks);
  mark_one(&task_info->Core.file_tasks);
}

size_t ClampBufferSizeByPolicy_(size_t requested,
                                const TransferBufferPolicy &p) {
  const size_t min_buffer = std::max<size_t>(1, p.min_buffer_size);
  const size_t max_buffer = std::max(min_buffer, p.max_buffer_size);
  return std::min<size_t>(std::max<size_t>(requested, min_buffer), max_buffer);
}

ClientHandle ResolveTaskClientHelper(const TransferClientContainer &clients,
                                     const std::string &nickname,
                                     bool use_dst_role) {
  if (use_dst_role) {
    return clients.GetDstClient(nickname);
  }
  return clients.GetSrcClient(nickname);
}

class UnionFileHandle {
public:
  // Local file handle
#ifdef _WIN32
  HANDLE file_handle = INVALID_HANDLE_VALUE;
#else
  int file_handle = -1;
#endif

  // SFTP file handle
  LIBSSH2_SFTP_HANDLE *sftp_handle = nullptr;
  AMSFTPIOCore *client = nullptr;
  RuntimeProgress *pd = nullptr;
  ControlComponent control = {};

  // Common members
  std::string path;
  bool is_write = false;
  size_t file_size = 0;
  size_t offset = 0;
  bool is_sftp = false;

  ~UnionFileHandle() { Close(); }

  void Close() {
    if (is_sftp) {
      if (sftp_handle) {
        if (client) {
          std::lock_guard<std::recursive_mutex> lock(client->TransferMutex());
          (void)client->NBPerform(control, [&]() {
            return libssh2_sftp_close_handle(sftp_handle);
          });
        }
        sftp_handle = nullptr;
      }
    } else {
#ifdef _WIN32
      if (file_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(file_handle);
        file_handle = INVALID_HANDLE_VALUE;
      }
#else
      if (file_handle != -1) {
        close(file_handle);
        file_handle = -1;
      }
#endif
    }
  }

  ECM Init(const std::string &path, size_t file_size,
           AMSFTPIOCore *client = nullptr, bool is_write = false,
           bool sequential = true, bool truncate = true,
           RuntimeProgress *progress = nullptr) {
    this->path = path;
    this->is_write = is_write;
    this->file_size = file_size;
    this->client = client;
    this->is_sftp = (client != nullptr);
    this->pd = progress;
    if (pd && pd->task_info) {
      control = pd->task_info->Core.control;
    } else {
      control = {};
    }

    if (is_sftp) {
      // SFTP file
      auto *sftp = client->SFTPHandle();
      if (sftp == nullptr) {
        return Err(EC::NoConnection, "transfer.file.open", path,
                   "SFTP session not initialized");
      }
      std::lock_guard<std::recursive_mutex> lock(client->TransferMutex());
      auto open_sftp = [&](int flags, long mode) {
        return client->NBPerform(control, [&]() {
          return libssh2_sftp_open(sftp, path.c_str(), flags, mode);
        });
      };

      if (is_write) {
        int flags = LIBSSH2_FXF_WRITE;
        if (truncate) {
          flags |= LIBSSH2_FXF_TRUNC | LIBSSH2_FXF_CREAT;
        }
        auto nb_res = open_sftp(flags, 0744);
        if (!nb_res) {
          return ContextualizeTransferRCM_(nb_res.rcm, "transfer.file.open",
                                           path);
        }
        sftp_handle = nb_res.value;
      } else {
        auto nb_res = open_sftp(LIBSSH2_FXF_READ, 0400);
        if (!nb_res) {
          return ContextualizeTransferRCM_(nb_res.rcm, "transfer.file.open",
                                           path);
        }
        sftp_handle = nb_res.value;
      }
      if (!sftp_handle) {
        return Err(client->GetLastEC(), "transfer.file.open", path,
                   AMStr::fmt("Open sftp file \"{}\" failed: {}", path,
                              client->GetLastErrorMsg()));
      }
    } else {
      // Local file
#ifdef _WIN32
      DWORD access = is_write ? (GENERIC_READ | GENERIC_WRITE) : GENERIC_READ;
      DWORD share = is_write ? 0 : FILE_SHARE_READ;
      DWORD creation =
          is_write ? (truncate ? CREATE_ALWAYS : OPEN_EXISTING) : OPEN_EXISTING;
      DWORD flags =
          sequential ? FILE_FLAG_SEQUENTIAL_SCAN : FILE_ATTRIBUTE_NORMAL;

      file_handle = CreateFileW(AMStr::wstr(path).c_str(), access, share,
                                nullptr, creation, flags, nullptr);

      if (file_handle == INVALID_HANDLE_VALUE) {
        const int win_ec = static_cast<int>(GetLastError());
        return {EC::LocalFileOpenError,
                AMStr::fmt("Failed to open local file \"{}\": error code {}",
                           path, win_ec),
                RawError{RawErrorSource::WindowsAPI, win_ec}};
      }
#else
      int flags = is_write ? O_RDWR : O_RDONLY;
      if (is_write && truncate) {
        flags |= (O_CREAT | O_TRUNC);
      }
      file_handle = open(path.c_str(), flags, 0644);

      if (file_handle == -1) {
        return {EC::LocalFileOpenError, "", "",
                AMStr::fmt("Failed to open local file \"{}\": {}", path,
                           strerror(errno))};
      }
#endif
    }

    return OK;
  }

  [[nodiscard]] bool IsValid() const {
    if (is_sftp) {
      return sftp_handle != nullptr;
    } else {
#ifdef _WIN32
      return file_handle != INVALID_HANDLE_VALUE;
#else
      return file_handle != -1;
#endif
    }
  }

  /**
   * @brief Seek to the specified offset for subsequent reads/writes.
   */
  ECM Seek(size_t new_offset) {
    if (!IsValid()) {
      return {EC::LocalFileOpenError, "", "", "File not initialized"};
    }
    if (new_offset == 0) {
      offset = 0;
      return OK;
    }
    if (is_sftp) {
      if (!client) {
        return {EC::InvalidArg, "", "", "SFTP client not available"};
      }
      std::lock_guard<std::recursive_mutex> lock(client->TransferMutex());
      libssh2_sftp_seek64(sftp_handle,
                          static_cast<libssh2_uint64_t>(new_offset));
      offset = new_offset;
      return OK;
    }
#ifdef _WIN32
    LARGE_INTEGER li;
    li.QuadPart = static_cast<LONGLONG>(new_offset);
    LARGE_INTEGER new_pos;
    if (!SetFilePointerEx(file_handle, li, &new_pos, FILE_BEGIN)) {
      const int win_ec = static_cast<int>(GetLastError());
      return {EC::LocalFileReadError,
              AMStr::fmt("Seek local file \"{}\" failed: error code {}", path,
                         win_ec),
              RawError{RawErrorSource::WindowsAPI, win_ec}};
    }
    offset = static_cast<size_t>(new_pos.QuadPart);
    return OK;
#else
    off_t res = lseek(file_handle, static_cast<off_t>(new_offset), SEEK_SET);
    if (res == static_cast<off_t>(-1)) {
      return {EC::LocalFileReadError, "", "",
              AMStr::fmt("Seek local file \"{}\" failed: {}", path,
                         strerror(errno))};
    }
    offset = static_cast<size_t>(res);
    return OK;
#endif
  }

  std::pair<ssize_t, ECM> Read() {
    if (!IsValid()) {
      return {-1, {EC::LocalFileOpenError, "", "", "File not initialized"}};
    }
    if (!pd || !pd->ring_buffer) {
      return {-1, {EC::InvalidArg, "", "", "Progress data not initialized"}};
    }

    auto write_span = pd->ring_buffer->get_write_span();
    char *write_ptr = write_span.data();
    size_t max_write = write_span.size();
    ssize_t to_read = std::min<ssize_t>(max_write, (file_size - offset));
    ssize_t bytes_read;
    if (to_read > 0) {
      if (is_sftp) {
        // SFTP read (non-blocking)
        std::lock_guard<std::recursive_mutex> lock(client->TransferMutex());
        auto nb_res = client->NBPerform(control, [&]() {
          return libssh2_sftp_read(sftp_handle, write_ptr, to_read);
        });
        if (!nb_res) {
          return {-1, ContextualizeTransferRCM_(nb_res.rcm,
                                                "transfer.file.read", path)};
        }
        bytes_read = nb_res.value;
        if (bytes_read > 0) {
          pd->ring_buffer->commit_write(bytes_read);
          offset += bytes_read;
          return {bytes_read, OK};
        }
        if (bytes_read == 0) {
          return {0, {EC::EndOfFile, "", "", "End of file"}};
        }
        return {bytes_read, Err(client->GetLastEC(), "transfer.file.read", path,
                                AMStr::fmt("Read sftp file \"{}\" failed: {}",
                                           path, client->GetLastErrorMsg()))};
      } else {
        // Local file read
#ifdef _WIN32
        DWORD bytes_read = 0;
        if (!ReadFile(file_handle, write_ptr, static_cast<DWORD>(to_read),
                      &bytes_read, nullptr)) {
          const int win_ec = static_cast<int>(GetLastError());
          return {-1,
                  {EC::LocalFileReadError,
                   AMStr::fmt("Read local file \"{}\" failed: error code {}",
                              path, win_ec),
                   RawError{RawErrorSource::WindowsAPI, win_ec}}};
        }
        if (bytes_read > 0) {
          pd->ring_buffer->commit_write(bytes_read);
          offset += bytes_read;
          return {static_cast<int>(bytes_read), OK};
        } else {
          return {0, {EC::EndOfFile, "", "", "End of file"}};
        }
#else
        ssize_t bytes_read = read(file_handle, write_ptr, to_read);
        if (bytes_read > 0) {
          pd->ring_buffer->commit_write(bytes_read);
          offset += bytes_read;
          return {static_cast<int>(bytes_read), OK};
        } else if (bytes_read == 0) {
          return {0, {EC::EndOfFile, "", "", "End of file"}};
        } else {
          return {-1,
                  {EC::LocalFileReadError, "", "",
                   AMStr::fmt("Read local file \"{}\" failed: {}", path,
                              strerror(errno))}};
        }
#endif
      }
    }
    return {0, OK};
  }

  std::pair<ssize_t, ECM> ReadChunk(char *buffer, size_t buffer_size) {
    if (!IsValid()) {
      return {-1, {EC::LocalFileOpenError, "", "", "File not initialized"}};
    }
    if (buffer == nullptr || buffer_size == 0) {
      return {0, OK};
    }

    const size_t remaining =
        file_size > offset ? (file_size - offset) : size_t{0};
    const size_t to_read = std::min(buffer_size, remaining);
    if (to_read == 0) {
      return {0, {EC::EndOfFile, "", "", "End of file"}};
    }

    if (is_sftp) {
      std::lock_guard<std::recursive_mutex> lock(client->TransferMutex());
      auto nb_res = client->NBPerform(control, [&]() {
        return libssh2_sftp_read(sftp_handle, buffer,
                                 static_cast<ssize_t>(to_read));
      });
      if (!nb_res) {
        return {-1,
                ContextualizeTransferRCM_(nb_res.rcm, "transfer.file.read",
                                          path)};
      }
      const ssize_t bytes_read = nb_res.value;
      if (bytes_read > 0) {
        offset += static_cast<size_t>(bytes_read);
        return {bytes_read, OK};
      }
      if (bytes_read == 0) {
        return {0, {EC::EndOfFile, "", "", "End of file"}};
      }
      return {bytes_read, Err(client->GetLastEC(), "transfer.file.read", path,
                              AMStr::fmt("Read sftp file \"{}\" failed: {}",
                                         path, client->GetLastErrorMsg()))};
    }

#ifdef _WIN32
    DWORD bytes_read = 0;
    if (!ReadFile(file_handle, buffer, static_cast<DWORD>(to_read), &bytes_read,
                  nullptr)) {
      const int win_ec = static_cast<int>(GetLastError());
      return {-1,
              {EC::LocalFileReadError,
               AMStr::fmt("Read local file \"{}\" failed: error code {}", path,
                          win_ec),
               RawError{RawErrorSource::WindowsAPI, win_ec}}};
    }
    if (bytes_read > 0) {
      offset += static_cast<size_t>(bytes_read);
      return {static_cast<ssize_t>(bytes_read), OK};
    }
    return {0, {EC::EndOfFile, "", "", "End of file"}};
#else
    ssize_t bytes_read = read(file_handle, buffer, to_read);
    if (bytes_read > 0) {
      offset += static_cast<size_t>(bytes_read);
      return {bytes_read, OK};
    }
    if (bytes_read == 0) {
      return {0, {EC::EndOfFile, "", "", "End of file"}};
    }
    return {-1,
            {EC::LocalFileReadError, "", "",
             AMStr::fmt("Read local file \"{}\" failed: {}", path,
                        strerror(errno))}};
#endif
  }

  std::pair<ssize_t, ECM> Write() {
    if (!IsValid()) {
      return {-1, {EC::LocalFileOpenError, "", "", "File not initialized"}};
    }
    if (!pd || !pd->ring_buffer) {
      return {-1, {EC::InvalidArg, "", "", "Progress data not initialized"}};
    }

    auto read_span = pd->ring_buffer->get_read_span();
    char *read_ptr = read_span.data();
    size_t max_read = read_span.size();
    ssize_t to_write = std::min<ssize_t>(max_read, (file_size - offset));
    ssize_t bytes_written;
    if (to_write > 0) {
      if (is_sftp) {
        // SFTP write (non-blocking)
        std::lock_guard<std::recursive_mutex> lock(client->TransferMutex());
        NoteSftpWriteRequest_(pd, static_cast<size_t>(to_write));
        auto nb_res = client->NBPerform(control, [&]() {
          const ssize_t rc = libssh2_sftp_write(sftp_handle, read_ptr, to_write);
          NoteSftpWriteAttempt_(pd, static_cast<size_t>(to_write), rc);
          return rc;
        });
        if (!nb_res) {
          return {-1, ContextualizeTransferRCM_(nb_res.rcm,
                                                "transfer.file.write", path)};
        }
        bytes_written = nb_res.value;
        if (bytes_written > 0) {
          pd->ring_buffer->commit_read(bytes_written);
          offset += bytes_written;
          pd->UpdateSize(static_cast<size_t>(bytes_written));
          pd->CallInnerCallback(false);
          return {bytes_written, OK};
        }
        if (bytes_written == 0) {
          return {0, {EC::EndOfFile, "", "", "End of file"}};
        }
        return {bytes_written,
                Err(client->GetLastEC(), "transfer.file.write", path,
                    AMStr::fmt("Write sftp file \"{}\" failed: {}", path,
                               client->GetLastErrorMsg()))};
      } else {
        // Local file write
#ifdef _WIN32
        DWORD bytes_written = 0;
        if (!WriteFile(file_handle, read_ptr, static_cast<DWORD>(to_write),
                       &bytes_written, nullptr)) {
          const int win_ec = static_cast<int>(GetLastError());
          return {-1,
                  {EC::LocalFileWriteError,
                   AMStr::fmt("Write local file \"{}\" failed: error code {}",
                              path, win_ec),
                   RawError{RawErrorSource::WindowsAPI, win_ec}}};
        }
        if (bytes_written > 0) {
          pd->ring_buffer->commit_read(bytes_written);
          offset += bytes_written;
          pd->UpdateSize(static_cast<size_t>(bytes_written));
          pd->CallInnerCallback(false);
          return {static_cast<int>(bytes_written), OK};
        } else {
          return {0, {EC::EndOfFile, "", "", "End of file"}};
        }
#else
        ssize_t bytes_written = write(file_handle, read_ptr, to_write);
        if (bytes_written > 0) {
          pd->ring_buffer->commit_read(bytes_written);
          offset += bytes_written;
          pd->UpdateSize(static_cast<size_t>(bytes_written));
          pd->CallInnerCallback(false);
          return {static_cast<int>(bytes_written), OK};
        } else if (bytes_written == 0) {
          return {0, {EC::EndOfFile, "", "", "End of file"}};
        } else {
          return {-1,
                  {EC::LocalFileWriteError, "", "",
                   AMStr::fmt("Write local file \"{}\" failed: {}", path,
                              strerror(errno))}};
        }
#endif
      }
    }
    return {0, OK};
  }

  std::pair<ssize_t, ECM> WriteChunk(const char *buffer, size_t buffer_size) {
    if (!IsValid()) {
      return {-1, {EC::LocalFileOpenError, "", "", "File not initialized"}};
    }
    if (buffer == nullptr || buffer_size == 0) {
      return {0, OK};
    }

    const size_t remaining =
        file_size > offset ? (file_size - offset) : size_t{0};
    const size_t to_write = std::min(buffer_size, remaining);
    if (to_write == 0) {
      return {0, {EC::EndOfFile, "", "", "End of file"}};
    }

    if (is_sftp) {
      std::lock_guard<std::recursive_mutex> lock(client->TransferMutex());
      NoteSftpWriteRequest_(pd, to_write);
      auto nb_res = client->NBPerform(control, [&]() {
        const ssize_t rc =
            libssh2_sftp_write(sftp_handle, buffer,
                               static_cast<ssize_t>(to_write));
        NoteSftpWriteAttempt_(pd, to_write, rc);
        return rc;
      });
      if (!nb_res) {
        return {-1,
                ContextualizeTransferRCM_(nb_res.rcm, "transfer.file.write",
                                          path)};
      }
      const ssize_t bytes_written = nb_res.value;
      if (bytes_written > 0) {
        offset += static_cast<size_t>(bytes_written);
        return {bytes_written, OK};
      }
      if (bytes_written == 0) {
        return {0, {EC::EndOfFile, "", "", "End of file"}};
      }
      return {bytes_written,
              Err(client->GetLastEC(), "transfer.file.write", path,
                  AMStr::fmt("Write sftp file \"{}\" failed: {}", path,
                             client->GetLastErrorMsg()))};
    }

#ifdef _WIN32
    DWORD bytes_written = 0;
    if (!WriteFile(file_handle, buffer, static_cast<DWORD>(to_write),
                   &bytes_written, nullptr)) {
      const int win_ec = static_cast<int>(GetLastError());
      return {-1,
              {EC::LocalFileWriteError,
               AMStr::fmt("Write local file \"{}\" failed: error code {}", path,
                          win_ec),
               RawError{RawErrorSource::WindowsAPI, win_ec}}};
    }
    if (bytes_written > 0) {
      offset += static_cast<size_t>(bytes_written);
      return {static_cast<ssize_t>(bytes_written), OK};
    }
    return {0, {EC::EndOfFile, "", "", "End of file"}};
#else
    ssize_t bytes_written = write(file_handle, buffer, to_write);
    if (bytes_written > 0) {
      offset += static_cast<size_t>(bytes_written);
      return {bytes_written, OK};
    }
    if (bytes_written == 0) {
      return {0, {EC::EndOfFile, "", "", "End of file"}};
    }
    return {-1,
            {EC::LocalFileWriteError, "", "",
             AMStr::fmt("Write local file \"{}\" failed: {}", path,
                        strerror(errno))}};
#endif
  }
};

class TransferEndpointRouter {
public:
  /**
   * @brief Construct one execution implementation.
   */
  TransferEndpointRouter() = default;

public:
  // XToBuffer - read from source to ring buffer
  void XToBuffer(ClientHandle client, TaskHandle task_info,
                 RuntimeProgress &pd) const {
    if (!client || !task_info) {
      return;
    }
    auto *task = task_info->GetCurrentTask();
    if (!task) {
      return;
    }

    if (auto *client_http = dynamic_cast<AMHTTPIOCore *>(&client->IOPort());
        client_http != nullptr) {
      ReadHttpToBuffer_(client, *task, pd);
      return;
    }

    switch (client->ConfigPort().GetProtocol()) {
    case ClientProtocol::SFTP: {
      auto *client_sftp = dynamic_cast<AMSFTPIOCore *>(&client->IOPort());
      if (client_sftp == nullptr) {
        SignalTaskIoAbort_(pd);
        task->rcm = {EC::InvalidArg, "", "",
                     "SFTP IO port implementation mismatch"};
        return;
      }
      ReadSftpToBuffer_(client_sftp, *task, pd);
      return;
    }
    case ClientProtocol::LOCAL:
      ReadLocalToBuffer_(*task, pd);
      return;
    case ClientProtocol::FTP: {
      auto *client_ftp = dynamic_cast<AMFTPIOCore *>(&client->IOPort());
      if (client_ftp == nullptr) {
        SignalTaskIoAbort_(pd);
        task->rcm = {EC::InvalidArg, "", "",
                     "FTP IO port implementation mismatch"};
        return;
      }
      ReadFtpToBuffer_(client_ftp, *task, pd);
      return;
    }
    default:
      return;
    }
  }

  // BufferToX - write from ring buffer to destination
  void BufferToX(ClientHandle client, TaskHandle task_info,
                 RuntimeProgress &pd) const {
    if (!client || !task_info) {
      return;
    }
    auto *task = task_info->GetCurrentTask();
    if (!task) {
      return;
    }

    switch (client->ConfigPort().GetProtocol()) {
    case ClientProtocol::SFTP: {
      auto *client_sftp = dynamic_cast<AMSFTPIOCore *>(&client->IOPort());
      if (client_sftp == nullptr) {
        SignalTaskIoAbort_(pd);
        task->rcm = {EC::InvalidArg, "", "",
                     "SFTP IO port implementation mismatch"};
        return;
      }
      WriteBufferToSftp_(client_sftp, *task, pd);
      return;
    }
    case ClientProtocol::LOCAL:
      WriteBufferToLocal_(*task, pd);
      return;
    case ClientProtocol::FTP: {
      auto *client_ftp = dynamic_cast<AMFTPIOCore *>(&client->IOPort());
      if (client_ftp == nullptr) {
        SignalTaskIoAbort_(pd);
        task->rcm = {EC::InvalidArg, "", "",
                     "FTP IO port implementation mismatch"};
        return;
      }
      WriteBufferToFtp_(client_ftp, *task, pd);
      return;
    }
    default:
      return;
    }
  }

private:
  static bool WaitWritableUntilReady_(RuntimeProgress &pd,
                                      const UnionFileHandle &file_handle) {
    const auto token = pd.task_info ? pd.task_info->Core.control.ControlToken()
                                    : nullptr;
    const AMDomain::client::InterruptWakeupSafeGuard wake_guard(
        token, [&pd]() {
          if (pd.ring_buffer) {
            pd.ring_buffer->NotifyAll();
          }
        });
    while (pd.ring_buffer->full() && !IsTaskInterrupted_(pd) &&
           file_handle.offset < file_handle.file_size) {
      const int wait_ms = ResolveRingBufferWaitMs_(pd);
      (void)pd.ring_buffer->WaitWritable([&]() {
        return IsTaskInterrupted_(pd) ||
               file_handle.offset >= file_handle.file_size;
      }, wait_ms);
    }
    return !IsTaskInterrupted_(pd);
  }

  static bool WaitReadableUntilReady_(RuntimeProgress &pd) {
    const auto token = pd.task_info ? pd.task_info->Core.control.ControlToken()
                                    : nullptr;
    const AMDomain::client::InterruptWakeupSafeGuard wake_guard(
        token, [&pd]() {
          if (pd.ring_buffer) {
            pd.ring_buffer->NotifyAll();
          }
        });
    while (pd.ring_buffer->empty() && !IsTaskInterrupted_(pd)) {
      const int wait_ms = ResolveRingBufferWaitMs_(pd);
      (void)pd.ring_buffer->WaitReadable(
          [&]() { return IsTaskInterrupted_(pd); }, wait_ms);
    }
    return !IsTaskInterrupted_(pd);
  }

  void ReadHttpToBuffer_(const ClientHandle &client, const TransferTask &task,
                         RuntimeProgress &pd) const {
    HTTPDownloadSet(LoadHttpTransferRuntime_(client), task.src, &pd);
  }

  void ReadSftpToBuffer_(AMSFTPIOCore *client_sftp, TransferTask &task,
                         RuntimeProgress &pd) const {
    UnionFileHandle file_handle = {};
    ECM rcm = file_handle.Init(task.src, task.size, client_sftp, false, true,
                               true, &pd);
    if (rcm.code != EC::Success) {
      SignalTaskIoAbort_(pd);
      task.rcm = rcm;
      return;
    }
    if (task.transferred > 0) {
      ECM seek_rcm = file_handle.Seek(task.transferred);
      if (seek_rcm.code != EC::Success) {
        SignalTaskIoAbort_(pd);
        task.rcm = seek_rcm;
        return;
      }
    }
    while (file_handle.offset < file_handle.file_size &&
           !IsTaskInterrupted_(pd)) {
      if (!WaitWritableUntilReady_(pd, file_handle)) {
        return;
      }
      auto [bytes_read, ecm] = file_handle.Read();
      (void)bytes_read;
      if (ecm.code != EC::Success && ecm.code != EC::EndOfFile) {
        SignalTaskIoAbort_(pd);
        task.rcm = ecm;
        return;
      }
    }
  }

  void ReadLocalToBuffer_(TransferTask &task, RuntimeProgress &pd) const {
    UnionFileHandle file_handle = {};
    ECM rcm =
        file_handle.Init(task.src, task.size, nullptr, false, true, true, &pd);
    if (rcm.code != EC::Success) {
      SignalTaskIoAbort_(pd);
      task.rcm = rcm;
      return;
    }
    if (task.transferred > 0) {
      ECM seek_rcm = file_handle.Seek(task.transferred);
      if (seek_rcm.code != EC::Success) {
        SignalTaskIoAbort_(pd);
        task.rcm = seek_rcm;
        return;
      }
    }
    while (file_handle.offset < file_handle.file_size &&
           !IsTaskInterrupted_(pd)) {
      if (!WaitWritableUntilReady_(pd, file_handle)) {
        return;
      }
      auto [bytes_read, ecm] = file_handle.Read();
      (void)bytes_read;
      if (ecm.code != EC::Success && ecm.code != EC::EndOfFile) {
        SignalTaskIoAbort_(pd);
        task.rcm = ecm;
        return;
      }
    }
  }

  void ReadFtpToBuffer_(AMFTPIOCore *client_ftp, const TransferTask &task,
                        RuntimeProgress &pd) const {
    FTPDownloadSet(client_ftp, task.src, FTPToBufferWk, &pd);
  }

  void WriteBufferToSftp_(AMSFTPIOCore *client_sftp, TransferTask &task,
                          RuntimeProgress &pd) const {
    UnionFileHandle file_handle = {};
    const bool resume = task.transferred > 0;
    ECM rcm = file_handle.Init(task.dst, task.size, client_sftp, true, true,
                               !resume, &pd);
    if (rcm.code != EC::Success) {
      SignalTaskIoAbort_(pd);
      task.rcm = rcm;
      return;
    }
    if (resume) {
      ECM seek_rcm = file_handle.Seek(task.transferred);
      if (seek_rcm.code != EC::Success) {
        SignalTaskIoAbort_(pd);
        task.rcm = seek_rcm;
        return;
      }
    }
    while (file_handle.offset < file_handle.file_size &&
           !IsTaskInterrupted_(pd)) {
      if (!WaitReadableUntilReady_(pd)) {
        return;
      }
      auto [bytes_write, ecm] = file_handle.Write();
      if (ecm.code != EC::Success && ecm.code != EC::EndOfFile) {
        SignalTaskIoAbort_(pd);
        task.rcm = ecm;
        return;
      }
      (void)bytes_write;
    }
  }

  void WriteBufferToLocal_(TransferTask &task, RuntimeProgress &pd) const {
    UnionFileHandle file_handle = {};
    const bool resume = task.transferred > 0;
    ECM rcm = file_handle.Init(task.dst, task.size, nullptr, true, true,
                               !resume, &pd);
    if (rcm.code != EC::Success) {
      SignalTaskIoAbort_(pd);
      task.rcm = rcm;
      return;
    }
    if (resume) {
      ECM seek_rcm = file_handle.Seek(task.transferred);
      if (seek_rcm.code != EC::Success) {
        SignalTaskIoAbort_(pd);
        task.rcm = seek_rcm;
        return;
      }
    }
    while (file_handle.offset < file_handle.file_size &&
           !IsTaskInterrupted_(pd)) {
      if (!WaitReadableUntilReady_(pd)) {
        return;
      }
      auto [bytes_write, ecm] = file_handle.Write();
      if (ecm.code != EC::Success && ecm.code != EC::EndOfFile) {
        SignalTaskIoAbort_(pd);
        task.rcm = ecm;
        return;
      }
      (void)bytes_write;
    }
  }

  void WriteBufferToFtp_(AMFTPIOCore *client_ftp, const TransferTask &task,
                         RuntimeProgress &pd) const {
    FTPUploadSet(client_ftp, task.dst, &pd, BufferToFTPWk);
  }

  static size_t HTTPToBufferWk(char *ptr, size_t size, size_t nmemb,
                               void *userdata) {
    auto *pd = static_cast<RuntimeProgress *>(userdata);
    if (!pd || !ptr) {
      return 0;
    }
    auto *cur_task = pd->GetCurrentTask();
    if (!cur_task) {
      return 0;
    }

    const size_t total = size * nmemb;
    size_t copied = 0;
    while (copied < total) {
      if (IsTaskInterrupted_(*pd)) {
        return 0;
      }
      while (pd->ring_buffer->writable() == 0 && !IsTaskInterrupted_(*pd)) {
        (void)pd->ring_buffer->WaitWritable(
            [&]() { return IsTaskInterrupted_(*pd); });
      }
      if (IsTaskInterrupted_(*pd)) {
        return 0;
      }
      auto write_span = pd->ring_buffer->get_write_span();
      char *write_ptr = write_span.data();
      size_t write_len = write_span.size();
      const size_t to_write = std::min<size_t>(write_len, total - copied);
      if (to_write == 0) {
        continue;
      }
      try {
        memcpy(write_ptr, ptr + copied, to_write);
      } catch (const std::exception &e) {
        SignalTaskIoAbort_(*pd);
        cur_task->rcm =
            Err(EC::BufferWriteError, "http.read", cur_task->src, e.what());
        return 0;
      }
      pd->ring_buffer->commit_write(to_write);
      copied += to_write;
    }
    return total;
  }

  static int HTTPProgressWk(void *userdata, curl_off_t dltotal,
                            curl_off_t dlnow, curl_off_t ultotal,
                            curl_off_t ulnow) {
    (void)dltotal;
    (void)dlnow;
    (void)ultotal;
    (void)ulnow;
    auto *pd = static_cast<RuntimeProgress *>(userdata);
    if (!pd || !pd->task_info) {
      return 0;
    }
    if (IsTaskInterrupted_(*pd)) {
      return 1;
    }
    if (pd->task_info->Core.control.IsTimeout()) {
      return 1;
    }
    return 0;
  }

  static void HTTPDownloadSet(const HttpTransferRuntime &runtime,
                              const std::string &src, RuntimeProgress *pd) {
    if (!pd) {
      return;
    }
    TransferTask *cur_task = pd->GetCurrentTask();
    if (!cur_task) {
      SignalTaskIoAbort_(*pd);
      return;
    }

    CURL *curl = curl_easy_init();
    if (!curl) {
      cur_task->rcm =
          Err(EC::InvalidHandle, "http.download", src, "curl_easy_init failed");
      SignalTaskIoAbort_(*pd);
      return;
    }

    curl_easy_setopt(curl, CURLOPT_URL, src.c_str());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, kHttpUserAgent);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, HTTPToBufferWk);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, pd);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, HTTPProgressWk);
    curl_easy_setopt(curl, CURLOPT_XFERINFODATA, pd);
    if (!runtime.proxy.empty()) {
      curl_easy_setopt(curl, CURLOPT_PROXY, runtime.proxy.c_str());
    }

    struct curl_slist *headers = nullptr;
    if (!runtime.bear_token.empty()) {
      headers = curl_slist_append(
          headers,
          AMStr::fmt("Authorization: Bearer {}", runtime.bear_token).c_str());
      curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    } else if (!runtime.username.empty() || !runtime.password.empty()) {
      curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
      curl_easy_setopt(curl, CURLOPT_USERNAME, runtime.username.c_str());
      curl_easy_setopt(curl, CURLOPT_PASSWORD, runtime.password.c_str());
    }

    const size_t resume_offset = cur_task->transferred;
    std::string range_header = {};
    if (resume_offset > 0) {
      range_header = AMStr::fmt("bytes={}-", resume_offset);
      curl_easy_setopt(curl, CURLOPT_RANGE, range_header.c_str());
    }

    const CURLcode curl_rcm = curl_easy_perform(curl);
    long response = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);

    if (headers) {
      curl_slist_free_all(headers);
    }
    curl_easy_cleanup(curl);

    if (pd->task_info && pd->task_info->Core.control.IsTimeout()) {
      cur_task->rcm =
          Err(EC::OperationTimeout, "http.download", src, "Task timeout");
      SignalTaskIoAbort_(*pd);
      return;
    }
    if (pd->task_info && IsTaskHardInterrupted_(pd->task_info) &&
        !pd->task_info->IsPauseRequested()) {
      cur_task->rcm =
          Err(EC::Terminate, "http.download", src, "Task terminated by user");
      SignalTaskIoAbort_(*pd);
      return;
    }
    if (curl_rcm != CURLE_OK) {
      cur_task->rcm = Err(
          EC::NetworkError, "http.download", src, curl_easy_strerror(curl_rcm),
          RawError{RawErrorSource::Curl, static_cast<int>(curl_rcm)});
      SignalTaskIoAbort_(*pd);
      return;
    }
    if (response >= 400) {
      if (response == 404) {
        cur_task->rcm = Err(EC::PathNotExist, "http.download", src,
                            "Remote file not found");
      } else if (response == 401 || response == 403) {
        cur_task->rcm = Err(EC::PermissionDenied, "http.download", src,
                            "Permission denied");
      } else if (response == 416) {
        cur_task->rcm = Err(EC::InvalidOffset, "http.download", src,
                            "Invalid resume offset");
      } else {
        cur_task->rcm = Err(EC::CommonFailure, "http.download", src,
                            AMStr::fmt("HTTP status {}", response));
      }
      SignalTaskIoAbort_(*pd);
      return;
    }
    if (resume_offset > 0 && response != 206) {
      cur_task->rcm = Err(EC::InvalidOffset, "http.download", src,
                          "Server does not support resume range request");
      SignalTaskIoAbort_(*pd);
      return;
    }
    cur_task->rcm = OK;
  }

  // Static callbacks for FTP using RuntimeProgress
  static size_t BufferToFTPWk(char *ptr, size_t size, size_t nmemb,
                              void *userdata) {
    auto *pd = static_cast<RuntimeProgress *>(userdata);
    // Check if transfer complete
    TransferTask *cur_task = pd->GetCurrentTask();
    if (!cur_task) {
      return CURL_READFUNC_ABORT;
    }
    while (true) {
      if (IsTaskInterrupted_(*pd)) {
        return CURL_READFUNC_ABORT;
      }

      if (cur_task && cur_task->transferred >= cur_task->size) {
        return 0;
      }
      if (pd->ring_buffer->available() == 0) {
        (void)pd->ring_buffer->WaitReadable(
            [&]() { return IsTaskInterrupted_(*pd); });
        continue;
      }
      auto read_span = pd->ring_buffer->get_read_span();
      char *read_ptr = read_span.data();
      size_t read_len = read_span.size();
      ssize_t to_read = read_len > size * nmemb ? size * nmemb : read_len;
      if (to_read > 0) {
        try {
          memcpy(ptr, read_ptr, to_read);
          pd->ring_buffer->commit_read(to_read);
          pd->UpdateSize(to_read);
          pd->CallInnerCallback(false);
          return to_read;
        } catch (const std::exception &e) {
          SignalTaskIoAbort_(*pd);
          if (cur_task) {
            cur_task->rcm = ECM{EC::BufferReadError, "", "", e.what()};
          }
          return CURL_READFUNC_ABORT;
        }
      } else if (to_read < 0) {
        SignalTaskIoAbort_(*pd);
        if (cur_task) {
          cur_task->rcm = ECM{EC::BufferReadError, "", "",
                              "Get negative value for data size"};
        }
        return CURL_READFUNC_ABORT;
      }
    }
  }

  static size_t FTPToBufferWk(char *ptr, size_t size, size_t nmemb,
                              void *userdata) {
    auto *pd = static_cast<RuntimeProgress *>(userdata);

    auto *cur_task = pd->GetCurrentTask();
    if (!cur_task) {
      return 0;
    }
    size_t total = size * nmemb;
    size_t written = 0;
    while (written < total) {
      if (IsTaskInterrupted_(*pd)) {
        return 0;
      }

      while (pd->ring_buffer->writable() == 0 && !IsTaskInterrupted_(*pd)) {
        (void)pd->ring_buffer->WaitWritable(
            [&]() { return IsTaskInterrupted_(*pd); });
      }
      if (IsTaskInterrupted_(*pd)) {
        return 0;
      }
      auto write_span = pd->ring_buffer->get_write_span();
      char *write_ptr = write_span.data();
      size_t write_len = write_span.size();
      size_t remaining = total - written;
      size_t to_write = std::min<size_t>(write_len, remaining);
      if (to_write > 0) {
        try {
          memcpy(write_ptr, ptr + written, to_write);
          pd->ring_buffer->commit_write(to_write);
          written += to_write;
        } catch (const std::exception &e) {
          SignalTaskIoAbort_(*pd);
          if (cur_task) {
            cur_task->rcm = ECM{EC::BufferWriteError, "", "", e.what()};
          }
          return 0;
        }
      }
    }
    return total;
  }

  // Upload with ProgressData (legacy - for AMSFTPWorker)
  static void FTPUploadSet(AMFTPIOCore *client, const std::string &dst,
                           RuntimeProgress *pd,
                           curl_read_callback read_callback) {
    if (!client || !pd) {
      return;
    }
    std::lock_guard<std::recursive_mutex> lock(client->TransferMutex());

    TransferTask *cur_task = pd->GetCurrentTask();
    if (!cur_task) {
      SignalTaskIoAbort_(*pd);
      return;
    }
    const size_t resume_offset = cur_task->transferred;
    ECM ecm = client->SetupPath(dst, false);
    if (ecm.code != EC::Success) {
      cur_task->rcm = ecm;
      SignalTaskIoAbort_(*pd);
      return;
    }
    CURL *curl = client->GetCURL();
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
    curl_easy_setopt(curl, CURLOPT_READDATA, pd);
    curl_easy_setopt(curl, CURLOPT_RESUME_FROM_LARGE,
                     static_cast<curl_off_t>(resume_offset));
    curl_easy_setopt(
        curl, CURLOPT_INFILESIZE_LARGE,
        static_cast<curl_off_t>(resume_offset < cur_task->size
                                    ? (cur_task->size - resume_offset)
                                    : 0));
    curl_easy_setopt(curl, CURLOPT_FTP_CREATE_MISSING_DIRS, CURLFTP_CREATE_DIR);

    CURLcode res = curl_easy_perform(curl);

    if (res == CURLE_ABORTED_BY_CALLBACK || res == CURLE_WRITE_ERROR) {
      SignalTaskIoAbort_(*pd);
    } else if (res != CURLE_OK) {
      cur_task->rcm =
          ECM{EC::FTPUploadFailed,
              AMStr::fmt("Upload failed: {}", curl_easy_strerror(res)),
              RawError{RawErrorSource::Curl, static_cast<int>(res)}};
      SignalTaskIoAbort_(*pd);
    }
  }

  // Download with ProgressData (legacy - for AMSFTPWorker)
  static void FTPDownloadSet(AMFTPIOCore *client, const std::string &src,
                             curl_write_callback write_callback,
                             RuntimeProgress *pd) {
    if (!client || !pd) {
      return;
    }
    std::lock_guard<std::recursive_mutex> lock(client->TransferMutex());

    TransferTask *cur_task = pd->GetCurrentTask();

    if (!cur_task) {
      SignalTaskIoAbort_(*pd);
      return;
    }
    const size_t resume_offset = cur_task->transferred;
    ECM ecm = client->SetupPath(src, false);
    if (ecm.code != EC::Success) {
      cur_task->rcm = ecm;
      SignalTaskIoAbort_(*pd);
      return;
    }
    auto curl = client->GetCURL();
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, pd);
    curl_easy_setopt(curl, CURLOPT_RESUME_FROM_LARGE,
                     static_cast<curl_off_t>(resume_offset));
    CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_ABORTED_BY_CALLBACK || res == CURLE_WRITE_ERROR) {
      SignalTaskIoAbort_(*pd);
    } else if (res != CURLE_OK) {
      cur_task->rcm =
          ECM{EC::FTPDownloadFailed,
              AMStr::fmt("Download failed: {}", curl_easy_strerror(res)),
              RawError{RawErrorSource::Curl, static_cast<int>(res)}};
      SignalTaskIoAbort_(*pd);
    }
  }
};
} // namespace

namespace AMInfra::transfer::detail {
ECM EnsureTransferClientReady(const ClientHandle &client,
                              const char *operation) {
  return EnsureTransferClientReady_(client, operation);
}

bool IsTaskHardInterrupted(const TaskHandle &task_info) {
  return IsTaskHardInterrupted_(task_info);
}

void SignalTaskIoAbort(TransferRuntimeProgress &progress) {
  SignalTaskIoAbort_(progress);
}

bool IsTaskIDUsed(const TaskID &task_id, TaskRegistry &task_registry,
                  std::mutex &conducting_mtx,
                  const std::unordered_set<TaskID> &conducting_tasks) {
  return IsTaskIDUsedHelper(task_id, task_registry, conducting_mtx,
                            conducting_tasks);
}

bool ShouldSkipTask(const TaskHandle &task_info) {
  return ShouldSkipTaskHelper(task_info);
}

void MarkUnfinishedTransferEntries(
    const TaskHandle &task_info, ECM entry_rcm,
    std::function<void(const std::optional<ECM> &)> on_mark) {
  MarkUnfinishedTransferEntries_(task_info, entry_rcm, std::move(on_mark));
}

size_t ClampBufferSizeByPolicy(size_t requested,
                               const TransferBufferPolicy &policy) {
  return ClampBufferSizeByPolicy_(requested, policy);
}

ClientHandle ResolveTaskClient(const TransferClientContainer &clients,
                               const std::string &nickname, bool use_dst_role) {
  return ResolveTaskClientHelper(clients, nickname, use_dst_role);
}

ECM ExecuteSourceToBuffer(const ClientHandle &client,
                          const TaskHandle &task_info,
                          TransferRuntimeProgress &progress) {
  if (!client || !task_info) {
    return Err(EC::InvalidArg, "", "", "Invalid source transfer input");
  }
  TransferEndpointRouter helper = {};
  helper.XToBuffer(client, task_info, progress);
  auto *task = progress.GetCurrentTask();
  if (task && task->rcm.has_value() && task->rcm->code != EC::Success) {
    return *task->rcm;
  }
  return OK;
}

ECM ExecuteBufferToSink(const ClientHandle &client, const TaskHandle &task_info,
                        TransferRuntimeProgress &progress) {
  if (!client || !task_info) {
    return Err(EC::InvalidArg, "", "", "Invalid sink transfer input");
  }
  TransferEndpointRouter helper = {};
  helper.BufferToX(client, task_info, progress);
  auto *task = progress.GetCurrentTask();
  if (task && task->rcm.has_value() && task->rcm->code != EC::Success) {
    return *task->rcm;
  }
  return OK;
}

ECM ExecuteSequentialDirectTransfer(const ClientHandle &src_client,
                                    const ClientHandle &dst_client,
                                    const TaskHandle &task_info,
                                    TransferRuntimeProgress &progress,
                                    size_t chunk_size) {
  if (!src_client || !dst_client || !task_info) {
    return Err(EC::InvalidArg, "", "", "Invalid direct transfer input");
  }

  auto *task = progress.GetCurrentTask();
  if (!task) {
    return Err(EC::InvalidArg, "", "", "Current transfer task is null");
  }

  const auto src_protocol = src_client->ConfigPort().GetProtocol();
  const auto dst_protocol = dst_client->ConfigPort().GetProtocol();
  const bool local_to_sftp =
      src_protocol == ClientProtocol::LOCAL &&
      dst_protocol == ClientProtocol::SFTP;
  const bool sftp_to_local =
      src_protocol == ClientProtocol::SFTP &&
      dst_protocol == ClientProtocol::LOCAL;
  if (!local_to_sftp && !sftp_to_local) {
    return Err(EC::OperationUnsupported, "transfer.direct", task->src,
               "Direct transfer currently supports LOCAL <-> SFTP only");
  }

  auto *src_sftp =
      src_protocol == ClientProtocol::SFTP
          ? dynamic_cast<AMSFTPIOCore *>(&src_client->IOPort())
          : nullptr;
  auto *dst_sftp =
      dst_protocol == ClientProtocol::SFTP
          ? dynamic_cast<AMSFTPIOCore *>(&dst_client->IOPort())
          : nullptr;
  if (src_protocol == ClientProtocol::SFTP && src_sftp == nullptr) {
    return Err(EC::InvalidHandle, "transfer.direct", task->src,
               "SFTP source IO port implementation mismatch");
  }
  if (dst_protocol == ClientProtocol::SFTP && dst_sftp == nullptr) {
    return Err(EC::InvalidHandle, "transfer.direct", task->dst,
               "SFTP destination IO port implementation mismatch");
  }

  UnionFileHandle src_handle = {};
  ECM rcm = src_handle.Init(task->src, task->size, src_sftp, false, true, true,
                            &progress);
  if (!(rcm)) {
    return rcm;
  }

  const bool resume = task->transferred > 0;
  UnionFileHandle dst_handle = {};
  rcm = dst_handle.Init(task->dst, task->size, dst_sftp, true, true, !resume,
                        &progress);
  if (!(rcm)) {
    return rcm;
  }

  if (resume) {
    rcm = src_handle.Seek(task->transferred);
    if (!(rcm)) {
      return rcm;
    }
    rcm = dst_handle.Seek(task->transferred);
    if (!(rcm)) {
      return rcm;
    }
  }

  std::vector<char> chunk(std::max<size_t>(1, chunk_size));
  while (src_handle.offset < src_handle.file_size &&
         !IsTaskInterrupted_(progress)) {
    auto [bytes_read, read_rcm] =
        src_handle.ReadChunk(chunk.data(), chunk.size());
    if (read_rcm.code != EC::Success && read_rcm.code != EC::EndOfFile) {
      return read_rcm;
    }
    if (bytes_read <= 0) {
      break;
    }

    size_t written_total = 0;
    const size_t bytes_to_write = static_cast<size_t>(bytes_read);
    while (written_total < bytes_to_write && !IsTaskInterrupted_(progress)) {
      auto [bytes_written, write_rcm] = dst_handle.WriteChunk(
          chunk.data() + written_total, bytes_to_write - written_total);
      if (write_rcm.code != EC::Success && write_rcm.code != EC::EndOfFile) {
        return write_rcm;
      }
      if (bytes_written <= 0) {
        return Err(EC::CommonFailure, "transfer.direct", task->dst,
                   "Destination write returned zero bytes");
      }
      written_total += static_cast<size_t>(bytes_written);
      progress.UpdateSize(static_cast<size_t>(bytes_written));
      progress.CallInnerCallback(false);
    }
  }

  return OK;
}
} // namespace AMInfra::transfer::detail
