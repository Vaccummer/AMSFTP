#include "domain/client/ClientModel.hpp"
#include "foundation/core/DataClass.hpp"
#include "foundation/tools/path.hpp"
#include "foundation/tools/string.hpp"
#include "foundation/tools/time.hpp"
#include "infrastructure/client/ftp/FTP.hpp"
#include "infrastructure/client/http/HTTP.hpp"
#include "infrastructure/client/sftp/SFTP.hpp"
#include "infrastructure/transfer/core.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <curl/curl.h>
#include <mutex>
#include <thread>
#include <utility>

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
using SocketWaitType = AMInfra::client::SFTP::detail::SocketWaitType;
using DeathClockProtocol = AMInfra::client::SFTP::detail::DeathClockProtocol;
using AMFTPIOCore = AMInfra::client::FTP::AMFTPIOCore;
using AMHTTPIOCore = AMInfra::client::HTTP::AMHTTPIOCore;
using TransferTask = AMDomain::transfer::TransferTask;
using TaskStatus = AMDomain::transfer::TaskStatus;
using TaskId = TaskInfo::ID;
using TaskRegistry = AMAtomic<std::unordered_map<TaskId, TaskHandle>>;
using TransferClientContainer = AMDomain::transfer::TransferClientContainer;
using TransferBufferPolicy = AMInfra::transfer::TransferBufferPolicy;
constexpr const char *kHttpUserAgent = "amsftp-wget/1.0";

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

void SignalTaskIoAbort_(RuntimeProgress &pd) {
  pd.io_abort.store(true, std::memory_order_relaxed);
  if (pd.ring_buffer) {
    pd.ring_buffer->NotifyAll();
  }
}

bool IsTaskIdUsedHelper(const TaskId &task_id, TaskRegistry &task_registry,
                        std::mutex &conducting_mtx,
                        const std::unordered_set<TaskId> &conducting_tasks) {
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
  AMDomain::client::ControlComponent control = {};

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
          DeathClockProtocol close_death_clock(
              control, AMDomain::client::kHandleCloseGraceWaitMs);
          (void)client->nb_call(close_death_clock, [&]() {
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
      std::lock_guard<std::recursive_mutex> lock(client->TransferMutex());
      libssh2_session_set_blocking(client->session, 0);
      NBResult<LIBSSH2_SFTP_HANDLE *> nb_res{nullptr, WaitResult::Ready};
      DeathClockProtocol death_clock(
          control, AMDomain::client::kTransferInterruptGraceWaitMs);

      if (is_write) {
        int flags = LIBSSH2_FXF_WRITE;
        if (truncate) {
          flags |= LIBSSH2_FXF_TRUNC | LIBSSH2_FXF_CREAT;
        }
        nb_res = client->nb_call(death_clock, [&]() {
          return libssh2_sftp_open(client->sftp, path.c_str(), flags, 0744);
        });
        sftp_handle = nb_res.value;
      } else {
        nb_res = client->nb_call(death_clock, [&]() {
          return libssh2_sftp_open(client->sftp, path.c_str(), LIBSSH2_FXF_READ,
                                   0400);
        });
        sftp_handle = nb_res.value;
      }
      if (nb_res.status == WaitResult::Interrupted) {
        if (pd) {
          return {EC::Terminate, "", "", "Task terminated by user"};
        }
      }
      if (!sftp_handle) {
        EC rc = client->GetLastEC();
        std::string msg = client->GetLastErrorMsg();
        return {rc, AMStr::fmt("Open sftp file \"{}\" failed: {}", path, msg)};
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
      return {-1,
              {EC::LocalFileOpenError, "", "", "File not initialized"}};
    }
    if (!pd || !pd->ring_buffer) {
      return {-1,
              {EC::InvalidArg, "", "", "Progress data not initialized"}};
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
        while (true) {
          if (IsTaskInterrupted_(*pd)) {
            return {-1,
                    {EC::Terminate, "", "", "Task terminated by user"}};
          }
          bytes_read = libssh2_sftp_read(sftp_handle, write_ptr, to_read);
          if (bytes_read > 0) {
            pd->ring_buffer->commit_write(bytes_read);
            offset += bytes_read;
            return {bytes_read, OK};
          }
          if (bytes_read == 0) {
            return {0, {EC::EndOfFile, "", "", "End of file"}};
          }
          if (bytes_read == LIBSSH2_ERROR_EAGAIN) {
            WaitResult wr = client->wait_for_socket(
                SocketWaitType::Read, control,
                AMDomain::client::kTransferInterruptGraceWaitMs);
            if (wr == WaitResult::Error) {
              return {
                  -1,
                  {wait_result_to_error_code(wr), "SFTP read socket error"}};
            }
            if (wr == WaitResult::Interrupted) {
              return {
                  static_cast<ssize_t>(EC::Terminate),
                  ECM{EC::Terminate, "", "", "Task terminated by user"}};
            }
            continue;
          }
          return {bytes_read,
                  {client->GetLastEC(),
                   AMStr::fmt("Read sftp file \"{}\" failed: {}", path,
                              client->GetLastErrorMsg())}};
        }
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

  std::pair<ssize_t, ECM> Write() {
    if (!IsValid()) {
      return {-1,
              {EC::LocalFileOpenError, "", "", "File not initialized"}};
    }
    if (!pd || !pd->ring_buffer) {
      return {-1,
              {EC::InvalidArg, "", "", "Progress data not initialized"}};
    }

    auto read_span = pd->ring_buffer->get_read_span();
    char *read_ptr = read_span.data();
    size_t max_read = read_span.size();
    ssize_t to_write = std::min<ssize_t>(max_read, (file_size - offset));
    ssize_t bytes_written;
    if (to_write > 0) {
      if (is_sftp) {
        // SFTP write (non-blocking)
        while (true) {
          if (IsTaskInterrupted_(*pd)) {
            return {-1,
                    {EC::Terminate, "", "", "Task terminated by user"}};
          }
          {
            std::lock_guard<std::recursive_mutex> lock(client->TransferMutex());
            bytes_written = libssh2_sftp_write(sftp_handle, read_ptr, to_write);
          }
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
          if (bytes_written == LIBSSH2_ERROR_EAGAIN) {
            WaitResult wr = client->wait_for_socket(
                SocketWaitType::Write, control,
                AMDomain::client::kTransferInterruptGraceWaitMs);
            if (wr == WaitResult::Error) {
              return {
                  LIBSSH2_ERROR_EAGAIN,
                  {wait_result_to_error_code(wr), "SFTP write socket error"}};
            }
            if (wr == WaitResult::Interrupted) {
              return {
                  static_cast<ssize_t>(EC::Terminate),
                  ECM{EC::Terminate, "", "", "Task terminated by user"}};
            }
            continue;
          }
          EC rc = client->GetLastEC();
          std::string msg = client->GetLastErrorMsg();
          return {
              bytes_written,
              {rc, AMStr::fmt("Write sftp file \"{}\" failed: {}", path, msg)}};
        }
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
};

class TransferExecutionHelper {
public:
  /**
   * @brief Construct one execution implementation.
   */
  TransferExecutionHelper() = default;

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
      ReadHttpToBuffer_(client_http, *task, pd);
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
    while (pd.ring_buffer->full() && !IsTaskInterrupted_(pd) &&
           file_handle.offset < file_handle.file_size) {
      (void)pd.ring_buffer->WaitWritable([&]() {
        return IsTaskInterrupted_(pd) ||
               file_handle.offset >= file_handle.file_size;
      });
    }
    return !IsTaskInterrupted_(pd);
  }

  static bool WaitReadableUntilReady_(RuntimeProgress &pd) {
    while (pd.ring_buffer->empty() && !IsTaskInterrupted_(pd)) {
      (void)pd.ring_buffer->WaitReadable(
          [&]() { return IsTaskInterrupted_(pd); });
    }
    return !IsTaskInterrupted_(pd);
  }

  void ReadHttpToBuffer_(AMHTTPIOCore *client_http, const TransferTask &task,
                         RuntimeProgress &pd) const {
    HTTPDownloadSet(client_http, task.src, &pd);
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
    std::lock_guard<std::recursive_mutex> lock(client_sftp->TransferMutex());
    libssh2_session_set_blocking(client_sftp->session, 0);
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
    libssh2_session_set_blocking(client_sftp->session, 0);
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

  static void HTTPDownloadSet(AMHTTPIOCore *client_http, const std::string &src,
                              RuntimeProgress *pd) {
    if (!client_http || !pd) {
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
    const std::string proxy = client_http->Proxy();
    if (!proxy.empty()) {
      curl_easy_setopt(curl, CURLOPT_PROXY, proxy.c_str());
    }

    struct curl_slist *headers = nullptr;
    const std::string bearer_token = client_http->BearerToken();
    if (!bearer_token.empty()) {
      headers = curl_slist_append(
          headers,
          AMStr::fmt("Authorization: Bearer {}", bearer_token).c_str());
      curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
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

private:
  size_t chunk_size_ = 256 * AMKB;
};
} // namespace

// TransferExecutionEngine
namespace AMInfra::transfer {
/**
 * @brief Construct one transfer execution engine.
 */
TransferExecutionEngine::TransferExecutionEngine(
    const TransferBufferPolicy &buffer_policy)
    : buffer_policy_(buffer_policy) {
  read_thread_ =
      std::jthread([this](std::stop_token stop_token) { ReadLoop_(stop_token); });
}

/**
 * @brief Destroy one transfer execution engine.
 */
TransferExecutionEngine::~TransferExecutionEngine() {
  if (read_thread_.joinable()) {
    read_thread_.request_stop();
  }
  read_queue_cv_.notify_all();
  if (read_thread_.joinable()) {
    read_thread_.join();
  }
}

void TransferExecutionEngine::ReadLoop_(std::stop_token stop_token) {
  while (true) {
    ReadJob job = {};
    {
      std::unique_lock<std::mutex> lock(read_queue_mtx_);
      read_queue_cv_.wait(lock, [this, &stop_token]() {
        return stop_token.stop_requested() || !read_queue_.empty();
      });
      if (stop_token.stop_requested() && read_queue_.empty()) {
        return;
      }
      job = std::move(read_queue_.front());
      read_queue_.pop_front();
    }

    ECM read_rcm = OK;
    try {
      if (!job.src_client || !job.task_info || !job.runtime_progress) {
        read_rcm = Err(EC::InvalidArg, "", "", "Invalid read job");
      } else {
        TransferExecutionHelper helper = {};
        helper.XToBuffer(job.src_client, job.task_info, *job.runtime_progress);
        auto *cur_task = job.runtime_progress->GetCurrentTask();
        if (cur_task && cur_task->rcm.has_value() &&
            cur_task->rcm->code != EC::Success) {
          read_rcm = *cur_task->rcm;
        }
      }
    } catch (const std::exception &e) {
      read_rcm = Err(EC::UnknownError, "", "", e.what());
    } catch (...) {
      read_rcm = Err(EC::UnknownError, "", "",
                     "Unknown read thread runtime error");
    }
    job.promise.set_value(read_rcm);
  }
}

std::future<ECM> TransferExecutionEngine::EnqueueReadJob_(
    ClientHandle src_client, const TaskHandle &task_info,
    TransferRuntimeProgress *runtime_progress) {
  ReadJob job = {};
  job.src_client = std::move(src_client);
  job.task_info = task_info;
  job.runtime_progress = runtime_progress;
  std::future<ECM> future = job.promise.get_future();
  {
    std::lock_guard<std::mutex> lock(read_queue_mtx_);
    read_queue_.push_back(std::move(job));
  }
  read_queue_cv_.notify_one();
  return future;
}

size_t TransferExecutionEngine::ResolveTaskBufferSize_(
    const TaskHandle &task_info) const {
  size_t effective = buffer_policy_.default_buffer_size;
  if (task_info) {
    const size_t hinted =
        task_info->Size.buffer.load(std::memory_order_relaxed);
    if (hinted > 0) {
      effective = hinted;
    }
  }
  return ClampBufferSizeByPolicy_(effective, buffer_policy_);
}

/**
 * @brief Execute one prepared single-file transfer task.
 */
ECM TransferExecutionEngine::TransferSignleFile(
    ClientHandle src_client, ClientHandle dst_client,
    RuntimeProgress &runtime_progress) {
  TransferExecutionHelper helper = {};
  auto task_info = runtime_progress.task_info;
  if (!src_client || !dst_client || !task_info) {
    return {EC::InvalidArg, "", "", "Invalid transfer input"};
  }
  {
    const ECM src_guard = EnsureTransferClientReady_(src_client, __func__);
    if (!(src_guard)) {
      return src_guard;
    }
    const ECM dst_guard = EnsureTransferClientReady_(dst_client, __func__);
    if (!(dst_guard)) {
      return dst_guard;
    }
  }

  auto &pd = runtime_progress;
  auto *task = task_info->GetCurrentTask();
  if (!task) {
    return {EC::InvalidArg, "", "", "Invalid transfer input"};
  }
  const auto src_protocol = src_client->ConfigPort().GetProtocol();
  const auto dst_protocol = dst_client->ConfigPort().GetProtocol();
  const bool src_is_http =
      dynamic_cast<AMHTTPIOCore *>(&src_client->IOPort()) != nullptr;

  const auto is_supported = [](ClientProtocol protocol) {
    return protocol == ClientProtocol::LOCAL ||
           protocol == ClientProtocol::FTP || protocol == ClientProtocol::SFTP;
  };

  const bool src_supported = is_supported(src_protocol) || src_is_http;
  const bool dst_supported = is_supported(dst_protocol);
  if (!src_supported || !dst_supported) {
    return {EC::OperationUnsupported, "transfer.single_file",
            AMStr::fmt("{} -> {}", task->src, task->dst),
            AMStr::fmt("Unsupported protocol (src={}{} dst={})",
                       AMStr::ToString(src_protocol),
                       src_is_http ? "/http" : "",
                       AMStr::ToString(dst_protocol))};
  }

  if (src_client->GetUID() == dst_client->GetUID()) {
    return {EC::InvalidHandle, "", "",
            "TransferSignleFile requires different source/destination client "
            "IDs"};
  }

  if (auto *http_io = dynamic_cast<AMHTTPIOCore *>(&src_client->IOPort());
      http_io != nullptr && task->transferred > 0) {
    const size_t resume_offset = task->transferred;
    bool can_resume = false;
    auto probe = http_io->ProbeResumeSupport(task->src, resume_offset,
                                             task_info->Core.control);
    if (probe.rcm.code == EC::Terminate ||
        probe.rcm.code == EC::OperationTimeout) {
      return probe.rcm;
    }
    if ((probe.rcm) && probe.data) {
      can_resume = true;
    }
    if (task->size > 0 && resume_offset >= task->size) {
      can_resume = false;
    }
    if (!can_resume) {
      const size_t current_offset =
          task_info->Size.cur_task_transferred.load(std::memory_order_relaxed);
      if (current_offset > 0 &&
          !task_info->Set.keep_start_time.load(std::memory_order_relaxed)) {
        task_info->Size.transferred.fetch_sub(current_offset,
                                              std::memory_order_relaxed);
      }
      task->transferred = 0;
      task_info->Size.cur_task_transferred.store(0, std::memory_order_relaxed);
    }
  }

  const size_t begin_transferred = task->transferred;

  std::future<ECM> read_future = EnqueueReadJob_(src_client, task_info, &pd);
  helper.BufferToX(dst_client, task_info, pd);
  if (read_future.valid()) {
    const ECM read_rcm = read_future.get();
    if ((!task->rcm.has_value() || task->rcm->code == EC::Success) &&
        read_rcm.code != EC::Success) {
      task->rcm = read_rcm;
    }
  }

  task->transferred =
      task_info->Size.cur_task_transferred.load(std::memory_order_relaxed);

  if (task_info->Core.control.IsTimeout()) {
    return {EC::OperationTimeout, "", "", "Task timeout"};
  }
  if (IsTaskHardInterrupted_(task_info) && !task_info->IsPauseRequested()) {
    return {EC::Terminate, "", "", "Task terminated by user"};
  }
  if (pd.io_abort.load(std::memory_order_relaxed) &&
      (!task->rcm.has_value() || task->rcm->code == EC::Success)) {
    return {EC::UnknownError, "", "", "Transfer interrupted by runtime"};
  }

  if (task->rcm.has_value() && task->rcm->code != EC::Success) {
    return *task->rcm;
  }

  if (task->size == 0) {
    if (task->transferred > begin_transferred) {
      return task->rcm.value_or(OK);
    }
    return Err(EC::CommonFailure, "transfer.single_file", task->src,
               "No data received from source");
  }

  if (task->transferred == task->size) {
    return task->rcm.value_or(OK);
  }

  return {EC::UnknownError, "", "",
          "Task not finished but exited unexpectedly"};
}

void TransferExecutionEngine::ExecuteTask(const TaskHandle &task_info) {
  if (!task_info) {
    return;
  }
  RuntimeProgress pd(task_info);

  task_info->SetStatus(TaskStatus::Conducting);
  if (!task_info->Set.keep_start_time.load(std::memory_order_relaxed) ||
      task_info->Time.start.load(std::memory_order_relaxed) <= 0.0) {
    task_info->Time.start.store(AMTime::seconds(), std::memory_order_relaxed);
  }

  if (task_info->Set.callback.need_total_size_cb) {
    task_info->Set.callback.CallTotalSize(
        task_info->Size.total.load(std::memory_order_relaxed));
  }

  const bool has_dir_tasks = !task_info->Core.dir_tasks.lock()->empty();
  const bool has_file_tasks = !task_info->Core.file_tasks.lock()->empty();
  if (!has_dir_tasks && !has_file_tasks) {
    task_info->SetStatus(TaskStatus::Finished);
    task_info->SetResult({EC::InvalidArg, "", "", "No task is provided"});
    task_info->Time.finish.store(AMTime::seconds(), std::memory_order_relaxed);
    return;
  }

  if (task_info->Core.clients.empty()) {
    task_info->SetStatus(TaskStatus::Finished);
    task_info->SetResult(
        {EC::InvalidHandle, "", "", "Task clients not found"});
    task_info->Time.finish.store(AMTime::seconds(), std::memory_order_relaxed);
    return;
  }

  struct ScopedTaskRingBuffer_ {
    TransferRuntimeProgress *progress = nullptr;
    explicit ScopedTaskRingBuffer_(TransferRuntimeProgress *pd, size_t size)
        : progress(pd) {
      if (progress) {
        progress->ring_buffer = std::make_shared<StreamRingBuffer>(size);
      }
    }
    ~ScopedTaskRingBuffer_() {
      if (progress && progress->ring_buffer) {
        progress->ring_buffer->NotifyAll();
      }
      if (progress) {
        progress->ring_buffer.reset();
      }
    }
  } scoped_task_buffer(&pd, ResolveTaskBufferSize_(task_info));

  const auto &task_clients = task_info->Core.clients;
  bool paused_requested = false;
  ECM last_non_ok = OK;

  const auto record_error = [&](const std::optional<ECM> &rcm_opt) {
    if (!rcm_opt.has_value()) {
      return;
    }
    if (rcm_opt->code != EC::Success) {
      last_non_ok = *rcm_opt;
    }
  };

  const auto emit_entry_error = [&](const TransferTask &task) {
    if (!task_info->Set.callback.need_error_cb || !task.rcm.has_value() ||
        task.rcm->code == EC::Success) {
      return;
    }
    if (task.rcm->code == EC::Terminate ||
        task.rcm->code == EC::OperationTimeout) {
      return;
    }
    task_info->Set.callback.CallError(ErrorCBInfo(
        *task.rcm, task.src, task.dst, task.src_host, task.dst_host));
  };

  const auto check_stop = [&]() -> std::optional<ECM> {
    if (task_info->Core.control.IsTimeout()) {
      return ECM{EC::OperationTimeout, "", "", "Task timeout"};
    }
    if (IsTaskHardInterrupted_(task_info) && !task_info->IsPauseRequested()) {
      return ECM{EC::Terminate, "", "", "Task terminated by user"};
    }
    return std::nullopt;
  };

  // Phase A: create all destination directories first.
  {
    auto dir_tasks_guard = task_info->Core.dir_tasks.lock();
    for (auto &task : *dir_tasks_guard) {
      if (task.IsFinished) {
        continue;
      }
      task_info->SetCurrentTask(&task);
      if (task_info->IsPauseRequested()) {
        paused_requested = true;
        break;
      }
      auto stop_rcm = check_stop();
      if (stop_rcm.has_value()) {
        task.rcm = *stop_rcm;
        task.IsFinished = true;
        record_error(task.rcm);
        break;
      }

      const std::string dst_key =
          task.dst_host.empty() ? std::string("local") : task.dst_host;
      auto dst_client = ResolveTaskClientHelper(task_clients, dst_key, true);
      if (!dst_client) {
        task.rcm = {EC::ClientNotFound, "", "",
                    "Task destination client is not available"};
        task.IsFinished = true;
        record_error(task.rcm);
        emit_entry_error(task);
        continue;
      }
      {
        const ECM guard_rcm = EnsureTransferClientReady_(dst_client, __func__);
        if (!(guard_rcm)) {
          task.rcm = guard_rcm;
          task.IsFinished = true;
          record_error(task.rcm);
          emit_entry_error(task);
          continue;
        }
      }

      task.rcm = dst_client->IOPort().mkdirs(
          AMDomain::filesystem::MkdirsArgs{task.dst}, task_info->Core.control);
      task.IsFinished = true;
      if (task.rcm.has_value() && task.rcm->code != EC::Success) {
        record_error(task.rcm);
        emit_entry_error(task);
      }
      pd.CallInnerCallback(true);
    }
  }

  // Phase B: transfer file entries.
  {
    auto file_tasks_guard = task_info->Core.file_tasks.lock();
    for (auto &task : *file_tasks_guard) {
      if (task.IsFinished) {
        continue;
      }
      if (task_info->IsPauseRequested()) {
        paused_requested = true;
        break;
      }
      auto stop_rcm = check_stop();
      if (stop_rcm.has_value()) {
        task.rcm = *stop_rcm;
        task.IsFinished = true;
        record_error(task.rcm);
        break;
      }

      task_info->SetCurrentTask(&task);

      auto src_client = task_clients.GetSrcClient(task.src_host);
      auto dst_client = task_clients.GetDstClient(task.dst_host);

      if (!src_client || !dst_client) {
        task.rcm = {EC::ClientNotFound, "", "",
                    "Task client is not available in pool"};
        task.IsFinished = true;
        record_error(task.rcm);
        emit_entry_error(task);
        continue;
      }
      {
        const ECM src_guard = EnsureTransferClientReady_(src_client, __func__);
        if (!(src_guard)) {
          task.rcm = src_guard;
          task.IsFinished = true;
          record_error(task.rcm);
          emit_entry_error(task);
          continue;
        }
        const ECM dst_guard = EnsureTransferClientReady_(dst_client, __func__);
        if (!(dst_guard)) {
          task.rcm = dst_guard;
          task.IsFinished = true;
          record_error(task.rcm);
          emit_entry_error(task);
          continue;
        }
      }

      task.rcm = OK;
      size_t resume_offset = task.transferred;
      if (resume_offset > 0) {
        if (resume_offset > task.size) {
          task.rcm = {EC::InvalidOffset, "", "",
                      "Offset exceeds src size"};
          task.IsFinished = true;
          record_error(task.rcm);
          emit_entry_error(task);
          continue;
        }
        auto dst_stat = dst_client->IOPort().stat(
            AMDomain::filesystem::StatArgs{task.dst, false},
            task_info->Core.control);
        if (dst_stat.rcm.code != EC::Success) {
          task.rcm = dst_stat.rcm;
          task.IsFinished = true;
          record_error(task.rcm);
          emit_entry_error(task);
          continue;
        }
        if (dst_stat.data.info.type == PathType::DIR) {
          task.rcm = {EC::NotAFile, "", "",
                      "Dst already exists but is a directory"};
          task.IsFinished = true;
          record_error(task.rcm);
          emit_entry_error(task);
          continue;
        }
        if (resume_offset > dst_stat.data.info.size) {
          task.rcm = {EC::InvalidOffset, "", "",
                      "Offset exceeds dst file size"};
          task.IsFinished = true;
          record_error(task.rcm);
          emit_entry_error(task);
          continue;
        }
      }

      const std::string dst_parent = AMPath::dirname(task.dst);
      if (!dst_parent.empty()) {
        auto mkdir_parent_rcm = dst_client->IOPort().mkdirs(
            AMDomain::filesystem::MkdirsArgs{dst_parent},
            task_info->Core.control);
        if (!mkdir_parent_rcm) {
          task.rcm = mkdir_parent_rcm;
          task.IsFinished = true;
          record_error(task.rcm);
          emit_entry_error(task);
          continue;
        }
      }

      task_info->Size.cur_task_transferred.store(resume_offset,
                                                 std::memory_order_relaxed);
      if (resume_offset > 0 &&
          !task_info->Set.keep_start_time.load(std::memory_order_relaxed)) {
        task_info->Size.transferred.fetch_add(resume_offset,
                                              std::memory_order_relaxed);
      }

      pd.io_abort.store(false, std::memory_order_relaxed);
      if (pd.ring_buffer) {
        pd.ring_buffer->Reset();
      }
      task.rcm = TransferSignleFile(src_client, dst_client, pd);
      if (task_info->IsPauseRequested() && task.rcm.has_value() &&
          task.rcm->code == EC::Terminate) {
        task.rcm = std::nullopt;
        task.IsFinished = false;
        paused_requested = true;
        pd.CallInnerCallback(true);
        break;
      }
      task.IsFinished = true;
      if (!task.rcm.has_value() || task.rcm->code == EC::Success) {
        task_info->Size.success_filenum.fetch_add(1, std::memory_order_relaxed);
      } else {
        record_error(task.rcm);
        emit_entry_error(task);
      }
      pd.CallInnerCallback(true);
    }
  }

  task_info->ClearCurrentTask();

  if (paused_requested) {
    task_info->SetResult({EC::Success, "", "", "Task paused"});
    task_info->SetStatus(TaskStatus::Paused);
    task_info->Time.finish.store(AMTime::seconds(), std::memory_order_relaxed);
    return;
  }

  const bool terminated_requested =
      IsTaskHardInterrupted_(task_info) && !task_info->IsPauseRequested();
  if (terminated_requested) {
    const ECM terminate_rcm = {EC::Terminate, "", "",
                               "Task terminated by user"};
    MarkUnfinishedTransferEntries_(task_info, terminate_rcm, record_error);
  }

  if (task_info->Core.control.IsTimeout()) {
    task_info->SetResult({EC::OperationTimeout, "", "", "Task timeout"});
  } else if (IsTaskHardInterrupted_(task_info) &&
             !task_info->IsPauseRequested()) {
    task_info->SetResult(
        {EC::Terminate, "", "", "Task terminated by user"});
  } else if (last_non_ok.code != EC::Success) {
    task_info->SetResult(last_non_ok);
  } else {
    task_info->SetResult(OK);
  }
  task_info->SetStatus(TaskStatus::Finished);
  task_info->Time.finish.store(AMTime::seconds(), std::memory_order_relaxed);
}

} // namespace AMInfra::transfer

// TransferExecutionPool
namespace AMInfra::transfer {
void TransferExecutionPool::CancelPendingTasksOnExit_(
    const std::string &reason) {
  std::vector<TaskHandle> canceled_tasks;
  {
    std::lock_guard<std::mutex> queue_lock(queue_mtx_);
    auto task_registry = task_registry_.lock();
    auto cancel_one = [&](const TaskId &task_id) {
      auto it = task_registry->find(task_id);
      if (it == task_registry->end() || !it->second) {
        return;
      }
      auto task_info = it->second;
      task_registry->erase(it);
      task_info->RequestInterrupt();
      const ECM terminate_rcm = {EC::Terminate, "", "", reason};
      task_info->State.rcm.lock().store(terminate_rcm);
      MarkUnfinishedTransferEntries_(task_info, terminate_rcm);
      task_info->SetStatus(TaskStatus::Finished);
      task_info->Time.finish.store(AMTime::seconds(),
                                   std::memory_order_relaxed);
      task_info->Set.OnWhichThread.store(-1, std::memory_order_relaxed);
      canceled_tasks.push_back(std::move(task_info));
    };

    for (const auto &task_id : public_queue_) {
      cancel_one(task_id);
    }
    public_queue_.clear();

    for (auto &queue : affinity_queues_) {
      for (const auto &task_id : queue) {
        cancel_one(task_id);
      }
      queue.clear();
    }
  }

  for (const auto &task_info : canceled_tasks) {
    HandleCompletedTask(task_info);
  }
}

void TransferExecutionPool::RegisterTask(const TaskHandle &task_info,
                                         TaskAssignType assign_type,
                                         int affinity_thread) {
  std::lock_guard<std::mutex> queue_lock(queue_mtx_);
  auto task_registry = task_registry_.lock();
  std::list<TaskId> *target_queue = nullptr;
  const size_t active_count =
      desired_thread_count_.load(std::memory_order_relaxed);
  const bool affinity_valid =
      affinity_thread >= 0 &&
      static_cast<size_t>(affinity_thread) < active_count &&
      static_cast<size_t>(affinity_thread) < affinity_queues_.size();
  if (assign_type == TaskAssignType::Affinity && affinity_valid) {
    target_queue = &affinity_queues_[static_cast<size_t>(affinity_thread)];
  } else {
    assign_type = TaskAssignType::Public;
    affinity_thread = -1;
    target_queue = &public_queue_;
  }

  target_queue->push_back(task_info->id);

  task_info->Set.assign_type.store(assign_type, std::memory_order_relaxed);
  task_info->Set.affinity_thread.store(affinity_thread,
                                       std::memory_order_relaxed);
  task_info->Set.OnWhichThread.store(-1, std::memory_order_relaxed);
  (*task_registry)[task_info->id] = task_info;
}
std::optional<std::pair<TaskId, TaskHandle>>
TransferExecutionPool::DequeueTask(std::stop_token stop_token,
                                   size_t thread_index) {
  while (true) {
    std::unique_lock<std::mutex> lock(queue_mtx_);
    queue_cv_.wait(lock, [this, &stop_token, thread_index]() {
      if (stop_token.stop_requested()) {
        return true;
      }
      if (!running_.load(std::memory_order_acquire)) {
        return true;
      }
      const bool has_affinity = thread_index < affinity_queues_.size() &&
                                !affinity_queues_[thread_index].empty();
      if (has_affinity) {
        return true;
      }
      const size_t desired =
          desired_thread_count_.load(std::memory_order_relaxed);
      if (thread_index >= desired) {
        return false;
      }
      return HasPendingTasksUnsafe_();
    });

    if (stop_token.stop_requested()) {
      return std::nullopt;
    }

    if (!running_.load(std::memory_order_relaxed) &&
        !HasPendingTasksUnsafe_()) {
      return std::nullopt;
    }

    const size_t desired =
        desired_thread_count_.load(std::memory_order_relaxed);
    if (thread_index >= desired) {
      const bool has_affinity = thread_index < affinity_queues_.size() &&
                                !affinity_queues_[thread_index].empty();
      if (!has_affinity) {
        continue;
      }
    }

    TaskId task_id = 0;
    if (thread_index < affinity_queues_.size() &&
        !affinity_queues_[thread_index].empty()) {
      task_id = affinity_queues_[thread_index].front();
      affinity_queues_[thread_index].pop_front();
    } else if (!public_queue_.empty()) {
      task_id = public_queue_.front();
      public_queue_.pop_front();
    } else {
      continue;
    }

    lock.unlock();

    auto task_registry = task_registry_.lock();
    auto it = task_registry->find(task_id);
    if (it == task_registry->end()) {
      continue;
    }
    return {{task_id, it->second}};
  }
}
void TransferExecutionPool::HandleCompletedTask(const TaskHandle &task_info) {
  if (!task_info || !task_info->TryMarkCompletionDispatched()) {
    return;
  }
  task_info->Core.clients.ReleaseAll();
  if (task_info->Callback.result) {
    CallCallbackSafe(task_info->Callback.result, task_info);
  }
}

void TransferExecutionPool::SetConducting(size_t thread_index,
                                          const TaskId &task_id,
                                          const TaskHandle &task_info) {
  {
    std::lock_guard<std::mutex> lock(conducting_mtx_);
    if (thread_index >= conducting_by_thread_.size()) {
      conducting_by_thread_.resize(thread_index + 1);
      conducting_infos_.resize(thread_index + 1);
    }
    conducting_by_thread_[thread_index] = task_id;
    conducting_infos_[thread_index] = task_info;
    conducting_tasks_.insert(task_id);
  }
  RecomputeDesiredThreadCount_();
}
void TransferExecutionPool::ClearConducting(size_t thread_index) {
  bool removed_task = false;
  TaskHandle finished_info = nullptr;
  {
    std::lock_guard<std::mutex> lock(conducting_mtx_);
    if (thread_index < conducting_by_thread_.size()) {
      const TaskId id = conducting_by_thread_[thread_index];
      if (id != 0) {
        conducting_tasks_.erase(id);
        removed_task = true;
      }
      finished_info = conducting_infos_[thread_index];
      conducting_by_thread_[thread_index] = 0;
      conducting_infos_[thread_index] = nullptr;
    }
  }
  if (finished_info) {
    finished_info->Set.OnWhichThread.store(-1, std::memory_order_relaxed);
  }
  if (removed_task) {
    conducting_cv_.notify_all();
  }
  RecomputeDesiredThreadCount_();
}
void TransferExecutionPool::WorkerLoop(std::stop_token stop_token,
                                       size_t thread_index) {
  while (running_.load(std::memory_order_relaxed) &&
         !stop_token.stop_requested()) {
    auto task_opt = DequeueTask(stop_token, thread_index);
    if (!task_opt.has_value()) {
      break;
    }

    const auto &[task_id, task_info] = *task_opt;
    SetConducting(thread_index, task_id, task_info);
    task_info->Set.OnWhichThread.store(static_cast<int>(thread_index),
                                       std::memory_order_relaxed);

    if (ShouldSkipTaskHelper(task_info)) {
      task_info->Set.OnWhichThread.store(-1, std::memory_order_relaxed);
      {
        auto task_registry = task_registry_.lock();
        task_registry->erase(task_id);
      }
      HandleCompletedTask(task_info);
      ClearConducting(thread_index);
      continue;
    }

    TransferExecutionEngine *engine = nullptr;
    if (thread_index < engines_.size()) {
      engine = engines_[thread_index].get();
    }
    if (!engine) {
      task_info->SetStatus(TaskStatus::Finished);
      task_info->SetResult(Err(EC::InvalidHandle, "", "",
                               "Worker transfer engine is null"));
      task_info->Time.finish.store(AMTime::seconds(),
                                   std::memory_order_relaxed);
    } else {
      engine->ExecuteTask(task_info);
    }

    if (task_info->GetStatus() == TaskStatus::Paused) {
      {
        auto task_registry = task_registry_.lock();
        task_registry->erase(task_info->id);
      }
      HandleCompletedTask(task_info);
      ClearConducting(thread_index);
      continue;
    }

    {
      auto task_registry = task_registry_.lock();
      task_registry->erase(task_info->id);
    }
    HandleCompletedTask(task_info);
    ClearConducting(thread_index);
  }

  ClearConducting(thread_index);
}
TransferExecutionPool::TransferExecutionPool(
    const AMDomain::transfer::TransferManagerArg &arg)
    : manager_arg_(arg) {
  const size_t max_threads = ClampMaxThreads_(
      static_cast<size_t>(std::max(1, manager_arg_.max_threads)));
  max_thread_count_.store(max_threads, std::memory_order_relaxed);
  desired_thread_count_.store(0, std::memory_order_relaxed);

  {
    std::lock_guard<std::mutex> lock(queue_mtx_);
    affinity_queues_.resize(max_threads);
  }
  {
    std::lock_guard<std::mutex> lock(conducting_mtx_);
    conducting_by_thread_.resize(max_threads);
    conducting_infos_.resize(max_threads);
  }

  heartbeat_interval_s_.store(std::max(0, manager_arg_.heartbeat_interval_s),
                              std::memory_order_relaxed);
  heartbeat_timeout_ms_.store(std::max(1, manager_arg_.heartbeat_timeout_ms),
                              std::memory_order_relaxed);
  StartHeartbeat_();
  RecomputeDesiredThreadCount_();
}
TransferExecutionPool::~TransferExecutionPool() { (void)Shutdown(3000); }

ECM TransferExecutionPool::Shutdown(int timeout_ms) {
  if (is_deconstruct.load(std::memory_order_relaxed)) {
    return OK;
  }
  running_.store(false, std::memory_order_relaxed);
  StopHeartbeat_();
  CancelPendingTasksOnExit_();
  queue_cv_.notify_all();
  {
    std::lock_guard<std::mutex> lock(conducting_mtx_);
    for (const auto &info : conducting_infos_) {
      if (info) {
        info->RequestInterrupt();
      }
    }
  }
  std::vector<TaskHandle> paused_tasks;
  {
    auto task_registry = task_registry_.lock();
    for (auto it = task_registry->begin(); it != task_registry->end();) {
      const TaskHandle &task_info = it->second;
      if (!task_info || task_info->GetStatus() != TaskStatus::Paused) {
        ++it;
        continue;
      }
      task_info->RequestInterrupt();
      task_info->SetResult(
          {EC::Terminate, "", "", "Task canceled while shutting down"});
      task_info->SetStatus(TaskStatus::Finished);
      task_info->Time.finish.store(AMTime::seconds(),
                                   std::memory_order_relaxed);
      task_info->Set.OnWhichThread.store(-1, std::memory_order_relaxed);
      paused_tasks.push_back(task_info);
      it = task_registry->erase(it);
    }
  }
  for (const auto &task_info : paused_tasks) {
    HandleCompletedTask(task_info);
  }
  {
    std::unique_lock<std::mutex> lock(conducting_mtx_);
    if (timeout_ms < 0) {
      conducting_cv_.wait(lock, [this]() { return conducting_tasks_.empty(); });
    } else {
      const bool no_conducting = conducting_cv_.wait_for(
          lock, std::chrono::milliseconds(timeout_ms),
          [this]() { return conducting_tasks_.empty(); });
      if (!no_conducting) {
        return {EC::OperationTimeout, "", "",
                "Graceful terminate timed out"};
      }
    }
  }

  {
    std::lock_guard<std::mutex> worker_lock(worker_mtx_);
    for (auto &thread : worker_threads_) {
      if (thread.joinable()) {
        thread.join();
      }
    }
  }
  engines_.clear();
  is_deconstruct.store(true, std::memory_order_relaxed);
  return OK;
}

size_t TransferExecutionPool::ClampMaxThreads_(size_t value) const {
  constexpr size_t kHardMaxThreads = 1024;
  if (value == 0) {
    return 1;
  }
  return std::min(value, kHardMaxThreads);
}

bool TransferExecutionPool::HasPendingTasksUnsafe_() const {
  if (!public_queue_.empty()) {
    return true;
  }
  for (const auto &queue : affinity_queues_) {
    if (!queue.empty()) {
      return true;
    }
  }
  return false;
}

size_t TransferExecutionPool::ComputeDesiredThreadCount_() const {
  size_t pending_count = 0;
  {
    std::lock_guard<std::mutex> lock(queue_mtx_);
    pending_count += public_queue_.size();
    for (const auto &queue : affinity_queues_) {
      pending_count += queue.size();
    }
  }

  size_t conducting_count = 0;
  {
    std::lock_guard<std::mutex> lock(conducting_mtx_);
    conducting_count = conducting_tasks_.size();
  }

  const size_t max_threads =
      ClampMaxThreads_(max_thread_count_.load(std::memory_order_relaxed));
  const size_t active_count = pending_count + conducting_count;
  return std::min(max_threads, active_count);
}

void TransferExecutionPool::EnsureWorkerCapacity_(size_t worker_count) {
  const size_t max_threads =
      ClampMaxThreads_(max_thread_count_.load(std::memory_order_relaxed));
  worker_count = std::min(worker_count, max_threads);
  if (worker_count == 0) {
    return;
  }

  std::lock_guard<std::mutex> worker_lock(worker_mtx_);
  if (worker_count <= worker_threads_.size()) {
    return;
  }

  {
    std::lock_guard<std::mutex> lock(queue_mtx_);
    if (worker_count > affinity_queues_.size()) {
      affinity_queues_.resize(worker_count);
    }
  }
  {
    std::lock_guard<std::mutex> lock(conducting_mtx_);
    if (worker_count > conducting_by_thread_.size()) {
      conducting_by_thread_.resize(worker_count);
      conducting_infos_.resize(worker_count);
    }
  }

  const TransferBufferPolicy policy = {manager_arg_.buffer_size,
                                       manager_arg_.min_buffer,
                                       manager_arg_.max_buffer};
  if (worker_count > engines_.size()) {
    engines_.reserve(worker_count);
    for (size_t idx = engines_.size(); idx < worker_count; ++idx) {
      engines_.push_back(std::make_unique<TransferExecutionEngine>(policy));
    }
  }

  const size_t begin = worker_threads_.size();
  for (size_t idx = begin; idx < worker_count; ++idx) {
    worker_threads_.emplace_back(
        [this, idx](std::stop_token stop_token) { WorkerLoop(stop_token, idx); });
  }
}

void TransferExecutionPool::RecomputeDesiredThreadCount_() {
  const size_t desired = ComputeDesiredThreadCount_();
  EnsureWorkerCapacity_(desired);
  desired_thread_count_.store(desired, std::memory_order_relaxed);
  queue_cv_.notify_all();
}

void TransferExecutionPool::StartHeartbeat_() {
  if (heartbeat_interval_s_.load(std::memory_order_relaxed) <= 0) {
    heartbeat_running_.store(false, std::memory_order_relaxed);
    return;
  }
  if (heartbeat_running_.exchange(true, std::memory_order_acq_rel)) {
    return;
  }
  heartbeat_thread_ = std::jthread(
      [this](std::stop_token stop_token) { HeartbeatLoop_(stop_token); });
}

void TransferExecutionPool::StopHeartbeat_() {
  heartbeat_running_.store(false, std::memory_order_release);
  if (heartbeat_thread_.joinable()) {
    heartbeat_thread_.request_stop();
  }
  heartbeat_cv_.notify_all();
  if (heartbeat_thread_.joinable()) {
    heartbeat_thread_.join();
  }
}

void TransferExecutionPool::HeartbeatLoop_(std::stop_token stop_token) {
  while (running_.load(std::memory_order_acquire) &&
         heartbeat_running_.load(std::memory_order_acquire) &&
         !stop_token.stop_requested()) {
    const int interval_s =
        std::max(1, heartbeat_interval_s_.load(std::memory_order_relaxed));
    std::unique_lock<std::mutex> lock(heartbeat_wait_mtx_);
    (void)heartbeat_cv_.wait_for(
        lock, std::chrono::seconds(interval_s), [this, &stop_token]() {
          if (stop_token.stop_requested()) {
            return true;
          }
          return !running_.load(std::memory_order_acquire) ||
                 !heartbeat_running_.load(std::memory_order_acquire);
        });
    lock.unlock();
    if (!running_.load(std::memory_order_acquire) ||
        !heartbeat_running_.load(std::memory_order_acquire) ||
        stop_token.stop_requested()) {
      break;
    }
    HeartbeatTick_();
  }
}

void TransferExecutionPool::HeartbeatTick_() {
  const int timeout_ms =
      std::max(1, heartbeat_timeout_ms_.load(std::memory_order_relaxed));
  const auto active_tasks = GetRegistryCopy();
  for (const auto &pair : active_tasks) {
    auto task_info = pair.second;
    if (!task_info) {
      continue;
    }
    const auto status = task_info->GetStatus();
    if (status != TaskStatus::Pending && status != TaskStatus::Conducting) {
      continue;
    }
    if (task_info->IsPauseRequested() || task_info->IsTerminateRequested()) {
      continue;
    }

    std::unordered_set<AMDomain::client::IClientPort *> visited = {};
    std::vector<ClientHandle> clients = {};
    const auto collect_client = [&visited,
                                 &clients](const ClientHandle &client) {
      if (!client) {
        return;
      }
      if (!visited.insert(client.get()).second) {
        return;
      }
      clients.push_back(client);
    };

    for (const auto &nickname : task_info->Core.nicknames) {
      collect_client(task_info->Core.clients.GetSrcClient(nickname));
      collect_client(task_info->Core.clients.GetDstClient(nickname));
    }

    if (clients.empty()) {
      const auto collect_from_tasks = [&collect_client,
                                       task_info](auto &tasks) {
        auto task_lock = tasks.lock();

        for (const auto &task : *task_lock) {
          collect_client(task_info->Core.clients.GetSrcClient(task.src_host));
          collect_client(task_info->Core.clients.GetDstClient(task.dst_host));
        }
      };
      collect_from_tasks(task_info->Core.dir_tasks);
      collect_from_tasks(task_info->Core.file_tasks);
    }

    for (const auto &client : clients) {
      if (!client) {
        continue;
      }
      const auto lease_state =
          client->MetaDataPort().QueryNamedValue<bool>("transfer.lease");
      if (lease_state.name_found && lease_state.type_match &&
          lease_state.value.has_value() && lease_state.value.value()) {
        continue;
      }

      auto check_result = client->IOPort().Check(
          {}, AMDomain::client::ControlComponent(nullptr, timeout_ms));
      if (!(check_result.rcm)) {
        if (!task_info->IsPauseRequested() &&
            !task_info->IsTerminateRequested()) {
          task_info->RequestInterrupt();
        }
        break;
      }
    }
  }
}

size_t TransferExecutionPool::ThreadCount(size_t new_count) {
  if (new_count > 0) {
    (void)MaxThreadCount(new_count);
  }
  return desired_thread_count_.load(std::memory_order_relaxed);
}

size_t TransferExecutionPool::MaxThreadCount(size_t new_max) {
  if (new_max == 0) {
    return max_thread_count_.load(std::memory_order_relaxed);
  }
  const size_t clamped = ClampMaxThreads_(new_max);
  max_thread_count_.store(clamped, std::memory_order_relaxed);
  manager_arg_.max_threads = static_cast<int>(clamped);
  RecomputeDesiredThreadCount_();
  return clamped;
}
std::unordered_map<size_t, bool> TransferExecutionPool::GetThreadIDs() const {
  std::unordered_map<size_t, bool> states;
  const size_t count = desired_thread_count_.load(std::memory_order_relaxed);
  states.reserve(count);
  std::lock_guard<std::mutex> lock(conducting_mtx_);
  for (size_t i = 0; i < count; ++i) {
    const bool busy =
        i < conducting_by_thread_.size() && conducting_by_thread_[i] != 0;
    states.emplace(i, busy);
  }
  return states;
}

ECM TransferExecutionPool::Submit(TaskHandle task_info) {
  if (!task_info) {
    return {EC::InvalidArg, "", "", "TaskInfo is nullptr"};
  }
  if (!running_.load(std::memory_order_acquire)) {
    return {EC::OperationUnsupported, "", "",
            "Work manager is shutting down"};
  }
  const bool has_dir_tasks = !task_info->Core.dir_tasks.lock()->empty();
  const bool has_file_tasks = !task_info->Core.file_tasks.lock()->empty();
  if (!has_dir_tasks && !has_file_tasks) {
    return {EC::InvalidArg, "", "", "Tasks is nullptr or empty"};
  }
  if (task_info->Core.clients.empty()) {
    return {EC::InvalidArg, "", "", "Transfer clients is empty"};
  }

  if (task_info->id == 0 ||
      IsTaskIdUsedHelper(task_info->id, task_registry_, conducting_mtx_,
                         conducting_tasks_)) {
    return {EC::InvalidArg, "", "", "Task ID is invalid or already used"};
  }
  task_info->ResetCompletionDispatch();
  task_info->State.intent.store(AMDomain::transfer::ControlIntent::Running,
                                std::memory_order_relaxed);
  task_info->Time.submit.store(AMTime::seconds(), std::memory_order_relaxed);
  task_info->SetStatus(TaskStatus::Pending);
  task_info->CalTotalSize();
  task_info->CalFileNum();

  const bool keep_progress =
      task_info->Set.keep_start_time.load(std::memory_order_relaxed);
  if (!keep_progress) {
    task_info->Size.transferred.store(0, std::memory_order_relaxed);
    task_info->Size.cur_task.store(0, std::memory_order_relaxed);
    task_info->Size.cur_task_transferred.store(0, std::memory_order_relaxed);
    task_info->Size.success_filenum.store(0, std::memory_order_relaxed);
  }
  task_info->Set.OnWhichThread.store(-1, std::memory_order_relaxed);

  const int requested_thread_id =
      task_info->Set.affinity_thread.load(std::memory_order_relaxed);
  const size_t active_count =
      desired_thread_count_.load(std::memory_order_relaxed);
  const bool affinity_valid =
      requested_thread_id >= 0 &&
      static_cast<size_t>(requested_thread_id) < active_count &&
      static_cast<size_t>(requested_thread_id) < affinity_queues_.size();
  const TaskAssignType assign_type =
      affinity_valid ? TaskAssignType::Affinity : TaskAssignType::Public;
  const int affinity_id = affinity_valid ? requested_thread_id : -1;

  RegisterTask(task_info, assign_type, affinity_id);
  RecomputeDesiredThreadCount_();
  return OK;
}

std::optional<TaskStatus>
TransferExecutionPool::GetStatus(const TaskId &id) const {
  auto task_registry = task_registry_.lock();
  auto it = task_registry->find(id);
  if (it != task_registry->end() && it->second) {
    return it->second->GetStatus();
  }
  return std::nullopt;
}

std::pair<TaskHandle, ECM>
TransferExecutionPool::StopActive(const TaskId &id,
                                  AMDomain::transfer::ActiveStopReason reason,
                                  int timeout_ms,
                                  int grace_period_ms) {
  TaskHandle existing = nullptr;
  {
    auto task_registry = task_registry_.lock();
    auto it = task_registry->find(id);
    if (it != task_registry->end()) {
      existing = it->second;
    }
  }
  if (!existing) {
    return {nullptr,
            {EC::TaskNotFound, "", AMStr::ToString(id),
             AMStr::fmt("Task not found: {}", id)}};
  }

  TaskStatus status_t = existing->GetStatus();
  if (status_t == TaskStatus::Finished || status_t == TaskStatus::Paused) {
    return {existing,
            {EC::OperationUnsupported, "", AMStr::ToString(id),
             AMStr::fmt("Task is not active: {}", id)}};
  }

  if (reason == AMDomain::transfer::ActiveStopReason::Pause) {
    if (existing->IsTerminateRequested()) {
      return {existing,
              {EC::OperationUnsupported, "", AMStr::ToString(id),
               AMStr::fmt("Task terminate requested: {}", id)}};
    }

    if (status_t == TaskStatus::Pending) {
      bool done_in_fast_path = false;
      {
        std::lock_guard<std::mutex> queue_lock(queue_mtx_);
        auto task_registry = task_registry_.lock();
        auto it = task_registry->find(id);
        if (it != task_registry->end() && it->second &&
            it->second->GetStatus() == TaskStatus::Pending) {
          TaskHandle task_info = it->second;
          const int affinity_thread =
              task_info->Set.affinity_thread.load(std::memory_order_relaxed);
          const TaskAssignType assign_type =
              task_info->Set.assign_type.load(std::memory_order_relaxed);
          if (assign_type == TaskAssignType::Affinity && affinity_thread >= 0 &&
              static_cast<size_t>(affinity_thread) < affinity_queues_.size()) {
            affinity_queues_[static_cast<size_t>(affinity_thread)].remove(id);
          } else {
            public_queue_.remove(id);
          }
          task_registry->erase(it);
          task_info->RequestPause(grace_period_ms > 0
                                      ? static_cast<size_t>(grace_period_ms)
                                      : size_t{0});
          task_info->SetResult(
              {EC::Success, "", AMStr::ToString(id), "Task paused"});
          task_info->SetStatus(TaskStatus::Paused);
          task_info->Set.OnWhichThread.store(-1, std::memory_order_relaxed);
          task_info->Time.finish.store(AMTime::seconds(),
                                       std::memory_order_relaxed);
          queue_cv_.notify_all();
          existing = task_info;
          done_in_fast_path = true;
        }
      }
      if (done_in_fast_path) {
        RecomputeDesiredThreadCount_();
        HandleCompletedTask(existing);
        return {existing, OK};
      }
    }

    existing->RequestPause(grace_period_ms > 0
                               ? static_cast<size_t>(grace_period_ms)
                               : size_t{0});
    const int64_t start_ms = AMTime::miliseconds();
    while (timeout_ms < 0 || (AMTime::miliseconds() - start_ms) < timeout_ms) {
      status_t = existing->GetStatus();
      if (status_t == TaskStatus::Finished) {
        const ECM final_rcm = existing->GetResult();
        if (final_rcm.code == EC::Terminate) {
          return {existing, final_rcm};
        }
        return {existing,
                {EC::OperationUnsupported, "", AMStr::ToString(id),
                 AMStr::fmt("Task finished before pause completed: {}", id)}};
      }
      const int on_thread =
          existing->Set.OnWhichThread.load(std::memory_order_relaxed);
      bool detached_from_worker = false;
      {
        std::lock_guard<std::mutex> lock(conducting_mtx_);
        detached_from_worker =
            !conducting_tasks_.contains(id);
      }
      if (status_t == TaskStatus::Paused && on_thread < 0 &&
          detached_from_worker) {
        return {existing, OK};
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return {existing,
            {EC::OperationTimeout, "", AMStr::ToString(id),
             AMStr::fmt("Task pause timeout: {}", id)}};
  }

  TaskHandle completed_without_wait = nullptr;
  if (status_t == TaskStatus::Pending) {
    bool done_in_fast_path = false;
    {
      std::lock_guard<std::mutex> queue_lock(queue_mtx_);
      auto task_registry = task_registry_.lock();
      auto it = task_registry->find(id);
      if (it != task_registry->end() && it->second &&
          it->second->GetStatus() == TaskStatus::Pending) {
        TaskHandle task_info = it->second;
        const int affinity_thread =
            task_info->Set.affinity_thread.load(std::memory_order_relaxed);
        const TaskAssignType assign_type =
            task_info->Set.assign_type.load(std::memory_order_relaxed);
        if (assign_type == TaskAssignType::Affinity && affinity_thread >= 0 &&
            static_cast<size_t>(affinity_thread) < affinity_queues_.size()) {
          affinity_queues_[static_cast<size_t>(affinity_thread)].remove(id);
        } else {
          public_queue_.remove(id);
        }
        task_registry->erase(it);
        task_info->RequestInterrupt(grace_period_ms > 0
                                        ? static_cast<size_t>(grace_period_ms)
                                        : size_t{0});
        const ECM terminate_rcm = {EC::Terminate, "", AMStr::ToString(id),
                                   "Task terminated"};
        MarkUnfinishedTransferEntries_(task_info, terminate_rcm);
        task_info->SetResult(terminate_rcm);
        task_info->SetStatus(TaskStatus::Finished);
        task_info->Time.finish.store(AMTime::seconds(),
                                     std::memory_order_relaxed);
        task_info->Set.OnWhichThread.store(-1, std::memory_order_relaxed);
        queue_cv_.notify_all();
        completed_without_wait = task_info;
        done_in_fast_path = true;
      }
    }
    if (done_in_fast_path && completed_without_wait) {
      RecomputeDesiredThreadCount_();
      HandleCompletedTask(completed_without_wait);
      return {completed_without_wait, OK};
    }
  }

  existing->RequestInterrupt(grace_period_ms > 0
                                 ? static_cast<size_t>(grace_period_ms)
                                 : size_t{0});
  const int64_t start_ms = AMTime::miliseconds();
  while (timeout_ms < 0 || (AMTime::miliseconds() - start_ms) < timeout_ms) {
    if (existing->GetStatus() == TaskStatus::Finished) {
      return {existing, OK};
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  return {existing,
          {EC::OperationTimeout, "", AMStr::ToString(id),
           AMStr::fmt("Task terminate timeout: {}", id)}};
}

std::pair<TaskHandle, ECM> TransferExecutionPool::Terminate(
    const TaskId &id, int timeout_ms, int grace_period_ms) {
  return StopActive(id, AMDomain::transfer::ActiveStopReason::Terminate,
                    timeout_ms, grace_period_ms);
}

std::unordered_map<TaskId, TaskHandle>
TransferExecutionPool::GetRegistryCopy() const {
  auto task_registry = task_registry_.lock();
  return *task_registry;
}

TaskHandle TransferExecutionPool::GetActiveTask(const TaskId &id) const {
  auto task_registry = task_registry_.lock();
  auto it = task_registry->find(id);
  if (it == task_registry->end()) {
    return nullptr;
  }
  return it->second;
}

std::unordered_map<TaskId, TaskHandle>
TransferExecutionPool::GetAllActiveTasks() const {
  return GetRegistryCopy();
}

std::unordered_map<TaskId, TaskHandle>
TransferExecutionPool::GetPendingTasks() const {
  std::unordered_map<TaskId, TaskHandle> out;
  auto task_registry = task_registry_.lock();
  out.reserve(task_registry->size());
  for (const auto &[id, task] : *task_registry) {
    if (task && task->GetStatus() == TaskStatus::Pending) {
      out.emplace(id, task);
    }
  }
  return out;
}

std::unordered_map<TaskId, TaskHandle>
TransferExecutionPool::GetConductingTasks() const {
  std::unordered_map<TaskId, TaskHandle> out;
  std::lock_guard<std::mutex> lock(conducting_mtx_);
  out.reserve(conducting_infos_.size());
  for (const auto &task : conducting_infos_) {
    if (task && task->id != 0) {
      out.emplace(task->id, task);
    }
  }
  return out;
}

} // namespace AMInfra::transfer

// Port Implemention
namespace AMDomain::transfer {
/**
 * @brief Create default infra-backed transfer pool adapter.
 */
std::unique_ptr<ITransferPoolPort>
CreateTransferPoolPort(const TransferManagerArg &arg) {
  return std::make_unique<AMInfra::transfer::TransferExecutionPool>(arg);
}
} // namespace AMDomain::transfer

