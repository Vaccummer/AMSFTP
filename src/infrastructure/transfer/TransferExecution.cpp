#include "foundation/core/DataClass.hpp"
#include "infrastructure/transfer/core.hpp"

#include "foundation/tools/time.hpp"
#include "infrastructure/client/ftp/FTP.hpp"
#include "infrastructure/client/sftp/SFTP.hpp"

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

  auto *cur_task = task_info->Core.cur_task.load(std::memory_order_relaxed);
  if (!cur_task) {
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

  if (cb_error.first != ErrorCode::Success &&
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
  if (!task_info) {
    return;
  }
  task_info->Size.cur_task_transferred.fetch_add(delta,
                                                 std::memory_order_relaxed);
  task_info->Size.transferred.fetch_add(delta, std::memory_order_relaxed);
}

TransferTask *TransferRuntimeProgress::GetCurrentTask() const {
  if (!task_info) {
    return nullptr;
  }
  return task_info->Core.cur_task.load(std::memory_order_relaxed);
}

} // namespace AMInfra::transfer

namespace {
constexpr size_t AMDefaultLocalBufferSize =
    AMDomain::client::ClientService::AMDefaultLocalBufferSize;
constexpr size_t AMDefaultRemoteBufferSize =
    AMDomain::client::ClientService::AMDefaultRemoteBufferSize;
constexpr size_t AMMinBufferSize =
    AMDomain::client::ClientService::AMMinBufferSize;
constexpr size_t AMMaxBufferSize =
    AMDomain::client::ClientService::AMMaxBufferSize;
using ECM = ECM;
using EC = ErrorCode;
using ClientHandle = AMInfra::transfer::ClientHandle;
using RuntimeProgress = AMInfra::transfer::TransferRuntimeProgress;
using TaskInfo = AMDomain::transfer::TaskInfo;
using TaskHandle = AMInfra::transfer::TaskHandle;
using ClientProtocol = AMDomain::client::ClientProtocol;
using AMSFTPIOCore = AMInfra::client::SFTP::AMSFTPIOCore;
using SocketWaitType = AMInfra::client::SFTP::detail::SocketWaitType;
using AMFTPIOCore = AMInfra::client::FTP::AMFTPIOCore;
using TransferTask = AMDomain::transfer::TransferTask;
using TaskStatus = AMDomain::transfer::TaskStatus;
using TaskId = TaskInfo::ID;
using TaskRegistry = AMAtomic<std::unordered_map<TaskId, TaskHandle>>;
using TransferClientContainer = AMDomain::transfer::TransferClientContainer;

bool IsTaskInterrupted_(const RuntimeProgress &pd) {
  return pd.task_info && pd.task_info->IsInterrupted();
}

void RequestTaskInterrupt_(RuntimeProgress &pd) {
  if (pd.task_info) {
    pd.task_info->RequestInterrupt();
  }
}

bool IsTaskIdUsedHelper(const TaskId &task_id, TaskRegistry &task_registry,
                        TaskRegistry &results, std::mutex &conducting_mtx,
                        const std::unordered_set<TaskId> &conducting_tasks) {
  {
    auto registry = task_registry.lock();
    if (registry->find(task_id) != registry->end()) {
      return true;
    }
  }
  {
    auto history = results.lock();
    if (history->find(task_id) != history->end()) {
      return true;
    }
  }
  std::lock_guard<std::mutex> lock(conducting_mtx);
  return conducting_tasks.find(task_id) != conducting_tasks.end();
}

bool ShouldSkipTaskHelper(const TaskHandle &task_info) {
  if (task_info && task_info->IsInterrupted() &&
      !task_info->IsPauseRequested()) {
    task_info->SetResult({EC::Terminate, "Task terminated before start"});
    task_info->SetStatus(TaskStatus::Finished);
    task_info->Time.finish.store(AMTime::seconds(), std::memory_order_relaxed);
    return true;
  }
  return false;
}

ssize_t CalculateBufferSizeHelper(const ClientHandle &src_client,
                                  const ClientHandle &dst_client,
                                  ssize_t provided_size) {
  const auto resolve_buffer_hint = [](const ClientHandle &client) -> ssize_t {
    if (!client) {
      return -1;
    }
    return client->ConfigPort().GetRequest().buffer_size;
  };

  const ssize_t src_size = resolve_buffer_hint(src_client);
  const ssize_t dst_size = resolve_buffer_hint(dst_client);
  const bool is_local = !src_client && !dst_client;
  if (provided_size >
          AMDomain::client::ClientService::AMDefaultLocalBufferSize &&
      provided_size < AMMaxBufferSize) {
    return provided_size;
  }
  if (src_size < 0 && dst_size < 0) {
    return is_local ? AMDefaultLocalBufferSize : AMDefaultRemoteBufferSize;
  }
  if (src_size > 0 && dst_size < 0) {
    return std::max<ssize_t>(std::min<ssize_t>(src_size, AMMaxBufferSize),
                             AMMinBufferSize);
  }
  if (src_size > 0 && dst_size > 0) {
    return std::max<ssize_t>(
        std::min<ssize_t>({src_size, dst_size, AMMaxBufferSize}),
        AMMinBufferSize);
  }
  return std::max<ssize_t>(std::min<ssize_t>(dst_size, AMMaxBufferSize),
                           AMMinBufferSize);
}

ClientHandle ResolveTaskClientHelper(const TransferClientContainer &clients,
                                     const std::string &nickname,
                                     bool prefer_secondary) {
  const std::string key = nickname.empty() ? std::string("local") : nickname;
  auto it = clients.find(key);
  if (it == clients.end()) {
    return nullptr;
  }
  const auto &holder = it->second;
  if (std::holds_alternative<ClientHandle>(holder)) {
    if (prefer_secondary) {
      return nullptr;
    }
    return std::get<ClientHandle>(holder);
  }
  const auto &pair_clients =
      std::get<std::pair<ClientHandle, ClientHandle>>(holder);
  if (prefer_secondary) {
    return pair_clients.second;
  }
  return pair_clients.first;
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
  AMDomain::client::ClientControlComponent control = {};

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
        libssh2_sftp_close_handle(sftp_handle);
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

      if (is_write) {
        int flags = LIBSSH2_FXF_WRITE;
        if (truncate) {
          flags |= LIBSSH2_FXF_TRUNC | LIBSSH2_FXF_CREAT;
        }
        nb_res = client->nb_call(control, [&]() {
          return libssh2_sftp_open(client->sftp, path.c_str(), flags, 0744);
        });
        sftp_handle = nb_res.value;
      } else {
        nb_res = client->nb_call(control, [&]() {
          return libssh2_sftp_open(client->sftp, path.c_str(), LIBSSH2_FXF_READ,
                                   0400);
        });
        sftp_handle = nb_res.value;
      }
      if (nb_res.status == WaitResult::Interrupted) {
        if (pd) {
          return {EC::Terminate, "Task terminated by user"};
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
        return {EC::LocalFileOpenError,
                AMStr::fmt("Failed to open local file \"{}\": error code {}",
                           path, GetLastError())};
      }
#else
      int flags = is_write ? O_RDWR : O_RDONLY;
      if (is_write && truncate) {
        flags |= (O_CREAT | O_TRUNC);
      }
      file_handle = open(path.c_str(), flags, 0644);

      if (file_handle == -1) {
        return {EC::LocalFileOpenError,
                AMStr::fmt("Failed to open local file \"{}\": {}", path,
                           strerror(errno))};
      }
#endif
    }

    return {EC::Success, ""};
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
      return {EC::LocalFileOpenError, "File not initialized"};
    }
    if (new_offset == 0) {
      offset = 0;
      return {EC::Success, ""};
    }
    if (is_sftp) {
      if (!client) {
        return {EC::InvalidArg, "SFTP client not available"};
      }
      std::lock_guard<std::recursive_mutex> lock(client->TransferMutex());
      libssh2_sftp_seek64(sftp_handle,
                          static_cast<libssh2_uint64_t>(new_offset));
      offset = new_offset;
      return {EC::Success, ""};
    }
#ifdef _WIN32
    LARGE_INTEGER li;
    li.QuadPart = static_cast<LONGLONG>(new_offset);
    LARGE_INTEGER new_pos;
    if (!SetFilePointerEx(file_handle, li, &new_pos, FILE_BEGIN)) {
      return {EC::LocalFileReadError,
              AMStr::fmt("Seek local file \"{}\" failed: error code {}", path,
                         GetLastError())};
    }
    offset = static_cast<size_t>(new_pos.QuadPart);
    return {EC::Success, ""};
#else
    off_t res = lseek(file_handle, static_cast<off_t>(new_offset), SEEK_SET);
    if (res == static_cast<off_t>(-1)) {
      return {EC::LocalFileReadError,
              AMStr::fmt("Seek local file \"{}\" failed: {}", path,
                         strerror(errno))};
    }
    offset = static_cast<size_t>(res);
    return {EC::Success, ""};
#endif
  }

  std::pair<ssize_t, ECM> Read() {
    if (!IsValid()) {
      return {-1, {EC::LocalFileOpenError, "File not initialized"}};
    }
    if (!pd || !pd->ring_buffer) {
      return {-1, {EC::InvalidArg, "Progress data not initialized"}};
    }

    auto [write_ptr, max_write] = pd->ring_buffer->get_write_ptr();
    ssize_t to_read = std::min<ssize_t>(max_write, (file_size - offset));
    ssize_t bytes_read;
    if (to_read > 0) {
      if (is_sftp) {
        // SFTP read (non-blocking)
        std::lock_guard<std::recursive_mutex> lock(client->TransferMutex());
        while (true) {
          if (IsTaskInterrupted_(*pd)) {
            return {-1, {EC::Terminate, "Task terminated by user"}};
          }
          bytes_read = libssh2_sftp_read(sftp_handle, write_ptr, to_read);
          if (bytes_read > 0) {
            pd->ring_buffer->commit_write(bytes_read);
            offset += bytes_read;
            return {bytes_read, {EC::Success, ""}};
          }
          if (bytes_read == 0) {
            return {0, {EC::EndOfFile, "End of file"}};
          }
          if (bytes_read == LIBSSH2_ERROR_EAGAIN) {
            WaitResult wr =
                client->wait_for_socket(SocketWaitType::Read, control);
            if (wr == WaitResult::Error) {
              return {
                  -1,
                  {wait_result_to_error_code(wr), "SFTP read socket error"}};
            }
            if (wr == WaitResult::Interrupted) {
              return {static_cast<ssize_t>(EC::Terminate),
                      ECM{EC::Terminate, "Task terminated by user"}};
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
          return {-1,
                  {EC::LocalFileReadError,
                   AMStr::fmt("Read local file \"{}\" failed: error code {}",
                              path, GetLastError())}};
        }
        if (bytes_read > 0) {
          pd->ring_buffer->commit_write(bytes_read);
          offset += bytes_read;
          return {static_cast<int>(bytes_read), {EC::Success, ""}};
        } else {
          return {0, {EC::EndOfFile, "End of file"}};
        }
#else
        ssize_t bytes_read = read(file_handle, write_ptr, to_read);
        if (bytes_read > 0) {
          pd->ring_buffer->commit_write(bytes_read);
          offset += bytes_read;
          return {static_cast<int>(bytes_read), {EC::Success, ""}};
        } else if (bytes_read == 0) {
          return {0, {EC::EndOfFile, "End of file"}};
        } else {
          return {-1,
                  {EC::LocalFileReadError,
                   AMStr::fmt("Read local file \"{}\" failed: {}", path,
                              strerror(errno))}};
        }
#endif
      }
    }
    return {0, {EC::Success, ""}};
  }

  std::pair<ssize_t, ECM> Write() {
    if (!IsValid()) {
      return {-1, {EC::LocalFileOpenError, "File not initialized"}};
    }
    if (!pd || !pd->ring_buffer) {
      return {-1, {EC::InvalidArg, "Progress data not initialized"}};
    }

    auto [read_ptr, max_read] = pd->ring_buffer->get_read_ptr();
    ssize_t to_write = std::min<ssize_t>(max_read, (file_size - offset));
    ssize_t bytes_written;
    if (to_write > 0) {
      if (is_sftp) {
        // SFTP write (non-blocking)
        while (true) {
          if (IsTaskInterrupted_(*pd)) {
            return {-1, {EC::Terminate, "Task terminated by user"}};
          }
          {
            std::lock_guard<std::recursive_mutex> lock(client->TransferMutex());
            bytes_written = libssh2_sftp_write(sftp_handle, read_ptr, to_write);
          }
          if (bytes_written > 0) {
            pd->ring_buffer->commit_read(bytes_written);
            offset += bytes_written;
            return {bytes_written, {EC::Success, ""}};
          }
          if (bytes_written == 0) {
            return {0, {EC::EndOfFile, "End of file"}};
          }
          if (bytes_written == LIBSSH2_ERROR_EAGAIN) {
            WaitResult wr =
                client->wait_for_socket(SocketWaitType::Write, control);
            if (wr == WaitResult::Error) {
              return {
                  LIBSSH2_ERROR_EAGAIN,
                  {wait_result_to_error_code(wr), "SFTP write socket error"}};
            }
            if (wr == WaitResult::Interrupted) {
              return {static_cast<ssize_t>(EC::Terminate),
                      ECM{EC::Terminate, "Task terminated by user"}};
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
          return {-1,
                  {EC::LocalFileWriteError,
                   AMStr::fmt("Write local file \"{}\" failed: error code {}",
                              path, GetLastError())}};
        }
        if (bytes_written > 0) {
          pd->ring_buffer->commit_read(bytes_written);
          offset += bytes_written;
          return {static_cast<int>(bytes_written), {EC::Success, ""}};
        } else {
          return {0, {EC::EndOfFile, "End of file"}};
        }
#else
        ssize_t bytes_written = write(file_handle, read_ptr, to_write);
        if (bytes_written > 0) {
          pd->ring_buffer->commit_read(bytes_written);
          offset += bytes_written;
          return {static_cast<int>(bytes_written), {EC::Success, ""}};
        } else if (bytes_written == 0) {
          return {0, {EC::EndOfFile, "End of file"}};
        } else {
          return {-1,
                  {EC::LocalFileWriteError,
                   AMStr::fmt("Write local file \"{}\" failed: {}", path,
                              strerror(errno))}};
        }
#endif
      }
    }
    return {0, {EC::Success, ""}};
  }
};

class TransferExecutionHelper {
public:
  /**
   * @brief Construct one execution implementation.
   */
  TransferExecutionHelper() = default;

public:
  /**
   * @brief Emit task progress through the scheduler-provided callback.
   */
  void EmitProgress(TaskHandle task_info, RuntimeProgress &pd,
                    bool force) const {
    (void)task_info;
    pd.CallInnerCallback(force);
  }

  // XToBuffer - read from source to ring buffer
  void XToBuffer(ClientHandle client, TaskHandle task_info,
                 RuntimeProgress &pd) const {
    if (!client || !task_info ||
        task_info->Core.cur_task.load(std::memory_order_relaxed) == nullptr) {
      return;
    }
    auto *task = task_info->Core.cur_task.load();
    if (client->ConfigPort().GetProtocol() == ClientProtocol::SFTP) {
      auto *clientf = dynamic_cast<AMSFTPIOCore *>(&client->IOPort());
      if (clientf == nullptr) {
        RequestTaskInterrupt_(pd);
        task->rcm = {EC::InvalidArg, "SFTP IO port implementation mismatch"};
        return;
      }
      UnionFileHandle file_handle;
      ECM rcm = file_handle.Init(task->src, task->size, clientf, false, true,
                                 true, &pd);
      if (rcm.first != EC::Success) {
        RequestTaskInterrupt_(pd);
        task->rcm = rcm;
        return;
      }
      if (task->transferred > 0) {
        ECM seek_rcm = file_handle.Seek(task->transferred);
        if (seek_rcm.first != EC::Success) {
          RequestTaskInterrupt_(pd);
          task->rcm = seek_rcm;
          return;
        }
      }
      std::lock_guard<std::recursive_mutex> lock(clientf->TransferMutex());
      libssh2_session_set_blocking(clientf->session, 0);
      while (file_handle.offset < file_handle.file_size &&
             !IsTaskInterrupted_(pd)) {
        while (pd.ring_buffer->full() && !IsTaskInterrupted_(pd) &&
               file_handle.offset < file_handle.file_size) {
          std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        if (IsTaskInterrupted_(pd)) {
          return;
        }
        auto [bytes_read, ecm] = file_handle.Read();
        if (ecm.first != EC::Success && ecm.first != EC::EndOfFile) {
          RequestTaskInterrupt_(pd);
          task->rcm = ecm;
          return;
        }
      }
    } else if (client->ConfigPort().GetProtocol() == ClientProtocol::LOCAL) {
      UnionFileHandle file_handle;
      ECM rcm = file_handle.Init(task->src, task->size, nullptr, false, true,
                                 true, &pd);
      if (rcm.first != EC::Success) {
        RequestTaskInterrupt_(pd);
        task->rcm = rcm;
        return;
      }
      if (task->transferred > 0) {
        ECM seek_rcm = file_handle.Seek(task->transferred);
        if (seek_rcm.first != EC::Success) {
          RequestTaskInterrupt_(pd);
          task->rcm = seek_rcm;
          return;
        }
      }
      while (file_handle.offset < file_handle.file_size) {
        while (pd.ring_buffer->full() && !IsTaskInterrupted_(pd) &&
               file_handle.offset < file_handle.file_size) {
          std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        if (IsTaskInterrupted_(pd)) {
          return;
        }
        auto [bytes_read, ecm] = file_handle.Read();
        if (ecm.first != EC::Success && ecm.first != EC::EndOfFile) {
          RequestTaskInterrupt_(pd);
          task->rcm = ecm;
          return;
        }
      }
    } else if (client->ConfigPort().GetProtocol() == ClientProtocol::FTP) {
      auto *client_ftp_raw = dynamic_cast<AMFTPIOCore *>(&client->IOPort());
      if (client_ftp_raw == nullptr) {
        RequestTaskInterrupt_(pd);
        task->rcm = {EC::InvalidArg, "FTP IO port implementation mismatch"};
        return;
      }
      ECM out_rcm;
      std::shared_ptr<AMFTPIOCore> client_ftp(client_ftp_raw,
                                              [](AMFTPIOCore *) {});
      FTPDownloadSet(client_ftp, task->src, FTPToBufferWk, &pd);
      if (out_rcm.first != EC::Success) {
        RequestTaskInterrupt_(pd);
        task->rcm = out_rcm;
      }
    }
  }

  // BufferToX - write from ring buffer to destination
  void BufferToX(ClientHandle client, TaskHandle task_info,
                 RuntimeProgress &pd) const {
    if (!client || !task_info ||
        task_info->Core.cur_task.load(std::memory_order_relaxed) == nullptr) {
      return;
    }
    auto *task = task_info->Core.cur_task.load();
    if (client->ConfigPort().GetProtocol() == ClientProtocol::SFTP) {
      auto *clientf = dynamic_cast<AMSFTPIOCore *>(&client->IOPort());
      if (clientf == nullptr) {
        RequestTaskInterrupt_(pd);
        task->rcm = {EC::InvalidArg, "SFTP IO port implementation mismatch"};
        return;
      }
      UnionFileHandle file_handle;
      const bool resume = task->transferred > 0;
      ECM rcm = file_handle.Init(task->dst, task->size, clientf, true, true,
                                 !resume, &pd);
      if (rcm.first != EC::Success) {
        RequestTaskInterrupt_(pd);
        task->rcm = rcm;
        return;
      }
      if (resume) {
        ECM seek_rcm = file_handle.Seek(task->transferred);
        if (seek_rcm.first != EC::Success) {
          RequestTaskInterrupt_(pd);
          task->rcm = seek_rcm;
          return;
        }
      }
      libssh2_session_set_blocking(clientf->session, 0);
      while (file_handle.offset < file_handle.file_size &&
             !IsTaskInterrupted_(pd)) {
        while (pd.ring_buffer->full() && !IsTaskInterrupted_(pd)) {
          std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        if (IsTaskInterrupted_(pd)) {
          return;
        }
        auto [bytes_write, ecm] = file_handle.Write();
        if (ecm.first != EC::Success && ecm.first != EC::EndOfFile) {
          RequestTaskInterrupt_(pd);
          task->rcm = ecm;
          return;
        }
        if (bytes_write > 0) {
          task_info->Size.transferred.fetch_add(
              static_cast<size_t>(bytes_write), std::memory_order_relaxed);
          task_info->Size.cur_task_transferred.store(
              static_cast<size_t>(file_handle.offset),
              std::memory_order_relaxed);
        }
        task->transferred = task_info->Size.cur_task_transferred.load(
            std::memory_order_relaxed);
        EmitProgress(task_info, pd, false);
      }
    } else if (client->ConfigPort().GetProtocol() == ClientProtocol::LOCAL) {
      UnionFileHandle file_handle;
      const bool resume = task->transferred > 0;
      ECM rcm = file_handle.Init(task->dst, task->size, nullptr, true, true,
                                 !resume, &pd);
      if (rcm.first != EC::Success) {
        RequestTaskInterrupt_(pd);
        task->rcm = rcm;
        return;
      }
      if (resume) {
        ECM seek_rcm = file_handle.Seek(task->transferred);
        if (seek_rcm.first != EC::Success) {
          RequestTaskInterrupt_(pd);
          task->rcm = seek_rcm;
          return;
        }
      }
      while (file_handle.offset < file_handle.file_size &&
             !IsTaskInterrupted_(pd)) {
        while (pd.ring_buffer->full() && !IsTaskInterrupted_(pd)) {
          std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        if (IsTaskInterrupted_(pd)) {
          return;
        }
        auto [bytes_write, ecm] = file_handle.Write();
        if (ecm.first != EC::Success && ecm.first != EC::EndOfFile) {
          RequestTaskInterrupt_(pd);
          task->rcm = ecm;
          return;
        }
        if (bytes_write > 0) {
          task_info->Size.transferred.fetch_add(
              static_cast<size_t>(bytes_write), std::memory_order_relaxed);
          task_info->Size.cur_task_transferred.store(
              static_cast<size_t>(file_handle.offset),
              std::memory_order_relaxed);
        }
        task->transferred = task_info->Size.cur_task_transferred.load(
            std::memory_order_relaxed);
        EmitProgress(task_info, pd, false);
      }
    } else if (client->ConfigPort().GetProtocol() == ClientProtocol::FTP) {
      auto *client_ftp_raw = dynamic_cast<AMFTPIOCore *>(&client->IOPort());
      if (client_ftp_raw == nullptr) {
        RequestTaskInterrupt_(pd);
        task->rcm = {EC::InvalidArg, "FTP IO port implementation mismatch"};
        return;
      }
      ECM out_rcm;
      std::shared_ptr<AMFTPIOCore> client_ftp(client_ftp_raw,
                                              [](AMFTPIOCore *) {});
      FTPUploadSet(client_ftp, task->dst, &pd, BufferToFTPWk);
      if (out_rcm.first != EC::Success) {
        RequestTaskInterrupt_(pd);
        task->rcm = out_rcm;
      }
    }
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
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        continue;
      }
      auto [read_ptr, read_len] = pd->ring_buffer->get_read_ptr();
      ssize_t to_read = read_len > size * nmemb ? size * nmemb : read_len;
      if (to_read > 0) {
        try {
          memcpy(ptr, read_ptr, to_read);
          pd->ring_buffer->commit_read(to_read);
          pd->UpdateSize(to_read);
          pd->CallInnerCallback(false);
          return to_read;
        } catch (const std::exception &e) {
          RequestTaskInterrupt_(*pd);
          if (cur_task) {
            cur_task->rcm = ECM{EC::BufferReadError, e.what()};
          }
          return CURL_READFUNC_ABORT;
        }
      } else if (to_read < 0) {
        RequestTaskInterrupt_(*pd);
        if (cur_task) {
          cur_task->rcm =
              ECM{EC::BufferReadError, "Get negative value for data size"};
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
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
      }
      if (IsTaskInterrupted_(*pd)) {
        return 0;
      }
      auto [write_ptr, write_len] = pd->ring_buffer->get_write_ptr();
      size_t remaining = total - written;
      size_t to_write = std::min<size_t>(write_len, remaining);
      if (to_write > 0) {
        try {
          memcpy(write_ptr, ptr + written, to_write);
          pd->ring_buffer->commit_write(to_write);
          written += to_write;
        } catch (const std::exception &e) {
          RequestTaskInterrupt_(*pd);
          if (cur_task) {
            cur_task->rcm = ECM{EC::BufferWriteError, e.what()};
          }
          return 0;
        }
      }
    }
    return total;
  }

  // Upload with ProgressData (legacy - for AMSFTPWorker)
  static void FTPUploadSet(std::shared_ptr<AMFTPIOCore> client,
                           const std::string &dst, RuntimeProgress *pd,
                           curl_read_callback read_callback) {
    std::lock_guard<std::recursive_mutex> lock(client->TransferMutex());

    TransferTask *cur_task = pd->GetCurrentTask();
    if (!cur_task) {
      RequestTaskInterrupt_(*pd);
      return;
    }
    const size_t resume_offset = cur_task->transferred;
    ECM ecm = client->SetupPath(dst, false);
    if (ecm.first != EC::Success) {
      cur_task->rcm = ecm;
      RequestTaskInterrupt_(*pd);
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
      RequestTaskInterrupt_(*pd);
    } else if (res != CURLE_OK) {
      cur_task->rcm =
          ECM{EC::FTPUploadFailed,
              AMStr::fmt("Upload failed: {}", curl_easy_strerror(res))};
      RequestTaskInterrupt_(*pd);
    }
  }

  // Download with ProgressData (legacy - for AMSFTPWorker)
  static void FTPDownloadSet(std::shared_ptr<AMFTPIOCore> client,
                             const std::string &src,
                             curl_write_callback write_callback,
                             RuntimeProgress *pd) {
    std::lock_guard<std::recursive_mutex> lock(client->TransferMutex());

    TransferTask *cur_task = pd->GetCurrentTask();

    if (!cur_task) {
      RequestTaskInterrupt_(*pd);
      return;
    }
    const size_t resume_offset = cur_task->transferred;
    ECM ecm = client->SetupPath(src, false);
    if (ecm.first != EC::Success) {
      cur_task->rcm = ecm;
      RequestTaskInterrupt_(*pd);
      return;
    }
    auto curl = client->GetCURL();
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, pd);
    curl_easy_setopt(curl, CURLOPT_RESUME_FROM_LARGE,
                     static_cast<curl_off_t>(resume_offset));
    CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_ABORTED_BY_CALLBACK || res == CURLE_WRITE_ERROR) {
      RequestTaskInterrupt_(*pd);
    } else if (res != CURLE_OK) {
      cur_task->rcm =
          ECM{EC::FTPDownloadFailed,
              AMStr::fmt("Download failed: {}", curl_easy_strerror(res))};
      RequestTaskInterrupt_(*pd);
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
TransferExecutionEngine::TransferExecutionEngine() = default;

/**
 * @brief Destroy one transfer execution engine.
 */
TransferExecutionEngine::~TransferExecutionEngine() = default;

/**
 * @brief Execute one prepared single-file transfer task.
 */
ECM TransferExecutionEngine::TransferSignleFile(
    ClientHandle src_client, ClientHandle dst_client,
    RuntimeProgress &runtime_progress) const {
  TransferExecutionHelper helper;
  auto task_info = runtime_progress.task_info;
  if (!src_client || !dst_client || !task_info ||
      task_info->Core.cur_task.load(std::memory_order_relaxed) == nullptr) {
    return {EC::InvalidArg, "Invalid transfer input"};
  }

  auto &pd = runtime_progress;
  auto *task = task_info->Core.cur_task.load();
  const auto src_protocol = src_client->ConfigPort().GetProtocol();
  const auto dst_protocol = dst_client->ConfigPort().GetProtocol();

  const auto is_supported = [](ClientProtocol protocol) {
    return protocol == ClientProtocol::LOCAL ||
           protocol == ClientProtocol::FTP || protocol == ClientProtocol::SFTP;
  };

  if (!is_supported(src_protocol) || !is_supported(dst_protocol)) {
    return {EC::OperationUnsupported, "Unsupported client protocol"};
  }

  if (src_client->GetUID() == dst_client->GetUID()) {
    return {EC::InvalidHandle,
            "TransferSignleFile requires different source/destination client "
            "IDs"};
  }

  std::thread reading_thread([&helper, src_client, task_info, &pd]() {
    helper.XToBuffer(src_client, task_info, pd);
  });

  helper.BufferToX(dst_client, task_info, pd);

  if (reading_thread.joinable()) {
    reading_thread.join();
  }

  task->transferred =
      task_info->Size.cur_task_transferred.load(std::memory_order_relaxed);

  if (task->rcm.first != EC::Success) {
    return task->rcm;
  }

  if (task->transferred == task->size) {
    return task->rcm;
  }

  return {EC::UnknownError, "Task not finished but exited unexpectedly"};
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
      task_info->State.rcm.lock().store({EC::Terminate, reason});
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
TransferExecutionPool::DequeueTask(size_t thread_index) {
  auto has_pending_tasks = [this]() {
    if (!public_queue_.empty()) {
      return true;
    }
    for (const auto &queue : affinity_queues_) {
      if (!queue.empty()) {
        return true;
      }
    }
    return false;
  };

  while (true) {
    {
      std::unique_lock<std::mutex> lock(queue_mtx_);
      queue_cv_.wait(lock, [this, thread_index]() {
        return !running_.load(std::memory_order_acquire) ||
               !public_queue_.empty() ||
               std::any_of(affinity_queues_.begin(), affinity_queues_.end(),
                           [](const auto &q) { return !q.empty(); }) ||
               thread_index >=
                   desired_thread_count_.load(std::memory_order_relaxed);
      });

      if (!running_.load(std::memory_order_relaxed) && !has_pending_tasks()) {
        return std::nullopt;
      }

      if (thread_index >=
          desired_thread_count_.load(std::memory_order_relaxed)) {
        const bool has_affinity = thread_index < affinity_queues_.size() &&
                                  !affinity_queues_[thread_index].empty();
        if (!has_affinity) {
          return std::nullopt;
        }
      }

      TaskId task_id;
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
      auto task_info = it->second;
      return {{task_id, task_info}};
    }
  }
}

void TransferExecutionPool::HandleCompletedTask(const TaskHandle &task_info) {
  if (!task_info || !task_info->TryMarkCompletionDispatched()) {
    return;
  }
  if (task_info->Callback.result) {
    CallCallbackSafe(task_info->Callback.result, task_info);
    return;
  }
  auto results = results_.lock();
  (*results)[task_info->id] = task_info;
}

void TransferExecutionPool::SetConducting(size_t thread_index,
                                          const TaskId &task_id,
                                          const TaskHandle &task_info) {
  std::lock_guard<std::mutex> lock(conducting_mtx_);
  if (thread_index >= conducting_by_thread_.size()) {
    conducting_by_thread_.resize(thread_index + 1);
    conducting_infos_.resize(thread_index + 1);
  }
  conducting_by_thread_[thread_index] = task_id;
  conducting_infos_[thread_index] = task_info;
  conducting_tasks_.insert(task_id);
}

void TransferExecutionPool::ClearConducting(size_t thread_index) {
  bool removed_task = false;
  TaskHandle finished_info = nullptr;
  {
    std::lock_guard<std::mutex> lock(conducting_mtx_);
    if (thread_index < conducting_by_thread_.size()) {
      const TaskId id = conducting_by_thread_[thread_index];
      if (!id.empty()) {
        conducting_tasks_.erase(id);
        removed_task = true;
      }
      finished_info = conducting_infos_[thread_index];
      conducting_by_thread_[thread_index].clear();
      conducting_infos_[thread_index] = nullptr;
    }
  }
  if (finished_info) {
    finished_info->Set.OnWhichThread.store(-1, std::memory_order_relaxed);
  }
  if (removed_task) {
    conducting_cv_.notify_all();
  }
}

void TransferExecutionPool::WorkerLoop(size_t thread_index) {
  while (running_.load(std::memory_order_relaxed)) {
    if (thread_index >= desired_thread_count_.load(std::memory_order_relaxed)) {
      std::lock_guard<std::mutex> lock(queue_mtx_);
      const bool has_affinity = thread_index < affinity_queues_.size() &&
                                !affinity_queues_[thread_index].empty();
      if (!has_affinity) {
        break;
      }
    }

    auto task_opt = DequeueTask(thread_index);
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

    ExecuteTask(task_info);

    if (task_info->GetStatus() == TaskStatus::Paused) {
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

void TransferExecutionPool::ExecuteTask(const TaskHandle &task_info) {
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

  if (task_info->Core.tasks.lock()->empty()) {
    task_info->SetStatus(TaskStatus::Finished);
    task_info->SetResult({EC::InvalidArg, "No task is provided"});
    task_info->Time.finish.store(AMTime::seconds(), std::memory_order_relaxed);
    return;
  }

  if (task_info->Core.clients.empty()) {
    task_info->SetStatus(TaskStatus::Finished);
    task_info->SetResult({EC::InvalidHandle, "Task clients not found"});
    task_info->Time.finish.store(AMTime::seconds(), std::memory_order_relaxed);
    return;
  }
  const auto &task_clients = task_info->Core.clients;
  bool paused_requested = false;
  {
    auto tasks_locked = task_info->Core.tasks.lock();
    for (auto &task : *tasks_locked) {
      if (task_info->IsPauseRequested()) {
        paused_requested = true;
        break;
      }
      if (IsTaskInterrupted_(pd)) {
        task.rcm = {EC::Terminate, "Task terminated by user"};
        task.IsFinished = true;
        continue;
      }

      if (task.IsFinished) {
        continue;
      }

      const std::string src_key =
          task.src_host.empty() ? std::string("local") : task.src_host;
      const std::string dst_key =
          task.dst_host.empty() ? std::string("local") : task.dst_host;
      const bool same_host_transfer = src_key == dst_key;
      auto src_client = ResolveTaskClientHelper(task_clients, src_key, false);
      auto dst_client =
          ResolveTaskClientHelper(task_clients, dst_key, same_host_transfer);
      if (!src_client || !dst_client) {
        task.rcm = {EC::ClientNotFound, "Task client is not available in pool"};
        task.IsFinished = true;
        if (task_info->Set.callback.need_error_cb) {
          task_info->Set.callback.CallError(ErrorCBInfo(
              task.rcm, task.src, task.dst, task.src_host, task.dst_host));
        }
        continue;
      }

      task_info->Core.cur_task.store(&task, std::memory_order_relaxed);
      task.rcm = ECM(EC::Success, "");
      size_t resume_offset = task.transferred;
      if (resume_offset > 0) {
        if (resume_offset > task.size) {
          task.rcm = {EC::InvalidOffset, "Offset exceeds src size"};
          task.IsFinished = true;
          if (task_info->Set.callback.need_error_cb) {
            task_info->Set.callback.CallError(ErrorCBInfo(
                task.rcm, task.src, task.dst, task.src_host, task.dst_host));
          }
          continue;
        }
        auto dst_stat = dst_client->IOPort().stat(
            AMDomain::filesystem::StatArgs{task.dst, false},
            task_info->Core.control);
        if (dst_stat.rcm.first != EC::Success) {
          task.rcm = {EC::InvalidOffset, "Dst stat failed but offset is given"};
          task.IsFinished = true;
          goto OffsetErrorCB;
        }
        if (dst_stat.info.type == PathType::DIR) {
          task.rcm = {EC::NotAFile, "Dst already exists but is a directory"};
          task.IsFinished = true;
          goto OffsetErrorCB;
        }
        if (resume_offset > dst_stat.info.size) {
          task.rcm = {EC::InvalidOffset, "Offset exceeds dst file size"};
          task.IsFinished = true;
          goto OffsetErrorCB;
        }
        goto PassOffsetCheck;
      OffsetErrorCB:
        if (task_info->Set.callback.need_error_cb) {
          task_info->Set.callback.CallError(ErrorCBInfo(
              task.rcm, task.src, task.dst, task.src_host, task.dst_host));
        }
        continue;
      }
    PassOffsetCheck:
      task_info->Size.cur_task_transferred.store(resume_offset,
                                                 std::memory_order_relaxed);
      if (resume_offset > 0 &&
          !task_info->Set.keep_start_time.load(std::memory_order_relaxed)) {
        task_info->Size.transferred.fetch_add(resume_offset,
                                              std::memory_order_relaxed);
      }

      pd.ring_buffer =
          std::make_shared<StreamRingBuffer>(CalculateBufferSizeHelper(
              src_client, dst_client,
              task_info->Size.buffer.load(std::memory_order_relaxed)));

      task.rcm =
          transfer_engine_.TransferSignleFile(src_client, dst_client, pd);
      if (task_info->IsPauseRequested() && task.rcm.first == EC::Terminate) {
        task.rcm = {EC::Success, ""};
        task.IsFinished = false;
        paused_requested = true;
        pd.CallInnerCallback(true);
        break;
      }
      task.IsFinished = true;
      if (task.rcm.first == EC::Success) {
        task_info->Size.success_filenum.fetch_add(1, std::memory_order_relaxed);
      } else if (task.rcm.first != EC::Success &&
                 task_info->Set.callback.need_error_cb &&
                 task.rcm.first != EC::Terminate) {
        task_info->Set.callback.CallError(ErrorCBInfo(
            task.rcm, task.src, task.dst, task.src_host, task.dst_host));
      }

      pd.CallInnerCallback(true);
    }
  }

  if (paused_requested) {
    task_info->SetResult({EC::Success, "Task paused"});
    task_info->Core.cur_task.store(nullptr, std::memory_order_relaxed);
    task_info->SetStatus(TaskStatus::Paused);
    return;
  }

  if (!IsTaskInterrupted_(pd)) {
    bool any_error = false;
    {
      auto tasks_locked = task_info->Core.tasks.lock();
      for (auto &task : *tasks_locked) {
        if (task.rcm.first != EC::Success) {
          any_error = true;
          task_info->SetResult(task.rcm);
          break;
        }
      }
    }

    if (!any_error) {
      task_info->SetResult({EC::Success, ""});
    }
  } else {
    task_info->SetResult({EC::Terminate, "Task terminated by user"});
  }
  task_info->Core.cur_task.store(nullptr, std::memory_order_relaxed);
  task_info->SetStatus(TaskStatus::Finished);
  task_info->Time.finish.store(AMTime::seconds(), std::memory_order_relaxed);
}

TransferExecutionPool::TransferExecutionPool() {
  affinity_queues_.resize(1);
  conducting_by_thread_.resize(1);
  conducting_infos_.resize(1);
  worker_threads_.emplace_back([this]() { WorkerLoop(0); });
}

TransferExecutionPool::~TransferExecutionPool() { (void)Shutdown(3000); }

ECM TransferExecutionPool::Shutdown(int timeout_ms) {
  if (is_deconstruct.load(std::memory_order_relaxed)) {
    return {EC::Success, ""};
  }
  running_.store(false, std::memory_order_relaxed);
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
          {EC::Terminate, "Task canceled while shutting down"});
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
        return {EC::OperationTimeout, "Graceful terminate timed out"};
      }
    }
  }

  for (auto &thread : worker_threads_) {
    if (thread.joinable()) {
      thread.join();
    }
  }
  is_deconstruct.store(true, std::memory_order_relaxed);
  return {EC::Success, ""};
}

size_t TransferExecutionPool::ThreadCount(size_t new_count) {
  if (new_count == 0) {
    return desired_thread_count_.load(std::memory_order_relaxed);
  }

  constexpr size_t kMinThreads = 1;
  constexpr size_t kMaxThreads = 99999;
  new_count =
      std::max<size_t>(kMinThreads, std::min<size_t>(new_count, kMaxThreads));
  const size_t current = desired_thread_count_.load(std::memory_order_relaxed);
  if (new_count == current) {
    return current;
  }

  if (new_count > current) {
    {
      std::lock_guard<std::mutex> lock(queue_mtx_);
      if (new_count > affinity_queues_.size()) {
        affinity_queues_.resize(new_count);
      }
    }
    {
      std::lock_guard<std::mutex> lock(conducting_mtx_);
      if (new_count > conducting_by_thread_.size()) {
        conducting_by_thread_.resize(new_count);
        conducting_infos_.resize(new_count);
      }
    }

    desired_thread_count_.store(new_count, std::memory_order_relaxed);
    const size_t existing_threads = worker_threads_.size();
    for (size_t idx = existing_threads; idx < new_count; ++idx) {
      worker_threads_.emplace_back([this, idx]() { WorkerLoop(idx); });
    }
    queue_cv_.notify_all();
    return new_count;
  }

  desired_thread_count_.store(new_count, std::memory_order_relaxed);
  queue_cv_.notify_all();
  return new_count;
}

std::unordered_map<size_t, bool> TransferExecutionPool::GetThreadIDs() const {
  std::unordered_map<size_t, bool> states;
  const size_t count = desired_thread_count_.load(std::memory_order_relaxed);
  states.reserve(count);
  std::lock_guard<std::mutex> lock(conducting_mtx_);
  for (size_t i = 0; i < count; ++i) {
    const bool busy =
        i < conducting_by_thread_.size() && !conducting_by_thread_[i].empty();
    states.emplace(i, busy);
  }
  return states;
}

ECM TransferExecutionPool::Submit(TaskHandle task_info,
                                  TransferClientContainer clients) {
  if (!task_info) {
    return {EC::InvalidArg, "TaskInfo is nullptr"};
  }
  if (!running_.load(std::memory_order_acquire)) {
    return {EC::OperationUnsupported, "Work manager is shutting down"};
  }
  if (task_info->Core.tasks.lock()->empty()) {
    return {EC::InvalidArg, "Tasks is nullptr or empty"};
  }
  if (!clients.empty()) {
    task_info->Core.clients = std::move(clients);
  }
  if (task_info->Core.clients.empty()) {
    return {EC::InvalidArg, "Transfer clients is empty"};
  }

  if (task_info->id.empty() ||
      IsTaskIdUsedHelper(task_info->id, task_registry_, results_,
                         conducting_mtx_, conducting_tasks_)) {
    return {EC::InvalidArg, "Task ID is empty or already used"};
  }
  task_info->ResetCompletionDispatch();
  task_info->State.intent.store(AMDomain::transfer::ControlIntent::Running,
                                std::memory_order_relaxed);
  task_info->Time.submit.store(AMTime::seconds(), std::memory_order_relaxed);
  task_info->SetStatus(TaskStatus::Pending);
  task_info->CalTotalSize();
  task_info->CalFileNum();

  task_info->Size.transferred.store(0, std::memory_order_relaxed);
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
  queue_cv_.notify_all();
  return {EC::Success, ""};
}

std::optional<TaskStatus>
TransferExecutionPool::GetStatus(const TaskId &id) const {
  {
    auto task_registry = task_registry_.lock();
    auto it = task_registry->find(id);
    if (it != task_registry->end() && it->second) {
      return it->second->GetStatus();
    }
  }
  {
    auto results = results_.lock();
    auto it = results->find(id);
    if (it != results->end() && it->second) {
      return it->second->GetStatus();
    }
  }
  return std::nullopt;
}

ECM TransferExecutionPool::Pause(const TaskId &id, int timeout_ms) {
  TaskHandle existing = nullptr;
  {
    auto task_registry = task_registry_.lock();
    auto it = task_registry->find(id);
    if (it != task_registry->end()) {
      existing = it->second;
    }
  }
  if (!existing) {
    return {EC::TaskNotFound, AMStr::fmt("Task not found: {}", id)};
  }
  TaskStatus status_t = existing->GetStatus();
  if (status_t == TaskStatus::Pending) {
    return {EC::OperationUnsupported,
            AMStr::fmt("Task is still pending: {}", id)};
  }
  if (status_t == TaskStatus::Finished) {
    return {EC::OperationUnsupported,
            AMStr::fmt("Task is already finished: {}", id)};
  }
  if (existing->IsTerminateRequested()) {
    return {EC::OperationUnsupported,
            AMStr::fmt("Task terminate requested: {}", id)};
  }
  if (status_t == TaskStatus::Paused || existing->IsPauseRequested()) {
    return {EC::Success, AMStr::fmt("Task already paused: {}", id)};
  }
  existing->RequestPause();
  const int64_t start = AMTime::miliseconds();
  while (timeout_ms < 0 || (AMTime::miliseconds() - start) < timeout_ms) {
    status_t = existing->GetStatus();
    if (status_t == TaskStatus::Paused) {
      return {EC::Success, ""};
    }
    if (status_t == TaskStatus::Finished) {
      return {EC::OperationUnsupported,
              AMStr::fmt("Task is already finished: {}", id)};
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  return {EC::OperationTimeout, AMStr::fmt("Task pause timeout: {}", id)};
}

ECM TransferExecutionPool::Resume(const TaskId &id, int timeout_ms) {
  TaskHandle existing = nullptr;
  {
    auto task_registry = task_registry_.lock();
    auto it = task_registry->find(id);
    if (it != task_registry->end()) {
      existing = it->second;
    }
  }
  if (!existing) {
    return {EC::TaskNotFound, AMStr::fmt("Task not found: {}", id)};
  }
  TaskStatus status_t = existing->GetStatus();
  if (status_t == TaskStatus::Pending) {
    return {EC::OperationUnsupported,
            AMStr::fmt("Task is still pending: {}", id)};
  }
  if (status_t == TaskStatus::Finished) {
    return {EC::OperationUnsupported,
            AMStr::fmt("Task is already finished: {}", id)};
  }
  if (existing->IsTerminateRequested()) {
    return {EC::OperationUnsupported,
            AMStr::fmt("Task terminate requested: {}", id)};
  }
  if (existing->IsPauseRequested() && status_t != TaskStatus::Paused) {
    const int64_t start = AMTime::miliseconds();
    while (timeout_ms < 0 || (AMTime::miliseconds() - start) < timeout_ms) {
      status_t = existing->GetStatus();
      if (status_t == TaskStatus::Paused) {
        break;
      }
      if (status_t == TaskStatus::Finished) {
        return {EC::OperationUnsupported,
                AMStr::fmt("Task is already finished: {}", id)};
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    if (status_t != TaskStatus::Paused) {
      return {EC::OperationTimeout, AMStr::fmt("Task pause timeout: {}", id)};
    }
  }
  status_t = existing->GetStatus();
  if (status_t == TaskStatus::Paused || existing->IsPauseRequested()) {
    existing->SetRunningIntent();
    existing->ClearInterrupt();
    const int64_t release_start = AMTime::miliseconds();
    int on_thread = existing->Set.OnWhichThread.load(std::memory_order_relaxed);
    while (on_thread >= 0 && (timeout_ms < 0 || (AMTime::miliseconds() -
                                                 release_start) < timeout_ms)) {
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
      on_thread = existing->Set.OnWhichThread.load(std::memory_order_relaxed);
    }
    if (on_thread >= 0) {
      return {EC::OperationTimeout,
              AMStr::fmt("Task resume wait timeout: {}", id)};
    }
    existing->Set.keep_start_time.store(true, std::memory_order_relaxed);
    existing->SetStatus(TaskStatus::Pending);
    existing->Set.OnWhichThread.store(-1, std::memory_order_relaxed);
    const int requested_thread_id =
        existing->Set.affinity_thread.load(std::memory_order_relaxed);
    const size_t active_count =
        desired_thread_count_.load(std::memory_order_relaxed);
    const bool affinity_valid =
        requested_thread_id >= 0 &&
        static_cast<size_t>(requested_thread_id) < active_count &&
        static_cast<size_t>(requested_thread_id) < affinity_queues_.size();
    const TaskAssignType assign_type =
        affinity_valid ? TaskAssignType::Affinity : TaskAssignType::Public;
    const int affinity_id = affinity_valid ? requested_thread_id : -1;
    RegisterTask(existing, assign_type, affinity_id);
    queue_cv_.notify_all();
    return {EC::Success, ""};
  }
  return {EC::Success, AMStr::fmt("Task is conducting: {}", id)};
}

std::pair<TaskHandle, ECM> TransferExecutionPool::Terminate(const TaskId &id,
                                                            int timeout_ms) {
  TaskHandle existing = nullptr;
  {
    auto task_registry = task_registry_.lock();
    auto it = task_registry->find(id);
    if (it != task_registry->end()) {
      existing = it->second;
    }
  }
  if (!existing) {
    return {nullptr, {EC::TaskNotFound, AMStr::fmt("Task not found: {}", id)}};
  }
  if (existing->GetStatus() == TaskStatus::Finished) {
    return {existing,
            {EC::OperationUnsupported,
             AMStr::fmt("Task already finished: {}", id)}};
  }

  if (existing->GetStatus() == TaskStatus::Pending ||
      existing->GetStatus() == TaskStatus::Paused) {
    std::lock_guard<std::mutex> queue_lock(queue_mtx_);
    auto task_registry = task_registry_.lock();
    auto it = task_registry->find(id);
    if (it != task_registry->end() && it->second) {
      const auto &task_info = it->second;
      if (task_info->GetStatus() == TaskStatus::Pending) {
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
      }
      task_registry->erase(it);
      task_info->RequestInterrupt();
      task_info->SetResult({EC::Terminate, "Task terminated"});
      task_info->SetStatus(TaskStatus::Finished);
      task_info->Time.finish.store(AMTime::seconds(),
                                   std::memory_order_relaxed);
      task_info->Set.OnWhichThread.store(-1, std::memory_order_relaxed);
      queue_cv_.notify_all();
      HandleCompletedTask(task_info);
      return {task_info, {EC::Success, ""}};
    }
  }

  existing->RequestInterrupt();

  const int64_t start_ms = AMTime::miliseconds();
  while (timeout_ms < 0 || (AMTime::miliseconds() - start_ms) < timeout_ms) {
    if (existing->GetStatus() == TaskStatus::Finished) {
      return {existing, {EC::Success, ""}};
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  return {existing,
          {EC::OperationTimeout, AMStr::fmt("Task terminate timeout: {}", id)}};
}

void TransferExecutionPool::ClearResults() {
  {
    auto results = results_.lock();
    results->clear();
  }
}

bool TransferExecutionPool::RemoveResult(const TaskId &id) {
  auto results = results_.lock();
  const bool removed = results->erase(id) > 0;
  return removed;
}

std::unordered_map<TaskId, TaskHandle>
TransferExecutionPool::GetRegistryCopy() const {
  auto task_registry = task_registry_.lock();
  return *task_registry;
}

TaskHandle TransferExecutionPool::GetResultTask(const TaskId &id, bool remove) {
  auto results = results_.lock();
  auto it = results->find(id);
  if (it == results->end()) {
    return nullptr;
  }
  TaskHandle task_info = it->second;
  if (remove) {
    results->erase(it);
  }
  return task_info;
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
    if (task && !task->id.empty()) {
      out.emplace(task->id, task);
    }
  }
  return out;
}

std::unordered_map<TaskId, TaskHandle>
TransferExecutionPool::GetAllHistoryTasks() const {
  auto results = results_.lock();
  std::unordered_map<TaskId, TaskHandle> out = {};
  out.reserve(results->size());
  for (const auto &[id, task] : *results) {
    if (task) {
      out.emplace(id, task);
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
std::unique_ptr<ITransferPoolPort> CreateTransferPoolPort() {
  return std::make_unique<AMInfra::transfer::TransferExecutionPool>();
}
} // namespace AMDomain::transfer
