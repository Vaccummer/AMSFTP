#include "infrastructure/client/runtime/TransferExecution.hpp"

#include "foundation/tools/time.hpp"
#include "infrastructure/client/ftp/FTP.hpp"
#include "infrastructure/client/sftp/SFTP.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <mutex>
#include <thread>
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

namespace {

using ECM = std::pair<ErrorCode, std::string>;
using EC = ErrorCode;
using ClientHandle = std::shared_ptr<AMDomain::client::IClientPort>;
using ProgressCallback =
    AMInfra::ClientRuntime::TransferExecutionEngine::ProgressCallback;

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
  WkProgressData *pd = nullptr;

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
           WkProgressData *progress = nullptr) {
    this->path = path;
    this->is_write = is_write;
    this->file_size = file_size;
    this->client = client;
    this->is_sftp = (client != nullptr);
    this->pd = progress;

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
        nb_res = client->nb_call(-1, AMTime::miliseconds(), [&]() {
          return libssh2_sftp_open(client->sftp, path.c_str(), flags, 0744);
        });
        sftp_handle = nb_res.value;
      } else {
        nb_res = client->nb_call(-1, AMTime::miliseconds(), [&]() {
          return libssh2_sftp_open(client->sftp, path.c_str(), LIBSSH2_FXF_READ,
                                   0400);
        });
        sftp_handle = nb_res.value;
      }
      if (nb_res.status == WaitResult::Interrupted) {
        return pd ? pd->InterruptECM("Task paused before opening file",
                                     "Task terminated before opening file")
                  : ECM{EC::Terminate, "Task terminated before opening file"};
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
        while (true) {
          if (pd->is_terminate()) {
            return {-1, {EC::Terminate, "Task terminated by user"}};
          }
          while (pd->is_pause() && !pd->is_terminate()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
          }
          {
            std::lock_guard<std::recursive_mutex> lock(client->TransferMutex());
            bytes_read = libssh2_sftp_read(sftp_handle, write_ptr, to_read);
          }
          if (bytes_read > 0) {
            pd->ring_buffer->commit_write(bytes_read);
            offset += bytes_read;
            return {bytes_read, {EC::Success, ""}};
          }
          if (bytes_read == 0) {
            return {0, {EC::EndOfFile, "End of file"}};
          }
          if (bytes_read == LIBSSH2_ERROR_EAGAIN) {
            WaitResult wr = client->wait_for_socket(SocketWaitType::Read,
                                                    AMTime::miliseconds(), 200);
            if (wr == WaitResult::Error) {
              return {
                  -1,
                  {wait_result_to_error_code(wr), "SFTP read socket error"}};
            }
            if (wr == WaitResult::Interrupted) {
              return {-1, pd ? pd->InterruptECM()
                             : ECM{EC::Terminate, "Task terminated by user"}};
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
          if (pd->is_terminate()) {
            return {-1, {EC::Terminate, "Task terminated by user"}};
          }
          while (pd->is_pause() && !pd->is_terminate()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
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
            WaitResult wr = client->wait_for_socket(SocketWaitType::Write,
                                                    AMTime::miliseconds(), 200);
            if (wr == WaitResult::Error) {
              return {
                  LIBSSH2_ERROR_EAGAIN,
                  {wait_result_to_error_code(wr), "SFTP write socket error"}};
            }
            if (wr == WaitResult::Interrupted) {
              return {-1, pd ? pd->InterruptECM()
                             : ECM{EC::Terminate, "Task terminated by user"}};
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

} // namespace

namespace AMInfra::ClientRuntime {

class TransferExecutionEngine::Impl {
public:
  /**
   * @brief Construct one execution implementation.
   */
  Impl(size_t chunk_size, ProgressCallback progress_callback)
      : chunk_size_(chunk_size),
        progress_callback_(std::move(progress_callback)) {}

  /**
   * @brief Set the transfer chunk size.
   */
  void SetChunkSize(size_t chunk_size) { chunk_size_ = chunk_size; }

  /**
   * @brief Return the current transfer chunk size.
   */
  [[nodiscard]] size_t GetChunkSize() const { return chunk_size_; }

  /**
   * @brief Execute one prepared single-file transfer task.
   */
  [[nodiscard]] ECM
  ExecuteSingleFileTransfer(const ClientHandle &src_client,
                            const ClientHandle &dst_client,
                            const std::shared_ptr<TaskInfo> &task_info) const {
    return TransferSingleFile(src_client, dst_client, task_info);
  }

private:
  class ITransferEndpoint {
  public:
    virtual ~ITransferEndpoint() = default;
    [[nodiscard]] virtual ClientProtocol Protocol() const = 0;
    virtual ECM ReadToBuffer(const std::shared_ptr<TaskInfo> &task_info) = 0;
    virtual ECM WriteFromBuffer(const std::shared_ptr<TaskInfo> &task_info) = 0;
    virtual ECM Transit(const std::shared_ptr<TaskInfo> &task_info) {
      (void)task_info;
      return {EC::OperationUnsupported, "Transit is unsupported for endpoint"};
    }
  };

  /**
   * @brief Local endpoint adapter.
   */
  class LocalEndpoint : public ITransferEndpoint {
  public:
    LocalEndpoint(const Impl *owner, ClientHandle client)
        : owner_(owner), client_(std::move(client)) {}

    ClientProtocol Protocol() const override { return ClientProtocol::LOCAL; }

    ECM ReadToBuffer(const std::shared_ptr<TaskInfo> &task_info) override {
      owner_->XToBuffer(client_, task_info);
      if (!task_info || !task_info->cur_task) {
        return {EC::InvalidArg, "Invalid transfer task"};
      }
      return task_info->cur_task->rcm;
    }

    ECM WriteFromBuffer(const std::shared_ptr<TaskInfo> &task_info) override {
      owner_->BufferToX(client_, task_info);
      if (!task_info || !task_info->cur_task) {
        return {EC::InvalidArg, "Invalid transfer task"};
      }
      return task_info->cur_task->rcm;
    }

  private:
    const Impl *owner_ = nullptr;
    ClientHandle client_;
  };

  /**
   * @brief FTP endpoint adapter.
   */
  class FTPEndpoint : public ITransferEndpoint {
  public:
    FTPEndpoint(const Impl *owner, ClientHandle client)
        : owner_(owner), client_(std::move(client)) {}

    ClientProtocol Protocol() const override { return ClientProtocol::FTP; }

    ECM ReadToBuffer(const std::shared_ptr<TaskInfo> &task_info) override {
      owner_->XToBuffer(client_, task_info);
      if (!task_info || !task_info->cur_task) {
        return {EC::InvalidArg, "Invalid transfer task"};
      }
      return task_info->cur_task->rcm;
    }

    ECM WriteFromBuffer(const std::shared_ptr<TaskInfo> &task_info) override {
      owner_->BufferToX(client_, task_info);
      if (!task_info || !task_info->cur_task) {
        return {EC::InvalidArg, "Invalid transfer task"};
      }
      return task_info->cur_task->rcm;
    }

  private:
    const Impl *owner_ = nullptr;
    ClientHandle client_;
  };

  /**
   * @brief SFTP endpoint adapter.
   */
  class SFTPEndpoint : public ITransferEndpoint {
  public:
    SFTPEndpoint(const Impl *owner, ClientHandle client)
        : owner_(owner), client_(std::move(client)) {}

    ClientProtocol Protocol() const override { return ClientProtocol::SFTP; }

    ECM ReadToBuffer(const std::shared_ptr<TaskInfo> &task_info) override {
      owner_->XToBuffer(client_, task_info);
      if (!task_info || !task_info->cur_task) {
        return {EC::InvalidArg, "Invalid transfer task"};
      }
      return task_info->cur_task->rcm;
    }

    ECM WriteFromBuffer(const std::shared_ptr<TaskInfo> &task_info) override {
      owner_->BufferToX(client_, task_info);
      if (!task_info || !task_info->cur_task) {
        return {EC::InvalidArg, "Invalid transfer task"};
      }
      return task_info->cur_task->rcm;
    }

    ECM Transit(const std::shared_ptr<TaskInfo> &task_info) override {
      if (!client_) {
        return {EC::InvalidArg, "Missing SFTP client"};
      }
      auto *sftp = dynamic_cast<AMSFTPIOCore *>(&client_->IOPort());
      if (sftp == nullptr) {
        return {EC::InvalidArg, "SFTP IO port implementation mismatch"};
      }
      return owner_->Transit(sftp, task_info);
    }

  private:
    const Impl *owner_ = nullptr;
    ClientHandle client_;
  };

  /**
   * @brief Build endpoint adapter by protocol from one client handle.
   */
  [[nodiscard]] std::unique_ptr<ITransferEndpoint>
  CreateEndpoint_(const ClientHandle &client) const {
    if (!client) {
      return nullptr;
    }
    switch (client->ConfigPort().GetProtocol()) {
    case ClientProtocol::LOCAL:
      return std::make_unique<LocalEndpoint>(this, client);
    case ClientProtocol::FTP:
      return std::make_unique<FTPEndpoint>(this, client);
    case ClientProtocol::SFTP:
      return std::make_unique<SFTPEndpoint>(this, client);
    default:
      return nullptr;
    }
  }

  /**
   * @brief Emit task progress through the scheduler-provided callback.
   */
  void EmitProgress(const std::shared_ptr<TaskInfo> &task_info,
                    WkProgressData &pd, bool force) const {
    if (progress_callback_) {
      progress_callback_(task_info, pd, force);
    }
  }

  // Transit for SFTP same-host copy (non-blocking read/write)
  ECM Transit(AMSFTPIOCore *client, std::shared_ptr<TaskInfo> task_info) const {
    if (client == nullptr || !task_info || !task_info->pd ||
        !task_info->cur_task) {
      return {EC::InvalidArg, "Invalid SFTP transit input"};
    }
    auto &pd = *(task_info->pd);
    auto *task = task_info->cur_task;
    ECM rcm = ECM{EC::Success, ""};
    std::lock_guard<std::recursive_mutex> lock(client->TransferMutex());
    rcm = client->mkdir(AMPathStr::dirname(task->dst));
    if (rcm.first != EC::Success) {
      return rcm;
    }

    auto src_open = client->nb_call(-1, AMTime::miliseconds(), [&]() {
      return libssh2_sftp_open(client->sftp, task->src.c_str(),
                               LIBSSH2_FXF_READ, 0400);
    });
    if (src_open.status == WaitResult::Interrupted) {
      return pd.InterruptECM("Transfer paused while opening source file",
                             "Transfer interrupted while opening source file");
    }
    LIBSSH2_SFTP_HANDLE *srcFile = src_open.value;
    if (!srcFile) {
      EC rc = client->GetLastEC();
      std::string msg = client->GetLastErrorMsg();
      return {rc,
              AMStr::fmt("Failed to open src file \"{}\": {}", task->src, msg)};
    }

    const size_t resume_offset = task->transferred;
    int dst_flags = LIBSSH2_FXF_WRITE;
    if (resume_offset == 0) {
      dst_flags |= LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC;
    }
    auto dst_open = client->nb_call(-1, AMTime::miliseconds(), [&]() {
      return libssh2_sftp_open(client->sftp, task->dst.c_str(), dst_flags,
                               0744);
    });
    if (dst_open.status == WaitResult::Interrupted) {
      libssh2_sftp_close_handle(srcFile);
      return pd.InterruptECM(
          "Transfer paused while opening destination file",
          "Transfer interrupted while opening destination file");
    }
    LIBSSH2_SFTP_HANDLE *dstFile = dst_open.value;
    if (!dstFile) {
      libssh2_sftp_close_handle(srcFile);
      EC rc = client->GetLastEC();
      std::string msg = client->GetLastErrorMsg();
      return {rc,
              AMStr::fmt("Failed to open dst file \"{}\": {}", task->dst, msg)};
    }

    libssh2_session_set_blocking(client->session, 0);
    std::vector<char> buffer(chunk_size_);
    size_t total_written = resume_offset;
    ssize_t bytes_read, bytes_written;

    if (resume_offset > 0) {
      libssh2_sftp_seek64(srcFile,
                          static_cast<libssh2_uint64_t>(resume_offset));
      libssh2_sftp_seek64(dstFile,
                          static_cast<libssh2_uint64_t>(resume_offset));
    }

    while (total_written < task->size) {
      if (pd.is_terminate()) {
        rcm = pd.InterruptECM("Task paused by user",
                              "Transfer interrupted by user");
        goto clean;
      }
      while (pd.is_pause() && !pd.is_terminate()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
      }

      size_t to_read =
          std::min<size_t>(chunk_size_, task->size - total_written);
      size_t buffer_filled = 0;
      while (buffer_filled < to_read) {
        bytes_read = libssh2_sftp_read(srcFile, buffer.data() + buffer_filled,
                                       to_read - buffer_filled);
        if (bytes_read > 0) {
          buffer_filled += bytes_read;
        } else if (bytes_read == 0) {
          break;
        } else if (bytes_read == LIBSSH2_ERROR_EAGAIN) {
          WaitResult wr = client->wait_for_socket(SocketWaitType::Read,
                                                  AMTime::miliseconds(), 200);
          if (wr == WaitResult::Interrupted) {
            rcm = pd.InterruptECM("Task paused by user",
                                  "Transfer interrupted by user");
            goto clean;
          }
          if (wr == WaitResult::Error) {
            rcm = {wait_result_to_error_code(wr), "SFTP read socket error"};
            goto clean;
          }
          continue;
        } else {
          EC rc = client->GetLastEC();
          std::string msg = client->GetLastErrorMsg();
          rcm = {rc, AMStr::fmt("Read error: {}", msg)};
          goto clean;
        }
      }

      if (buffer_filled == 0) {
        break;
      }

      size_t buffer_written = 0;
      while (buffer_written < buffer_filled) {
        bytes_written =
            libssh2_sftp_write(dstFile, buffer.data() + buffer_written,
                               buffer_filled - buffer_written);
        if (bytes_written > 0) {
          buffer_written += bytes_written;
          total_written += bytes_written;
          task_info->total_transferred_size.fetch_add(
              static_cast<size_t>(bytes_written), std::memory_order_relaxed);
          task_info->this_task_transferred_size.store(
              total_written, std::memory_order_relaxed);
          task->transferred = task_info->this_task_transferred_size.load(
              std::memory_order_relaxed);
          EmitProgress(task_info, pd, false);
        } else if (bytes_written == 0) {
          break;
        } else if (bytes_written == LIBSSH2_ERROR_EAGAIN) {
          WaitResult wr = client->wait_for_socket(SocketWaitType::Write,
                                                  AMTime::miliseconds(), 200);
          if (wr == WaitResult::Interrupted) {
            rcm = pd.InterruptECM("Task paused by user",
                                  "Transfer interrupted by user");
            goto clean;
          }
          if (wr == WaitResult::Error) {
            rcm = {wait_result_to_error_code(wr), "SFTP write socket error"};
            goto clean;
          }
          continue;
        } else {
          EC rc = client->GetLastEC();
          std::string msg = client->GetLastErrorMsg();
          rcm = {rc, AMStr::fmt("Write error: {}", msg)};
          goto clean;
        }
      }
    }

  clean:
    if (srcFile) {
      libssh2_sftp_close_handle(srcFile);
    }
    if (dstFile) {
      libssh2_sftp_close_handle(dstFile);
    }
    EmitProgress(task_info, pd, true);
    return rcm;
  }

  // XToBuffer - read from source to ring buffer
  void XToBuffer(const ClientHandle &client,
                 std::shared_ptr<TaskInfo> task_info) const {
    if (!client || !task_info || !task_info->pd || !task_info->cur_task) {
      return;
    }
    auto &pd = *(task_info->pd);
    auto *task = task_info->cur_task;
    if (client->ConfigPort().GetProtocol() == ClientProtocol::SFTP) {
      auto *clientf = dynamic_cast<AMSFTPIOCore *>(&client->IOPort());
      if (clientf == nullptr) {
        pd.set_terminate();
        task->rcm = {EC::InvalidArg, "SFTP IO port implementation mismatch"};
        return;
      }
      UnionFileHandle file_handle;
      ECM rcm = file_handle.Init(task->src, task->size, clientf, false, true,
                                 true, &pd);
      if (rcm.first != EC::Success) {
        pd.set_terminate();
        task->rcm = rcm;
        return;
      }
      if (task->transferred > 0) {
        ECM seek_rcm = file_handle.Seek(task->transferred);
        if (seek_rcm.first != EC::Success) {
          pd.set_terminate();
          task->rcm = seek_rcm;
          return;
        }
      }
      std::lock_guard<std::recursive_mutex> lock(clientf->TransferMutex());
      libssh2_session_set_blocking(clientf->session, 0);
      while (file_handle.offset < file_handle.file_size && !pd.is_terminate()) {
        while (pd.ring_buffer->writable() == 0 && !pd.is_terminate() &&
               file_handle.offset < file_handle.file_size) {
          std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        while (pd.is_pause() && !pd.is_terminate()) {
          std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        if (pd.is_terminate()) {
          return;
        }
        auto [bytes_read, ecm] = file_handle.Read();
        if (ecm.first != EC::Success && ecm.first != EC::EndOfFile) {
          pd.set_terminate();
          task->rcm = ecm;
          return;
        }
      }
    } else if (client->ConfigPort().GetProtocol() == ClientProtocol::LOCAL) {
      UnionFileHandle file_handle;
      ECM rcm = file_handle.Init(task->src, task->size, nullptr, false, true,
                                 true, &pd);
      if (rcm.first != EC::Success) {
        pd.set_terminate();
        task->rcm = rcm;
        return;
      }
      if (task->transferred > 0) {
        ECM seek_rcm = file_handle.Seek(task->transferred);
        if (seek_rcm.first != EC::Success) {
          pd.set_terminate();
          task->rcm = seek_rcm;
          return;
        }
      }
      while (file_handle.offset < file_handle.file_size) {
        while (pd.ring_buffer->writable() == 0 && !pd.is_terminate() &&
               file_handle.offset < file_handle.file_size) {
          std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        while (pd.is_pause() && !pd.is_terminate()) {
          std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        if (pd.is_terminate()) {
          return;
        }
        auto [bytes_read, ecm] = file_handle.Read();
        if (ecm.first != EC::Success && ecm.first != EC::EndOfFile) {
          pd.set_terminate();
          task->rcm = ecm;
          return;
        }
      }
    } else if (client->ConfigPort().GetProtocol() == ClientProtocol::FTP) {
      auto *client_ftp_raw = dynamic_cast<AMFTPIOCore *>(&client->IOPort());
      if (client_ftp_raw == nullptr) {
        pd.set_terminate();
        task->rcm = {EC::InvalidArg, "FTP IO port implementation mismatch"};
        return;
      }
      ECM out_rcm;
      std::shared_ptr<AMFTPIOCore> client_ftp(client_ftp_raw,
                                              [](AMFTPIOCore *) {});
      FTPDownloadSet(client_ftp, task->src, FTPToBufferWk, &pd);
      if (out_rcm.first != EC::Success) {
        pd.set_terminate();
        task->rcm = out_rcm;
      }
    }
  }

  // BufferToX - write from ring buffer to destination
  void BufferToX(const ClientHandle &client,
                 std::shared_ptr<TaskInfo> task_info) const {
    if (!client || !task_info || !task_info->pd || !task_info->cur_task) {
      return;
    }
    auto &pd = *(task_info->pd);
    auto *task = task_info->cur_task;
    if (client->ConfigPort().GetProtocol() == ClientProtocol::SFTP) {
      auto *clientf = dynamic_cast<AMSFTPIOCore *>(&client->IOPort());
      if (clientf == nullptr) {
        pd.set_terminate();
        task->rcm = {EC::InvalidArg, "SFTP IO port implementation mismatch"};
        return;
      }
      UnionFileHandle file_handle;
      const bool resume = task->transferred > 0;
      ECM rcm = file_handle.Init(task->dst, task->size, clientf, true, true,
                                 !resume, &pd);
      if (rcm.first != EC::Success) {
        pd.set_terminate();
        task->rcm = rcm;
        return;
      }
      if (resume) {
        ECM seek_rcm = file_handle.Seek(task->transferred);
        if (seek_rcm.first != EC::Success) {
          pd.set_terminate();
          task->rcm = seek_rcm;
          return;
        }
      }
      libssh2_session_set_blocking(clientf->session, 0);
      while (file_handle.offset < file_handle.file_size && !pd.is_terminate()) {
        while (pd.ring_buffer->available() == 0 && !pd.is_terminate()) {
          std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        while (pd.is_pause() && !pd.is_terminate()) {
          std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        if (pd.is_terminate()) {
          return;
        }
        auto [bytes_write, ecm] = file_handle.Write();
        if (ecm.first != EC::Success && ecm.first != EC::EndOfFile) {
          pd.set_terminate();
          task->rcm = ecm;
          return;
        }
        if (bytes_write > 0) {
          task_info->total_transferred_size.fetch_add(
              static_cast<size_t>(bytes_write), std::memory_order_relaxed);
          task_info->this_task_transferred_size.store(
              static_cast<size_t>(file_handle.offset),
              std::memory_order_relaxed);
        }
        task->transferred = task_info->this_task_transferred_size.load(
            std::memory_order_relaxed);
        EmitProgress(task_info, pd, false);
      }
    } else if (client->ConfigPort().GetProtocol() == ClientProtocol::LOCAL) {
      UnionFileHandle file_handle;
      const bool resume = task->transferred > 0;
      ECM rcm = file_handle.Init(task->dst, task->size, nullptr, true, true,
                                 !resume, &pd);
      if (rcm.first != EC::Success) {
        pd.set_terminate();
        task->rcm = rcm;
        return;
      }
      if (resume) {
        ECM seek_rcm = file_handle.Seek(task->transferred);
        if (seek_rcm.first != EC::Success) {
          pd.set_terminate();
          task->rcm = seek_rcm;
          return;
        }
      }
      while (file_handle.offset < file_handle.file_size && !pd.is_terminate()) {
        while (pd.ring_buffer->available() == 0 && !pd.is_terminate()) {
          std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        while (pd.is_pause() && !pd.is_terminate()) {
          std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        if (pd.is_terminate()) {
          return;
        }
        auto [bytes_write, ecm] = file_handle.Write();
        if (ecm.first != EC::Success && ecm.first != EC::EndOfFile) {
          pd.set_terminate();
          task->rcm = ecm;
          return;
        }
        if (bytes_write > 0) {
          task_info->total_transferred_size.fetch_add(
              static_cast<size_t>(bytes_write), std::memory_order_relaxed);
          task_info->this_task_transferred_size.store(
              static_cast<size_t>(file_handle.offset),
              std::memory_order_relaxed);
        }
        task->transferred = task_info->this_task_transferred_size.load(
            std::memory_order_relaxed);
        EmitProgress(task_info, pd, false);
      }
    } else if (client->ConfigPort().GetProtocol() == ClientProtocol::FTP) {
      auto *client_ftp_raw = dynamic_cast<AMFTPIOCore *>(&client->IOPort());
      if (client_ftp_raw == nullptr) {
        pd.set_terminate();
        task->rcm = {EC::InvalidArg, "FTP IO port implementation mismatch"};
        return;
      }
      ECM out_rcm;
      std::shared_ptr<AMFTPIOCore> client_ftp(client_ftp_raw,
                                              [](AMFTPIOCore *) {});
      FTPUploadSet(client_ftp, task->dst, task_info->pd.get(), BufferToFTPWk);
      if (out_rcm.first != EC::Success) {
        pd.set_terminate();
        task->rcm = out_rcm;
      }
    }
  }

  // Static callbacks for FTP using WkProgressData
  static size_t BufferToFTPWk(char *ptr, size_t size, size_t nmemb,
                              void *userdata) {
    auto *pd = static_cast<WkProgressData *>(userdata);
    while (true) {
      if (pd->is_terminate()) {
        return CURL_READFUNC_ABORT;
      }
      while (pd->is_pause() && !pd->is_terminate()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
      }
      // Check if transfer complete
      auto ti = pd->task_info.lock();
      TransferTask *cur_task = nullptr;
      if (ti) {
        std::lock_guard<std::mutex> lock(ti->mtx);
        cur_task = ti->cur_task;
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
          if (cur_task) {
            const size_t delta = static_cast<size_t>(to_read);
            const size_t total = ti->this_task_transferred_size.fetch_add(
                                     delta, std::memory_order_relaxed) +
                                 delta;
            cur_task->transferred = total;
            ti->total_transferred_size.fetch_add(static_cast<size_t>(to_read),
                                                 std::memory_order_relaxed);
          }
          pd->CallInnerCallback(false);
          return to_read;
        } catch (const std::exception &e) {
          pd->set_terminate();
          if (cur_task) {
            cur_task->rcm = ECM{EC::BufferReadError, e.what()};
          }
          return CURL_READFUNC_ABORT;
        }
      } else if (to_read < 0) {
        pd->set_terminate();
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
    auto *pd = static_cast<WkProgressData *>(userdata);
    size_t total = size * nmemb;
    size_t written = 0;
    while (written < total) {
      if (pd->is_terminate()) {
        return 0;
      }
      while (pd->is_pause() && !pd->is_terminate()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
      }
      while (pd->ring_buffer->writable() == 0 && !pd->is_terminate()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
      }
      if (pd->is_terminate()) {
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
          pd->set_terminate();
          auto ti = pd->task_info.lock();
          TransferTask *cur_task = nullptr;
          if (ti) {
            std::lock_guard<std::mutex> lock(ti->mtx);
            cur_task = ti->cur_task;
          }
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
                           const std::string &dst, WkProgressData *pd,
                           curl_read_callback read_callback) {
    std::lock_guard<std::recursive_mutex> lock(client->TransferMutex());
    auto ti = pd->task_info.lock();
    TransferTask *cur_task = nullptr;
    if (ti) {
      std::lock_guard<std::mutex> tlock(ti->mtx);
      cur_task = ti->cur_task;
    }
    if (!cur_task) {
      pd->set_terminate();
      return;
    }
    const size_t resume_offset = cur_task->transferred;
    ECM ecm = client->SetupPath(dst, false);
    if (ecm.first != EC::Success) {
      cur_task->rcm = ecm;
      pd->set_terminate();
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
      pd->set_terminate();
    } else if (res != CURLE_OK) {
      cur_task->rcm =
          ECM{EC::FTPUploadFailed,
              AMStr::fmt("Upload failed: {}", curl_easy_strerror(res))};
      pd->set_terminate();
    }
  }

  // Download with ProgressData (legacy - for AMSFTPWorker)
  static void FTPDownloadSet(std::shared_ptr<AMFTPIOCore> client,
                             const std::string &src,
                             curl_write_callback write_callback,
                             WkProgressData *pd) {
    std::lock_guard<std::recursive_mutex> lock(client->TransferMutex());
    auto ti = pd->task_info.lock();
    TransferTask *cur_task = nullptr;
    if (ti) {
      std::lock_guard<std::mutex> tlock(ti->mtx);
      cur_task = ti->cur_task;
    }
    if (!cur_task) {
      pd->set_terminate();
      return;
    }
    const size_t resume_offset = cur_task->transferred;
    ECM ecm = client->SetupPath(src, false);
    if (ecm.first != EC::Success) {
      cur_task->rcm = ecm;
      pd->set_terminate();
      return;
    }
    auto curl = client->GetCURL();
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, pd);
    curl_easy_setopt(curl, CURLOPT_RESUME_FROM_LARGE,
                     static_cast<curl_off_t>(resume_offset));
    CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_ABORTED_BY_CALLBACK || res == CURLE_WRITE_ERROR) {
      pd->set_terminate();
    } else if (res != CURLE_OK) {
      cur_task->rcm =
          ECM{EC::FTPDownloadFailed,
              AMStr::fmt("Download failed: {}", curl_easy_strerror(res))};
      pd->set_terminate();
    }
  }

  // Single file transfer
  [[nodiscard]] ECM
  TransferSingleFile(ClientHandle src_client, ClientHandle dst_client,
                     std::shared_ptr<TaskInfo> task_info) const {
    if (!src_client || !dst_client || !task_info || !task_info->pd ||
        !task_info->cur_task) {
      return {EC::InvalidArg, "Invalid transfer input"};
    }

    auto src_endpoint = CreateEndpoint_(src_client);
    auto dst_endpoint = CreateEndpoint_(dst_client);
    if (!src_endpoint || !dst_endpoint) {
      return {EC::OperationUnsupported, "Unsupported transfer endpoint"};
    }
    auto &pd = *(task_info->pd);
    auto *task = task_info->cur_task;
    if (src_client->GetUID() == dst_client->GetUID()) {
      if (src_endpoint->Protocol() == ClientProtocol::SFTP) {
        return src_endpoint->Transit(task_info);
      }
      if (src_endpoint->Protocol() == ClientProtocol::FTP) {
        ECM copy_rcm =
            src_client->IOPort().copy(task->src, task->dst, true, -1);
        if (copy_rcm.first == EC::Success) {
          task_info->this_task_transferred_size.store(
              task->size, std::memory_order_relaxed);
          task_info->total_transferred_size.fetch_add(
              task->size, std::memory_order_relaxed);
          task->transferred = task->size;
          EmitProgress(task_info, pd, true);
        }
        return copy_rcm;
      }
    }

    std::thread reading_thread(
        [&]() { (void)src_endpoint->ReadToBuffer(task_info); });

    (void)dst_endpoint->WriteFromBuffer(task_info);

    if (reading_thread.joinable()) {
      reading_thread.join();
    }

    task->transferred =
        task_info->this_task_transferred_size.load(std::memory_order_relaxed);
    if (task->rcm.first != EC::Success) {
      return task->rcm;
    }
    if (task->transferred >= task->size) {
      return task->rcm;
    } else if (pd.is_pause_only()) {
      return {EC::TransferPause, "Task paused by user"};
    } else if (pd.is_terminate_only()) {
      return {EC::Terminate, "Task terminated by user"};
    }
    return {EC::UnknownError, "Task not finished but exited unexpectedly"};
  }

  /**
   * @brief Worker thread function with affinity-aware scheduling.
   */

  size_t chunk_size_ = 256 * AMKB;
  ProgressCallback progress_callback_;
};

/**
 * @brief Construct one transfer execution engine.
 */
TransferExecutionEngine::TransferExecutionEngine(
    size_t chunk_size, ProgressCallback progress_callback)
    : impl_(std::make_unique<Impl>(chunk_size, std::move(progress_callback))) {}

/**
 * @brief Destroy one transfer execution engine.
 */
TransferExecutionEngine::~TransferExecutionEngine() = default;

/**
 * @brief Move-construct one transfer execution engine.
 */
TransferExecutionEngine::TransferExecutionEngine(
    TransferExecutionEngine &&) noexcept = default;

/**
 * @brief Move-assign one transfer execution engine.
 */
TransferExecutionEngine &TransferExecutionEngine::operator=(
    TransferExecutionEngine &&) noexcept = default;

/**
 * @brief Set the transfer chunk size.
 */
void TransferExecutionEngine::SetChunkSize(size_t chunk_size) {
  impl_->SetChunkSize(chunk_size);
}

/**
 * @brief Return the current transfer chunk size.
 */
size_t TransferExecutionEngine::GetChunkSize() const {
  return impl_->GetChunkSize();
}

/**
 * @brief Execute one prepared single-file transfer task.
 */
TransferExecutionEngine::ECM
TransferExecutionEngine::ExecuteSingleFileTransfer(
    const ClientHandle &src_client, const ClientHandle &dst_client,
    const std::shared_ptr<TaskInfo> &task_info) const {
  return impl_->ExecuteSingleFileTransfer(src_client, dst_client, task_info);
}

} // namespace AMInfra::ClientRuntime
