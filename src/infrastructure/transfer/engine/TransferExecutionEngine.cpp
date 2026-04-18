#include "foundation/tools/path.hpp"
#include "foundation/tools/time.hpp"
#include "infrastructure/client/http/HTTP.hpp"
#include "infrastructure/transfer/Engine.hpp"
#include "infrastructure/transfer/engine/TransferExecutionDetail.hpp"

namespace {
using AMDomain::client::ClientProtocol;
using AMHTTPIOCore = AMInfra::client::HTTP::AMHTTPIOCore;
using ClientHandle = AMInfra::transfer::ClientHandle;
using EC = ErrorCode;
using ErrorCBInfo = AMDomain::transfer::ErrorCBInfo;
using RuntimeProgress = AMInfra::transfer::TransferRuntimeProgress;
using TaskHandle = AMInfra::transfer::TaskHandle;
using TaskStatus = AMInfra::transfer::TaskStatus;
using TransferTask = AMDomain::transfer::TransferTask;
} // namespace

namespace AMInfra::transfer {
TransferExecutionEngine::TransferExecutionEngine(
    const TransferBufferPolicy &buffer_policy)
    : buffer_policy_(buffer_policy) {
  read_thread_ = std::jthread(
      [this](std::stop_token stop_token) { ReadLoop_(stop_token); });
}

TransferExecutionEngine::~TransferExecutionEngine() {
  if (read_thread_.joinable()) {
    read_thread_.request_stop();
  }
  read_queue_ready_.release();
  if (read_thread_.joinable()) {
    read_thread_.join();
  }
}

void TransferExecutionEngine::ReadLoop_(std::stop_token stop_token) {
  while (true) {
    read_queue_ready_.acquire();
    if (stop_token.stop_requested()) {
      std::lock_guard<std::mutex> lock(read_queue_mtx_);
      if (read_queue_.empty()) {
        return;
      }
    }

    ReadJob job = {};
    {
      std::lock_guard<std::mutex> lock(read_queue_mtx_);
      if (read_queue_.empty()) {
        if (stop_token.stop_requested()) {
          return;
        }
        continue;
      }
      job = std::move(read_queue_.front());
      read_queue_.pop_front();
    }

    ECM read_rcm = OK;
    try {
      if (!job.src_client || !job.task_info || !job.runtime_progress) {
        read_rcm = Err(EC::InvalidArg, "", "", "Invalid read job");
      } else {
        read_rcm = detail::ExecuteSourceToBuffer(job.src_client, job.task_info,
                                                 *job.runtime_progress);
      }
    } catch (const std::exception &e) {
      read_rcm = Err(EC::UnknownError, "", "", e.what());
    } catch (...) {
      read_rcm =
          Err(EC::UnknownError, "", "", "Unknown read thread runtime error");
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
  read_queue_ready_.release();
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
  return detail::ClampBufferSizeByPolicy(effective, buffer_policy_);
}

ECM TransferExecutionEngine::TransferSignleFile(
    ClientHandle src_client, ClientHandle dst_client,
    RuntimeProgress &runtime_progress) {
  auto task_info = runtime_progress.task_info;
  if (!src_client || !dst_client || !task_info) {
    return {EC::InvalidArg, "", "", "Invalid transfer input"};
  }
  {
    const ECM src_guard =
        detail::EnsureTransferClientReady(src_client, __func__);
    if (!(src_guard)) {
      return src_guard;
    }
    const ECM dst_guard =
        detail::EnsureTransferClientReady(dst_client, __func__);
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
  const ECM write_rcm = detail::ExecuteBufferToSink(dst_client, task_info, pd);
  if (write_rcm.code != EC::Success &&
      (!task->rcm.has_value() || task->rcm->code == EC::Success)) {
    task->rcm = write_rcm;
  }
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
  if (detail::IsTaskHardInterrupted(task_info) &&
      !task_info->IsPauseRequested()) {
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
    task_info->SetResult({EC::InvalidHandle, "", "", "Task clients not found"});
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
    if (detail::IsTaskHardInterrupted(task_info) &&
        !task_info->IsPauseRequested()) {
      return ECM{EC::Terminate, "", "", "Task terminated by user"};
    }
    return std::nullopt;
  };

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
      auto dst_client = detail::ResolveTaskClient(task_clients, dst_key, true);
      if (!dst_client) {
        task.rcm = {EC::ClientNotFound, "", "",
                    "Task destination client is not available"};
        task.IsFinished = true;
        record_error(task.rcm);
        emit_entry_error(task);
        continue;
      }
      {
        const ECM guard_rcm =
            detail::EnsureTransferClientReady(dst_client, __func__);
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
        const ECM src_guard =
            detail::EnsureTransferClientReady(src_client, __func__);
        if (!(src_guard)) {
          task.rcm = src_guard;
          task.IsFinished = true;
          record_error(task.rcm);
          emit_entry_error(task);
          continue;
        }
        const ECM dst_guard =
            detail::EnsureTransferClientReady(dst_client, __func__);
        if (!(dst_guard)) {
          task.rcm = dst_guard;
          task.IsFinished = true;
          record_error(task.rcm);
          emit_entry_error(task);
          continue;
        }
      }

      task.rcm = OK;
      const size_t resume_offset = task.transferred;
      if (resume_offset > 0) {
        if (resume_offset > task.size) {
          task.rcm = {EC::InvalidOffset, "", "", "Offset exceeds src size"};
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

  const bool terminated_requested = detail::IsTaskHardInterrupted(task_info) &&
                                    !task_info->IsPauseRequested();
  if (terminated_requested) {
    const ECM terminate_rcm = {EC::Terminate, "", "",
                               "Task terminated by user"};
    detail::MarkUnfinishedTransferEntries(task_info, terminate_rcm,
                                          record_error);
  }

  if (task_info->Core.control.IsTimeout()) {
    task_info->SetResult({EC::OperationTimeout, "", "", "Task timeout"});
  } else if (detail::IsTaskHardInterrupted(task_info) &&
             !task_info->IsPauseRequested()) {
    task_info->SetResult({EC::Terminate, "", "", "Task terminated by user"});
  } else if (last_non_ok.code != EC::Success) {
    task_info->SetResult(last_non_ok);
  } else {
    task_info->SetResult(OK);
  }
  task_info->SetStatus(TaskStatus::Finished);
  task_info->Time.finish.store(AMTime::seconds(), std::memory_order_relaxed);
}
} // namespace AMInfra::transfer
