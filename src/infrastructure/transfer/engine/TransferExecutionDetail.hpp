#pragma once

#include "infrastructure/transfer/Common.hpp"
#include "infrastructure/transfer/RuntimeProgress.hpp"

namespace AMInfra::transfer::detail {
[[nodiscard]] ECM EnsureTransferClientReady(const ClientHandle &client,
                                            const char *operation);
[[nodiscard]] bool IsTaskHardInterrupted(const TaskHandle &task_info);
void SignalTaskIoAbort(TransferRuntimeProgress &progress);
[[nodiscard]] bool IsTaskIDUsed(const TaskID &task_id,
                                TaskRegistry &task_registry,
                                std::mutex &conducting_mtx,
                                const std::unordered_set<TaskID>
                                    &conducting_tasks);
[[nodiscard]] bool ShouldSkipTask(const TaskHandle &task_info);
void MarkUnfinishedTransferEntries(
    const TaskHandle &task_info, ECM entry_rcm,
    std::function<void(const std::optional<ECM> &)> on_mark = {});
[[nodiscard]] size_t ClampBufferSizeByPolicy(
    size_t requested, const TransferBufferPolicy &policy);
[[nodiscard]] ClientHandle ResolveTaskClient(
    const TransferClientContainer &clients, const std::string &nickname,
    bool use_dst_role);
[[nodiscard]] ECM ExecuteSourceToBuffer(const ClientHandle &client,
                                        const TaskHandle &task_info,
                                        TransferRuntimeProgress &progress);
[[nodiscard]] ECM ExecuteBufferToSink(const ClientHandle &client,
                                      const TaskHandle &task_info,
                                      TransferRuntimeProgress &progress);
[[nodiscard]] ECM ExecuteSequentialDirectTransfer(
    const ClientHandle &src_client, const ClientHandle &dst_client,
    const TaskHandle &task_info, TransferRuntimeProgress &progress,
    size_t chunk_size);
} // namespace AMInfra::transfer::detail
