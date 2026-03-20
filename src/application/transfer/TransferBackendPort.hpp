#pragma once

#include "domain/client/ClientPort.hpp"
#include "foundation/DataClass.hpp"

#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace AMApplication::TransferRuntime {
class ITransferClientPoolPort;
/**
 * @brief Application-side backend port for transfer runtime orchestration.
 */
class ITransferBackendPort {
public:
  using ECM = std::pair<ErrorCode, std::string>;
  using ID = std::string;

  virtual ~ITransferBackendPort() = default;

  /**
   * @brief Initialize transfer backend runtime.
   */
  virtual ECM Init() = 0;

  /**
   * @brief Execute one prepared task synchronously.
   */
  virtual ECM TransferTaskSync(
      const std::shared_ptr<TaskInfo> &task_info,
      AMDomain::client::amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Execute one prepared task asynchronously.
   */
  virtual ECM TransferTaskAsync(
      const std::shared_ptr<TaskInfo> &task_info,
      AMDomain::client::amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Create one task-info object bound to a transfer client pool.
   */
  [[nodiscard]] virtual std::shared_ptr<TaskInfo> CreateTaskInfo(
      std::shared_ptr<TASKS> tasks,
      const std::shared_ptr<ITransferClientPoolPort> &pool,
      TransferCallback callback = TransferCallback(),
      ssize_t buffer_size = -1, bool quiet = false,
      int thread_id = -1) = 0;

  /**
   * @brief List transfer task ids.
   */
  [[nodiscard]] virtual std::vector<ID> ListTaskIds() const = 0;

  /**
   * @brief Find transfer task by id.
   */
  [[nodiscard]] virtual std::shared_ptr<TaskInfo> FindTask(const ID &task_id) const = 0;

  /**
   * @brief Get counts of pending and conducting tasks.
   */
  virtual void GetTaskCounts(size_t *pending_count,
                             size_t *conducting_count) const = 0;

  /**
   * @brief Get or set worker thread count.
   */
  virtual ECM Thread(int num = -1) = 0;

  /**
   * @brief Apply worker thread count without presentation side effects.
   */
  virtual ECM SetWorkerThreadCount(size_t count) = 0;

  /**
   * @brief Terminate one task.
   */
  virtual ECM Terminate(const ID &task_id, int timeout_ms = 5000) = 0;

  /**
   * @brief Terminate tasks in batch.
   */
  virtual ECM Terminate(const std::vector<ID> &task_ids,
                        int timeout_ms = 5000) = 0;

  /**
   * @brief Pause one task.
   */
  virtual ECM Pause(const ID &task_id) = 0;

  /**
   * @brief Pause tasks in batch.
   */
  virtual ECM Pause(const std::vector<ID> &task_ids) = 0;

  /**
   * @brief Resume one task.
   */
  virtual ECM Resume(const ID &task_id) = 0;

  /**
   * @brief Resume tasks in batch.
   */
  virtual ECM Resume(const std::vector<ID> &task_ids) = 0;

  /**
   * @brief Retry one finished task.
   */
  virtual ECM Retry(const ID &task_id, bool is_async = false, bool quiet = false,
                    const std::vector<int> &indices = {}) = 0;
};

/**
 * @brief Create the application-native transfer backend.
 *
 * `thread_count_provider` resolves initial worker thread count when backend
 * initialization runs. `pool_provider` resolves the transfer client pool used
 * by retry flows.
 */
std::shared_ptr<ITransferBackendPort> CreateDefaultTransferBackend(
    std::function<int()> thread_count_provider = {},
    std::function<std::shared_ptr<ITransferClientPoolPort>()> pool_provider = {});
} // namespace AMApplication::TransferRuntime
