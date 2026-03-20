#pragma once

#include "../transfer/TransferRuntimePorts.hpp"
#include "domain/client/ClientPort.hpp"
#include "foundation/core/DataClass.hpp"

#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace AMApplication::client {
/**
 * @brief Transfer-only reusable client pool with per-task lease control.
 */
class ClientPublicPool final : private NonCopyableNonMovable,
                               public AMApplication::TransferRuntime::ITransferClientPoolPort {
public:
  using ECM = std::pair<ErrorCode, std::string>;
  using ClientHandle = AMDomain::client::ClientHandle;
  using CreateClientFn = std::function<std::pair<ECM, ClientHandle>(
      const std::string &, int, int64_t)>;

  /**
   * @brief Per-client transfer lease marker stored in metadata named data.
   */
  struct ClientLeaseState {
    bool in_use = false;
    std::string owner_task_id = "";
  };

  /**
   * @brief Construct pool with optional client creation callback.
   */
  explicit ClientPublicPool(CreateClientFn create_client = {});

  /**
   * @brief Replace the client creation callback used for pool misses.
   */
  void SetCreateClientFn(CreateClientFn create_client);

  /**
   * @brief Acquire one transfer client for a task and nickname.
   */
  std::pair<ECM, ClientHandle>
  AcquireClient(const std::string &task_id, const std::string &nickname,
                int timeout_ms = -1, int64_t start_time = -1,
                bool force_new_instance = false) override;

  /**
   * @brief Acquire all distinct clients required by one task.
   */
  std::pair<ECM, std::unordered_map<std::string, ClientHandle>>
  AcquireClients(const std::string &task_id,
                 const std::vector<std::string> &nicknames,
                 int timeout_ms = -1, int64_t start_time = -1) override;

  /**
   * @brief Release all leased clients owned by one task.
   */
  void ReleaseTask(const std::string &task_id) override;

private:
  static inline constexpr const char *kLeaseDataName_ = "transfer.lease";

  /**
   * @brief Normalize one nickname to the canonical pool key.
   */
  static std::string CanonicalNickname_(const std::string &nickname);

  /**
   * @brief Read current lease state from one client metadata store.
   */
  static ClientLeaseState
  ReadLeaseStateLocked_(const AMDomain::client::IClientMetaDataPort &metadata);

  /**
   * @brief Write lease state into one client metadata store.
   */
  static void
  WriteLeaseStateLocked_(AMDomain::client::IClientMetaDataPort &metadata,
                         const ClientLeaseState &state);

  /**
   * @brief Append one client into the task lease table when missing.
   */
  void TrackTaskLeaseLocked_(const std::string &task_id,
                             const ClientHandle &client);

  /**
   * @brief Remove one client from the task lease table when present.
   */
  void EraseTaskLeaseLocked_(const std::string &task_id,
                             const ClientHandle &client);

  /**
   * @brief Remove one client instance from the nickname bucket.
   */
  void RemoveClientLocked_(const std::string &nickname,
                           const ClientHandle &client);

  /**
   * @brief Try to reuse one pooled client from an existing nickname bucket.
   */
  std::pair<ECM, ClientHandle>
  TryAcquireExistingLocked_(const std::string &task_id,
                            const std::string &nickname, int timeout_ms,
                            int64_t start_time);

  mutable std::mutex mutex_;
  std::unordered_map<std::string, std::list<ClientHandle>> clients_;
  std::unordered_map<std::string, std::vector<ClientHandle>> task_leases_;
  CreateClientFn create_client_;
};
} // namespace AMApplication::client
