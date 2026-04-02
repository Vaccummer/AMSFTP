#pragma once

#include "domain/client/ClientModel.hpp"
#include "domain/filesystem/ClientIOPortInterfaceArgs.hpp"
#include "domain/host/HostModel.hpp"
#include "foundation/core/DataClass.hpp"
#include <any>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <type_traits>
#include <typeindex>
#include <utility>
#include <vector>

namespace AMDomain::client {
class IClientPort;
class IClientControlToken;
class IClientTimeoutPort;

using ClientHandle = std::shared_ptr<IClientPort>;
using CB =
    std::shared_ptr<std::function<void(std::string, std::string, std::string)>>;
using WalkErrorCallback =
    std::shared_ptr<std::function<void(const std::string &, const ECM &)>>;
using WRD =
    std::vector<std::pair<std::vector<std::string>, std::vector<PathInfo>>>;
using amf = std::shared_ptr<IClientControlToken>;
using timeoutf = std::shared_ptr<IClientTimeoutPort>;
using WER = std::vector<std::pair<std::string, ECM>>;
using WRI = std::pair<std::vector<PathInfo>, WER>;
using RemoveErrors = std::vector<std::pair<std::string, ECM>>;
using ClientProtocol = host::ClientProtocol;
using KnownHostQuery = host::KnownHostQuery;
using KnownHostCallback = std::function<ECM(const KnownHostQuery &)>;
using TraceCallback = std::function<void(const TraceInfo &)>;
using AuthCallback =
    std::function<std::optional<std::string>(const AuthCBInfo &)>;
using ConRequest = host::ConRequest;
using OSType = OS_TYPE;
using ParsedClientPath =
    std::tuple<std::string, std::string, ClientHandle, ECM>;
using DisconnectCallback =
    std::function<void(const ClientHandle &, const ECM &)>;

amf CreateClientControlToken();
timeoutf CreateClientTimeoutPort();

/**
 * @brief Port for runtime metadata access.
 */
class IClientMetaDataPort {
public:
  using RawTypeMutator = std::function<void(std::any *, bool)>;
  using RawNamedMutator = std::function<void(std::any *, bool, bool)>;

  template <typename T> using TypeValueMutator = std::function<void(T *)>;
  template <typename T>
  using NamedValueMutator = std::function<void(T *, bool, bool)>;

  template <typename T> struct NamedValueQueryResult {
    std::optional<T> value = std::nullopt;
    bool name_found = false;
    bool type_match = false;
  };

  /**
   * @brief Virtual destructor for polymorphic use.
   */
  virtual ~IClientMetaDataPort() = default;

  /**
   * @brief Store one named runtime data blob.
   */
  virtual bool StoreNamedData(const std::string &name, std::any value,
                              bool overwrite = true) = 0;

  /**
   * @brief Store one type-indexed runtime data blob.
   */
  virtual bool StoreTypedData(const std::type_index &type_key, std::any value,
                              bool overwrite = true) = 0;

  /**
   * @brief Query one named runtime data blob.
   */
  [[nodiscard]] virtual std::optional<std::any>
  QueryNamedData(const std::string &name) const = 0;

  /**
   * @brief Query one type-indexed runtime data blob.
   */
  [[nodiscard]] virtual std::optional<std::any>
  QueryTypedData(const std::type_index &type_key) const = 0;

  /**
   * @brief Mutate one type-indexed runtime data blob.
   */
  virtual void MutateTypedData(const std::type_index &type_key,
                               RawTypeMutator mutator) = 0;

  /**
   * @brief Mutate one named runtime data blob with type-match status.
   */
  virtual void MutateNamedData(const std::string &name,
                               const std::type_index &type_key,
                               RawNamedMutator mutator) = 0;

  /**
   * @brief Erase one named runtime data blob.
   */
  virtual bool EraseNamedData(const std::string &name) = 0;

  virtual bool EraseTypedData(const std::type_index &type_key) = 0;

  template <typename T> [[nodiscard]] bool EraseTypedData() {
    using ValueT = std::decay_t<T>;
    static_assert(!std::is_reference_v<ValueT>,
                  "EraseTypedData expects value-like type");
    return EraseTypedData(std::type_index(typeid(ValueT)));
  }

  /**
   * @brief Store one typed runtime value.
   */
  template <typename T>
  [[nodiscard]] bool StoreTypedValue(T value, bool overwrite = true) {
    using ValueT = std::decay_t<T>;
    static_assert(!std::is_reference_v<ValueT>,
                  "StoreTypedValue expects value-like type");
    return StoreTypedData(std::type_index(typeid(ValueT)),
                          std::any(std::forward<T>(value)), overwrite);
  }

  /**
   * @brief Query one typed runtime value.
   */
  template <typename T> [[nodiscard]] std::optional<T> QueryTypedValue() const {
    using ValueT = std::remove_cv_t<std::remove_reference_t<T>>;
    auto payload_opt = QueryTypedData(std::type_index(typeid(ValueT)));
    if (!payload_opt.has_value()) {
      return std::nullopt;
    }
    auto &payload = *payload_opt;
    if (auto *typed = std::any_cast<ValueT>(&payload); typed != nullptr) {
      return *typed;
    }
    return std::nullopt;
  }

  /**
   * @brief Query one named typed runtime value.
   */
  template <typename T>
  [[nodiscard]] NamedValueQueryResult<T>
  QueryNamedValue(const std::string &name) const {
    using ValueT = std::remove_cv_t<std::remove_reference_t<T>>;
    NamedValueQueryResult<ValueT> out = {};
    auto payload_opt = QueryNamedData(name);
    out.name_found = payload_opt.has_value();
    if (!payload_opt.has_value()) {
      out.type_match = false;
      return out;
    }
    auto &payload = *payload_opt;
    out.type_match = (std::any_cast<ValueT>(&payload) != nullptr);
    if (out.type_match) {
      out.value = *std::any_cast<ValueT>(&payload);
    }

    return out;
  }

  /**
   * @brief Mutate one typed runtime value in-place.
   */
  template <typename T> void MutateTypeValue(TypeValueMutator<T> mutator) {
    using ValueT = std::remove_cv_t<std::remove_reference_t<T>>;
    if (!mutator) {
      return;
    }
    MutateTypedData(std::type_index(typeid(ValueT)),
                    [&mutator](std::any *payload, bool type_found) {
                      ValueT *typed = nullptr;
                      if (type_found && payload != nullptr) {
                        typed = std::any_cast<ValueT>(payload);
                      }
                      mutator(typed);
                    });
  }

  /**
   * @brief Mutate one named typed runtime value in-place.
   */
  template <typename T>
  void MutateNamedValue(const std::string &name, NamedValueMutator<T> mutator) {
    using ValueT = std::remove_cv_t<std::remove_reference_t<T>>;
    if (!mutator) {
      return;
    }
    MutateNamedData(
        name, std::type_index(typeid(ValueT)),
        [&mutator](std::any *payload, bool name_found, bool type_match) {
          ValueT *typed = nullptr;
          if (name_found && type_match && payload != nullptr) {
            typed = std::any_cast<ValueT>(payload);
          }
          mutator(typed, name_found, type_match);
        });
  }
};

/**
 * @brief Port for internal runtime config/state data.
 */
class IClientConfigPort {
public:
  /**
   * @brief Virtual destructor for polymorphic use.
   */
  virtual ~IClientConfigPort() = default;

  /**
   * @brief Return configured nickname.
   */
  [[nodiscard]] virtual std::string GetNickname() const = 0;

  /**
   * @brief Return request payload used to build this client.
   */
  [[nodiscard]] virtual ConRequest GetRequest() const = 0;

  /**
   * @brief Return atomic request storage for advanced coordinated updates.
   */
  [[nodiscard]] virtual AMAtomic<ConRequest> &RequestAtomic() = 0;

  /**
   * @brief Return atomic request storage for read-only coordinated access.
   */
  [[nodiscard]] virtual const AMAtomic<ConRequest> &RequestAtomic() const = 0;

  /**
   * @brief Return atomic state storage for advanced coordinated updates.
   */
  [[nodiscard]] virtual AMAtomic<ECMData<AMDomain::filesystem::CheckResult>> &
  StateAtomic() = 0;

  /**
   * @brief Return atomic state storage for read-only coordinated access.
   */
  [[nodiscard]] virtual const AMAtomic<ECMData<AMDomain::filesystem::CheckResult>> &
  StateAtomic() const = 0;

  /**
   * @brief Return protocol kind.
   */
  [[nodiscard]] virtual ClientProtocol GetProtocol() const = 0;

  /**
   * @brief Return cached state from last check/connect action.
   */
  [[nodiscard]] virtual ECMData<AMDomain::filesystem::CheckResult>
  GetState() const = 0;

  /**
   * @brief Return remote/local OS type.
   */
  virtual OS_TYPE GetOSType() = 0;

  /**
   * @brief Return home directory.
   */
  virtual std::string GetHomeDir() = 0;

  /**
   * @brief Update request payload used to build this client.
   */
  virtual void SetRequest(ConRequest request) = 0;

  /**
   * @brief Update configured nickname.
   */
  virtual void SetNickname(const std::string &nickname) = 0;

  /**
   * @brief Update cached state from last check/connect action.
   */
  virtual void
  SetState(const ECMData<AMDomain::filesystem::CheckResult> &state) = 0;

  /**
   * @brief Update remote/local OS type.
   */
  virtual void SetOSType(OS_TYPE os_type) = 0;

  /**
   * @brief Update home directory cache.
   */
  virtual void SetHomeDir(const std::string &home_dir) = 0;
};

/**
 * @brief Port for interrupt/task-control operations.
 */
class IClientControlToken {
public:
  /**
   * @brief Virtual destructor for polymorphic use.
   */
  virtual ~IClientControlToken() = default;

  /**
   * @brief Request interruption for this client instance.
   */
  virtual void RequestInterrupt() = 0;

  /**
   * @brief Clear client-level interruption state.
   */
  virtual void ClearInterrupt() = 0;

  /**
   * @brief Return true when client-level interruption is requested.
   */
  [[nodiscard]] virtual bool IsInterrupted() const = 0;

  /**
   * @brief Register one wake callback for interruption.
   */
  virtual size_t RegisterWakeup(std::function<void()> wake_cb) = 0;

  /**
   * @brief Unregister one wake callback token.
   */
  virtual bool UnregisterWakeup(size_t token) = 0;
};

class ControlTokenWakeupSafeGaurd {
private:
  const amf &control_token_;
  size_t wake_token_ = 0;

public:
  explicit ControlTokenWakeupSafeGaurd(const amf &control_token,
                                       std::function<void()> wake_cb)
      : control_token_(control_token) {
    if (control_token_) {
      wake_token_ = control_token_->RegisterWakeup(std::move(wake_cb));
    }
  }

  ~ControlTokenWakeupSafeGaurd() {
    if (wake_token_ != 0 && control_token_) {
      control_token_->UnregisterWakeup(wake_token_);
    }
  }
};

/**
 * @brief Port for timeout-budget tracking.
 */
class IClientTimeoutPort {
public:
  /**
   * @brief Virtual destructor for polymorphic use.
   */
  virtual ~IClientTimeoutPort() = default;

  /**
   * @brief Return true when timeout budget has elapsed.
   */
  [[nodiscard]] virtual bool IsTimeout() const = 0;

  /**
   * @brief Return remaining timeout budget in milliseconds.
   * When SetTimeout is called with a negative value, there is no timeout and
   * this returns std::nullopt.
   * When timed out, this returns 0.
   * Otherwise this returns remaining milliseconds.
   */
  [[nodiscard]] virtual std::optional<unsigned int> RemainTimeMs() const = 0;

  /**
   * @brief Set timeout budget in milliseconds.
   * @param timeout_ms Timeout budget in milliseconds; negative value means
   * no timeout.
   */
  virtual void SetTimeout(float timeout_ms) = 0;
};

class ClientControlComponent {
private:
  amf control_port = nullptr;
  timeoutf timeout_port = nullptr;

public:
  ClientControlComponent(amf control_port = nullptr,
                         timeoutf timeout_port = nullptr)
      : control_port(std::move(control_port)),
        timeout_port(std::move(timeout_port)) {}

  ClientControlComponent(amf control_port, int timeout_ms)
      : control_port(std::move(control_port)),
        timeout_port(CreateClientTimeoutPort()) {
    if (timeout_port) {
      timeout_port->SetTimeout(static_cast<float>(timeout_ms));
    }
  }

  [[nodiscard]] bool IsInterrupted() const {
    return (control_port && control_port->IsInterrupted());
  }

  [[nodiscard]] bool IsTimeout() const {
    return (timeout_port && timeout_port->IsTimeout());
  }

  [[nodiscard]] std::optional<unsigned int> RemainingTimeMs() const {
    if (timeout_port) {
      return timeout_port->RemainTimeMs();
    }
    return std::nullopt;
  }

  [[nodiscard]] const amf &ControlToken() const { return control_port; }

  [[nodiscard]] bool CheckStop(ECM &rcm) const {
    if (IsInterrupted()) {
      rcm = ECM{EC::Terminate, "Operation interrupted by user"};
      return true;
    }
    if (IsTimeout()) {
      rcm = ECM{EC::OperationTimeout, "Operation timed out"};
      return true;
    }
    return false;
  }
};

/**
 * @brief Port for IO worker operations.
 */
class IClientIOPort {
public:
  /**
   * @brief Virtual destructor for polymorphic use.
   */
  virtual ~IClientIOPort() = default;

  /**
   * @brief Register one trace callback for IO worker records.
   */
  virtual void RegisterTraceCallback(TraceCallback trace_cb) = 0;

  /**
   * @brief Unregister current trace callback.
   */
  virtual void UnregisterTraceCallback() = 0;

  /**
   * @brief Register one auth callback for IO worker auth flow.
   */
  virtual void RegisterAuthCallback(AuthCallback auth_cb) = 0;

  /**
   * @brief Unregister current auth callback.
   */
  virtual void UnregisterAuthCallback() = 0;

  /**
   * @brief Register one known-host verification callback for IO worker flow.
   */
  virtual void RegisterKnownHostCallback(KnownHostCallback known_host_cb) = 0;

  /**
   * @brief Unregister current known-host verification callback.
   */
  virtual void UnregisterKnownHostCallback() = 0;

  /**
   * @brief Update and return remote/local OS type.
   */
  virtual ECMData<AMDomain::filesystem::UpdateOSTypeResult>
  UpdateOSType(const AMDomain::filesystem::UpdateOSTypeArgs &args = {},
               const ClientControlComponent &control = {}) = 0;

  /**
   * @brief Update and return home directory.
   */
  virtual ECMData<AMDomain::filesystem::UpdateHomeDirResult>
  UpdateHomeDir(const AMDomain::filesystem::UpdateHomeDirArgs &args = {},
                const ClientControlComponent &control = {}) = 0;

  /**
   * @brief Validate connection health.
   */
  virtual ECMData<AMDomain::filesystem::CheckResult>
  Check(const AMDomain::filesystem::CheckArgs &args = {},
        const ClientControlComponent &control = {}) = 0;

  /**
   * @brief Connect or reconnect this client.
   */
  virtual ECMData<AMDomain::filesystem::ConnectResult>
  Connect(const AMDomain::filesystem::ConnectArgs &args = {},
          const ClientControlComponent &control = {}) = 0;

  /**
   * @brief Measure round trip time when supported.
   */
  virtual ECMData<AMDomain::filesystem::RTTResult>
  GetRTT(const AMDomain::filesystem::GetRTTArgs &args = {},
         const ClientControlComponent &control = {}) = 0;

  /**
   * @brief Execute command and return output + exit code when supported.
   */
  virtual ECMData<AMDomain::filesystem::RunResult>
  ConductCmd(const AMDomain::filesystem::ConductCmdArgs &args,
             const ClientControlComponent &control = {}) = 0;

  /**
   * @brief Query path metadata.
   */
  virtual ECMData<AMDomain::filesystem::StatResult>
  stat(const AMDomain::filesystem::StatArgs &args,
       const ClientControlComponent &control = {}) = 0;

  /**
   * @brief List one directory.
   */
  virtual ECMData<AMDomain::filesystem::ListResult>
  listdir(const AMDomain::filesystem::ListdirArgs &args,
          const ClientControlComponent &control = {}) = 0;

  /**
   * @brief List one directory and return only entry names.
   */
  virtual ECMData<AMDomain::filesystem::ListNamesResult>
  listnames(const AMDomain::filesystem::ListNamesArgs &args,
            const ClientControlComponent &control = {}) = 0;

  /**
   * @brief Create one directory.
   */
  virtual ECMData<AMDomain::filesystem::MkdirResult>
  mkdir(const AMDomain::filesystem::MkdirArgs &args,
        const ClientControlComponent &control = {}) = 0;

  /**
   * @brief Create multi-level directories.
   */
  virtual ECMData<AMDomain::filesystem::MkdirsResult>
  mkdirs(const AMDomain::filesystem::MkdirsArgs &args,
         const ClientControlComponent &control = {}) = 0;

  /**
   * @brief Remove one directory.
   */
  virtual ECMData<AMDomain::filesystem::RMResult>
  rmdir(const AMDomain::filesystem::RmdirArgs &args,
        const ClientControlComponent &control = {}) = 0;

  /**
   * @brief Remove one file.
   */
  virtual ECMData<AMDomain::filesystem::RMResult>
  rmfile(const AMDomain::filesystem::RmfileArgs &args,
         const ClientControlComponent &control = {}) = 0;

  /**
   * @brief Rename or move one path.
   */
  virtual ECMData<AMDomain::filesystem::MoveResult>
  rename(const AMDomain::filesystem::RenameArgs &args,
         const ClientControlComponent &control = {}) = 0;

  /**
   * Deprecated orchestration APIs (migration reference only):
   * virtual AMDomain::filesystem::GetsizeResult
   * getsize(const AMDomain::filesystem::GetsizeArgs &args,
   *         const ClientControlComponent &control = {}) = 0;
   * virtual AMDomain::filesystem::FindResult
   * find(const AMDomain::filesystem::FindArgs &args,
   *      const ClientControlComponent &control = {}) = 0;
   * virtual AMDomain::filesystem::DeleteResult
   * remove(const AMDomain::filesystem::RemoveArgs &args,
   *        const ClientControlComponent &control = {}) = 0;
   * virtual ECM
   * saferm(const AMDomain::filesystem::SafermArgs &args,
   *        const ClientControlComponent &control = {}) = 0;
   * virtual ECM
   * copy(const AMDomain::filesystem::CopyArgs &args,
   *      const ClientControlComponent &control = {}) = 0;
   * virtual AMDomain::filesystem::IWalkResult
   * iwalk(const AMDomain::filesystem::IWalkArgs &args,
   *       const ClientControlComponent &control = {}) = 0;
   * virtual AMDomain::filesystem::WalkResult
   * walk(const AMDomain::filesystem::WalkArgs &args,
   *      const ClientControlComponent &control = {}) = 0;
   */
};

/**
 * @brief Aggregate client port exposing split capability ports.
 */
class IClientPort {
public:
  using ID = std::string;
  /**
   * @brief Virtual destructor for polymorphic use.
   */
  virtual ~IClientPort() = default;

  /**
   * @brief Return runtime client UID.
   */
  virtual ID GetUID() = 0;

  /**
   * @brief Return metadata port.
   */
  [[nodiscard]] virtual IClientMetaDataPort &MetaDataPort() = 0;

  /**
   * @brief Return metadata port.
   */
  [[nodiscard]] virtual const IClientMetaDataPort &MetaDataPort() const = 0;

  /**
   * @brief Return config port.
   */
  [[nodiscard]] virtual IClientConfigPort &ConfigPort() = 0;

  /**
   * @brief Return config port.
   */
  [[nodiscard]] virtual const IClientConfigPort &ConfigPort() const = 0;

  /**
   * @brief Return task-control port.
   */
  [[nodiscard]] virtual IClientControlToken &TaskControlPort() = 0;

  /**
   * @brief Return task-control port.
   */
  [[nodiscard]] virtual const IClientControlToken &TaskControlPort() const = 0;

  /**
   * @brief Return IO port.
   */
  [[nodiscard]] virtual IClientIOPort &IOPort() = 0;

  /**
   * @brief Return IO port.
   */
  [[nodiscard]] virtual const IClientIOPort &IOPort() const = 0;
};

using ClientID = IClientPort::ID;
using ClientName = std::string;

class IClientMaintainerPort {
public:
  /**
   * @brief Virtual destructor for polymorphic use.
   */
  virtual ~IClientMaintainerPort() = default;

  virtual ClientHandle GetClient(const ClientName &name) = 0;

  virtual ECM CheckClient(const ClientName &name) = 0;

  virtual std::map<ClientName, ClientHandle> GetAllClients() = 0;

  virtual bool RemoveClient(const ClientName &name) = 0;

  virtual void RemoveDisconnectedClients() = 0;

  virtual void RemoveAllClients() = 0;

  virtual bool AddClient(ClientHandle client, bool overwrite) = 0;

  virtual std::vector<bool> AddClients(const std::vector<ClientHandle> &clients,
                                       bool overwrite) = 0;

  virtual void SetHeartbeatInterval(int interval_s) = 0;

  virtual void SetCheckTimeout(int timeout_ms) = 0;

  virtual void SetDisconnectCallback(DisconnectCallback callback) = 0;

  [[nodiscard]] virtual bool IsHeartbeatRunning() const = 0;

  virtual void TerminateHeartbeat() = 0;

  virtual void PauseHeartbeat() = 0;

  virtual void StartHeartbeat() = 0;
};

std::pair<ECM, ClientHandle>
CreateClient(const ConRequest &request,
             KnownHostCallback known_host_cb = nullptr,
             TraceCallback trace_cb = nullptr, AuthCallback auth_cb = nullptr,
             const std::vector<std::string> &private_keys = {});

std::unique_ptr<IClientMaintainerPort>
CreateClientMaintainer(int heartbeat_interval_s = 60,
                       int check_timeout_ms = 500,
                       DisconnectCallback disconnect_callback = {},
                       std::vector<ClientHandle> init_clients = {});
} // namespace AMDomain::client
