#pragma once

#include "domain/client/ClientModel.hpp"
#include "domain/host/HostModel.hpp"
#include "foundation/DataClass.hpp"

#include <any>
#include <functional>
#include <optional>
#include <shared_mutex>
#include <string>
#include <tuple>
#include <type_traits>
#include <typeindex>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>


namespace AMDomain::client {
class IClientPort;
class IClientTaskControlPort;
using ClientHandle = std::shared_ptr<IClientPort>;

using CB =
    std::shared_ptr<std::function<void(std::string, std::string, std::string)>>;
using WalkErrorCallback =
    std::shared_ptr<std::function<void(const std::string &, const ECM &)>>;
using WRD =
    std::vector<std::pair<std::vector<std::string>, std::vector<PathInfo>>>;
using amf = std::shared_ptr<IClientTaskControlPort>;
using EC = ErrorCode;
using ECM = std::pair<ErrorCode, std::string>;
enum class ClientStatus {
  OK = 0,
  NotInitialized = 1,
  NoConnection = 2,
  ConnectionBroken = 3,
};
using ClientState = std::pair<ClientStatus, ECM>;
using WER = std::vector<std::pair<std::string, ECM>>;
using WRI = std::pair<std::vector<PathInfo>, WER>;
using RemoveErrors = std::vector<std::pair<std::string, ECM>>;
using StatResult = std::pair<ECM, PathInfo>;
using ListResult = std::pair<ECM, std::vector<PathInfo>>;
using IWalkResult = std::pair<ECM, WRI>;
using WalkResult = std::pair<ECM, std::pair<WRD, WER>>;
using ChmodResult = std::pair<ECM, std::unordered_map<std::string, ECM>>;
using CommandResult = std::pair<ECM, std::pair<std::string, int>>;
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

/**
 * @brief Port for runtime metadata access.
 */
class IClientMetaDataPort {
public:
  /**
   * @brief Virtual destructor for polymorphic use.
   */
  virtual ~IClientMetaDataPort() = default;

  /**
   * @brief Return metadata mutex for external lock coordination.
   */
  [[nodiscard]] virtual std::shared_mutex &Mutex() const = 0;

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
  [[nodiscard]] virtual std::pair<bool, std::any>
  QueryNamedData(const std::string &name) const = 0;

  /**
   * @brief Query one named runtime blob by pointer.
   */
  [[nodiscard]] virtual std::any *QueryNamedData(const std::string &name,
                                                 bool &name_exists) = 0;

  /**
   * @brief Query one named runtime blob by pointer (const overload).
   */
  [[nodiscard]] virtual const std::any *
  QueryNamedData(const std::string &name, bool &name_exists) const = 0;

  /**
   * @brief Query one type-indexed runtime blob by pointer.
   */
  [[nodiscard]] virtual std::any *
  QueryTypedData(const std::type_index &type_key, bool &type_exists) = 0;

  /**
   * @brief Query one type-indexed runtime blob by pointer (const overload).
   */
  [[nodiscard]] virtual const std::any *
  QueryTypedData(const std::type_index &type_key, bool &type_exists) const = 0;

  /**
   * @brief Erase one named runtime data blob.
   */
  virtual bool EraseNamedData(const std::string &name) = 0;

  /**
   * @brief Store one typed runtime value.
   */
  template <typename T>
  [[nodiscard]] bool StoreTypedValue(T &&value, bool overwrite = true) {
    using ValueT = std::decay_t<T>;
    static_assert(!std::is_reference_v<ValueT>,
                  "StoreTypedValue expects value-like type");
    return StoreTypedData(std::type_index(typeid(ValueT)),
                          std::any(std::forward<T>(value)), overwrite);
  }

  /**
   * @brief Query one typed runtime value.
   */
  template <typename T> [[nodiscard]] T *QueryTypedValue(bool &type_exists) {
    using ValueT = std::remove_cv_t<std::remove_reference_t<T>>;
    std::any *payload =
        QueryTypedData(std::type_index(typeid(ValueT)), type_exists);
    if (!payload) {
      return nullptr;
    }
    return std::any_cast<ValueT>(payload);
  }

  /**
   * @brief Query one typed runtime value (const overload).
   */
  template <typename T>
  [[nodiscard]] const T *QueryTypedValue(bool &type_exists) const {
    using ValueT = std::remove_cv_t<std::remove_reference_t<T>>;
    const std::any *payload =
        QueryTypedData(std::type_index(typeid(ValueT)), type_exists);
    if (!payload) {
      return nullptr;
    }
    return std::any_cast<ValueT>(payload);
  }

  /**
   * @brief Query one named typed runtime value.
   */
  template <typename T>
  [[nodiscard]] T *QueryNamedValue(const std::string &name, bool &name_exists) {
    using ValueT = std::remove_cv_t<std::remove_reference_t<T>>;
    std::any *payload = QueryNamedData(name, name_exists);
    if (!payload) {
      return nullptr;
    }
    return std::any_cast<ValueT>(payload);
  }

  /**
   * @brief Query one named typed runtime value (const overload).
   */
  template <typename T>
  [[nodiscard]] const T *QueryNamedValue(const std::string &name,
                                         bool &name_exists) const {
    using ValueT = std::remove_cv_t<std::remove_reference_t<T>>;
    const std::any *payload = QueryNamedData(name, name_exists);
    if (!payload) {
      return nullptr;
    }
    return std::any_cast<ValueT>(payload);
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
  [[nodiscard]] virtual AMAtomic<ClientState> &StateAtomic() = 0;

  /**
   * @brief Return atomic state storage for read-only coordinated access.
   */
  [[nodiscard]] virtual const AMAtomic<ClientState> &StateAtomic() const = 0;

  /**
   * @brief Return protocol kind.
   */
  [[nodiscard]] virtual ClientProtocol GetProtocol() const = 0;

  /**
   * @brief Return cached state from last check/connect action.
   */
  [[nodiscard]] virtual ClientState GetState() const = 0;

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
  virtual void SetState(const ClientState &state) = 0;

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
class IClientTaskControlPort {
public:
  /**
   * @brief Virtual destructor for polymorphic use.
   */
  virtual ~IClientTaskControlPort() = default;

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
  virtual void UnregisterWakeup(size_t token) = 0;
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
  virtual OSType UpdateOSType(int timeout_ms = -1, int64_t start_time = -1,
                              amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Update and return home directory.
   */
  virtual std::string UpdateHomeDir(int timeout_ms = -1,
                                    int64_t start_time = -1,
                                    amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Validate connection health.
   */
  virtual ECM Check(int timeout_ms = -1, int64_t start_time = -1,
                    amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Connect or reconnect this client.
   */
  virtual ECM Connect(bool force = false, int timeout_ms = -1,
                      int64_t start_time = -1,
                      amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Measure round trip time when supported.
   */
  virtual double GetRTT(ssize_t times = 5) = 0;

  /**
   * @brief Execute command and return output + exit code when supported.
   */
  virtual CommandResult ConductCmd(const std::string &cmd,
                                   int max_time_ms = 3000,
                                   amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Resolve path to real absolute path when supported.
   */
  virtual std::pair<ECM, std::string>
  realpath(const std::string &path, int timeout_ms = -1,
           int64_t start_time = -1, amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Change mode for path(s) when supported.
   */
  virtual ChmodResult chmod(const std::string &path,
                            std::variant<std::string, size_t> mode,
                            bool recursive = false, int timeout_ms = -1,
                            int64_t start_time = -1,
                            amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Query path metadata.
   */
  virtual StatResult stat(const std::string &path, bool trace_link = false,
                          int timeout_ms = -1, int64_t start_time = -1,
                          amf interrupt_flag = nullptr) = 0;

  /**
   * @brief List one directory.
   */
  virtual ListResult listdir(const std::string &path, int timeout_ms = -1,
                             int64_t start_time = -1,
                             amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Compute recursive total size for a path.
   */
  virtual int64_t getsize(const std::string &path,
                          bool ignore_special_file = true, int timeout_ms = -1,
                          int64_t start_time = -1,
                          amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Find entries by wildcard path pattern.
   */
  virtual std::vector<PathInfo> find(const std::string &path,
                                     SearchType type = SearchType::All,
                                     int timeout_ms = -1,
                                     int64_t start_time = -1,
                                     amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Create one directory.
   */
  virtual ECM mkdir(const std::string &path, int timeout_ms = -1,
                    int64_t start_time = -1, amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Create directory tree.
   */
  virtual ECM mkdirs(const std::string &path, int timeout_ms = -1,
                     int64_t start_time = -1, amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Remove one directory.
   */
  virtual ECM rmdir(const std::string &path, int timeout_ms = -1,
                    int64_t start_time = -1, amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Remove one file.
   */
  virtual ECM rmfile(const std::string &path, int timeout_ms = -1,
                     int64_t start_time = -1, amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Rename or move one path.
   */
  virtual ECM rename(const std::string &src, const std::string &dst,
                     bool mkdir = true, bool overwrite = false,
                     int timeout_ms = -1, int64_t start_time = -1,
                     amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Remove one path recursively.
   */
  virtual std::pair<ECM, RemoveErrors>
  remove(const std::string &path, WalkErrorCallback error_callback = nullptr,
         int timeout_ms = -1, int64_t start_time = -1,
         amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Safe-remove one path.
   */
  virtual ECM saferm(const std::string &path, int timeout_ms = -1,
                     int64_t start_time = -1, amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Copy one path in-host when supported.
   */
  virtual ECM copy(const std::string &src, const std::string &dst,
                   bool need_mkdir = false, int timeout_ms = -1,
                   amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Walk and return flattened leaf-oriented view.
   */
  virtual IWalkResult iwalk(const std::string &path, bool show_all = false,
                            bool ignore_special_file = true,
                            WalkErrorCallback error_callback = nullptr,
                            int timeout_ms = -1, int64_t start_time = -1,
                            amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Walk and return tree-oriented view.
   */
  virtual WalkResult walk(const std::string &path, int max_depth = -1,
                          bool show_all = false,
                          bool ignore_special_file = false,
                          WalkErrorCallback error_callback = nullptr,
                          int timeout_ms = -1, int64_t start_time = -1,
                          amf interrupt_flag = nullptr) = 0;
};

/**
 * @brief Aggregate client port exposing split capability ports.
 */
class IClientPort {
public:
  /**
   * @brief Virtual destructor for polymorphic use.
   */
  virtual ~IClientPort() = default;

  /**
   * @brief Return runtime client UID.
   */
  virtual std::string GetUID() = 0;

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
  [[nodiscard]] virtual IClientTaskControlPort &TaskControlPort() = 0;

  /**
   * @brief Return task-control port.
   */
  [[nodiscard]] virtual const IClientTaskControlPort &
  TaskControlPort() const = 0;

  /**
   * @brief Return IO port.
   */
  [[nodiscard]] virtual IClientIOPort &IOPort() = 0;

  /**
   * @brief Return IO port.
   */
  [[nodiscard]] virtual const IClientIOPort &IOPort() const = 0;
};

/**
 * @brief Port for constructing concrete client instances from connection
 * request data.
 */
class IClientFactoryPort {
public:
  /**
   * @brief Virtual destructor for polymorphic use.
   */
  virtual ~IClientFactoryPort() = default;

  /**
   * @brief Create one concrete client by request protocol and request payload.
   * @param request Connection request payload.
   * @return Pair of status and constructed client instance.
   */
  virtual std::pair<ECM, std::shared_ptr<IClientPort>>
  CreateClient(const ConRequest &request) = 0;
};

/**
 * @brief Port for runtime client registry/session state.
 */
class IClientRuntimePort {
public:
  /**
   * @brief Virtual destructor for polymorphic use.
   */
  virtual ~IClientRuntimePort() = default;

  /**
   * @brief Return one client by nickname.
   */
  [[nodiscard]] virtual ClientHandle
  GetClient(const std::string &nickname) const = 0;

  /**
   * @brief Return local client instance.
   */
  [[nodiscard]] virtual ClientHandle GetLocalClient() const = 0;

  /**
   * @brief Return current active client instance.
   */
  [[nodiscard]] virtual ClientHandle GetCurrentClient() const = 0;

  /**
   * @brief Return current active nickname.
   */
  [[nodiscard]] virtual std::string CurrentNickname() const = 0;

  /**
   * @brief Set current active client instance.
   */
  virtual void SetCurrentClient(const ClientHandle &client) = 0;

  /**
   * @brief Return all current client nicknames.
   */
  [[nodiscard]] virtual std::vector<std::string> GetClientNames() const = 0;

  /**
   * @brief Return all current client handles.
   */
  [[nodiscard]] virtual std::vector<ClientHandle> GetClients() const = 0;
};

/**
 * @brief Port for runtime client connect/check/remove operations.
 */
class IClientLifecyclePort {
public:
  /**
   * @brief Virtual destructor for polymorphic use.
   */
  virtual ~IClientLifecyclePort() = default;

  /**
   * @brief Connect one configured nickname.
   */
  virtual std::pair<ECM, ClientHandle> ConnectNickname(
      const std::string &nickname, const ClientConnectOptions &options = {},
      TraceCallback trace_cb = {}, amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Connect one explicit request payload.
   */
  virtual std::pair<ECM, ClientHandle>
  ConnectRequest(const ClientConnectContext &context,
                 TraceCallback trace_cb = {}, amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Ensure one client exists and is connected.
   */
  virtual std::pair<ECM, ClientHandle>
  EnsureClient(const std::string &nickname, amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Check one client by nickname.
   */
  virtual std::pair<ECM, ClientHandle> CheckClient(const std::string &nickname,
                                                   bool update = false,
                                                   amf interrupt_flag = nullptr,
                                                   int timeout_ms = -1,
                                                   int64_t start_time = -1) = 0;

  /**
   * @brief Remove one client from runtime registry.
   */
  virtual ECM RemoveClient(const std::string &nickname) = 0;
};

/**
 * @brief Port for runtime client path/session-state operations.
 */
class IClientPathPort {
public:
  /**
   * @brief Virtual destructor for polymorphic use.
   */
  virtual ~IClientPathPort() = default;

  /**
   * @brief Parse one raw path token into nickname/path/client form.
   */
  [[nodiscard]] virtual ParsedClientPath
  ParseScopedPath(const std::string &input, amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Resolve one raw path against a client into absolute path.
   */
  [[nodiscard]] virtual std::string
  ResolveClientPath(const std::string &path,
                    const ClientHandle &client = nullptr) const = 0;

  /**
   * @brief Return stored workdir state for one nickname.
   */
  [[nodiscard]] virtual ClientWorkdirState
  GetWorkdirState(const std::string &nickname) const = 0;

  /**
   * @brief Store workdir state for one nickname.
   */
  virtual ECM SetWorkdirState(const std::string &nickname,
                              const ClientWorkdirState &state) = 0;

  /**
   * @brief Return current workdir, initializing when absent.
   */
  [[nodiscard]] virtual std::string
  GetOrInitWorkdir(const ClientHandle &client) = 0;

  /**
   * @brief Build absolute path from client workdir/home context.
   */
  [[nodiscard]] virtual std::string
  BuildAbsolutePath(const ClientHandle &client,
                    const std::string &path) const = 0;
};

} // namespace AMDomain::client
