#pragma once
// project header
#include "domain/client/ClientModel.hpp"
#include "domain/client/ClientPort.hpp"
#include "domain/host/HostModel.hpp"
#include "foundation/core/DataClass.hpp"
#include "foundation/core/Enum.hpp"

#include <magic_enum/magic_enum.hpp>
#include <mutex>
#include <shared_mutex>
#include <typeindex>
#include <unordered_map>

namespace AMInfra::client {
namespace fs = std::filesystem;
using AMDomain::client::AuthCBInfo;
using AMDomain::client::ClientID;
using AMDomain::client::ClientStatus;
using AMDomain::client::ConnectStateCallback;
using AMDomain::client::KnownHostCallback;
using AMDomain::client::KnownHostQuery;
using AMDomain::client::NBResult;
using AMDomain::client::OS_TYPE;
using AMDomain::client::TraceInfo;
using AMDomain::client::WaitResult;
using AMDomain::filesystem::CheckResult;
using AMDomain::filesystem::SearchType;
using AMDomain::host::ClientProtocol;
using AMDomain::host::ConRequest;

using AuthCallback =
    std::function<std::optional<std::string>(const AuthCBInfo &)>;
using TraceCallback = std::function<void(const TraceInfo &)>;

namespace AMFSI = AMDomain::filesystem;

class ClientMetaDataStore : public AMDomain::client::IClientMetaDataPort {
private:
  using TypeVarStore = std::unordered_map<std::type_index, std::any>;
  using NamedVarStore = std::unordered_map<std::string, std::any>;
  mutable std::shared_mutex var_cache_mtx_;
  TypeVarStore type_var_cache_;
  NamedVarStore named_var_cache_;

public:
  [[nodiscard]] bool StoreTypedData(const std::type_index &type_key,
                                    std::any value,
                                    bool overwrite = true) override {
    std::unique_lock<std::shared_mutex> lock(var_cache_mtx_);
    auto it = type_var_cache_.find(type_key);
    if (it != type_var_cache_.end() && !overwrite) {
      return false;
    }
    type_var_cache_[type_key] = std::move(value);
    return true;
  }

  [[nodiscard]] std::optional<std::any>
  QueryTypedData(const std::type_index &type_key) const override {
    std::shared_lock<std::shared_mutex> lock(var_cache_mtx_);
    auto it = type_var_cache_.find(type_key);
    if (it == type_var_cache_.end()) {
      return std::nullopt;
    }
    return it->second;
  }

  void MutateTypedData(const std::type_index &type_key,
                       RawTypeMutator mutator) override {
    if (!mutator) {
      return;
    }
    std::unique_lock<std::shared_mutex> lock(var_cache_mtx_);
    auto it = type_var_cache_.find(type_key);
    const bool type_found = (it != type_var_cache_.end());
    std::any *payload = type_found ? &(it->second) : nullptr;
    mutator(payload, type_found);
  }

  [[nodiscard]] bool StoreNamedData(const std::string &name, std::any value,
                                    bool overwrite = true) override {
    if (name.empty()) {
      return false;
    }
    std::unique_lock<std::shared_mutex> lock(var_cache_mtx_);
    auto it = named_var_cache_.find(name);
    if (it != named_var_cache_.end() && !overwrite) {
      return false;
    }
    named_var_cache_[name] = std::move(value);
    return true;
  }

  [[nodiscard]] std::optional<std::any>
  QueryNamedData(const std::string &name) const override {
    std::shared_lock<std::shared_mutex> lock(var_cache_mtx_);
    auto it = named_var_cache_.find(name);
    if (it == named_var_cache_.end()) {
      return std::nullopt;
    }
    return it->second;
  }

  void MutateNamedData(const std::string &name, const std::type_index &type_key,
                       RawNamedMutator mutator) override {
    if (!mutator) {
      return;
    }
    std::unique_lock<std::shared_mutex> lock(var_cache_mtx_);
    auto it = named_var_cache_.find(name);
    const bool name_found = (it != named_var_cache_.end());
    bool type_match = false;
    std::any *payload = nullptr;
    if (name_found) {
      type_match = (std::type_index(it->second.type()) == type_key);
      payload = type_match ? &(it->second) : nullptr;
    }
    mutator(payload, name_found, type_match);
  }

  [[nodiscard]] bool EraseNamedData(const std::string &name) override {
    if (name.empty()) {
      return false;
    }
    std::unique_lock<std::shared_mutex> lock(var_cache_mtx_);
    return named_var_cache_.erase(name) > 0;
  }

  [[nodiscard]] bool EraseTypedData(const std::type_index &type_key) override {
    std::unique_lock<std::shared_mutex> lock(var_cache_mtx_);
    return type_var_cache_.erase(type_key) > 0;
  }
};

class ClientConfigStore : public AMDomain::client::IClientConfigPort {
private:
  mutable AMAtomic<ConRequest> request_;
  mutable AMAtomic<ECMData<CheckResult>> state_;
  std::atomic<OS_TYPE> os_type_{OS_TYPE::Uncertain};
  mutable AMAtomic<std::string> home_dir_;

public:
  explicit ClientConfigStore(ConRequest request)
      : request_(std::move(request)), home_dir_(std::string{}) {}

  [[nodiscard]] ConRequest GetRequest() const override {
    return request_.lock().load();
  }

  [[nodiscard]] ClientProtocol GetProtocol() const override {
    return request_.lock()->protocol;
  }

  [[nodiscard]] AMAtomic<ConRequest> &RequestAtomic() override {
    return request_;
  }

  [[nodiscard]] const AMAtomic<ConRequest> &RequestAtomic() const override {
    return request_;
  }

  [[nodiscard]] AMAtomic<ECMData<CheckResult>> &StateAtomic() override {
    return state_;
  }

  [[nodiscard]] const AMAtomic<ECMData<CheckResult>> &
  StateAtomic() const override {
    return state_;
  }

  void SetRequest(ConRequest request) override {
    auto req = request_.lock();
    req.store(std::move(request));
  }

  [[nodiscard]] std::string GetNickname() const override {
    auto req = request_.lock();
    return req->nickname;
  }

  void SetNickname(const std::string &nickname) override {
    auto req = request_.lock();
    req->nickname = nickname;
  }

  [[nodiscard]] ECMData<CheckResult> GetState() const override {
    auto st = state_.lock();
    return st.load();
  }

  void SetState(const ECMData<CheckResult> &state) override {
    auto st = state_.lock();
    st.store(state);
  }

  [[nodiscard]] OS_TYPE GetOSType() override {
    return os_type_.load(std::memory_order_acquire);
  }

  void SetOSType(OS_TYPE os_type) override {
    os_type_.store(os_type, std::memory_order_release);
  }

  [[nodiscard]] std::string GetHomeDir() override {
    return home_dir_.lock().load();
  }

  void SetHomeDir(const std::string &home_dir) override {
    auto home = home_dir_.lock();
    home.store(home_dir);
  }
};

class ClientIOBase : public AMDomain::client::IClientIOPort {
protected:
  mutable AMAtomic<TraceCallback> trace_callback_;
  mutable AMAtomic<ConnectStateCallback> connect_state_callback_;
  mutable AMAtomic<AuthCallback> auth_callback_;
  mutable AMAtomic<KnownHostCallback> known_host_callback_;
  AMDomain::client::IClientConfigPort *config_part_ = nullptr;
  AMAtomic<ConRequest> &request_atomic_;

public:
  ClientIOBase(AMDomain::client::IClientConfigPort *config,
               InterruptControl *control)
      : request_atomic_(
            config ? config->RequestAtomic()
                   : throw std::invalid_argument(
                         "ClientIOBase requires non-null config port")) {
    if (config == nullptr) {
      throw std::invalid_argument("ClientIOBase requires non-null config port");
    }
    this->config_part_ = config;
    (void)control;
  }

  void BindPorts(AMDomain::client::IClientConfigPort *config,
                 InterruptControl *control) {
    config_part_ = config;
    (void)control;
  }

  void RegisterTraceCallback(TraceCallback cb) override {
    auto trace = trace_callback_.lock();
    trace.store(std::move(cb));
  }

  void UnregisterTraceCallback() override {
    auto trace = trace_callback_.lock();
    trace.store(TraceCallback{});
  }

  void RegisterConnectStateCallback(ConnectStateCallback cb) override {
    auto connect_state = connect_state_callback_.lock();
    connect_state.store(std::move(cb));
  }

  void UnregisterConnectStateCallback() override {
    auto connect_state = connect_state_callback_.lock();
    connect_state.store(ConnectStateCallback{});
  }

  void RegisterAuthCallback(AuthCallback cb) override {
    auto auth_cb = auth_callback_.lock();
    auth_cb.store(std::move(cb));
  }

  void UnregisterAuthCallback() override {
    auto auth_cb = auth_callback_.lock();
    auth_cb.store(AuthCallback{});
  }

  void RegisterKnownHostCallback(KnownHostCallback cb) override {
    auto known_host_cb = known_host_callback_.lock();
    known_host_cb.store(std::move(cb));
  }

  void UnregisterKnownHostCallback() override {
    auto known_host_cb = known_host_callback_.lock();
    known_host_cb.store(KnownHostCallback{});
  }

protected:
  void connect_state(const std::string &state_info,
                     const std::string &target) const {
    ConnectStateCallback cb;
    {
      auto connect_state_cb = connect_state_callback_.lock();
      cb = connect_state_cb.load();
    }
    if (cb) {
      (void)CallCallbackSafe(cb, state_info, target);
    }
  }

  void trace(const TraceInfo &trace_info) const {
    TraceCallback cb;
    {
      auto trace = trace_callback_.lock();
      cb = trace.load();
    }
    if (cb) {
      (void)CallCallbackSafe(cb, trace_info);
    }
  }

  [[nodiscard]] std::optional<std::string>
  auth(const AuthCBInfo &auth_info) const {
    AuthCallback cb;
    {
      auto auth_cb = auth_callback_.lock();
      cb = auth_cb.load();
    }
    auto [res, _] =
        CallCallbackSafeRet<std::optional<std::string>>(cb, auth_info);
    return res;
  }

  [[nodiscard]] ECM known_host(const KnownHostQuery &known_host_info) const {
    KnownHostCallback cb;
    {
      auto known_host_cb = known_host_callback_.lock();
      cb = known_host_cb.load();
    }
    if (!cb) {
      return OK;
    }
    auto [res, cb_ecm] = CallCallbackSafeRet<ECM>(cb, known_host_info);
    if (cb_ecm.code != EC::Success) {
      return cb_ecm;
    }
    return res;
  }
};

class BaseClient : public AMDomain::client::IClientPort {
private:
  ClientID uid_;
  std::unique_ptr<AMDomain::client::IClientMetaDataPort> metadata_port_;
  std::unique_ptr<AMDomain::client::IClientConfigPort> config_port_;
  std::unique_ptr<InterruptControl> control_port_;
  std::unique_ptr<AMDomain::client::IClientIOPort> io_port_;

public:
  using amf = AMDomain::client::amf;
  /**
   * @brief Construct one assembled client from injected port implementations.
   */
  BaseClient(
      std::unique_ptr<AMDomain::client::IClientMetaDataPort> metadata_port,
      std::unique_ptr<AMDomain::client::IClientConfigPort> config_port,
      std::unique_ptr<InterruptControl> control_port,
      std::unique_ptr<AMDomain::client::IClientIOPort> io_port,
      ClientID uid = "") {
    if (!metadata_port || !config_port || !control_port || !io_port) {
      throw std::invalid_argument(
          "AMClient requires non-null metadata/config/control/io ports");
    }
    this->metadata_port_ = std::move(metadata_port);
    this->config_port_ = std::move(config_port);
    this->control_port_ = std::move(control_port);
    this->io_port_ = std::move(io_port);
    this->uid_ = std::move(uid);
  }

  /**
   * @brief Return runtime client UID.
   */
  ClientID GetUID() override { return uid_; }

  /**
   * @brief Return metadata port.
   */
  [[nodiscard]] AMDomain::client::IClientMetaDataPort &MetaDataPort() override {
    return *metadata_port_;
  }

  /**
   * @brief Return metadata port.
   */
  [[nodiscard]] const AMDomain::client::IClientMetaDataPort &
  MetaDataPort() const override {
    return *metadata_port_;
  }

  /**
   * @brief Return config port.
   */
  [[nodiscard]] AMDomain::client::IClientConfigPort &ConfigPort() override {
    return *config_port_;
  }

  /**
   * @brief Return config port.
   */
  [[nodiscard]] const AMDomain::client::IClientConfigPort &
  ConfigPort() const override {
    return *config_port_;
  }

  /**
   * @brief Return task-control port.
   */
  [[nodiscard]] InterruptControl &InterruptPort() override {
    return *control_port_;
  }

  /**
   * @brief Return task-control port.
   */
  [[nodiscard]] const InterruptControl &InterruptPort() const override {
    return *control_port_;
  }

  /**
   * @brief Return io port.
   */
  [[nodiscard]] AMDomain::client::IClientIOPort &IOPort() override {
    return *io_port_;
  }

  /**
   * @brief Return io port.
   */
  [[nodiscard]] const AMDomain::client::IClientIOPort &IOPort() const override {
    return *io_port_;
  }
};
} // namespace AMInfra::client
