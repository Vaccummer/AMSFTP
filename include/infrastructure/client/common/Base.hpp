#pragma once
// standard library
#include <any>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <fcntl.h>
#include <list>
#include <memory>
#include <mutex>
#include <regex>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <typeindex>
#include <unordered_map>
#include <utility>
#include <vector>

// project header
#include "domain/client/ClientModel.hpp"
#include "domain/client/ClientPort.hpp"
#include "domain/host/HostModel.hpp"
#include "foundation/DataClass.hpp"
#include "foundation/Enum.hpp"
#include "foundation/Path.hpp"

// 3rd party library
#include <curl/curl.h>
#include <libssh2.h>
#include <libssh2_sftp.h>
#include <magic_enum/magic_enum.hpp>
#include <openssl/pem.h>
#include <openssl/rsa.h>

// #define _DISABLE_CONSTEXPR_MUTEX_CONSTRUCTOR // in case mutex constructor is
// not constexpr in some environments (like pybind11's embedded MSVC 2015),
// which causes static initialization failure
/*
inline size_t GenerateUIDInt() {
  try {
    std::random_device rd;
    std::mt19937_64 eng(rd());
    std::uniform_int_distribution<size_t> dist(0, SIZE_MAX);
    return dist(eng);
  } catch (...) {
    // fallback: time + counter
    static std::atomic<size_t> counter{0};
    size_t t = static_cast<size_t>(
        std::chrono::steady_clock::now().time_since_epoch().count());
    return t ^ ((counter.fetch_add(1, std::memory_order_relaxed) + 1) *
                0x9e3779b97f4a7c15ULL);
  }
}

inline std::string GenerateUID(int length = 10) {
  static const std::array<char, 32> AMcharset = {
      '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C',
      'D', 'E', 'F', 'G', 'H', 'J', 'K', 'M', 'N', 'P', 'Q',
      'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'};
  static constexpr size_t AMbase = sizeof(AMcharset) - 1;
  length = length < 1 ? 1 : length;
  length = length > 32 ? 32 : length;
  size_t uid = GenerateUIDInt();
  // Generate a string using AMcharset
  std::string uid_str;
  uid_str.reserve(static_cast<size_t>(length));
  for (int i = 0; i < length; i++) {
    uid_str += AMcharset[static_cast<size_t>(uid % AMbase)];
    uid /= AMbase;
  }
  std::reverse(uid_str.begin(), uid_str.end());
  return uid_str;
}
*/

namespace {
namespace fs = std::filesystem;
using TraceInfo = AMDomain::client::TraceInfo;
using ConRequest = AMDomain::host::ConRequest;
using ClientProtocol = AMDomain::host::ClientProtocol;
using ClientStatus = AMDomain::client::ClientStatus;
using ClientState = AMDomain::client::ClientState;
using AuthCBInfo = AMDomain::client::AuthCBInfo;
using OS_TYPE = AMDomain::client::OS_TYPE;
using AuthCallback =
    std::function<std::optional<std::string>(const AuthCBInfo &)>;
using RMR = std::vector<std::pair<std::string, ECM>>; // rm func return type
using BR = std::pair<bool, ECM>;                      // is_dir func return type
using SR = std::pair<ECM, PathInfo>;                  // stat func return type
using WRV = std::vector<PathInfo>;                    // iwalk func return type
using CB =
    std::shared_ptr<std::function<void(std::string, std::string, std::string)>>;
using WalkErrorCallback =
    std::shared_ptr<std::function<void(const std::string &, const ECM &)>>;
using WRD =
    std::vector<std::pair<std::vector<std::string>,
                          std::vector<PathInfo>>>; // walk func return type
using WRI = std::pair<WRV, AMFS::WER>;             // iwalk data + errors
using WRDR = std::pair<WRD, AMFS::WER>;            // walk data + errors
using WR = std::pair<ECM, WRI>;                    // iwalk func return type
using SIZER = std::pair<ECM, size_t>;              // getsize func return type
using TraceCallback = std::function<void(const TraceInfo &)>;
using CR =
    std::pair<ECM, std::pair<std::string, int>>; // ConductCmd func return type
} // namespace

/*
class AMTracer : public virtual AMDomain::client::IClientPort {
private:
  using TypeVarStore = std::unordered_map<std::type_index, std::any>;
  using NamedVarStore = std::unordered_map<std::string, std::any>;
  TraceCallback trace_cb;
  std::list<TraceInfo> buffer = {};
  std::mutex buffer_mutex;
  mutable std::shared_mutex var_cache_mtx_;
  TypeVarStore type_var_cache_;
  NamedVarStore named_var_cache_;
  ssize_t capacity = 10;
  std::atomic<bool> is_trace_cb = false;
  std::atomic<bool> is_trace_pause = false;


  std::unordered_map<TraceLevel, std::string> trace_level_str = {
      {TraceLevel::Debug, "🐛"},   {TraceLevel::Info, "ℹ️"},
      {TraceLevel::Warning, "⚠️"},  {TraceLevel::Error, "❌"},
      {TraceLevel::Critical, "☠️"},
  };

  void WriteLog(const TraceInfo &trace_info) {
    std::ofstream file("AMSFTP.log", std::ios::app);
    if (!file.is_open()) {
      return;
    }
    std::string sign;
    if (trace_level_str.find(trace_info.level) != trace_level_str.end()) {
      sign = trace_level_str[trace_info.level];
    } else {
      sign = "ℹ️";
    }
    auto time_now = FormatTime(AMTime::seconds(), "%Y/%m/%d %H:%M:%S");
    auto out = time_now + " " + sign + " " +
               std::string(magic_enum::enum_name(trace_info.level)) + " " +
               std::string(trace_info.message);
    file << out << std::endl;
  }

protected:
using ClientProtocol = AMDomain::host::ClientProtocol;
using ConRequest = AMDomain::host::ConRequest;
ConRequest res_data;
std::string nickname;

void push(const TraceInfo &value) {
  std::lock_guard<std::mutex> lock(buffer_mutex);
  if (buffer.size() >= static_cast<size_t>(capacity)) {
    buffer.pop_front();
  }
  buffer.push_back(value);
}

public:
enum class NamedVarQueryState {
  Found = 0,
  NameNotFound = 1,
  TypeMismatch = 2,
};


[[nodiscard]] bool StoreTypedData(const std::type_index &type_key,
                                  std::any value, bool overwrite = true) {
  std::lock_guard<std::mutex> lock(var_cache_mtx_);
  auto it = type_var_cache_.find(type_key);
  if (it != type_var_cache_.end() && !overwrite) {
    return false;
  }
  type_var_cache_[type_key] = std::move(value);
  return true;
}


[[nodiscard]] std::any *QueryTypedData(const std::type_index &type_key,
                                       bool &type_exists) {
  std::lock_guard<std::mutex> lock(var_cache_mtx_);
  auto it = type_var_cache_.find(type_key);
  type_exists = (it != type_var_cache_.end());
  if (!type_exists) {
    return nullptr;
  }
  return &(it->second);
}


[[nodiscard]] const std::any *QueryTypedData(const std::type_index &type_key,
                                             bool &type_exists) const {
  std::lock_guard<std::mutex> lock(var_cache_mtx_);
  auto it = type_var_cache_.find(type_key);
  type_exists = (it != type_var_cache_.end());
  if (!type_exists) {
    return nullptr;
  }
  return &(it->second);
}


template <typename T>
[[nodiscard]] bool StoreTypedValue(T &&value, bool overwrite = true) {
  using ValueT = std::decay_t<T>;
  static_assert(!std::is_reference_v<ValueT>,
                "StoreTypedValue expects value-like type");
  return StoreTypedData(std::type_index(typeid(ValueT)),
                        std::any(std::forward<T>(value)), overwrite);
}


template <typename T> [[nodiscard]] T *QueryTypedValue() {
  bool type_exists = false;
  return QueryTypedValue<T>(type_exists);
}


template <typename T> [[nodiscard]] T *QueryTypedValue(bool &type_exists) {
  using ValueT = std::remove_cv_t<std::remove_reference_t<T>>;
  std::any *payload =
      QueryTypedData(std::type_index(typeid(ValueT)), type_exists);
  if (!payload) {
    return nullptr;
  }
  return std::any_cast<ValueT>(payload);
}


template <typename T> [[nodiscard]] const T *QueryTypedValue() const {
  bool type_exists = false;
  return QueryTypedValue<T>(type_exists);
}


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


template <typename T>
[[nodiscard]] bool StoreNamedValue(const std::string &name, T &&value,
                                   bool overwrite = true) {
  return StoreNamedData(name, std::any(std::forward<T>(value)), overwrite);
}


[[nodiscard]] std::any *QueryNamedData(const std::string &name,
                                       bool &name_exists) {
  std::lock_guard<std::mutex> lock(var_cache_mtx_);
  auto it = named_var_cache_.find(name);
  name_exists = (it != named_var_cache_.end());
  if (!name_exists) {
    return nullptr;
  }
  return &(it->second);
}


[[nodiscard]] const std::any *QueryNamedData(const std::string &name,
                                             bool &name_exists) const {
  std::lock_guard<std::mutex> lock(var_cache_mtx_);
  auto it = named_var_cache_.find(name);
  name_exists = (it != named_var_cache_.end());
  if (!name_exists) {
    return nullptr;
  }
  return &(it->second);
}


template <typename T>
[[nodiscard]] T *QueryNamedValue(const std::string &name, bool &name_exists) {
  using ValueT = std::remove_cv_t<std::remove_reference_t<T>>;
  std::any *payload = QueryNamedData(name, name_exists);
  if (!payload) {
    return nullptr;
  }
  return std::any_cast<ValueT>(payload);
}


template <typename T>
[[nodiscard]] T *QueryNamedValue(const std::string &name,
                                 NamedVarQueryState *state = nullptr) {
  bool name_exists = false;
  auto *ptr = QueryNamedValue<T>(name, name_exists);
  if (!state) {
    return ptr;
  }
  if (!name_exists) {
    *state = NamedVarQueryState::NameNotFound;
  } else if (!ptr) {
    *state = NamedVarQueryState::TypeMismatch;
  } else {
    *state = NamedVarQueryState::Found;
  }
  return ptr;
}


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


template <typename T>
[[nodiscard]] const T *
QueryNamedValue(const std::string &name,
                NamedVarQueryState *state = nullptr) const {
  bool name_exists = false;
  const T *ptr = QueryNamedValue<T>(name, name_exists);
  if (!state) {
    return ptr;
  }
  if (!name_exists) {
    *state = NamedVarQueryState::NameNotFound;
  } else if (!ptr) {
    *state = NamedVarQueryState::TypeMismatch;
  } else {
    *state = NamedVarQueryState::Found;
  }
  return ptr;
}


[[nodiscard]] bool StoreNamedData(const std::string &name, std::any value,
                                  bool overwrite = true) {
  if (name.empty()) {
    return false;
  }
  std::lock_guard<std::mutex> lock(var_cache_mtx_);
  auto it = named_var_cache_.find(name);
  if (it != named_var_cache_.end() && !overwrite) {
    return false;
  }
  named_var_cache_[name] = std::move(value);
  return true;
}


[[nodiscard]] std::pair<bool, std::any>
QueryNamedData(const std::string &name) const {
  std::lock_guard<std::mutex> lock(var_cache_mtx_);
  auto it = named_var_cache_.find(name);
  if (it == named_var_cache_.end()) {
    return {false, std::any{}};
  }
  return {true, it->second};
}


[[nodiscard]] bool EraseNamedData(const std::string &name) override {
  if (name.empty()) {
    return false;
  }
  std::lock_guard<std::mutex> lock(var_cache_mtx_);
  return named_var_cache_.erase(name) > 0;
}

AMTracer(const ConRequest &request, int buffer_capacity = 10,
         TraceCallback trace_cb = {})
    : trace_cb(std::move(trace_cb)), res_data(request),
      nickname(request.nickname) {
  capacity = buffer_capacity > 0 ? buffer_capacity : 10;
  this->is_trace_cb = static_cast<bool>(this->trace_cb);
}
size_t GetTraceNum() {
  std::lock_guard<std::mutex> lock(buffer_mutex);
  return buffer.size();
}

std::shared_ptr<TraceInfo> LastTrace() {
  std::lock_guard<std::mutex> lock(buffer_mutex);
  if (buffer.empty()) {
    return nullptr;
  }
  return std::make_shared<TraceInfo>(buffer.back());
}

std::vector<TraceInfo> GetAllTraces() {
  std::vector<TraceInfo> result;
  result.reserve(buffer.size());
  for (auto &item : buffer) {
    result.push_back(item);
  }
  return result;
}

void ClearTracer() {
  std::lock_guard<std::mutex> lock(buffer_mutex);
  buffer.clear();
}

size_t TracerCapacity(ssize_t size = 0) {
  if (size <= 0) {
    return capacity;
  }

  if (size > capacity) {
    capacity = size;
    return capacity;
  } else {
    std::lock_guard<std::mutex> lock(buffer_mutex);
    while (buffer.size() > static_cast<size_t>(size)) {
      buffer.pop_front();
    }
    capacity = size;
    return capacity;
  }
}

void trace(TraceLevel level, EC error_code, const std::string &target = "",
           const std::string &action = "", const std::string &msg = "") {
  this->trace(TraceInfo(level, error_code, nickname, target, action, msg,
                        res_data, TraceSource::Client));
}

void trace(const TraceInfo &trace_info) {
  if (is_trace_pause.load(std::memory_order_relaxed)) {
    return;
  }
  this->push(trace_info);
  if (is_trace_cb.load(std::memory_order_relaxed)) {
    CallCallbackSafe(trace_cb, trace_info);
  }
}

void SetTraceState(bool is_pause) {
  is_trace_pause.store(is_pause, std::memory_order_relaxed);
}

void SetTraceCallback(TraceCallback trace = {}) {
  trace_cb = std::move(trace);
  is_trace_cb.store(static_cast<bool>(trace_cb), std::memory_order_relaxed);
}

[[nodiscard]] const std::string &GetNickname() const {
  return res_data.nickname;
}

[[nodiscard]] const ConRequest &GetRequest() const { return res_data; }
}
;
class ClientTracer {
private:
  TraceCallback trace_cb_;
  std::list<TraceInfo> buffer_;
  std::mutex buffer_mutex_;
  ssize_t capacity_ = 10;
  std::atomic<bool> trace_enabled_ = false;
  std::atomic<bool> is_trace_pause_ = false;

public:
  explicit ClientTracer(int buffer_capacity = 10, TraceCallback trace_cb = {})
      : trace_cb_(std::move(trace_cb)) {
    capacity_ = buffer_capacity > 0 ? buffer_capacity : 10;
    trace_enabled_.store(static_cast<bool>(trace_cb_),
                         std::memory_order_relaxed);
  }

  void Trace(const TraceInfo &trace_info) {
    if (is_trace_pause_.load(std::memory_order_relaxed)) {
      return;
    }
    {
      std::lock_guard<std::mutex> lock(buffer_mutex_);
      if (buffer_.size() >= static_cast<size_t>(capacity_)) {
        buffer_.pop_front();
      }
      buffer_.push_back(trace_info);
    }
    if (trace_enabled_.load(std::memory_order_relaxed)) {
      CallCallbackSafe(trace_cb_, trace_info);
    }
  }

  void SetTraceState(bool is_pause) {
    is_trace_pause_.store(is_pause, std::memory_order_relaxed);
  }

  void SetTraceCallback(TraceCallback trace = {}) {
    trace_cb_ = std::move(trace);
    trace_enabled_.store(static_cast<bool>(trace_cb_),
                         std::memory_order_relaxed);
  }

  size_t GetTraceNum() {
    std::lock_guard<std::mutex> lock(buffer_mutex_);
    return buffer_.size();
  }

  std::shared_ptr<TraceInfo> LastTrace() {
    std::lock_guard<std::mutex> lock(buffer_mutex_);
    if (buffer_.empty()) {
      return nullptr;
    }
    return std::make_shared<TraceInfo>(buffer_.back());
  }

  std::vector<TraceInfo> GetAllTraces() {
    std::lock_guard<std::mutex> lock(buffer_mutex_);
    std::vector<TraceInfo> out;
    out.reserve(buffer_.size());
    for (const auto &item : buffer_) {
      out.push_back(item);
    }
    return out;
  }

  void ClearTracer() {
    std::lock_guard<std::mutex> lock(buffer_mutex_);
    buffer_.clear();
  }
};
 */

/*
class BaseClient : public BasePathMatch {
private:
  static std::string GenerateUID() {
    static std::mutex uid_mtx;
    static size_t seed = 0;
    std::lock_guard<std::mutex> lock(uid_mtx);
    return std::to_string(seed++);
  }

  ClientMetaDataStore metadata_part_;
  ClientControl control_part_;
  ClientConfigStore config_part_;
  AMAtomic<TraceCallback> trace_callback_;
  AMAtomic<AuthCallback> auth_callback_;
  ClientIOBase *io_part_ = nullptr;

protected:
  ECM state = {EC::NoConnection, "Client Not Initialized"};
  mutable std::mutex state_mtx;
  OS_TYPE os_type = OS_TYPE::Uncertain;
  std::string home_dir;
  ConRequest res_data;
  std::string nickname;

  void SetState(const ECM &state_in) {
    {
      std::lock_guard<std::mutex> lock(state_mtx);
      state = state_in;
    }
    config_part_.SetState(state_in);
  }

public:
  std::string uid;
  std::recursive_mutex mtx;

  ~BaseClient() = default;

  BaseClient(const ConRequest &request,
             [[maybe_unused]] int buffer_capacity = 10,
             TraceCallback trace_cb = {}, AuthCallback auth_cb = {})
      : metadata_part_(), control_part_(), config_part_(request),
        trace_callback_(), auth_callback_(), io_part_(nullptr),
        res_data(request), nickname(request.nickname) {
    uid = GenerateUID();
    res_data = config_part_.GetRequest();
    nickname = res_data.nickname;
    state = config_part_.GetState();
    os_type = config_part_.GetOSType();
    home_dir = config_part_.GetHomeDir();
    RegisterTraceCallback(std::move(trace_cb));
    RegisterAuthCallback(std::move(auth_cb));
  }

  void BindIOPort(ClientIOBase &io_part) {
    io_part_ = &io_part;
    {
      auto trace = trace_callback_.lock();
      io_part_->RegisterTraceCallback(trace.load());
    }
    {
      auto auth_cb = auth_callback_.lock();
      io_part_->RegisterAuthCallback(auth_cb.load());
    }
  }

  void RegisterTraceCallback(TraceCallback cb) {
    {
      auto trace = trace_callback_.lock();
      trace.store(cb);
    }
    if (io_part_ != nullptr) {
      io_part_->RegisterTraceCallback(std::move(cb));
    }
  }

  void UnregisterTraceCallback() {
    {
      auto trace = trace_callback_.lock();
      trace.store(TraceCallback{});
    }
    if (io_part_ != nullptr) {
      io_part_->UnregisterTraceCallback();
    }
  }

  void RegisterAuthCallback(AuthCallback cb) {
    {
      auto auth_cb = auth_callback_.lock();
      auth_cb.store(cb);
    }
    if (io_part_ != nullptr) {
      io_part_->RegisterAuthCallback(std::move(cb));
    }
  }

  void UnregisterAuthCallback() {
    {
      auto auth_cb = auth_callback_.lock();
      auth_cb.store(AuthCallback{});
    }
    if (io_part_ != nullptr) {
      io_part_->UnregisterAuthCallback();
    }
  }

  std::string GetUID() override { return uid; }
  [[nodiscard]] const std::string &GetNickname() const override {
    return nickname;
  }
  [[nodiscard]] const ConRequest &GetRequest() const override {
    return res_data;
  }
  [[nodiscard]] ClientProtocol GetProtocol() const override {
    return res_data.protocol;
  }

  bool StoreNamedData(const std::string &name, std::any value,
                      bool overwrite = true) override {
    return metadata_part_.StoreNamedData(name, std::move(value), overwrite);
  }

  bool StoreTypedData(const std::type_index &type_key, std::any value,
                      bool overwrite = true) override {
    return metadata_part_.StoreTypedData(type_key, std::move(value), overwrite);
  }

  [[nodiscard]] std::pair<bool, std::any>
  QueryNamedData(const std::string &name) const override {
    return metadata_part_.QueryNamedData(name);
  }

  [[nodiscard]] std::any *QueryNamedData(const std::string &name,
                                         bool &name_exists) override {
    return metadata_part_.QueryNamedData(name, name_exists);
  }

  [[nodiscard]] const std::any *
  QueryNamedData(const std::string &name, bool &name_exists) const override {
    return metadata_part_.QueryNamedData(name, name_exists);
  }

  [[nodiscard]] std::any *QueryTypedData(const std::type_index &type_key,
                                         bool &type_exists) override {
    return metadata_part_.QueryTypedData(type_key, type_exists);
  }

  [[nodiscard]] const std::any *
  QueryTypedData(const std::type_index &type_key,
                 bool &type_exists) const override {
    return metadata_part_.QueryTypedData(type_key, type_exists);
  }

  bool EraseNamedData(const std::string &name) override {
    return metadata_part_.EraseNamedData(name);
  }

  void RequestInterrupt() override { control_part_.RequestInterrupt(); }
  void ClearInterrupt() override { control_part_.ClearInterrupt(); }
  void ResetInterrupt() { control_part_.ClearInterrupt(); }
  [[nodiscard]] bool IsInterrupted() const override {
    return control_part_.IsInterrupted();
  }

protected:
  [[nodiscard]] bool
  IsOperationInterrupted_(const amf &interrupt_flag = nullptr) const {
    if (interrupt_flag && !interrupt_flag->IsRunning()) {
      return true;
    }
    return control_part_.IsInterrupted();
  }

  size_t RegisterInterruptWakeup_(std::function<void()> wake_cb) {
    return control_part_.RegisterWakeup(std::move(wake_cb));
  }

  size_t RegisterInterruptWakeup_(const amf &interrupt_flag,
                                  std::function<void()> wake_cb) {
    if (interrupt_flag) {
      return interrupt_flag->RegisterWakeup(std::move(wake_cb));
    }
    return control_part_.RegisterWakeup(std::move(wake_cb));
  }

  void UnregisterInterruptWakeup_(size_t token) {
    control_part_.UnregisterWakeup(token);
  }

  void UnregisterInterruptWakeup_(const amf &interrupt_flag, size_t token) {
    if (token == 0) {
      return;
    }
    if (interrupt_flag) {
      interrupt_flag->UnregisterWakeup(token);
      return;
    }
    control_part_.UnregisterWakeup(token);
  }

public:
  ssize_t TransferRingBufferSize(ssize_t buffer_size = -1) {
    if (buffer_size <= 0) {
      return res_data.buffer_size;
    }
    res_data.buffer_size = buffer_size;
    {
      auto req = config_part_.RequestAtomic().lock();
      req->buffer_size = buffer_size;
    }
    return res_data.buffer_size;
  }

  std::variant<ECM, std::string> TrashDir(const std::string &trash_dir = "",
                                          int timeout_ms = -1,
                                          int64_t start_time = -1) {
    if (trash_dir.empty()) {
      return res_data.trash_dir;
    }
    ECM rcm = mkdirs(trash_dir, nullptr, timeout_ms, start_time);
    if (rcm.first == EC::Success) {
      res_data.trash_dir = trash_dir;
      {
        auto req = config_part_.RequestAtomic().lock();
        req->trash_dir = trash_dir;
      }
    }
    return rcm;
  }

  ECM GetState() const override {
    std::lock_guard<std::mutex> lock(state_mtx);
    return state;
  }

  ECM move(const std::string &src, const std::string &dst,
           bool need_mkdir = false, bool force_write = false,
           amf interrupt_flag = nullptr, int timeout_ms = -1,
           int64_t start_time = -1) {
    return rename(src, AMPathStr::join(dst, AMPathStr::basename(src)),
                  need_mkdir, force_write, interrupt_flag, timeout_ms,
                  start_time);
  }

  int64_t getsize(const std::string &path, bool ignore_sepcial_file = true,
                  amf interrupt_flag = nullptr, int timeout_ms = -1,
                  int64_t start_time = -1) override {
    auto [rcm, pack] = iwalk(path, true, ignore_sepcial_file, nullptr,
                             interrupt_flag, timeout_ms, start_time);
    if (rcm.first != EC::Success || IsOperationInterrupted_(interrupt_flag)) {
      return -1;
    }
    int64_t size = 0;
    for (auto &item : pack.first) {
      size += static_cast<int64_t>(item.size);
    }
    return size;
  }

  std::vector<PathInfo> find(const std::string &path,
                             SearchType type = SearchType::All,
                             amf interrupt_flag = nullptr, int timeout_ms = -1,
                             int64_t start_time = -1) override {
    if (IsOperationInterrupted_(interrupt_flag)) {
      return {};
    }
    return BasePathMatch::find(path, type, timeout_ms, start_time);
  }

  void trace(TraceLevel level, EC error_code, const std::string &target = "",
             const std::string &action = "", const std::string &msg = "") {
    trace(TraceInfo(level, error_code, nickname, target, action, msg, res_data,
                    TraceSource::Client));
  }

  void trace(const TraceInfo &trace_info) {
    if (io_part_ != nullptr) {
      io_part_->trace(trace_info);
      return;
    }
    TraceCallback cb;
    {
      auto trace_cb = trace_callback_.lock();
      cb = trace_cb.load();
    }
    if (cb) {
      (void)CallCallbackSafe(cb, trace_info);
    }
  }

  [[nodiscard]] std::optional<std::string> auth(const AuthCBInfo &auth_info) {
    if (io_part_ != nullptr) {
      return io_part_->auth(auth_info);
    }
    AuthCallback cb;
    {
      auto auth_cb = auth_callback_.lock();
      cb = auth_cb.load();
    }
    auto [res, _] =
        CallCallbackSafeRet<std::optional<std::string>>(cb, auth_info);
    return res;
  }

  void SetTraceState(bool is_pause) {
    if (is_pause) {
      UnregisterTraceCallback();
    }
  }

  void SetTraceCallback(TraceCallback trace_cb = {}) {
    if (!trace_cb) {
      UnregisterTraceCallback();
      return;
    }
    RegisterTraceCallback(std::move(trace_cb));
  }

  virtual ECM Check(amf interrupt_flag = nullptr, int timeout_ms = -1,
                    int64_t start_time = -1) = 0;
  virtual ECM Connect(bool force = false, amf interrupt_flag = nullptr,
                      int timeout_ms = -1, int64_t start_time = -1) = 0;
  OS_TYPE GetOSType([[maybe_unused]] bool update = false) override = 0;

  virtual double GetRTT([[maybe_unused]] ssize_t times = 5,
                        [[maybe_unused]] amf interrupt_flag = nullptr) {
    return -1.0;
  }

  virtual CR ConductCmd([[maybe_unused]] const std::string &cmd,
                        [[maybe_unused]] int max_time_ms = 3000,
                        [[maybe_unused]] amf interrupt_flag = nullptr) {
    return {{EC::OperationUnsupported, "ConductCmd not supported"}, {"", -1}};
  }

  std::string GetHomeDir() override = 0;

  virtual std::pair<ECM, std::string>
  realpath([[maybe_unused]] const std::string &path,
           [[maybe_unused]] amf interrupt_flag = nullptr,
           [[maybe_unused]] int timeout_ms = -1,
           [[maybe_unused]] int64_t start_time = -1) {
    return {{EC::OperationUnsupported, "realpath not supported"}, ""};
  }

  virtual std::pair<ECM, std::unordered_map<std::string, ECM>>
  chmod([[maybe_unused]] const std::string &path,
        [[maybe_unused]] std::variant<std::string, size_t> mode,
        [[maybe_unused]] bool recursive = false,
        [[maybe_unused]] amf interrupt_flag = nullptr,
        [[maybe_unused]] int timeout_ms = -1,
        [[maybe_unused]] int64_t start_time = -1) {
    return {{EC::OperationUnsupported, "chmod not supported"}, {}};
  }

  virtual SR stat(const std::string &path, bool trace_link = false,
                  amf interrupt_flag = nullptr, int timeout_ms = -1,
                  int64_t start_time = -1) = 0;

  virtual std::pair<ECM, std::vector<PathInfo>>
  listdir(const std::string &path, amf interrupt_flag = nullptr,
          int timeout_ms = -1, int64_t start_time = -1) = 0;

  virtual ECM mkdir(const std::string &path, amf interrupt_flag = nullptr,
                    int timeout_ms = -1, int64_t start_time = -1) = 0;

  virtual ECM mkdirs(const std::string &path, amf interrupt_flag = nullptr,
                     int timeout_ms = -1, int64_t start_time = -1) = 0;

  virtual ECM rmdir(const std::string &path, amf interrupt_flag = nullptr,
                    int timeout_ms = -1, int64_t start_time = -1) = 0;

  virtual ECM rmfile(const std::string &path, amf interrupt_flag = nullptr,
                     int timeout_ms = -1, int64_t start_time = -1) = 0;

  virtual ECM rename(const std::string &src, const std::string &dst,
                     bool mkdir = true, bool overwrite = false,
                     amf interrupt_flag = nullptr, int timeout_ms = -1,
                     int64_t start_time = -1) = 0;

  virtual std::pair<ECM, RMR> remove(const std::string &path,
                                     WalkErrorCallback error_callback = nullptr,
                                     amf interrupt_flag = nullptr,
                                     int timeout_ms = -1,
                                     int64_t start_time = -1) = 0;

  virtual ECM saferm([[maybe_unused]] const std::string &path,
                     [[maybe_unused]] amf interrupt_flag = nullptr,
                     [[maybe_unused]] int timeout_ms = -1,
                     [[maybe_unused]] int64_t start_time = -1) {
    return {EC::OperationUnsupported, "saferm not supported"};
  }

  virtual ECM copy([[maybe_unused]] const std::string &src,
                   [[maybe_unused]] const std::string &dst,
                   [[maybe_unused]] bool need_mkdir = false,
                   [[maybe_unused]] int timeout_ms = -1,
                   [[maybe_unused]] amf interrupt_flag = nullptr) {
    return {EC::OperationUnsupported, "copy not supported"};
  }

  virtual std::pair<ECM, WRI> iwalk(const std::string &path,
                                    bool show_all = false,
                                    bool ignore_special_file = true,
                                    WalkErrorCallback error_callback = nullptr,
                                    amf interrupt_flag = nullptr,
                                    int timeout_ms = -1,
                                    int64_t start_time = -1) = 0;

  virtual std::pair<ECM, WRDR>
  walk(const std::string &path, int max_depth = -1, bool show_all = false,
       bool ignore_special_file = false,
       WalkErrorCallback error_callback = nullptr, amf interrupt_flag = nullptr,
       int timeout_ms = -1, int64_t start_time = -1) = 0;
};
*/

/**
 * @brief BaseClient-local interrupt token independent from TaskControlToken.
 *
 * This token is intentionally minimal: interrupt/reset state and wakeup
 * callback registration for breaking blocking waits.
 */
class ClientControlToken {
public:
  /**
   * @brief Return true when no interruption is requested.
   */
  [[nodiscard]] bool IsRunning() const {
    return !interrupted_.load(std::memory_order_acquire);
  }

  /**
   * @brief Return true when interruption is requested.
   */
  [[nodiscard]] bool IsInterrupted() const {
    return interrupted_.load(std::memory_order_acquire);
  }

  /**
   * @brief Request interruption and wake all registered waiters.
   */
  bool Interrupt() {
    const bool already = interrupted_.exchange(true, std::memory_order_acq_rel);
    if (already) {
      return false;
    }
    NotifyWakeups_();
    return true;
  }

  /**
   * @brief Clear interruption state.
   */
  bool Reset() {
    const bool changed =
        interrupted_.exchange(false, std::memory_order_acq_rel);
    return changed;
  }

  /**
   * @brief Register a wakeup callback invoked on interruption.
   *
   * @return Callback id, 0 on invalid callback.
   */
  size_t RegisterWakeup(std::function<void()> wake_cb) {
    if (!wake_cb) {
      return 0;
    }
    const size_t id = wake_seed_.fetch_add(1, std::memory_order_relaxed);
    {
      std::lock_guard<std::mutex> lock(wake_mtx_);
      wakeups_[id] = std::move(wake_cb);
    }
    if (IsInterrupted()) {
      std::function<void()> callback;
      {
        std::lock_guard<std::mutex> lock(wake_mtx_);
        auto it = wakeups_.find(id);
        if (it != wakeups_.end()) {
          callback = it->second;
        }
      }
      if (callback) {
        callback();
      }
    }
    return id;
  }

  /**
   * @brief Unregister wakeup callback by id.
   */
  void UnregisterWakeup(size_t id) {
    if (id == 0) {
      return;
    }
    std::lock_guard<std::mutex> lock(wake_mtx_);
    wakeups_.erase(id);
  }

private:
  void NotifyWakeups_() {
    std::vector<std::function<void()>> callbacks;
    {
      std::lock_guard<std::mutex> lock(wake_mtx_);
      callbacks.reserve(wakeups_.size());
      for (const auto &[_, cb] : wakeups_) {
        if (cb) {
          callbacks.push_back(cb);
        }
      }
    }
    for (auto &cb : callbacks) {
      cb();
    }
  }

  std::atomic<bool> interrupted_{false};
  std::atomic<size_t> wake_seed_{1};
  mutable std::mutex wake_mtx_;
  std::unordered_map<size_t, std::function<void()>> wakeups_;
};

class SafeChannel {
public:
  LIBSSH2_CHANNEL *channel = nullptr;
  bool closed = false; // Mark whether it has been closed normally
  bool is_init = false;
  amf init_interrupt_flag = nullptr;
  int64_t init_start_time = -1;
  int init_timeout_ms = -1;

private:
  /**
   * @brief Persist initialization context used by retryable operations.
   */
  void StoreInitContext_(amf interrupt_flag, int timeout_ms,
                         int64_t start_time) {
    init_interrupt_flag = interrupt_flag;
    init_timeout_ms = timeout_ms;
    init_start_time = start_time == -1 ? AMTime::miliseconds() : start_time;
  }

  /**
   * @brief Check interruption/timeout state for retry operations.
   */
  ECM CheckControlState_(const std::string &action) const {
    if (init_interrupt_flag && !init_interrupt_flag->IsRunning()) {
      return {EC::Terminate, AMStr::fmt("{} interrupted", action)};
    }
    if (init_timeout_ms >= 0 && init_start_time >= 0 &&
        (AMTime::miliseconds() - init_start_time) >= init_timeout_ms) {
      return {EC::OperationTimeout, AMStr::fmt("{} timed out", action)};
    }
    return {EC::Success, ""};
  }

public:
  ~SafeChannel() {
    if (channel) {
      if (!closed) {
        // Best-effort graceful stop before releasing the channel handle.
        (void)graceful_exit(true, 50, true);
      }
      libssh2_channel_free(channel);
      channel = nullptr;
    }
    is_init = false;
  }

  // Close channel normally (blocking mode)
  // Return true on success, false on failure
  bool close() {
    if (!channel || closed) {
      is_init = false;
      return closed;
    }
    if (libssh2_channel_close(channel) == 0 &&
        libssh2_channel_wait_closed(channel) == 0) {
      closed = true;
      is_init = false;
    }
    return closed;
  }

  // Send exit signal (do not wait for close)
  void request_exit() {
    if (!channel) {
      return;
    }
    libssh2_channel_send_eof(channel);
    libssh2_channel_signal(channel, "TERM");
  }

  // Non-blocking close; use with wait_for_socket
  // Return values: 0=success, EAGAIN=wait required, <0=error
  int close_nonblock() {
    if (!channel)
      return -1;
    if (closed)
      return 0;

    int rc = libssh2_channel_close(channel);
    if (rc == 0) {
      rc = libssh2_channel_wait_closed(channel);
      if (rc == 0) {
        closed = true;
        is_init = false;
      }
    }
    return rc;
  }

  SafeChannel() = default;

  /**
   * @brief Construct with an existing channel and operation context.
   */
  explicit SafeChannel(LIBSSH2_CHANNEL *existing_channel,
                       amf interrupt_flag = nullptr, int timeout_ms = -1,
                       int64_t start_time = -1) {
    channel = existing_channel;
    closed = false;
    is_init = existing_channel != nullptr;
    StoreInitContext_(interrupt_flag, timeout_ms, start_time);
  }

  /**
   * @brief Initialize SSH channel with retry support in non-blocking sessions.
   *
   * @param session Active libssh2 session.
   * @param interrupt_flag Optional interruption flag.
   * @param timeout_ms Timeout in milliseconds; negative waits forever.
   * @param start_time Start timestamp for timeout budget; -1 uses now.
   * @return ECM status describing initialization result.
   */
  ECM Init(LIBSSH2_SESSION *session, amf interrupt_flag = nullptr,
           int timeout_ms = -1, int64_t start_time = -1) {
    StoreInitContext_(interrupt_flag, timeout_ms, start_time);
    if (!session) {
      is_init = false;
      return {EC::NoSession, "Session is null"};
    }
    if (channel) {
      if (!closed) {
        (void)graceful_exit(true, 50, true);
      }
      libssh2_channel_free(channel);
      channel = nullptr;
      closed = false;
      is_init = false;
    }

    while (true) {
      ECM control_retry = CheckControlState_("Channel init");
      if (control_retry.first != EC::Success) {
        is_init = false;
        return control_retry;
      }

      channel =
          libssh2_channel_open_ex(session, "session", sizeof("session") - 1,
                                  4 * AMMB, 32 * AMKB, nullptr, 0);
      if (channel) {
        closed = false;
        is_init = true;
        return {EC::Success, ""};
      }

      const int err = libssh2_session_last_errno(session);
      if (err != LIBSSH2_ERROR_EAGAIN) {
        is_init = false;
        return {EC::NoConnection,
                AMStr::fmt("Channel init failed with libssh2 error {}", err)};
      }
      ECM control = CheckControlState_("Channel init");
      if (control.first != EC::Success) {
        is_init = false;
        return control;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
  }

  /**
   * @brief Gracefully terminate a running channel and close it.
   *
   * @param send_exit Whether to send EOF/TERM before closing.
   * @param term_wait_ms Delay after TERM signal before close attempts.
   * @param force_kill Whether to send KILL if close fails after TERM.
   * @return ECM status describing exit result.
   */
  ECM graceful_exit(bool send_exit = true, int term_wait_ms = 50,
                    bool force_kill = true) {
    if (!channel || closed) {
      is_init = false;
      return {EC::Success, ""};
    }

    auto run_nonblocking_op = [&](auto &&op, const std::string &action) -> ECM {
      while (true) {
        const int rc = op();
        if (rc == 0) {
          return {EC::Success, ""};
        }
        if (rc != LIBSSH2_ERROR_EAGAIN) {
          return {EC::NoConnection,
                  AMStr::fmt("{} failed with libssh2 error {}", action, rc)};
        }
        ECM control = CheckControlState_(action);
        if (control.first != EC::Success) {
          return control;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
      }
    };

    if (send_exit) {
      ECM eof_rcm = run_nonblocking_op(
          [this]() { return libssh2_channel_send_eof(channel); },
          "channel send eof");
      if (eof_rcm.first != EC::Success && eof_rcm.first != EC::Terminate &&
          eof_rcm.first != EC::OperationTimeout) {
        return eof_rcm;
      }

      ECM term_rcm = run_nonblocking_op(
          [this]() { return libssh2_channel_signal(channel, "TERM"); },
          "channel signal TERM");
      if (term_rcm.first != EC::Success && term_rcm.first != EC::Terminate &&
          term_rcm.first != EC::OperationTimeout) {
        return term_rcm;
      }

      if (term_wait_ms > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(term_wait_ms));
      }
    }

    ECM close_rcm = run_nonblocking_op([this]() { return close_nonblock(); },
                                       "channel close");
    if (close_rcm.first == EC::Success) {
      return close_rcm;
    }

    if (force_kill && send_exit && channel && !closed) {
      (void)run_nonblocking_op(
          [this]() { return libssh2_channel_signal(channel, "KILL"); },
          "channel signal KILL");
      close_rcm = run_nonblocking_op([this]() { return close_nonblock(); },
                                     "channel close");
    }
    return close_rcm;
  }
};

class BasePathMatch {
protected:
  /**
   * @brief Return true when current client operation is interrupted.
   */
  [[nodiscard]] virtual bool IsInterrupted() const = 0;
  [[nodiscard]] virtual SR stat(const std::string &path,
                                bool trace_link = false, int timeout_ms = -1,
                                int64_t start_time = -1) = 0;
  [[nodiscard]] virtual std::pair<ECM, WRV>
  listdir(const std::string &path, int timeout_ms = -1,
          int64_t start_time = -1) const = 0;
  [[nodiscard]] virtual std::pair<ECM, WRI>
  iwalk(const std::string &path, bool show_all = false,
        bool ignore_special_file = true,
        AMFS::WalkErrorCallback error_callback = nullptr, int timeout_ms = -1,
        int64_t start_time = -1) const = 0;

private:
  void _find(std::vector<PathInfo> &results, const PathInfo &path,
             const std::vector<std::string> &match_parts,
             const SearchType &type, const std::string &sep,
             int timeout_ms = -1, int64_t start_time = -1) {
    if (match_parts.empty()) {
      if (type == SearchType::All ||
          (type == SearchType::Directory && path.type == PathType::DIR) ||
          (type == SearchType::File && path.type == PathType::FILE)) {
        results.push_back(path);
      }
      return;
    }

    if (path.type != PathType::DIR) {
      // Current path is already a file; cannot continue matching
      return;
    }

    std::string cur_pattern = match_parts[0];

    if (std::regex_search(cur_pattern, std::regex("^\\*\\*+$"))) {
      std::vector<std::string> relative_parts;
      auto [error, sub_pack] =
          iwalk(path.path, true, true, nullptr, timeout_ms, start_time);
      if (error.first != EC::Success) {
        return;
      }
      for (auto &sub : sub_pack.first) {
        if (IsInterrupted()) {
          return;
        }
        if (timeout_ms > 0 &&
            AMTime::miliseconds() - start_time >= timeout_ms) {
          return;
        }
        if ((sub.type == PathType::DIR && type == SearchType::File) ||
            (sub.type != PathType::DIR && type == SearchType::Directory)) {
          continue;
        }
        // sub.path relative to path.path
        relative_parts = AMPathStr::split(sub.path.substr(path.path.size()));
        if (walk_match(relative_parts, match_parts)) {
          results.push_back(sub);
        }
      }
      return;
    }
    // Handle non-matching mode
    else if (cur_pattern.find("*") == std::string::npos &&
             (cur_pattern.find("<") == std::string::npos ||
              cur_pattern.find(">") == std::string::npos)) {
      auto new_parts2 = match_parts;
      new_parts2.erase(new_parts2.begin());
      auto [error2, sub_list2] = listdir(path.path, timeout_ms, start_time);
      if (error2.first != EC::Success) {
        return;
      }
      for (auto &sub : sub_list2) {
        if (IsInterrupted()) {
          return;
        }
        if (timeout_ms > 0 &&
            AMTime::miliseconds() - start_time >= timeout_ms) {
          return;
        }
        if (sub.name == cur_pattern) {
          _find(results, sub, new_parts2, type, sep, timeout_ms, start_time);
        }
      }
    }
    // Enter matching mode
    else {
      auto new_parts3 = match_parts;
      new_parts3.erase(new_parts3.begin());
      auto [error3, sub_list3] = listdir(path.path, timeout_ms, start_time);
      if (error3.first != EC::Success) {
        return;
      }
      for (auto &sub : sub_list3) {
        if (IsInterrupted()) {
          return;
        }
        if (timeout_ms > 0 &&
            AMTime::miliseconds() - start_time >= timeout_ms) {
          return;
        }
        if (name_match(sub.name, cur_pattern)) {
          _find(results, sub, new_parts3, type, sep);
        }
      }
    }

    return;
  }

  std::string _rep(const std::string &str, const std::string &from,
                   const std::string &to) {
    std::string result = str;
    if (from.empty())
      return result; // Avoid infinite loop caused by empty string
    size_t pos = 0;
    while ((pos = result.find(from, pos)) != std::string::npos) {
      result.replace(pos, from.length(), to);
      pos += to.length(); // Skip replaced content to prevent repeated
                          // replacement (e.g. from is a substring of to)
    }
    return result;
  }

  bool str_match(const std::string &name, const std::string &pattern) {
    std::string patternf = "^" + pattern + "$";
    std::wstring w_pattern = AMStr::wstr(patternf);
    std::wstring w_name = AMStr::wstr(name);
    try {
      bool res = std::regex_search(w_name, std::wregex(w_pattern));
      return res;
    } catch (const std::regex_error) {
      return false;
    }
  }

  bool name_match(const std::string &name, const std::string &pattern) {
    // Replace * in pattern with star_rep, < with less_rep, and > with
    // greater_rep
    static const std::string star_rep = "XKSOX1S";
    static const std::string less_rep = "SORBVs8";
    static const std::string greater_rep = "YNBSkdu8";

    std::string pattern_new = pattern;
    pattern_new = _rep(pattern_new, "*", star_rep);
    pattern_new = _rep(pattern_new, "<", less_rep);
    pattern_new = _rep(pattern_new, ">", greater_rep);
    pattern_new = AMPathStr::RegexEscape(pattern_new);
    // Replace star_rep in path with .*, less_rep with [, and greater_rep with
    // ]; do not use regex replacement
    pattern_new = _rep(pattern_new, star_rep, ".*");
    pattern_new = _rep(pattern_new, less_rep, "[");
    pattern_new = _rep(pattern_new, greater_rep, "]");
    return str_match(name, pattern_new);
  };

  bool walk_match(const std::vector<std::string> &parts,
                  const std::vector<std::string> &match_parts) {
    if (match_parts.size() > parts.size()) {
      return false;
    }
    size_t pos = 0;
    bool is_match;
    for (auto &part : match_parts) {
      is_match = false;
      for (size_t i = pos; i < parts.size(); i++) {
        if (name_match(parts[i], part)) {
          is_match = true;
          pos = i + 1;
          break;
        }
      }
      if (!is_match) {
        return false;
      }
    }
    return true;
  }

public:
  std::vector<PathInfo> find(const std::string &path,
                             SearchType type = SearchType::All,
                             int timeout_ms = -1, int64_t start_time = -1) {
    std::vector<PathInfo> results = {};
    auto parts = AMPathStr::split(path);
    if (parts.empty()) {
      return results;
    } else if (parts.size() == 1) {
      auto [error, info] = stat(parts[0], false, timeout_ms, start_time);
      if (error.first != EC::Success) {
        return {};
      }
      if (error.first == EC::Success &&
          (type == SearchType::All ||
           (type == SearchType::Directory && info.type == PathType::DIR) ||
           (type == SearchType::File && info.type == PathType::FILE))) {
        results.push_back(info);
      }
      return results;
    }

    std::string sep = AMPathStr::GetPathSep(path);
    std::string cur_path = parts[0];
    bool is_stop = false;
    std::vector<std::string> match_parts = {};

    for (size_t i = 1; i < parts.size(); i++) {
      // When there is no * < >, join with cur_path
      if (parts[i].find("*") == std::string::npos &&
          parts[i].find("<") == std::string::npos &&
          parts[i].find(">") == std::string::npos && !is_stop) {
        cur_path = AMPathStr::join(cur_path, parts[i]);
      } else {
        is_stop = true;
        match_parts.push_back(parts[i]);
      }
    }

    // Check whether cur_path exists
    auto [error, info] = stat(cur_path, false, timeout_ms, start_time);
    if (error.first != EC::Success) {
      return {};
    }
    _find(results, info, match_parts, type, sep, timeout_ms, start_time);
    return results;
  }
};

class ClientMetaDataStore : public AMDomain::client::IClientMetaDataPort {
private:
  using TypeVarStore = std::unordered_map<std::type_index, std::any>;
  using NamedVarStore = std::unordered_map<std::string, std::any>;
  mutable std::shared_mutex var_cache_mtx_;
  TypeVarStore type_var_cache_;
  NamedVarStore named_var_cache_;

public:
  [[nodiscard]] std::shared_mutex &Mutex() const override {
    return var_cache_mtx_;
  }

  bool StoreTypedData(const std::type_index &type_key, std::any value,
                      bool overwrite = true) override {
    auto it = type_var_cache_.find(type_key);
    if (it != type_var_cache_.end() && !overwrite) {
      return false;
    }
    type_var_cache_[type_key] = std::move(value);
    return true;
  }

  std::any *QueryTypedData(const std::type_index &type_key,
                           bool &type_exists) override {
    auto it = type_var_cache_.find(type_key);
    type_exists = (it != type_var_cache_.end());
    return type_exists ? &(it->second) : nullptr;
  }

  const std::any *QueryTypedData(const std::type_index &type_key,
                                 bool &type_exists) const override {
    auto it = type_var_cache_.find(type_key);
    type_exists = (it != type_var_cache_.end());
    return type_exists ? &(it->second) : nullptr;
  }

  bool StoreNamedData(const std::string &name, std::any value,
                      bool overwrite = true) override {
    if (name.empty()) {
      return false;
    }
    auto it = named_var_cache_.find(name);
    if (it != named_var_cache_.end() && !overwrite) {
      return false;
    }
    named_var_cache_[name] = std::move(value);
    return true;
  }

  std::pair<bool, std::any>
  QueryNamedData(const std::string &name) const override {
    auto it = named_var_cache_.find(name);
    if (it == named_var_cache_.end()) {
      return {false, std::any{}};
    }
    return {true, it->second};
  }

  std::any *QueryNamedData(const std::string &name,
                           bool &name_exists) override {
    auto it = named_var_cache_.find(name);
    name_exists = (it != named_var_cache_.end());
    return name_exists ? &(it->second) : nullptr;
  }

  const std::any *QueryNamedData(const std::string &name,
                                 bool &name_exists) const override {
    auto it = named_var_cache_.find(name);
    name_exists = (it != named_var_cache_.end());
    return name_exists ? &(it->second) : nullptr;
  }

  bool EraseNamedData(const std::string &name) override {
    if (name.empty()) {
      return false;
    }
    return named_var_cache_.erase(name) > 0;
  }
};

class ClientConfigStore : public AMDomain::client::IClientConfigPort {
private:
  mutable AMAtomic<ConRequest> request_;
  mutable AMAtomic<ClientState> state_;
  std::atomic<OS_TYPE> os_type_{OS_TYPE::Uncertain};
  mutable AMAtomic<std::string> home_dir_;

public:
  explicit ClientConfigStore(ConRequest request)
      : request_(std::move(request)),
        state_(ClientState{ClientStatus::NotInitialized,
                           ECM{EC::NotInitialized, "Client Not Initialized"}}),
        home_dir_(std::string{}) {}

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

  [[nodiscard]] ClientState GetState() const override {
    auto st = state_.lock();
    return st.load();
  }

  void SetState(const ClientState &state) override {
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

class ClientControl : public AMDomain::client::IClientTaskControlPort {
private:
  ClientControlToken client_interrupt_token_;

public:
  void RequestInterrupt() override {
    (void)client_interrupt_token_.Interrupt();
  }

  void ClearInterrupt() override { (void)client_interrupt_token_.Reset(); }

  [[nodiscard]] bool IsInterrupted() const override {
    return client_interrupt_token_.IsInterrupted();
  }

  size_t RegisterWakeup(std::function<void()> wake_cb) override {
    return client_interrupt_token_.RegisterWakeup(std::move(wake_cb));
  }

  void UnregisterWakeup(size_t token) override {
    if (token == 0) {
      return;
    }
    client_interrupt_token_.UnregisterWakeup(token);
  }
};

class ClientIOBase : public AMDomain::client::IClientIOPort {
protected:
  mutable AMAtomic<TraceCallback> trace_callback_;
  mutable AMAtomic<AuthCallback> auth_callback_;
  AMDomain::client::IClientConfigPort *config_part_ = nullptr;
  AMDomain::client::IClientTaskControlPort *control_part_ = nullptr;

public:
  ClientIOBase(AMDomain::client::IClientConfigPort *config,
               AMDomain::client::IClientTaskControlPort *control) {
    if (!config_part_ || !control_part_) {
      throw std::invalid_argument(
          "ClientIOBase requires non-null config and control ports");
    }
    this->config_part_ = config;
    this->control_part_ = control;
  }

  void BindPorts(AMDomain::client::IClientConfigPort *config,
                 AMDomain::client::IClientTaskControlPort *control) {
    config_part_ = config;
    control_part_ = control;
  }

  void RegisterTraceCallback(TraceCallback cb) override {
    auto trace = trace_callback_.lock();
    trace.store(std::move(cb));
  }

  void UnregisterTraceCallback() override {
    auto trace = trace_callback_.lock();
    trace.store(TraceCallback{});
  }

  void RegisterAuthCallback(AuthCallback cb) override {
    auto auth_cb = auth_callback_.lock();
    auth_cb.store(std::move(cb));
  }

  void UnregisterAuthCallback() override {
    auto auth_cb = auth_callback_.lock();
    auth_cb.store(AuthCallback{});
  }

protected:
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
};

class BaseClient : public AMDomain::client::IClientPort {
private:
  static std::string GenerateUID_() {
    static std::atomic<size_t> seed{1};
    return AMStr::fmt("client-{}",
                      seed.fetch_add(1, std::memory_order_relaxed));
  }

  std::string uid_;
  std::unique_ptr<AMDomain::client::IClientMetaDataPort> metadata_port_;
  std::unique_ptr<AMDomain::client::IClientConfigPort> config_port_;
  std::unique_ptr<AMDomain::client::IClientTaskControlPort> control_port_;
  std::unique_ptr<AMDomain::client::IClientIOPort> io_port_;

public:
  /**
   * @brief Construct one assembled client from injected port implementations.
   */
  BaseClient(
      std::unique_ptr<AMDomain::client::IClientMetaDataPort> metadata_port,
      std::unique_ptr<AMDomain::client::IClientConfigPort> config_port,
      std::unique_ptr<AMDomain::client::IClientTaskControlPort> control_port,
      std::unique_ptr<AMDomain::client::IClientIOPort> io_port,
      std::string uid = "") {
    if (!metadata_port_ || !config_port_ || !control_port_ || !io_port_) {
      throw std::invalid_argument(
          "AMClient requires non-null metadata/config/control/io ports");
    } else if (uid.empty()) {
      throw std::invalid_argument("AMClient UID cannot be empty");
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
  std::string GetUID() override { return uid_; }

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
  [[nodiscard]] const AMDomain::client::IClientConfigPort &
  ConfigPort() const override {
    return *config_port_;
  }

  /**
   * @brief Return task-control port.
   */
  [[nodiscard]] const AMDomain::client::IClientTaskControlPort &
  TaskControlPort() const override {
    return *control_port_;
  }

  /**
   * @brief Return io port.
   */
  [[nodiscard]] const AMDomain::client::IClientIOPort &IOPort() const override {
    return *io_port_;
  }
};
