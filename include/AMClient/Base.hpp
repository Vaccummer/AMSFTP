#pragma once
// standard library
#include <any>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <list>
#include <memory>
#include <mutex>
#include <regex>
#include <string>
#include <thread>
#include <type_traits>
#include <typeindex>
#include <unordered_map>
#include <utility>
#include <vector>


// project header
#include "AMBase/DataClass.hpp"
#include "AMBase/Enum.hpp"
#include "AMBase/Path.hpp"

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

class UnimplementedMethodException : public std::exception {
public:
  UnimplementedMethodException(std::string message)
      : message(std::move(message)) {}
  [[nodiscard]] const char *what() const noexcept override {
    return message.c_str();
  }

private:
  std::string message;
};

namespace fs = std::filesystem;
using RMR = std::vector<std::pair<std::string, ECM>>; // rm func return type
using BR = std::pair<bool, ECM>;                      // is_dir func return type
using SR = std::pair<ECM, PathInfo>;                  // stat func return type
using WRV = std::vector<PathInfo>;                    // iwalk func return type
using WRD = AMFS::WRD;                                // walk func return type
using WRI = std::pair<WRV, AMFS::WER>;                // iwalk data + errors
using WRDR = std::pair<WRD, AMFS::WER>;               // walk data + errors
using WR = std::pair<ECM, WRI>;                       // iwalk func return type
using SIZER = std::pair<ECM, size_t>; // getsize func return type
using TraceCallback = std::function<void(const TraceInfo &)>;
using CR =
    std::pair<ECM, std::pair<std::string, int>>; // ConductCmd func return type

class BasePathMatch {
private:
  virtual std::pair<ECM, PathInfo> stat(const std::string &path,
                                        bool trace_link = false,
                                        amf interrupt_flag = nullptr,
                                        int timeout_ms = -1,
                                        int64_t start_time = -1) = 0;
  virtual std::pair<ECM, std::vector<PathInfo>>
  listdir(const std::string &path, amf interrupt_flag = nullptr,
          int timeout_ms = -1, int64_t start_time = -1) = 0;
  virtual std::pair<ECM, AMFS::WRI>
  iwalk(const std::string &path, bool show_all = false,
        bool ignore_sepcial_file = true,
        AMFS::WalkErrorCallback error_callback = nullptr,
        amf interrupt_flag = nullptr, int timeout_ms = -1,
        int64_t start_time = -1) = 0;

  void _find(std::vector<PathInfo> &results, const PathInfo &path,
             const std::vector<std::string> &match_parts,
             const SearchType &type, const std::string &sep,
             amf interrupt_flag = nullptr, int timeout_ms = -1,
             int64_t start_time = -1) {
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
      auto [error, sub_pack] = iwalk(path.path, true, true, nullptr,
                                     interrupt_flag, timeout_ms, start_time);
      if (error.first != EC::Success) {
        return;
      }
      for (auto &sub : sub_pack.first) {
        if (interrupt_flag && !interrupt_flag->IsRunning()) {
          return;
        }
        if (timeout_ms > 0 && am_ms() - start_time >= timeout_ms) {
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
      auto [error2, sub_list2] =
          listdir(path.path, interrupt_flag, timeout_ms, start_time);
      if (error2.first != EC::Success) {
        return;
      }
      for (auto &sub : sub_list2) {
        if (interrupt_flag && !interrupt_flag->IsRunning()) {
          return;
        }
        if (timeout_ms > 0 && am_ms() - start_time >= timeout_ms) {
          return;
        }
        if (sub.name == cur_pattern) {
          _find(results, sub, new_parts2, type, sep, interrupt_flag, timeout_ms,
                start_time);
        }
      }
    }
    // Enter matching mode
    else {
      auto new_parts3 = match_parts;
      new_parts3.erase(new_parts3.begin());
      auto [error3, sub_list3] =
          listdir(path.path, interrupt_flag, timeout_ms, start_time);
      if (error3.first != EC::Success) {
        return;
      }
      for (auto &sub : sub_list3) {
        if (interrupt_flag && !interrupt_flag->IsRunning()) {
          return;
        }
        if (timeout_ms > 0 && am_ms() - start_time >= timeout_ms) {
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

public:
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

  std::vector<PathInfo> find(const std::string &path,
                             SearchType type = SearchType::All,
                             amf interrupt_flag = nullptr, int timeout_ms = -1,
                             int64_t start_time = -1) {
    std::vector<PathInfo> results = {};
    auto parts = AMPathStr::split(path);
    if (parts.empty()) {
      return results;
    } else if (parts.size() == 1) {
      auto [error, info] =
          stat(parts[0], false, interrupt_flag, timeout_ms, start_time);
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
    auto [error, info] =
        stat(cur_path, false, interrupt_flag, timeout_ms, start_time);
    if (error.first != EC::Success) {
      return {};
    }
    _find(results, info, match_parts, type, sep, interrupt_flag, timeout_ms,
          start_time);
    return results;
  }
};

class AMTracer {
private:
  using TypeVarStore = std::unordered_map<std::type_index, std::any>;
  using NamedVarStore = std::unordered_map<std::string, std::any>;

  TraceCallback trace_cb;
  std::list<TraceInfo> buffer = {};
  std::mutex buffer_mutex;
  mutable std::mutex var_cache_mtx_;
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
    auto time_now = FormatTime(timenow(), "%Y/%m/%d %H:%M:%S");
    auto out = time_now + " " + sign + " " +
               std::string(magic_enum::enum_name(trace_info.level)) + " " +
               std::string(trace_info.message);
    file << out << std::endl;
  }

protected:
  ConRequest res_data;
  void push(const TraceInfo &value) {
    std::lock_guard<std::mutex> lock(buffer_mutex);
    if (buffer.size() >= static_cast<size_t>(capacity)) {
      buffer.pop_front();
    }
    buffer.push_back(value);
  }
  std::string nickname;

public:
  enum class NamedVarQueryState {
    Found = 0,
    NameNotFound = 1,
    TypeMismatch = 2,
  };

  /**
   * @brief Store one value in type-indexed cache.
   *
   * @param value Value to store.
   * @param overwrite Whether existing value with the same type can be replaced.
   * @return True when value is written.
   */
  template <typename T>
  [[nodiscard]] bool StoreTypedValue(T &&value, bool overwrite = true) {
    using ValueT = std::decay_t<T>;
    static_assert(!std::is_reference_v<ValueT>,
                  "StoreTypedValue expects value-like type");
    std::lock_guard<std::mutex> lock(var_cache_mtx_);
    const std::type_index key(typeid(ValueT));
    auto it = type_var_cache_.find(key);
    if (it != type_var_cache_.end() && !overwrite) {
      return false;
    }
    type_var_cache_[key] = std::forward<T>(value);
    return true;
  }

  /**
   * @brief Query one value from type-indexed cache.
   *
   * @return Typed pointer when found; otherwise nullptr.
   */
  template <typename T> [[nodiscard]] T *QueryTypedValue() {
    using ValueT = std::remove_cv_t<std::remove_reference_t<T>>;
    std::lock_guard<std::mutex> lock(var_cache_mtx_);
    auto it = type_var_cache_.find(std::type_index(typeid(ValueT)));
    if (it == type_var_cache_.end()) {
      return nullptr;
    }
    return std::any_cast<ValueT>(&(it->second));
  }

  /**
   * @brief Query one value from type-indexed cache (const overload).
   *
   * @return Typed pointer when found; otherwise nullptr.
   */
  template <typename T> [[nodiscard]] const T *QueryTypedValue() const {
    using ValueT = std::remove_cv_t<std::remove_reference_t<T>>;
    std::lock_guard<std::mutex> lock(var_cache_mtx_);
    auto it = type_var_cache_.find(std::type_index(typeid(ValueT)));
    if (it == type_var_cache_.end()) {
      return nullptr;
    }
    return std::any_cast<ValueT>(&(it->second));
  }

  /**
   * @brief Store one named value in cache.
   *
   * @param name Variable name key.
   * @param value Value to store.
   * @param overwrite Whether existing value can be replaced.
   * @return True when value is written.
   */
  template <typename T>
  [[nodiscard]] bool StoreNamedValue(const std::string &name, T &&value,
                                     bool overwrite = true) {
    if (name.empty()) {
      return false;
    }
    std::lock_guard<std::mutex> lock(var_cache_mtx_);
    auto it = named_var_cache_.find(name);
    if (it != named_var_cache_.end() && !overwrite) {
      return false;
    }
    named_var_cache_[name] = std::forward<T>(value);
    return true;
  }

  /**
   * @brief Query one named value in cache.
   *
   * @param name Variable name key.
   * @param state Optional query state output for not-found/type-mismatch split.
   * @return Typed pointer when found; otherwise nullptr.
   */
  template <typename T>
  [[nodiscard]] T *QueryNamedValue(const std::string &name,
                                   NamedVarQueryState *state = nullptr) {
    using ValueT = std::remove_cv_t<std::remove_reference_t<T>>;
    std::lock_guard<std::mutex> lock(var_cache_mtx_);
    auto it = named_var_cache_.find(name);
    if (it == named_var_cache_.end()) {
      if (state) {
        *state = NamedVarQueryState::NameNotFound;
      }
      return nullptr;
    }
    auto *ptr = std::any_cast<ValueT>(&(it->second));
    if (!ptr) {
      if (state) {
        *state = NamedVarQueryState::TypeMismatch;
      }
      return nullptr;
    }
    if (state) {
      *state = NamedVarQueryState::Found;
    }
    return ptr;
  }

  /**
   * @brief Query one named value in cache (const overload).
   *
   * @param name Variable name key.
   * @param state Optional query state output for not-found/type-mismatch split.
   * @return Typed pointer when found; otherwise nullptr.
   */
  template <typename T>
  [[nodiscard]] const T *
  QueryNamedValue(const std::string &name,
                  NamedVarQueryState *state = nullptr) const {
    using ValueT = std::remove_cv_t<std::remove_reference_t<T>>;
    std::lock_guard<std::mutex> lock(var_cache_mtx_);
    auto it = named_var_cache_.find(name);
    if (it == named_var_cache_.end()) {
      if (state) {
        *state = NamedVarQueryState::NameNotFound;
      }
      return nullptr;
    }
    auto *ptr = std::any_cast<ValueT>(&(it->second));
    if (!ptr) {
      if (state) {
        *state = NamedVarQueryState::TypeMismatch;
      }
      return nullptr;
    }
    if (state) {
      *state = NamedVarQueryState::Found;
    }
    return ptr;
  }

  /**
   * @brief Get a public metadata value by key.
   * @param key Metadata key.
   * @param value Output value pointer. When null, only existence is checked.
   * @return True when key exists.
   */
  [[nodiscard]] bool GetPublicValue(const std::string &key,
                                    std::string *value) const {
    std::lock_guard<std::mutex> lock(var_cache_mtx_);
    auto it = named_var_cache_.find(key);
    if (it == named_var_cache_.end()) {
      return false;
    }
    const std::string *ptr = std::any_cast<std::string>(&(it->second));
    if (!ptr) {
      return false;
    }
    if (value) {
      *value = *ptr;
    }
    return true;
  }

  /**
   * @brief Set a public metadata value.
   * @param key Metadata key.
   * @param value Metadata value.
   * @param force Overwrite when key already exists.
   * @return True when the value is written.
   */
  [[nodiscard]] bool SetPublicValue(const std::string &key,
                                    const std::string &value, bool force) {
    std::string tmp = value;
    return StoreNamedValue<std::string>(key, std::move(tmp), force);
  }

  /**
   * @brief Backward-compatible typo method; use SetPublicValue instead.
   */
  [[nodiscard]] bool SetPulbicValue(const std::string &key,
                                    const std::string &value, bool force) {
    return SetPublicValue(key, value, force);
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

  void SetPyTrace(TraceCallback trace = {}) { SetTraceCallback(trace); }

  [[nodiscard]] const std::string &GetNickname() const { return nickname; }

  [[nodiscard]] const ConRequest &GetRequest() const { return res_data; }
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
    init_start_time = start_time == -1 ? am_ms() : start_time;
  }

  /**
   * @brief Check interruption/timeout state for retry operations.
   */
  ECM CheckControlState_(const std::string &action) const {
    if (init_interrupt_flag && !init_interrupt_flag->IsRunning()) {
      return {EC::Terminate, AMStr::fmt("{} interrupted", action)};
    }
    if (init_timeout_ms >= 0 && init_start_time >= 0 &&
        (am_ms() - init_start_time) >= init_timeout_ms) {
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

class BaseClient : public AMTracer, public BasePathMatch {
private:
  static std::string GenerateUID() {
    static size_t seed = 0;
    return std::to_string(seed++);
  };

protected:
  amf ClientInterruptFlag = std::make_shared<TaskControlToken>();
  ECM state = {EC::NoConnection, "Client Not Initialized"};
  std::mutex state_mtx;
  // NOLINTNEXTLINE
  void SetState(const ECM &state) {
    std::lock_guard<std::mutex> lock(state_mtx);
    this->state = state;
  }

public:
  std::string uid;
  std::recursive_mutex mtx;
  OS_TYPE os_type = OS_TYPE::Uncertain;
  std::string home_dir = "";
  virtual ~BaseClient() = default;
  BaseClient(const ConRequest &request, int buffer_capacity = 10,
             TraceCallback trace_cb = {})
      : AMTracer(request, buffer_capacity, std::move(trace_cb)),
        BasePathMatch() {
    this->uid = BaseClient::GenerateUID();
    if (res_data.buffer_size <= 0) {
      res_data.buffer_size = 8 * AMMB;
    }
    if (res_data.protocol == ClientProtocol::Unknown) {
      res_data.protocol = ClientProtocol::Base;
    }
  }

  std::string GetUID() { return this->uid; }

  [[nodiscard]] ClientProtocol GetProtocol() const { return res_data.protocol; }

  ssize_t TransferRingBufferSize(ssize_t buffer_size = -1) {
    if (buffer_size <= 0) {
      return res_data.buffer_size;
    }
    res_data.buffer_size = buffer_size;
    return res_data.buffer_size;
  }

  std::string GetProtocolName() {
    switch (GetProtocol()) {
    case ClientProtocol::Base:
      return "base";
    case ClientProtocol::SFTP:
      return "sftp";
    case ClientProtocol::FTP:
      return "ftp";
    case ClientProtocol::LOCAL:
      return "local";
    default:
      return "unknown";
    }
  }

  std::variant<ECM, std::string> TrashDir(const std::string &trash_dir = "",
                                          amf interrupt_flag = nullptr,
                                          int timeout_ms = -1,
                                          int64_t start_time = -1) {
    if (trash_dir.empty()) {
      return res_data.trash_dir;
    }
    ECM rcm = mkdirs(trash_dir, interrupt_flag, timeout_ms, start_time);
    if (rcm.first == EC::Success) {
      res_data.trash_dir = trash_dir;
    }
    return rcm;
  }

  ECM GetState() { return this->state; };

  // On remote servers, move cannot cross filesystems; local move can
  // Remote move must use transfer then delete
  ECM move(const std::string &src, const std::string &dst,
           bool need_mkdir = false, bool force_write = false,
           amf interrupt_flag = nullptr, int timeout_ms = -1,
           int64_t start_time = -1) {

    return rename(src, AMPathStr::join(dst, AMPathStr::basename(src)),
                  need_mkdir, force_write, interrupt_flag, timeout_ms,
                  start_time);
  }

  // Get total size of all files and nested directories under a path,
  // If read errors occur, no throw and no size accounting; result may be biased
  virtual int64_t getsize(const std::string &path,
                          bool ignore_sepcial_file = true,
                          amf interrupt_flag = nullptr, int timeout_ms = -1,
                          int64_t start_time = -1) {
    auto [rcm, pack] = iwalk(path, true, ignore_sepcial_file, nullptr,
                             interrupt_flag, timeout_ms, start_time);
    if (rcm.first != EC::Success) {
      return -1;
    }
    if (interrupt_flag && !interrupt_flag->IsRunning()) {
      return -1;
    }
    size_t size = 0;
    for (auto &item : pack.first) {
      size += item.size;
    }
    return size;
  }

  std::pair<ECM, PathType> get_path_type(const std::string &path,
                                         amf interrupt_flag = nullptr,
                                         int timeout_ms = -1,
                                         int64_t start_time = -1) {
    auto [rcm, path_info] =
        stat(path, false, interrupt_flag, timeout_ms, start_time);
    if (rcm.first != EC::Success) {
      return {ECM{rcm.first, rcm.second}, PathType::Unknown};
    }
    return {rcm, path_info.type};
  }

  // Check whether path exists (with AMFS::abspath)
  std::pair<ECM, bool> exists(const std::string &path,
                              amf interrupt_flag = nullptr, int timeout_ms = -1,
                              int64_t start_time = -1) {
    auto [rcm, path_info] =
        stat(path, false, interrupt_flag, timeout_ms, start_time);
    if (rcm.first == EC::Success) {
      return {rcm, true};
    } else if (rcm.first == EC::PathNotExist || rcm.first == EC::FileNotExist) {
      return {{EC::Success, ""}, false};
    } else {
      return {rcm, false};
    }
  }

  std::pair<ECM, bool> is_regular(const std::string &path,
                                  amf interrupt_flag = nullptr,
                                  int timeout_ms = -1,
                                  int64_t start_time = -1) {
    auto [rcm, path_info] =
        stat(path, false, interrupt_flag, timeout_ms, start_time);
    if (rcm.first != EC::Success) {
      return {rcm, false};
    }
    return {ECM{EC::Success, ""},
            path_info.type == PathType::FILE ? true : false};
  }

  std::pair<ECM, bool> is_dir(const std::string &path,
                              amf interrupt_flag = nullptr, int timeout_ms = -1,
                              int64_t start_time = -1) {
    auto [rcm, path_info] =
        stat(path, false, interrupt_flag, timeout_ms, start_time);
    if (rcm.first != EC::Success) {
      return {rcm, false};
    }
    return {ECM{EC::Success, ""},
            path_info.type == PathType::DIR ? true : false};
  }

  std::pair<ECM, bool> is_symlink(const std::string &path,
                                  amf interrupt_flag = nullptr,
                                  int timeout_ms = -1,
                                  int64_t start_time = -1) {
    auto [rcm, path_info] =
        stat(path, false, interrupt_flag, timeout_ms, start_time);
    if (rcm.first != EC::Success) {
      return {rcm, false};
    }
    return {ECM{EC::Success, ""},
            path_info.type == PathType::SYMLINK ? true : false};
  }

  virtual ECM Check([[maybe_unused]] amf interrupt_flag = nullptr,
                    [[maybe_unused]] int timeout_ms = -1,
                    [[maybe_unused]] int64_t start_time = -1) {
    throw UnimplementedMethodException(AMStr::fmt(
        "{} Client doesn't implement funtion: Check", GetProtocolName()));
  }

  virtual ECM Connect([[maybe_unused]] bool force = false,
                      [[maybe_unused]] amf interrupt_flag = nullptr,
                      [[maybe_unused]] int timeout_ms = -1,
                      [[maybe_unused]] int64_t start_time = -1) {
    throw UnimplementedMethodException(AMStr::fmt(
        "{} Client doesn't implement funtion: Connect", GetProtocolName()));
  }

  virtual OS_TYPE GetOSType([[maybe_unused]] bool update = false) {
    throw UnimplementedMethodException(AMStr::fmt(
        "{} Client doesn't implement funtion: GetOSType", GetProtocolName()));
  }

  virtual double GetRTT([[maybe_unused]] ssize_t times = 5,
                        [[maybe_unused]] amf interrupt_flag = nullptr) {
    throw UnimplementedMethodException(AMStr::fmt(
        "{} Client doesn't implement funtion: GetRTT", GetProtocolName()));
  }

  virtual CR ConductCmd([[maybe_unused]] const std::string &cmd,
                        [[maybe_unused]] int max_time_s = 3000,
                        [[maybe_unused]] amf interrupt_flag = nullptr) {
    throw UnimplementedMethodException(AMStr::fmt(
        "{} Client doesn't implement funtion: ConductCmd", GetProtocolName()));
  }

  virtual std::string StrUid([[maybe_unused]] const long &uid) {
    throw UnimplementedMethodException(AMStr::fmt(
        "{} Client doesn't implement funtion: StrUid", GetProtocolName()));
  }

  virtual std::string GetHomeDir() {
    throw UnimplementedMethodException(AMStr::fmt(
        "{} Client doesn't implement funtion: GetHomeDir", GetProtocolName()));
  }

  virtual std::pair<ECM, std::string>
  realpath([[maybe_unused]] const std::string &path,
           [[maybe_unused]] amf interrupt_flag = nullptr,
           [[maybe_unused]] int timeout_ms = -1,
           [[maybe_unused]] int64_t start_time = -1) {

    throw UnimplementedMethodException(AMStr::fmt(
        "{} Client doesn't implement funtion: realpath", GetProtocolName()));
  }
  virtual std::pair<ECM, std::unordered_map<std::string, ECM>>
  chmod([[maybe_unused]] const std::string &path,
        [[maybe_unused]] std::variant<std::string, size_t> mode,
        [[maybe_unused]] bool recursive = false,
        [[maybe_unused]] amf interrupt_flag = nullptr,
        [[maybe_unused]] int timeout_ms = -1,
        [[maybe_unused]] int64_t start_time = -1) {
    throw UnimplementedMethodException(AMStr::fmt(
        "{} Client doesn't implement funtion: chmod", GetProtocolName()));
  }
  SR stat([[maybe_unused]] const std::string &path,
          [[maybe_unused]] bool trace_link = false,
          [[maybe_unused]] amf interrupt_flag = nullptr,
          [[maybe_unused]] int timeout_ms = -1,
          [[maybe_unused]] int64_t start_time = -1) override {
    throw UnimplementedMethodException(AMStr::fmt(
        "{} Client doesn't implement funtion: stat", GetProtocolName()));
  }
  std::pair<ECM, std::vector<PathInfo>>
  listdir([[maybe_unused]] const std::string &path,
          [[maybe_unused]] amf interrupt_flag = nullptr,
          [[maybe_unused]] int timeout_ms = -1,
          [[maybe_unused]] int64_t start_time = -1) override {
    throw UnimplementedMethodException(AMStr::fmt(
        "{} Client doesn't implement funtion: listdir", GetProtocolName()));
  }
  virtual ECM mkdir([[maybe_unused]] const std::string &path,
                    [[maybe_unused]] amf interrupt_flag = nullptr,
                    [[maybe_unused]] int timeout_ms = -1,
                    [[maybe_unused]] int64_t start_time = -1) {
    throw UnimplementedMethodException(AMStr::fmt(
        "{} Client doesn't implement funtion: mkdir", GetProtocolName()));
  }
  virtual ECM mkdirs([[maybe_unused]] const std::string &path,
                     [[maybe_unused]] amf interrupt_flag = nullptr,
                     [[maybe_unused]] int timeout_ms = -1,
                     [[maybe_unused]] int64_t start_time = -1) {
    throw UnimplementedMethodException(AMStr::fmt(
        "{} Client doesn't implement funtion: mkdirs", GetProtocolName()));
  };

  virtual ECM rmdir([[maybe_unused]] const std::string &path,
                    [[maybe_unused]] amf interrupt_flag = nullptr,
                    [[maybe_unused]] int timeout_ms = -1,
                    [[maybe_unused]] int64_t start_time = -1) {
    throw UnimplementedMethodException(AMStr::fmt(
        "{} Client doesn't implement funtion: rmdir", GetProtocolName()));
  }
  virtual ECM rmfile([[maybe_unused]] const std::string &path,
                     [[maybe_unused]] amf interrupt_flag = nullptr,
                     [[maybe_unused]] int timeout_ms = -1,
                     [[maybe_unused]] int64_t start_time = -1) {
    throw UnimplementedMethodException(AMStr::fmt(
        "{} Client doesn't implement funtion: rmfile", GetProtocolName()));
  }
  virtual ECM rename([[maybe_unused]] const std::string &src,
                     [[maybe_unused]] const std::string &dst,
                     [[maybe_unused]] bool mkdir = true,
                     [[maybe_unused]] bool overwrite = false,
                     [[maybe_unused]] amf interrupt_flag = nullptr,
                     [[maybe_unused]] int timeout_ms = -1,
                     [[maybe_unused]] int64_t start_time = -1) {
    throw UnimplementedMethodException(AMStr::fmt(
        "{} Client doesn't implement funtion: rename", GetProtocolName()));
  }

  virtual std::pair<ECM, RMR>
  remove([[maybe_unused]] const std::string &path,
         [[maybe_unused]] AMFS::WalkErrorCallback error_callback = nullptr,
         [[maybe_unused]] amf interrupt_flag = nullptr,
         [[maybe_unused]] int timeout_ms = -1,
         [[maybe_unused]] int64_t start_time = -1) {
    throw UnimplementedMethodException(AMStr::fmt(
        "{} Client doesn't implement funtion: remove", GetProtocolName()));
  };
  virtual ECM saferm([[maybe_unused]] const std::string &path,
                     [[maybe_unused]] amf interrupt_flag = nullptr,
                     [[maybe_unused]] int timeout_ms = -1,
                     [[maybe_unused]] int64_t start_time = -1) {
    throw UnimplementedMethodException(AMStr::fmt(
        "{} Client doesn't implement funtion: saferm", GetProtocolName()));
  }

  virtual ECM copy([[maybe_unused]] const std::string &src,
                   [[maybe_unused]] const std::string &dst,
                   [[maybe_unused]] bool need_mkdir = false,
                   [[maybe_unused]] int timeout_ms = -1,
                   [[maybe_unused]] amf interrupt_flag = nullptr) {
    throw UnimplementedMethodException(AMStr::fmt(
        "{} Client doesn't implement funtion: copy", GetProtocolName()));
  }

  std::pair<ECM, WRI>
  iwalk([[maybe_unused]] const std::string &path,
        [[maybe_unused]] bool show_all = false,
        [[maybe_unused]] bool ignore_special_file = true,
        [[maybe_unused]] AMFS::WalkErrorCallback error_callback = nullptr,
        [[maybe_unused]] amf interrupt_flag = nullptr,
        [[maybe_unused]] int timeout_ms = -1,
        [[maybe_unused]] int64_t start_time = -1) override {
    throw UnimplementedMethodException(AMStr::fmt(
        "{} Client doesn't implement funtion: iwalk", GetProtocolName()));
  }

  virtual std::pair<ECM, WRDR>
  walk([[maybe_unused]] const std::string &path,
       [[maybe_unused]] int max_depth = -1,
       [[maybe_unused]] bool show_all = false,
       [[maybe_unused]] bool ignore_special_file = false,
       [[maybe_unused]] AMFS::WalkErrorCallback error_callback = nullptr,
       [[maybe_unused]] amf interrupt_flag = nullptr,
       [[maybe_unused]] int timeout_ms = -1,
       [[maybe_unused]] int64_t start_time = -1) {
    throw UnimplementedMethodException(AMStr::fmt(
        "{} Client doesn't implement funtion: walk", GetProtocolName()));
  }
};
