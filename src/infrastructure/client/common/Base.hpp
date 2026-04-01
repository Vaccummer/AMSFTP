#pragma once
// project header
#include "domain/client/ClientModel.hpp"
#include "domain/client/ClientPort.hpp"
#include "domain/host/HostModel.hpp"
#include "foundation/core/DataClass.hpp"
#include "foundation/core/Enum.hpp"
#include "foundation/tools/path.hpp"

// 3rd party library
#include <algorithm>
#include <cmath>
#include <deque>
#include <magic_enum/magic_enum.hpp>
#include <map>
#include <mutex>
#include <set>
#include <shared_mutex>
#include <typeindex>
#include <unordered_map>
#include <unordered_set>

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

namespace AMInfra::client {
namespace fs = std::filesystem;
using ClientID = AMDomain::client::ClientID;
using TraceInfo = AMDomain::client::TraceInfo;
using ConRequest = AMDomain::host::ConRequest;
using ClientProtocol = AMDomain::host::ClientProtocol;
using ClientStatus = AMDomain::client::ClientStatus;
using CheckResult = AMDomain::filesystem::CheckResult;
using AuthCBInfo = AMDomain::client::AuthCBInfo;
using OS_TYPE = AMDomain::client::OS_TYPE;
using KnownHostQuery = AMDomain::client::KnownHostQuery;
using AuthCallback =
    std::function<std::optional<std::string>(const AuthCBInfo &)>;
using KnownHostCallback = AMDomain::client::KnownHostCallback;
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
using WRI = std::pair<WRV, AMPath::WER>;           // iwalk data + errors
using WRDR = std::pair<WRD, AMPath::WER>;          // walk data + errors
using WR = std::pair<ECM, WRI>;                    // iwalk func return type
using SIZER = std::pair<ECM, size_t>;              // getsize func return type
using TraceCallback = std::function<void(const TraceInfo &)>;
using CR =
    std::pair<ECM, std::pair<std::string, int>>; // ConductCmd func return type
using amf =
    AMDomain::client::amf; // atomic shared pointer for interrupt control
namespace AMFSI = AMDomain::filesystem;

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

class BasePathMatch {
protected:
  /**
   * @brief Return true when current client operation is interrupted.
   */
  [[nodiscard]] virtual bool IsInterrupted() const = 0;
  [[nodiscard]] virtual SR stat(const std::string &path,
                                bool trace_link = false, int timeout_ms = -1,
                                int64_t start_time = -1,
                                amf interrupt_flag = nullptr) = 0;
  [[nodiscard]] virtual std::pair<ECM, WRV>
  listdir(const std::string &path, int timeout_ms = -1, int64_t start_time = -1,
          amf interrupt_flag = nullptr) const = 0;
  [[nodiscard]] virtual std::pair<ECM, WRI>
  iwalk(const std::string &path, bool show_all = false,
        bool ignore_special_file = true,
        AMPath::WalkErrorCallback error_callback = nullptr, int timeout_ms = -1,
        int64_t start_time = -1, amf interrupt_flag = nullptr) const = 0;

private:
  [[nodiscard]] static bool IsTimedOut_(int timeout_ms, int64_t start_time) {
    return timeout_ms > 0 && AMTime::miliseconds() - start_time >= timeout_ms;
  }

  [[nodiscard]] bool ShouldStop_(amf interrupt_flag, int timeout_ms,
                                 int64_t start_time) const {
    if (interrupt_flag && interrupt_flag->IsInterrupted()) {
      return true;
    }
    return IsInterrupted() || IsTimedOut_(timeout_ms, start_time);
  }

  [[nodiscard]] static bool IsDoubleStarPattern_(const std::string &pattern) {
    return pattern.size() >= 2 && std::all_of(pattern.begin(), pattern.end(),
                                              [](char c) { return c == '*'; });
  }

  [[nodiscard]] static bool IsMatchPattern_(const std::string &pattern) {
    return pattern.find("*") != std::string::npos ||
           (pattern.find("<") != std::string::npos &&
            pattern.find(">") != std::string::npos);
  }

  void _find(std::vector<PathInfo> &results, const PathInfo &path,
             const std::vector<std::string> &match_parts, size_t match_index,
             SearchType type, int timeout_ms = -1, int64_t start_time = -1,
             amf interrupt_flag = nullptr) {
    if (match_index >= match_parts.size()) {
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

    const std::string &cur_pattern = match_parts[match_index];

    if (IsDoubleStarPattern_(cur_pattern)) {
      std::vector<std::string> relative_parts;
      auto [error, sub_pack] = iwalk(path.path, true, true, nullptr, timeout_ms,
                                     start_time, interrupt_flag);
      if (error.first != EC::Success) {
        return;
      }
      for (auto &sub : sub_pack.first) {
        if (ShouldStop_(interrupt_flag, timeout_ms, start_time)) {
          return;
        }
        if ((sub.type == PathType::DIR && type == SearchType::File) ||
            (sub.type != PathType::DIR && type == SearchType::Directory)) {
          continue;
        }
        // sub.path relative to path.path
        relative_parts = AMPath::split(sub.path.substr(path.path.size()));
        if (walk_match(relative_parts, match_parts, match_index)) {
          results.push_back(sub);
        }
      }
      return;
    }

    const bool is_match_mode = IsMatchPattern_(cur_pattern);
    auto [error, sub_list] =
        listdir(path.path, timeout_ms, start_time, interrupt_flag);
    if (error.first != EC::Success) {
      return;
    }

    for (auto &sub : sub_list) {
      if (ShouldStop_(interrupt_flag, timeout_ms, start_time)) {
        return;
      }
      const bool hit = is_match_mode ? name_match(sub.name, cur_pattern)
                                     : (sub.name == cur_pattern);
      if (!hit) {
        continue;
      }
      _find(results, sub, match_parts, match_index + 1, type, timeout_ms,
            start_time, interrupt_flag);
    }

    return;
  }

  static std::string _rep(const std::string &str, const std::string &from,
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

  static bool str_match(const std::string &name, const std::string &pattern) {
    std::string patternf = "^" + pattern + "$";
    std::wstring w_pattern = AMStr::wstr(patternf);
    std::wstring w_name = AMStr::wstr(name);
    try {
      bool res = std::regex_match(w_name, std::wregex(w_pattern));
      return res;
    } catch (const std::regex_error &) {
      return false;
    }
  }

  static bool name_match(const std::string &name, const std::string &pattern) {
    // Replace * in pattern with star_rep, < with less_rep, and > with
    // greater_rep
    static const std::string star_rep = "XKSOX1S";
    static const std::string less_rep = "SORBVs8";
    static const std::string greater_rep = "YNBSkdu8";

    std::string pattern_new = pattern;
    pattern_new = _rep(pattern_new, "*", star_rep);
    pattern_new = _rep(pattern_new, "<", less_rep);
    pattern_new = _rep(pattern_new, ">", greater_rep);
    pattern_new = AMPath::RegexEscape(pattern_new);
    // Replace star_rep in path with .*, less_rep with [, and greater_rep with
    // ]; do not use regex replacement
    pattern_new = _rep(pattern_new, star_rep, ".*");
    pattern_new = _rep(pattern_new, less_rep, "[");
    pattern_new = _rep(pattern_new, greater_rep, "]");
    return str_match(name, pattern_new);
  };

  static bool walk_match(const std::vector<std::string> &parts,
                         const std::vector<std::string> &match_parts,
                         size_t match_index = 0) {
    if (match_index >= match_parts.size()) {
      return true;
    }
    if (match_parts.size() - match_index > parts.size()) {
      return false;
    }
    size_t pos = 0;
    bool is_match;
    for (size_t mi = match_index; mi < match_parts.size(); ++mi) {
      const std::string &part = match_parts[mi];
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
  /**
   * @brief Return current wildcard match rules as plain text.
   */
  [[nodiscard]] static std::string MatchRuleText() {
    return "* matches within one path segment; ** uses legacy recursive "
           "subsequence matching; <...> maps to character class [...].";
  }

  /**
   * @brief Pure string matcher for tests (filesystem-independent).
   */
  [[nodiscard]] static bool
  MatchPathPatternLiteral(const std::string &path, const std::string &pattern) {
    const std::vector<std::string> path_parts = AMPath::split(path);
    const std::vector<std::string> pattern_parts = AMPath::split(pattern);
    if (path_parts.empty() || pattern_parts.empty()) {
      return path_parts.empty() && pattern_parts.empty();
    }

    size_t pi = 0;
    size_t mi = 0;
    while (pi < path_parts.size() && mi < pattern_parts.size() &&
           !IsMatchPattern_(pattern_parts[mi])) {
      if (path_parts[pi] != pattern_parts[mi]) {
        return false;
      }
      ++pi;
      ++mi;
    }

    if (mi >= pattern_parts.size()) {
      return pi == path_parts.size();
    }
    if (pi >= path_parts.size()) {
      return false;
    }

    if (IsDoubleStarPattern_(pattern_parts[mi])) {
      const std::vector<std::string> rel_parts(path_parts.begin() + pi,
                                               path_parts.end());
      return walk_match(rel_parts, pattern_parts, mi);
    }

    while (pi < path_parts.size() && mi < pattern_parts.size()) {
      const std::string &pat = pattern_parts[mi];
      const bool hit = IsMatchPattern_(pat) ? name_match(path_parts[pi], pat)
                                            : (path_parts[pi] == pat);
      if (!hit) {
        return false;
      }
      ++pi;
      ++mi;
    }
    return pi == path_parts.size() && mi == pattern_parts.size();
  }

  static bool IsUseMatch(const std::string &pattern) {
    return IsMatchPattern_(pattern);
  }

  std::vector<PathInfo> find(const std::string &path,
                             SearchType type = SearchType::All,
                             int timeout_ms = -1, int64_t start_time = -1,
                             amf interrupt_flag = nullptr) {
    std::vector<PathInfo> results = {};
    auto parts = AMPath::split(path);
    if (parts.empty()) {
      return results;
    } else if (parts.size() == 1) {
      auto [error, info] =
          stat(parts[0], false, timeout_ms, start_time, interrupt_flag);
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

    std::string cur_path = parts[0];
    bool is_stop = false;
    std::vector<std::string> match_parts = {};

    for (size_t i = 1; i < parts.size(); i++) {
      // When there is no * < >, join with cur_path; otherwise, stop joining and
      // add to match_parts
      if (!is_stop && !IsUseMatch(parts[i])) {
        cur_path = AMPath::join(cur_path, parts[i]);
      } else {
        is_stop = true;
        match_parts.push_back(parts[i]);
      }
    }

    // Check whether cur_path exists
    auto [error, info] =
        stat(cur_path, false, timeout_ms, start_time, interrupt_flag);
    if (error.first != EC::Success) {
      return {};
    }
    _find(results, info, match_parts, 0, type, timeout_ms, start_time,
          interrupt_flag);
    return results;
  }
};

class BasePathSearchV2 {
protected:
  /**
   * @brief Return true when current client operation is interrupted.
   */
  [[nodiscard]] virtual bool IsInterrupted() const = 0;
  [[nodiscard]] virtual SR stat(const std::string &path,
                                bool trace_link = false, int timeout_ms = -1,
                                int64_t start_time = -1,
                                amf interrupt_flag = nullptr) = 0;
  [[nodiscard]] virtual std::pair<ECM, WRV>
  listdir(const std::string &path, int timeout_ms = -1, int64_t start_time = -1,
          amf interrupt_flag = nullptr) const = 0;
  [[nodiscard]] virtual std::pair<ECM, WRI>
  iwalk(const std::string &path, bool show_all = false,
        bool ignore_special_file = true,
        AMPath::WalkErrorCallback error_callback = nullptr, int timeout_ms = -1,
        int64_t start_time = -1, amf interrupt_flag = nullptr) const = 0;

private:
  struct SearchRequest {
    std::string pattern = ".";
    SearchType type = SearchType::All;
    int timeout_ms = -1;
    int64_t start_time = -1;
    amf interrupt_flag = nullptr;
  };

  struct SearchPlan {
    std::string literal_root = ".";
    std::vector<std::string> segments = {};
  };

  struct CompiledSegment {
    enum class Kind {
      Literal = 0,
      Star = 1,
      DoubleStar = 2,
      CharClass = 3,
    };
    Kind kind = Kind::Literal;
    std::string raw = "";
    std::shared_ptr<std::wregex> regex = nullptr;
  };

  struct SearchCursor {
    PathInfo node = {};
    size_t segment_index = 0;
  };

  struct SearchStats {
    size_t scanned_dirs = 0;
    size_t visited_nodes = 0;
    size_t matched_nodes = 0;
  };

private:
  [[nodiscard]] static bool IsTimedOut_(int timeout_ms, int64_t start_time) {
    if (timeout_ms <= 0 || start_time < 0) {
      return false;
    }
    return AMTime::miliseconds() - start_time >= timeout_ms;
  }

  [[nodiscard]] bool ShouldStop_(const SearchRequest &request) const {
    if (request.interrupt_flag && request.interrupt_flag->IsInterrupted()) {
      return true;
    }
    return IsInterrupted() ||
           IsTimedOut_(request.timeout_ms, request.start_time);
  }

  [[nodiscard]] static bool IsDoubleStarPattern_(const std::string &pattern) {
    return pattern == "**";
  }

  [[nodiscard]] static bool IsMatchPattern_(const std::string &pattern) {
    return pattern.find('*') != std::string::npos ||
           (pattern.find('<') != std::string::npos &&
            pattern.find('>') != std::string::npos);
  }

  [[nodiscard]] static bool TypeAccepted_(SearchType type, PathType node_type) {
    return type == SearchType::All ||
           (type == SearchType::Directory && node_type == PathType::DIR) ||
           (type == SearchType::File && node_type == PathType::FILE);
  }

  [[nodiscard]] static std::wstring
  BuildSegmentRegex_(const std::string &segment) {
    std::string regex = "^";
    const auto append_escaped = [&regex](char c) {
      switch (c) {
      case '\\':
      case '^':
      case '$':
      case '.':
      case '|':
      case '?':
      case '+':
      case '(':
      case ')':
      case '[':
      case ']':
      case '{':
      case '}':
        regex.push_back('\\');
        break;
      default:
        break;
      }
      regex.push_back(c);
    };

    for (size_t i = 0; i < segment.size(); ++i) {
      const char c = segment[i];
      if (c == '*') {
        regex += ".*";
        continue;
      }
      if (c == '<') {
        const size_t close = segment.find('>', i + 1);
        if (close != std::string::npos && close > i + 1) {
          regex.push_back('[');
          regex += segment.substr(i + 1, close - i - 1);
          regex.push_back(']');
          i = close;
          continue;
        }
      }
      append_escaped(c);
    }
    regex.push_back('$');
    return AMStr::wstr(regex);
  }

  [[nodiscard]] static CompiledSegment
  CompileSegment_(const std::string &segment) {
    CompiledSegment out = {};
    out.raw = segment;
    if (IsDoubleStarPattern_(segment)) {
      out.kind = CompiledSegment::Kind::DoubleStar;
      return out;
    }
    if (!IsMatchPattern_(segment)) {
      out.kind = CompiledSegment::Kind::Literal;
      return out;
    }
    out.kind = (segment.find('<') != std::string::npos &&
                segment.find('>') != std::string::npos)
                   ? CompiledSegment::Kind::CharClass
                   : CompiledSegment::Kind::Star;
    try {
      out.regex = std::make_shared<std::wregex>(BuildSegmentRegex_(segment));
    } catch (const std::regex_error &) {
      out.regex = nullptr;
    }
    return out;
  }

  [[nodiscard]] static bool SegmentHit_(const CompiledSegment &segment,
                                        const std::string &name) {
    if (segment.kind == CompiledSegment::Kind::DoubleStar) {
      return true;
    }
    if (segment.kind == CompiledSegment::Kind::Literal) {
      return name == segment.raw;
    }
    if (!segment.regex) {
      return false;
    }
    try {
      return std::regex_match(AMStr::wstr(name), *segment.regex);
    } catch (const std::regex_error &) {
      return false;
    }
  }

  [[nodiscard]] SearchPlan ParseQuery_(const SearchRequest &request) const {
    SearchPlan plan = {};
    const std::string pattern =
        AMStr::Strip(request.pattern).empty() ? "." : request.pattern;
    const std::vector<std::string> parts = AMPath::split(pattern);
    if (parts.empty()) {
      plan.literal_root = ".";
      return plan;
    }

    if (parts.size() == 1 && IsMatchPattern_(parts[0])) {
      plan.literal_root = ".";
      plan.segments.push_back(parts[0]);
      return plan;
    }

    plan.literal_root = parts[0];
    bool wildcard_started = false;
    for (size_t i = 1; i < parts.size(); ++i) {
      if (!wildcard_started && !IsMatchPattern_(parts[i])) {
        plan.literal_root = AMPath::join(plan.literal_root, parts[i]);
      } else {
        wildcard_started = true;
        plan.segments.push_back(parts[i]);
      }
    }
    return plan;
  }

  [[nodiscard]] std::vector<CompiledSegment>
  CompilePlan_(const SearchPlan &plan) const {
    std::vector<CompiledSegment> out = {};
    out.reserve(plan.segments.size());
    for (const auto &segment : plan.segments) {
      CompiledSegment compiled = CompileSegment_(segment);
      if (!out.empty() &&
          out.back().kind == CompiledSegment::Kind::DoubleStar &&
          compiled.kind == CompiledSegment::Kind::DoubleStar) {
        continue;
      }
      out.push_back(std::move(compiled));
    }
    return out;
  }

  [[nodiscard]] static std::string
  BuildCursorStateKey_(const SearchCursor &cursor) {
    return cursor.node.path + '\x1F' + std::to_string(cursor.segment_index);
  }

  static bool PushCursorState_(std::deque<SearchCursor> &pending,
                               std::unordered_set<std::string> &visited,
                               const SearchCursor &cursor) {
    const std::string key = BuildCursorStateKey_(cursor);
    if (!visited.insert(key).second) {
      return false;
    }
    pending.push_back(cursor);
    return true;
  }

  [[nodiscard]] static bool
  MatchPartsWithGlobStar_(const std::vector<std::string> &parts,
                          const std::vector<CompiledSegment> &segments) {
    if (segments.empty()) {
      return parts.empty();
    }

    std::deque<std::pair<size_t, size_t>> pending = {};
    std::set<std::pair<size_t, size_t>> visited = {};
    pending.emplace_back(0, 0);
    visited.emplace(0, 0);

    while (!pending.empty()) {
      const auto [part_index, seg_index] = pending.front();
      pending.pop_front();

      if (seg_index >= segments.size()) {
        if (part_index >= parts.size()) {
          return true;
        }
        continue;
      }

      const CompiledSegment &segment = segments[seg_index];
      if (segment.kind == CompiledSegment::Kind::DoubleStar) {
        const std::pair<size_t, size_t> zero_consume = {part_index,
                                                        seg_index + 1};
        if (visited.insert(zero_consume).second) {
          pending.push_back(zero_consume);
        }
        if (part_index < parts.size()) {
          const std::pair<size_t, size_t> one_consume = {part_index + 1,
                                                         seg_index};
          if (visited.insert(one_consume).second) {
            pending.push_back(one_consume);
          }
        }
        continue;
      }

      if (part_index >= parts.size()) {
        continue;
      }
      if (!SegmentHit_(segment, parts[part_index])) {
        continue;
      }
      const std::pair<size_t, size_t> next_state = {part_index + 1,
                                                    seg_index + 1};
      if (visited.insert(next_state).second) {
        pending.push_back(next_state);
      }
    }
    return false;
  }

  [[nodiscard]] static std::vector<PathInfo>
  CanonicalizeResults_(std::vector<PathInfo> results) {
    std::stable_sort(
        results.begin(), results.end(),
        [](const PathInfo &a, const PathInfo &b) { return a.path < b.path; });
    results.erase(std::unique(results.begin(), results.end(),
                              [](const PathInfo &a, const PathInfo &b) {
                                return a.path == b.path;
                              }),
                  results.end());
    return results;
  }

  [[nodiscard]] std::vector<PathInfo>
  ExecuteSearch_(const SearchPlan &plan,
                 const std::vector<CompiledSegment> &segments,
                 const SearchRequest &request, SearchStats &stats) {
    std::vector<PathInfo> results = {};
    std::unordered_set<std::string> matched_paths = {};
    const auto push_result = [&](const PathInfo &node) {
      if (!TypeAccepted_(request.type, node.type)) {
        return;
      }
      if (!matched_paths.insert(node.path).second) {
        return;
      }
      results.push_back(node);
      ++stats.matched_nodes;
    };
    auto [error, root_info] = stat(plan.literal_root, false, request.timeout_ms,
                                   request.start_time, request.interrupt_flag);
    if (error.first != EC::Success) {
      return results;
    }

    if (segments.empty()) {
      push_result(root_info);
      return CanonicalizeResults_(std::move(results));
    }

    std::deque<SearchCursor> pending = {};
    std::unordered_set<std::string> visited = {};
    std::unordered_map<std::string, WRV> dir_children_cache = {};
    PushCursorState_(pending, visited, SearchCursor{root_info, 0});

    while (!pending.empty()) {
      if (ShouldStop_(request)) {
        break;
      }
      const SearchCursor cursor = pending.front();
      pending.pop_front();

      if (cursor.segment_index >= segments.size()) {
        push_result(cursor.node);
        continue;
      }

      const CompiledSegment &segment = segments[cursor.segment_index];
      if (segment.kind == CompiledSegment::Kind::DoubleStar) {
        PushCursorState_(pending, visited,
                         SearchCursor{cursor.node, cursor.segment_index + 1});
        if (cursor.node.type != PathType::DIR) {
          continue;
        }

        WRV *children = nullptr;
        auto cache_it = dir_children_cache.find(cursor.node.path);
        if (cache_it != dir_children_cache.end()) {
          children = &(cache_it->second);
        } else {
          ++stats.scanned_dirs;
          auto [error, sub_list] =
              listdir(cursor.node.path, request.timeout_ms, request.start_time,
                      request.interrupt_flag);
          if (error.first != EC::Success) {
            continue;
          }
          auto insert_it =
              dir_children_cache.emplace(cursor.node.path, std::move(sub_list))
                  .first;
          children = &(insert_it->second);
        }
        for (const auto &sub : *children) {
          if (ShouldStop_(request)) {
            break;
          }
          ++stats.visited_nodes;
          PushCursorState_(pending, visited,
                           SearchCursor{sub, cursor.segment_index});
        }
        continue;
      }

      if (cursor.node.type != PathType::DIR) {
        continue;
      }

      WRV *children = nullptr;
      auto cache_it = dir_children_cache.find(cursor.node.path);
      if (cache_it != dir_children_cache.end()) {
        children = &(cache_it->second);
      } else {
        ++stats.scanned_dirs;
        auto [error, sub_list] =
            listdir(cursor.node.path, request.timeout_ms, request.start_time,
                    request.interrupt_flag);
        if (error.first != EC::Success) {
          continue;
        }
        auto insert_it =
            dir_children_cache.emplace(cursor.node.path, std::move(sub_list))
                .first;
        children = &(insert_it->second);
      }

      for (const auto &sub : *children) {
        if (ShouldStop_(request)) {
          break;
        }
        ++stats.visited_nodes;
        if (!SegmentHit_(segment, sub.name)) {
          continue;
        }
        PushCursorState_(pending, visited,
                         SearchCursor{sub, cursor.segment_index + 1});
      }
    }

    return CanonicalizeResults_(std::move(results));
  }

public:
  /**
   * @brief Return current wildcard match rules as plain text.
   */
  [[nodiscard]] static std::string MatchRuleText() {
    return "* matches within one path segment; ** matches zero or more path "
           "segments; <...> maps to character class [...].";
  }

  /**
   * @brief Pure string matcher for tests (filesystem-independent).
   */
  [[nodiscard]] static bool
  MatchPathPatternLiteral(const std::string &path, const std::string &pattern) {
    const std::vector<std::string> path_parts = AMPath::split(path);
    const std::vector<std::string> pattern_parts = AMPath::split(pattern);
    if (path_parts.empty() || pattern_parts.empty()) {
      return path_parts.empty() && pattern_parts.empty();
    }

    size_t pi = 0;
    size_t mi = 0;
    while (pi < path_parts.size() && mi < pattern_parts.size() &&
           !IsMatchPattern_(pattern_parts[mi])) {
      if (path_parts[pi] != pattern_parts[mi]) {
        return false;
      }
      ++pi;
      ++mi;
    }

    if (mi >= pattern_parts.size()) {
      return pi == path_parts.size();
    }

    std::vector<CompiledSegment> segments = {};
    segments.reserve(pattern_parts.size() - mi);
    for (; mi < pattern_parts.size(); ++mi) {
      CompiledSegment compiled = CompileSegment_(pattern_parts[mi]);
      if (!segments.empty() &&
          segments.back().kind == CompiledSegment::Kind::DoubleStar &&
          compiled.kind == CompiledSegment::Kind::DoubleStar) {
        continue;
      }
      segments.push_back(std::move(compiled));
    }

    const std::vector<std::string> relative_parts(path_parts.begin() + pi,
                                                  path_parts.end());
    return MatchPartsWithGlobStar_(relative_parts, segments);
  }

  [[nodiscard]] static bool IsUseMatch(const std::string &pattern) {
    return IsMatchPattern_(pattern);
  }

  std::vector<PathInfo> find(const std::string &path,
                             SearchType type = SearchType::All,
                             int timeout_ms = -1, int64_t start_time = -1,
                             amf interrupt_flag = nullptr) {
    SearchRequest request = {};
    request.pattern = AMStr::Strip(path).empty() ? "." : path;
    request.type = type;
    request.timeout_ms = timeout_ms;
    request.start_time = (start_time < 0) ? AMTime::miliseconds() : start_time;
    request.interrupt_flag = std::move(interrupt_flag);

    SearchPlan plan = ParseQuery_(request);
    const std::vector<CompiledSegment> segments = CompilePlan_(plan);
    SearchStats stats = {};
    return ExecuteSearch_(plan, segments, request, stats);
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
      type_match = (std::type_index(typeid(it->second)) == type_key);
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
  mutable AMAtomic<CheckResult> state_;
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

  [[nodiscard]] AMAtomic<CheckResult> &StateAtomic() override { return state_; }

  [[nodiscard]] const AMAtomic<CheckResult> &StateAtomic() const override {
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

  [[nodiscard]] CheckResult GetState() const override {
    auto st = state_.lock();
    return st.load();
  }

  void SetState(const CheckResult &state) override {
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

class ClientControlToken : public AMDomain::client::IClientControlToken {
private:
  enum class State : uint8_t {
    Running = 0,
    Interrupted = 1,
  };

  std::atomic<State> state_{State::Running};
  std::atomic<size_t> wake_seed_{1};
  mutable AMAtomic<std::map<size_t, std::function<void()>>> wakeups_;

  void NotifyWakeups_() {
    std::vector<std::function<void()>> callbacks;
    {
      auto wakeups = wakeups_.lock();
      callbacks.reserve(wakeups->size());
      for (const auto &[_, cb] : *wakeups) {
        if (cb) {
          callbacks.push_back(cb);
        }
      }
    }
    for (auto &cb : callbacks) {
      cb();
    }
  }

public:
  [[nodiscard]] bool IsRunning() const {
    return state_.load(std::memory_order_acquire) == State::Running;
  }

  void RequestInterrupt() override {
    const State prev =
        state_.exchange(State::Interrupted, std::memory_order_acq_rel);
    if (prev == State::Interrupted) {
      return;
    }
    NotifyWakeups_();
  }

  void ClearInterrupt() override {
    (void)state_.exchange(State::Running, std::memory_order_acq_rel);
  }

  [[nodiscard]] bool IsInterrupted() const override {
    return state_.load(std::memory_order_acquire) == State::Interrupted;
  }

  size_t RegisterWakeup(std::function<void()> wake_cb) override {
    if (!wake_cb) {
      return 0;
    }
    const size_t id = wake_seed_.fetch_add(1, std::memory_order_relaxed);
    {
      auto wakeups = wakeups_.lock();
      (*wakeups)[id] = std::move(wake_cb);
    }
    if (IsInterrupted()) {
      std::function<void()> callback;
      {
        auto wakeups = wakeups_.lock();
        auto it = wakeups->find(id);
        if (it != wakeups->end()) {
          callback = it->second;
        }
      }
      if (callback) {
        callback();
      }
    }
    return id;
  }

  bool UnregisterWakeup(size_t token) override {
    if (token == 0) {
      return false;
    }
    auto wakeups = wakeups_.lock();
    return wakeups->erase(token) > 0;
  }
};

class ClientTimeoutPort : public AMDomain::client::IClientTimeoutPort {
private:
  mutable std::mutex timeout_mutex_;
  float timeout_ms_ = -1.0f;
  int64_t timeout_start_ms_ = -1;

public:
  [[nodiscard]] bool IsTimeout() const override {
    std::lock_guard<std::mutex> lock(timeout_mutex_);
    if (timeout_ms_ < 0.0f || timeout_start_ms_ < 0) {
      return false;
    }
    return static_cast<float>(AMTime::miliseconds() - timeout_start_ms_) >=
           timeout_ms_;
  }

  [[nodiscard]] std::optional<unsigned int> RemainTimeMs() const override {
    std::lock_guard<std::mutex> lock(timeout_mutex_);
    if (timeout_ms_ < 0.0f) {
      return std::nullopt;
    }
    if (timeout_start_ms_ < 0) {
      return static_cast<unsigned int>(timeout_ms_ > 0.0f ? timeout_ms_ : 0.0f);
    }
    const float remain =
        timeout_ms_ -
        static_cast<float>(AMTime::miliseconds() - timeout_start_ms_);
    if (remain <= 0.0f) {
      return 0U;
    }
    return static_cast<unsigned int>(std::ceil(remain));
  }

  void SetTimeout(float timeout_ms) override {
    std::lock_guard<std::mutex> lock(timeout_mutex_);
    timeout_ms_ = timeout_ms;
    timeout_start_ms_ = AMTime::miliseconds();
  }
};

class ClientIOBase : public AMDomain::client::IClientIOPort {
protected:
  mutable AMAtomic<TraceCallback> trace_callback_;
  mutable AMAtomic<AuthCallback> auth_callback_;
  mutable AMAtomic<KnownHostCallback> known_host_callback_;
  AMDomain::client::IClientConfigPort *config_part_ = nullptr;
  AMAtomic<ConRequest> &request_atomic_;

public:
  ClientIOBase(AMDomain::client::IClientConfigPort *config,
               AMDomain::client::IClientControlToken *control)
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
                 AMDomain::client::IClientControlToken *control) {
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
      return {EC::Success, ""};
    }
    auto [res, cb_ecm] = CallCallbackSafeRet<ECM>(cb, known_host_info);
    if (cb_ecm.first != EC::Success) {
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
  std::unique_ptr<AMDomain::client::IClientControlToken> control_port_;
  std::unique_ptr<AMDomain::client::IClientIOPort> io_port_;

public:
  using amf = std::shared_ptr<ClientControlToken>;
  /**
   * @brief Construct one assembled client from injected port implementations.
   */
  BaseClient(
      std::unique_ptr<AMDomain::client::IClientMetaDataPort> metadata_port,
      std::unique_ptr<AMDomain::client::IClientConfigPort> config_port,
      std::unique_ptr<AMDomain::client::IClientControlToken> control_port,
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
  [[nodiscard]] AMDomain::client::IClientControlToken &
  TaskControlPort() override {
    return *control_port_;
  }

  /**
   * @brief Return task-control port.
   */
  [[nodiscard]] const AMDomain::client::IClientControlToken &
  TaskControlPort() const override {
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
