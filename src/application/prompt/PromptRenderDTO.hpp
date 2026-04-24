#pragma once

#include "foundation/core/Enum.hpp"
#include "foundation/tools/string.hpp"

#include <array>
#include <cstdint>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace AMApplication::prompt {

struct PromptRenderDTO {
  enum class Attr {
    nickname = 1,
    username = 2,
    hostname = 3,
    cwd = 4,
    os_type = 5,
    sysicon = 6,
    task_pending = 7,
    task_running = 8,
    task_paused = 9,
    success_task = 10,
    failed_task = 11,
    channel_num = 12,
    term_num = 13,
    channel_ok = 14,
    channel_disconnected = 15,
    term_ok = 16,
    term_disconnected = 17,
    channel_name = 18,
    time_now = 19,
    elapsed = 20,
    is_success = 21,
    ec_name = 22,
    ec_code = 23,
  };

  std::string nickname = "local";
  std::string username = "";
  std::string hostname = "";
  std::string cwd = "/";
  std::string os_type = "windows";
  std::string sysicon = "PC";
  int64_t task_pending = 0;
  int64_t task_running = 0;
  int64_t task_paused = 0;
  int64_t success_task = 0;
  int64_t failed_task = 0;
  int64_t channel_num = 0;
  int64_t term_num = 0;
  int64_t channel_ok = 0;
  int64_t channel_disconnected = 0;
  int64_t term_ok = 0;
  int64_t term_disconnected = 0;
  std::string channel_name = "";
  std::string time_now = "";
  std::string elapsed = "";
  bool is_success = true;
  std::string ec_name = "";
  int64_t ec_code = 0;

  static constexpr auto FieldNames = magic_enum::enum_values<Attr>();
  using MemberPtr =
      std::variant<std::string PromptRenderDTO::*, bool PromptRenderDTO::*,
                   int64_t PromptRenderDTO::*, double PromptRenderDTO::*>;
  using Value = std::variant<std::string, bool, int64_t, double>;
  static_assert(magic_enum::enum_count<Attr>() == 23,
                "PromptRenderDTO::members must stay aligned with Attr values");
  static constexpr std::array<MemberPtr, magic_enum::enum_count<Attr>()>
      members{
          &PromptRenderDTO::nickname,     &PromptRenderDTO::username,
          &PromptRenderDTO::hostname,     &PromptRenderDTO::cwd,
          &PromptRenderDTO::os_type,      &PromptRenderDTO::sysicon,
          &PromptRenderDTO::task_pending, &PromptRenderDTO::task_running,
          &PromptRenderDTO::task_paused,  &PromptRenderDTO::success_task,
          &PromptRenderDTO::failed_task,  &PromptRenderDTO::channel_num,
          &PromptRenderDTO::term_num,     &PromptRenderDTO::channel_ok,
          &PromptRenderDTO::channel_disconnected,
          &PromptRenderDTO::term_ok,
          &PromptRenderDTO::term_disconnected,
          &PromptRenderDTO::channel_name, &PromptRenderDTO::time_now,
          &PromptRenderDTO::elapsed,      &PromptRenderDTO::is_success,
          &PromptRenderDTO::ec_name,      &PromptRenderDTO::ec_code};

  [[nodiscard]] std::vector<std::pair<Attr, Value>> GetDict() const {
    std::vector<std::pair<Attr, Value>> out;
    static_assert(members.size() == FieldNames.size(),
                  "PromptRenderDTO::members and FieldNames size mismatch");
    out.reserve(FieldNames.size());
    for (size_t i = 0; i < FieldNames.size(); ++i) {
      const Attr attr = FieldNames[i];
      const MemberPtr &mp = members[i];
      std::visit(
          [&](auto member) { out.emplace_back(attr, Value{this->*member}); },
          mp);
    }
    return out;
  }

  [[nodiscard]] std::vector<std::pair<std::string, std::string>>
  GetStrDict() const {
    const auto dict = GetDict();
    std::vector<std::pair<std::string, std::string>> out;
    out.reserve(dict.size());
    for (const auto &entry : dict) {
      const std::string key = std::string(magic_enum::enum_name(entry.first));
      const std::string value = std::visit(
          [](const auto &item) -> std::string {
            using VT = std::decay_t<decltype(item)>;
            static_assert(
                std::is_same_v<VT, std::string> || std::is_same_v<VT, bool> ||
                    std::is_same_v<VT, int64_t> || std::is_same_v<VT, double>,
                "Unsupported type in PromptRenderDTO::Value");
            return AMStr::ToString(item);
          },
          entry.second);
      out.emplace_back(key, value);
    }
    return out;
  }

  template <typename T>
  bool GetFieldValue(Attr attr, T *out_value, ECM *rcm = nullptr) const {
    if (!out_value) {
      if (rcm) {
        *rcm = {EC::InvalidArg, "", "", "null output pointer"};
      }
      return false;
    }

    auto idx = magic_enum::enum_index(attr);
    if (!idx) {
      if (rcm) {
        *rcm = {EC::InvalidArg, "", "", "invalid attr"};
      }
      return false;
    }

    const auto &mp = members[*idx];
    bool ok = std::visit(
        [&](auto member) -> bool {
          using Field = std::decay_t<decltype(this->*member)>;
          if constexpr (std::is_assignable_v<T &, Field>) {
            *out_value = this->*member;
            return true;
          }
          if constexpr (std::is_integral_v<T> && std::is_integral_v<Field> &&
                        !std::is_same_v<T, bool>) {
            *out_value = static_cast<T>(this->*member);
            return true;
          }
          return false;
        },
        mp);

    if (!ok && rcm) {
      *rcm = {EC::InvalidArg, "", "", "type mismatch"};
    }
    return ok;
  }
};

} // namespace AMApplication::prompt
