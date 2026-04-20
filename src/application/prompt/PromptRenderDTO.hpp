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
    client_connected = 2,
    username = 3,
    hostname = 4,
    cwd = 5,
    os_type = 6,
    sysicon = 7,
    task_pending = 8,
    task_running = 9,
    task_paused = 10,
    task_num = 11,
    time_now = 12,
    time_clock = 13,
    elapsed = 14,
    success = 15,
    ec_name = 16,
  };

  std::string nickname = "local";
  bool client_connected = true;
  std::string username = "";
  std::string hostname = "";
  std::string cwd = "/";
  std::string os_type = "windows";
  std::string sysicon = "PC";
  int64_t task_pending = 0;
  int64_t task_running = 0;
  int64_t task_paused = 0;
  int64_t task_num = 0;
  std::string time_now = "";
  std::string time_clock = "";
  std::string elapsed = "";
  bool success = true;
  std::string ec_name = "";

  static constexpr auto FieldNames = magic_enum::enum_values<Attr>();
  using MemberPtr =
      std::variant<std::string PromptRenderDTO::*, bool PromptRenderDTO::*,
                   int64_t PromptRenderDTO::*, double PromptRenderDTO::*>;
  using Value = std::variant<std::string, bool, int64_t, double>;
  static_assert(magic_enum::enum_count<Attr>() == 16,
                "PromptRenderDTO::members must stay aligned with Attr values");
  static constexpr std::array<MemberPtr, magic_enum::enum_count<Attr>()>
      members{
          &PromptRenderDTO::nickname,     &PromptRenderDTO::client_connected,
          &PromptRenderDTO::username,     &PromptRenderDTO::hostname,
          &PromptRenderDTO::cwd,          &PromptRenderDTO::os_type,
          &PromptRenderDTO::sysicon,      &PromptRenderDTO::task_pending,
          &PromptRenderDTO::task_running, &PromptRenderDTO::task_paused,
          &PromptRenderDTO::task_num,     &PromptRenderDTO::time_now,
          &PromptRenderDTO::time_clock,   &PromptRenderDTO::elapsed,
          &PromptRenderDTO::success,      &PromptRenderDTO::ec_name};

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
