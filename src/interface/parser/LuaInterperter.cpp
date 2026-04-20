#include "foundation/tools/string.hpp"
#include "interface/parser/LuaInterpreter.hpp"

#include <cctype>
#include <cstdlib>
#include <string>

extern "C" {
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
}

namespace AMInterface::prompt {
namespace {

void PushLuaValue_(lua_State *L, const PromptVarValue &value) {
  if (!L) {
    return;
  }
  std::visit(
      [L](const auto &item) {
        using VT = std::decay_t<decltype(item)>;
        if constexpr (std::is_same_v<VT, std::monostate>) {
          lua_pushnil(L);
        } else if constexpr (std::is_same_v<VT, bool>) {
          lua_pushboolean(L, item ? 1 : 0);
        } else if constexpr (std::is_same_v<VT, int64_t>) {
          lua_pushinteger(L, static_cast<lua_Integer>(item));
        } else if constexpr (std::is_same_v<VT, double>) {
          lua_pushnumber(L, static_cast<lua_Number>(item));
        } else if constexpr (std::is_same_v<VT, std::string>) {
          lua_pushlstring(L, item.c_str(), item.size());
        }
      },
      value);
}

std::string ReadLuaError_(lua_State *L) {
  if (!L) {
    return "lua state is null";
  }
  const char *err = lua_tostring(L, -1);
  std::string msg = err ? std::string(err) : std::string("unknown lua error");
  lua_pop(L, 1);
  return msg;
}

size_t ExtractLuaLineNumber_(const std::string &msg) {
  size_t start = 0;
  while (start < msg.size()) {
    const size_t marker = msg.find("]:", start);
    if (marker == std::string::npos) {
      return 0;
    }
    size_t p = marker + 2;
    size_t q = p;
    while (q < msg.size() &&
           std::isdigit(static_cast<unsigned char>(msg[q])) != 0) {
      ++q;
    }
    if (q > p && q < msg.size() && msg[q] == ':') {
      return static_cast<size_t>(
          std::strtoull(msg.substr(p, q - p).c_str(), nullptr, 10));
    }
    start = marker + 2;
  }
  return 0;
}

std::string SourceLineAt_(const std::string &source, size_t line_number) {
  if (line_number == 0 || source.empty()) {
    return "";
  }
  size_t current_line = 1;
  size_t begin = 0;
  for (size_t i = 0; i <= source.size(); ++i) {
    const bool end = (i == source.size());
    if (end || source[i] == '\n') {
      if (current_line == line_number) {
        std::string out = source.substr(begin, i - begin);
        if (!out.empty() && out.back() == '\r') {
          out.pop_back();
        }
        out = AMStr::replace_all(out, "\t", "\\t");
        if (out.size() > 160) {
          out = out.substr(0, 157) + "...";
        }
        return out;
      }
      begin = i + 1;
      ++current_line;
    }
  }
  return "";
}

std::string BuildLuaErrorMessage_(const std::string &raw,
                                  const std::string &source) {
  const size_t line = ExtractLuaLineNumber_(raw);
  if (line == 0) {
    return raw;
  }
  const std::string line_text = SourceLineAt_(source, line);
  if (line_text.empty()) {
    return raw;
  }
  return AMStr::fmt("{} | line {}: {}", raw, line, line_text);
}

} // namespace

ECMData<std::string> LUARender(const PromptTemplateContext &context,
                               const PromptVarMap &vars) {
  lua_State *L = luaL_newstate();
  if (!L) {
    const std::string msg = "failed to create lua state";
    return {std::string{}, Err(EC::LUAExecutionError, "", "", msg)};
  }
  luaL_openlibs(L);

  for (const auto &entry : vars) {
    PushLuaValue_(L, entry.second);
    lua_setglobal(L, entry.first.c_str());
  }

  if (luaL_dostring(L, context.source.c_str()) != LUA_OK) {
    const std::string msg =
        BuildLuaErrorMessage_(ReadLuaError_(L), context.source);
    lua_close(L);
    return {std::string{}, Err(EC::InvalidArg, "", "", msg)};
  }

  if (!lua_isstring(L, -1)) {
    lua_close(L);
    return {std::string{},
            Err(EC::InvalidArg, "", "", "lua script did not return a string")};
  }

  size_t len = 0;
  const char *result = lua_tolstring(L, -1, &len);
  std::string output = result ? std::string(result, len) : std::string();
  lua_pop(L, 1);
  lua_close(L);
  return {std::move(output), OK};
}

} // namespace AMInterface::prompt
