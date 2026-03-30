#pragma once
#include "domain/host/HostDomainService.hpp"
#include "foundation/core/Enum.hpp"
#include "foundation/tools/string.hpp"
#include <algorithm>
#include <cctype>
#include <map>
#include <string>
#include <string_view>
#include <utility>

namespace AMDomain::var {
using ECM = std::pair<ErrorCode, std::string>;
using VarSet = std::map<std::string, std::map<std::string, std::string>>;
inline constexpr const char *kRoot = "UserVars";
inline constexpr const char *kPublic = "*";

inline bool IsValidVarname(std::string_view varname) {
  if (varname.empty()) {
    return false;
  }
  for (const auto ch : varname) {
    if (std::isalnum(static_cast<unsigned char>(ch)) || ch == '_') {
      continue;
    }
    return false;
  }
  return true;
}

/**
 * @brief Single variable record identified by domain + var name.
 */
struct VarInfo {
  std::string domain = "";
  std::string varname = "";
  std::string varvalue = "";

  /**
   * @brief Return true when this variable belongs to public domain.
   */
  [[nodiscard]] bool IsPublic() const { return domain == kPublic; }
};

struct VarSetArg {
  VarSet set = {};
};

/**
 * @brief Parsed variable token model shared by interface/domain utilities.
 */
struct ParsedVarToken {
  bool valid = false;
  bool explicit_domain = false;
  bool braced = false;
  std::string domain = "";
  std::string varname = "";
};

using VarRef = ParsedVarToken;

inline bool IsValidZoneName(std::string_view zone_name) {
  if (zone_name.empty()) {
    return false;
  }
  if (zone_name == kPublic) {
    return true;
  }
  return AMDomain::host::HostService::ValidateNickname(std::string(zone_name));
}

/**
 * @brief Parse one variable reference from `[pos, limit)`.
 */
inline bool ParseVarRefAt(const std::string &input, size_t pos, size_t limit,
                          bool allow_incomplete_brace,
                          bool allow_empty_varname, size_t *out_end,
                          VarRef *out_ref) {
  if (out_end) {
    *out_end = pos;
  }
  if (out_ref) {
    *out_ref = {};
  }
  if (pos >= input.size() || pos >= limit || input[pos] != '$') {
    return false;
  }

  const size_t bound = std::min(limit, input.size());
  size_t cursor = pos + 1;
  bool braced = false;
  if (cursor < bound && input[cursor] == '{') {
    braced = true;
    ++cursor;
  }

  size_t token_end = cursor;
  std::string body = {};
  if (braced) {
    size_t close = cursor;
    while (close < bound && input[close] != '}') {
      ++close;
    }
    if (close >= bound) {
      if (!allow_incomplete_brace) {
        return false;
      }
      body = input.substr(cursor, bound - cursor);
      token_end = bound;
    } else {
      body = input.substr(cursor, close - cursor);
      token_end = close + 1;
    }
  } else {
    size_t end = cursor;
    while (end < bound) {
      const char c = input[end];
      const bool allowed =
          std::isalnum(static_cast<unsigned char>(c)) || c == '_' ||
          c == '-' || c == ':' || c == '*';
      if (!allowed) {
        break;
      }
      ++end;
    }
    if (end == cursor) {
      return false;
    }
    body = input.substr(cursor, end - cursor);
    token_end = end;
  }

  if (body.empty()) {
    return false;
  }

  VarRef parsed = {};
  parsed.braced = braced;
  const size_t colon = body.find(':');
  if (colon == std::string::npos) {
    parsed.explicit_domain = false;
    parsed.domain.clear();
    parsed.varname = body;
    if (!IsValidVarname(parsed.varname)) {
      return false;
    }
  } else {
    parsed.explicit_domain = true;
    const std::string zone_raw = body.substr(0, colon);
    parsed.domain = zone_raw.empty() ? std::string(kPublic) : zone_raw;
    parsed.varname = body.substr(colon + 1);
    if (!IsValidZoneName(parsed.domain)) {
      return false;
    }
    if (parsed.varname.empty()) {
      if (!allow_empty_varname) {
        return false;
      }
    } else if (!IsValidVarname(parsed.varname)) {
      return false;
    }
  }

  parsed.valid = true;
  if (out_end) {
    *out_end = token_end;
  }
  if (out_ref) {
    *out_ref = std::move(parsed);
  }
  return true;
}

/**
 * @brief Parse one full variable token and require full-token match.
 */
inline bool ParseVarToken(const std::string &token, VarRef *out_ref) {
  size_t end = 0;
  VarRef parsed = {};
  if (!ParseVarRefAt(token, 0, token.size(), false, false, &end, &parsed) ||
      end != token.size() || !parsed.valid || parsed.varname.empty()) {
    if (out_ref) {
      *out_ref = {};
    }
    return false;
  }
  if (out_ref) {
    *out_ref = std::move(parsed);
  }
  return true;
}

inline bool ParseVarToken(const std::string &token) {
  return ParseVarToken(token, nullptr);
}

/**
 * @brief Build variable token text from parsed model.
 */
inline std::string BuildVarToken(const VarRef &ref, bool force_braced = false) {
  if (!ref.valid) {
    return "";
  }
  std::string body = {};
  if (ref.explicit_domain) {
    if (ref.domain.empty() || ref.domain == AMDomain::var::kPublic) {
      body = ":" + ref.varname;
    } else {
      body = ref.domain + ":" + ref.varname;
    }
  } else {
    body = ref.varname;
  }
  if (ref.braced || force_braced) {
    return "${" + body + "}";
  }
  return "$" + body;
}
} // namespace AMDomain::var
