#include "foundation/tools/auth.hpp"

namespace AMAuth {
namespace {
constexpr bool IsAsciiAlpha_(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

constexpr bool IsAsciiDigit_(char c) { return c >= '0' && c <= '9'; }

constexpr bool IsAllowedKeyChar_(char c) {
  if (IsAsciiAlpha_(c) || IsAsciiDigit_(c)) {
    return true;
  }
  return c == '_' || c == '-' || c == ':' || c == '.';
}

constexpr bool IsPasswordKeyFormatAllowed_(std::string_view key) {
  if (key.size() < 16 || key.size() > 128) {
    return false;
  }
  bool has_alpha = false;
  bool has_digit = false;
  for (char c : key) {
    if (!IsAllowedKeyChar_(c)) {
      return false;
    }
    has_alpha = has_alpha || IsAsciiAlpha_(c);
    has_digit = has_digit || IsAsciiDigit_(c);
  }
  return has_alpha && has_digit;
}
} // namespace

static_assert(IsPasswordKeyFormatAllowed_(kPasswordKey),
              "AMSFTP_PASSWORD_KEY format invalid: use 16-128 chars, only "
              "[A-Za-z0-9_.:-], and include both letters and digits.");
} // namespace AMAuth
