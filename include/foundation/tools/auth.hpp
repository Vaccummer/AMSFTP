#pragma once

#include <string>
#include <string_view>

namespace AMAuth {
inline constexpr std::string_view kPasswordKey =
    "AMSFTP::FixedCompileTimeKey::DoNotReuse";
inline constexpr std::string_view kEncryptedPrefix = "enc:";

void SecureZero(std::string &value);
bool IsEncrypted(const std::string &value);
std::string HexEncode(const std::string &bytes);
std::string HexDecode(const std::string &hex);
std::string XorWithKey(const std::string &input);
std::string EncryptPassword(const std::string &plain);
std::string DecryptPassword(const std::string &stored);
} // namespace AMAuth
