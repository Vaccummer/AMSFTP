#pragma once

#include <string>
#include <string_view>

#ifndef AMSFTP_PASSWORD_KEY
#error "AMSFTP_PASSWORD_KEY must be defined via CMake compile definitions"
#endif

namespace AMAuth {
inline constexpr std::string_view kPasswordKey = AMSFTP_PASSWORD_KEY;
static_assert(kPasswordKey.size() >= 16,
              "AMSFTP_PASSWORD_KEY must be at least 16 characters");
inline constexpr std::string_view kEncryptedPrefix = "enc:";

void SecureZero(std::string &value);
bool IsEncrypted(const std::string &value);
std::string HexEncode(const std::string &bytes);
std::string HexDecode(const std::string &hex);
std::string EncryptPassword(const std::string &plain);
std::string DecryptPassword(const std::string &stored);
} // namespace AMAuth
