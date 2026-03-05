#include "domain/host/HostModel.hpp"
#include <mutex>

namespace {
/**
 * @brief Return whether the input is a local-loopback hostname.
 */
bool IsLocalHostname_(const std::string &hostname) {
  const std::string v = AMStr::lowercase(AMStr::Strip(hostname));
  return v == "localhost" || v == "127.0.0.1" || v == "::1";
}

/**
 * @brief Guarded global checker storage for hostname uniqueness validation.
 */
std::mutex &HostnameCheckerMutex_() {
  static std::mutex mtx;
  return mtx;
}

/**
 * @brief Accessor for hostname checker singleton storage.
 */
configkn::HostnameExistsChecker &HostnameChecker_() {
  static configkn::HostnameExistsChecker checker = {};
  return checker;
}
} // namespace

namespace configkn {
/**
 * @brief Bind hostname uniqueness checker used by validation.
 */
void SetHostnameExistsChecker(HostnameExistsChecker checker) {
  std::lock_guard<std::mutex> lock(HostnameCheckerMutex_());
  HostnameChecker_() = std::move(checker);
}

/**
 * @brief Validate one host attribute value.
 */
bool ValidateHostAttrValue(HostAttr attr, const std::string &value,
                           std::string *normalized, std::string *error_msg,
                           bool allow_exists_hostname,
                           bool allow_local_hostname, EC *code) {
  auto fail = [&error_msg, &code](EC ec, const std::string &msg) -> bool {
    if (code) {
      *code = ec;
    }
    if (error_msg) {
      *error_msg = msg;
    }
    return false;
  };

  auto set_norm = [&normalized](const std::string &v) {
    if (normalized) {
      *normalized = v;
    }
  };

  if (code) {
    *code = EC::Success;
  }

  switch (attr) {
  case HostAttr::Nickname: {
    const std::string v = AMStr::Strip(value);
    if (!ValidateNickname(v)) {
      return fail(EC::InvalidArg, "Nickname must match \\[A-Za-z0-9_-]+");
    }
    set_norm(v);
    return true;
  }
  case HostAttr::Hostname: {
    const std::string v = AMStr::Strip(value);
    if (v.empty()) {
      return fail(EC::InvalidArg, "Hostname cannot be empty");
    }
    if (!allow_local_hostname && IsLocalHostname_(v)) {
      return fail(EC::InvalidArg, "Local hostname is not allowed");
    }
    if (!allow_exists_hostname) {
      HostnameExistsChecker checker = {};
      {
        std::lock_guard<std::mutex> lock(HostnameCheckerMutex_());
        checker = HostnameChecker_();
      }
      if (checker) {
        try {
          if (checker(v)) {
            return fail(EC::KeyAlreadyExists, "Hostname already exists");
          }
        } catch (...) {
          return fail(EC::CommonFailure,
                      "hostname uniqueness checker callback failed");
        }
      }
    }
    set_norm(v);
    return true;
  }
  case HostAttr::Username: {
    const std::string v = AMStr::Strip(value);
    if (v.empty()) {
      return fail(EC::InvalidArg, "Username cannot be empty");
    }
    set_norm(v);
    return true;
  }
  case HostAttr::Port: {
    const std::string v = AMStr::Strip(value);
    int64_t parsed = 0;
    if (!AMJson::StrValueParse(v, &parsed) || parsed <= 0 || parsed > 65535) {
      return fail(EC::InvalidArg,
                  "Port must be an integer between 1 and 65535");
    }
    set_norm(std::to_string(parsed));
    return true;
  }
  case HostAttr::Protocol: {
    const std::string v = AMStr::lowercase(AMStr::Strip(value));
    if (v == "sftp" || v == "ftp" || v == "local") {
      set_norm(v);
      return true;
    }
    return fail(EC::InvalidArg, "Protocol must be sftp, ftp, or local");
  }
  case HostAttr::BufferSize: {
    const std::string v = AMStr::Strip(value);
    int64_t parsed = 0;
    if (!AMJson::StrValueParse(v, &parsed) || parsed <= 0) {
      return fail(EC::InvalidArg, "Buffer size must be a positive integer");
    }
    set_norm(std::to_string(parsed));
    return true;
  }
  case HostAttr::Compression: {
    const std::string v = AMStr::Strip(value);
    bool parsed = false;
    if (!AMJson::StrValueParse(v, &parsed)) {
      return fail(EC::InvalidArg, "Compression must be true or false");
    }
    set_norm(parsed ? "true" : "false");
    return true;
  }
  case HostAttr::CmdPrefix:
    set_norm(value);
    return true;
  case HostAttr::WrapCmd: {
    const std::string v = AMStr::Strip(value);
    bool parsed = false;
    if (!AMJson::StrValueParse(v, &parsed)) {
      return fail(EC::InvalidArg, "wrap_cmd must be true or false");
    }
    set_norm(parsed ? "true" : "false");
    return true;
  }
  case HostAttr::Password:
  case HostAttr::TrashDir:
  case HostAttr::LoginDir:
  case HostAttr::Keyfile:
    set_norm(value);
    return true;
  default:
    return fail(EC::InvalidArg, "unsupported host attribute");
  }
}
} // namespace configkn

