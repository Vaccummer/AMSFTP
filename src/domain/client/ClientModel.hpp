#pragma once
#include "domain/host/HostModel.hpp"
#include "foundation/core/Enum.hpp"
#include "foundation/tools/time.hpp"
#include <optional>
#include <string>
#include <utility>

namespace AMDomain::client {

enum class OS_TYPE {
  Windows = -1,
  Unknown = -2,
  Uncertain = 0,
  Linux = 1,
  MacOS = 2,
  FreeBSD = 3,
  Unix = 4
};

/**
 * @brief Canonical trace severity model shared by client/log domains.
 */
enum class TraceLevel {
  Critical = 0,
  Error = 1,
  Warning = 2,
  Info = 3,
  Debug = 4,
};

/**
 * @brief Canonical trace source model shared by client/log domains.
 */
enum class TraceSource {
  Client = 0,
  Programm = 1,
};

enum class ClientStatus {
  NullHandle = -1,
  OK = 0,
  NotInitialized = 1,
  NoConnection = 2,
  ConnectionBroken = 3,
};

struct AuthCBInfo {
  /**
   * @brief Whether a password is required for authentication.
   */
  bool NeedPassword = false;

  /**
   * @brief Connection request context for the callback.
   */
  AMDomain::host::ConRequest request;

  /**
   * @brief The password being used in this authentication step (encrypted).
   */
  std::string password_n;

  /**
   * @brief Whether the provided password is correct.
   */
  bool iscorrect = false;

  /**
   * @brief Construct a callback info payload.
   */
  AuthCBInfo(bool need_password, AMDomain::host::ConRequest request,
             std::string password_n, bool iscorrect)
      : NeedPassword(need_password), request(std::move(request)),
        password_n(std::move(password_n)), iscorrect(iscorrect) {}
};

/**
 * @brief Canonical trace payload shared by client/log domains.
 */
struct TraceInfo {
  TraceSource source = TraceSource::Client;
  TraceLevel level = TraceLevel::Info;
  ErrorCode error_code = ErrorCode::Success;
  std::string nickname = "";
  std::string target = "";
  std::string action = "";
  std::string message = "";
  std::optional<AMDomain::host::ConRequest> request = std::nullopt;
  double timestamp = 0.0;

  /**
   * @brief Construct one default trace payload.
   */
  TraceInfo() = default;

  /**
   * @brief Construct one fully populated trace payload.
   */
  TraceInfo(TraceLevel level, ErrorCode error_code, std::string nickname,
            std::string target, std::string action, std::string message,
            std::optional<AMDomain::host::ConRequest> request = std::nullopt,
            TraceSource source = TraceSource::Client)
      : source(source), level(level), error_code(error_code),
        nickname(std::move(nickname)), target(std::move(target)),
        action(std::move(action)), message(std::move(message)),
        request(std::move(request)), timestamp(AMTime::seconds()) {}
};

struct ClientServiceArg {
  int heartbeat_interval_s = 60;
  int heartbeat_timeout_ms = 100;
};
} // namespace AMDomain::client
