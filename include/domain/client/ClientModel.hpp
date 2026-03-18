#pragma once
#include "domain/host/HostModel.hpp"
#include "foundation/Enum.hpp"
#include "foundation/tools/time.hpp"
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace AMDomain::client {
using ECM = std::pair<ErrorCode, std::string>;

/**
 * @brief Parsed client-qualified path token (`nickname@path`).
 */
struct ScopedPath {
  /**
   * @brief True when the path contains a nickname prefix.
   */
  bool is_match_forbidden = false;
  /**
   * @brief True when input explicitly specified a nickname prefix.
   */
  bool explicit_client = false;

  /**
   * @brief Resolved nickname (`local` for local-path forms).
   */
  std::string nickname = "";

  /**
   * @brief Path segment after nickname/prefix parsing.
   */
  std::string path = "";
};

/**
 * @brief Minimal workdir state required for path normalization.
 */
struct ClientWorkdirState {
  /**
   * @brief Home directory returned by client runtime.
   */
  std::string home_dir = "";

  /**
   * @brief Persisted login directory from host metadata.
   */
  std::string login_dir = "";

  /**
   * @brief Current working directory snapshot.
   */
  std::string cwd = "";
};

/**
 * @brief Connection execution options independent from request payload.
 */
struct ClientConnectOptions {
  /**
   * @brief Force reconnect/create when runtime already has the client.
   */
  bool force = false;

  /**
   * @brief Disable progress rendering when true.
   */
  bool quiet = false;

  /**
   * @brief Register newly connected client into manager state when true.
   */
  bool register_to_manager = true;

  /**
   * @brief Bootstrap timeout used for client factory creation.
   */
  int timeout_seconds = 10;
};

/**
 * @brief Full input payload consumed by client connection workflow.
 */
struct ClientConnectContext {
  /**
   * @brief Target connection request.
   */
  AMDomain::host::ConRequest request = {};

  /**
   * @brief Candidate private key paths.
   */
  std::vector<std::string> private_keys = {};

  /**
   * @brief Runtime connection options.
   */
  ClientConnectOptions options = {};
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
  OK = 0,
  NotInitialized = 1,
  NoConnection = 2,
  ConnectionBroken = 3,
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
} // namespace AMDomain::client
