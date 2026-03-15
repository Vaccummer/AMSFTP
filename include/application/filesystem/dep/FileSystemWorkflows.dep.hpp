#pragma once

#include "application/client/ClientSessionWorkflows.hpp"
#include "application/client/FileCommandWorkflows.hpp"
#include "domain/filesystem/FileSystemModel.hpp"
#include "foundation/DataClass.hpp"
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#if !defined(AMSFTP_SUPPRESS_DEPRECATED_HEADER_NOTICE)
#if defined(_MSC_VER)
#pragma message("AMSFTP deprecated header: include/application/filesystem/dep/FileSystemWorkflows.dep.hpp; prefer application/client/{ClientSessionWorkflows,FileCommandWorkflows}.hpp")
#elif defined(__clang__) || defined(__GNUC__)
#warning "AMSFTP deprecated header: include/application/filesystem/dep/FileSystemWorkflows.dep.hpp; prefer application/client/{ClientSessionWorkflows,FileCommandWorkflows}.hpp"
#endif
#endif

#define AMSFTP_DEPRECATED_FS_WORKFLOW                                          \
  [[deprecated("Use application/client/{ClientSessionWorkflows,FileCommandWorkflows}.hpp")]]

namespace AMApplication::filesystem {
using ClientProtocol = AMDomain::host::ClientProtocol;
using SessionMode = AMApplication::ClientWorkflow::SessionMode;
using SessionWorkflowResult =
    AMApplication::FileCommandWorkflow::SessionWorkflowResult;
using ShellCommandResult = AMApplication::FileCommandWorkflow::ShellCommandResult;

/**
 * @brief Deprecated compatibility request for protocol connect workflow.
 */
struct ProtocolConnectRequest {
  ClientProtocol protocol = ClientProtocol::UnInitilized;
  std::vector<std::string> targets = {};
  int64_t port = 0;
  std::string password = "";
  std::string keyfile = "";
};

/**
 * @brief Deprecated compatibility request for multi-nickname connect workflow.
 */
struct ConnectNicknamesRequest {
  std::vector<std::string> nicknames = {};
  bool force = false;
};

/**
 * @brief Deprecated compatibility request for batch path operations.
 */
struct PathBatchRequest {
  std::vector<std::string> paths = {};
  int timeout_ms = -1;
};

/**
 * @brief Deprecated compatibility request for list workflow.
 */
struct ListPathRequest {
  std::string path = "";
  bool list_like = false;
  bool show_all = false;
  int timeout_ms = -1;
};

/**
 * @brief Deprecated compatibility request for remove workflow.
 */
struct RemoveRequest {
  std::vector<std::string> paths = {};
  AMDomain::filesystem::RemovePolicy policy = {};
  int timeout_ms = -1;
};

/**
 * @brief Deprecated compatibility request for walk workflow.
 */
struct WalkRequest {
  std::string path = "";
  AMDomain::filesystem::WalkPolicy policy = {};
  int timeout_ms = -1;
};

/**
 * @brief Deprecated compatibility request for tree workflow.
 */
struct TreeRequest {
  std::string path = "";
  AMDomain::filesystem::TreePolicy policy = {};
  int timeout_ms = -1;
};

/**
 * @brief Deprecated compatibility request for shell workflow.
 */
struct ShellCommandRequest {
  std::string cmd = "";
  int timeout_ms = -1;
};

/**
 * @brief Deprecated compatibility session gateway interface.
 */
class IFileSystemSessionGateway {
public:
  virtual ~IFileSystemSessionGateway() = default;

  virtual ECM ConnectNickname(const std::string &nickname, bool force,
                              bool switch_client,
                              amf interrupt_flag = nullptr) = 0;
  virtual ECM
  ConnectProtocol(ClientProtocol protocol,
                  const AMDomain::filesystem::ProtocolConnectTarget &target,
                  int64_t port, const std::string &password,
                  const std::string &keyfile, amf interrupt_flag = nullptr) = 0;
  virtual ECM ChangeCurrentClient(const std::string &nickname,
                                  amf interrupt_flag = nullptr) = 0;
  virtual ECM ListClients(bool detail, amf interrupt_flag = nullptr) = 0;
  virtual ECM DisconnectClients(const std::vector<std::string> &nicknames) = 0;
};

/**
 * @brief Deprecated compatibility command gateway interface.
 */
class IFileSystemCommandGateway {
public:
  virtual ~IFileSystemCommandGateway() = default;

  virtual ECM CheckClients(const std::vector<std::string> &nicknames,
                           bool detail, amf interrupt_flag = nullptr) = 0;
  virtual ECM StatPaths(const PathBatchRequest &request,
                        amf interrupt_flag = nullptr) = 0;
  virtual ECM ListPath(const ListPathRequest &request,
                       amf interrupt_flag = nullptr) = 0;
  virtual ECM GetSize(const PathBatchRequest &request,
                      amf interrupt_flag = nullptr) = 0;
  virtual ECM Find(const std::string &path, SearchType type,
                   amf interrupt_flag = nullptr, int timeout_ms = -1) = 0;
  virtual ECM Mkdir(const PathBatchRequest &request,
                    amf interrupt_flag = nullptr) = 0;
  virtual ECM Remove(const RemoveRequest &request,
                     amf interrupt_flag = nullptr) = 0;
  virtual ECM Walk(const WalkRequest &request,
                   amf interrupt_flag = nullptr) = 0;
  virtual ECM Tree(const TreeRequest &request,
                   amf interrupt_flag = nullptr) = 0;
  virtual ECM Realpath(const std::string &path, amf interrupt_flag = nullptr,
                       int timeout_ms = -1) = 0;
  virtual ECM TestRtt(int times, amf interrupt_flag = nullptr) = 0;
  virtual ECM Cd(const std::string &path, amf interrupt_flag = nullptr,
                 bool from_history = false) = 0;
  virtual std::pair<ECM, std::pair<std::string, int>>
  ShellRun(const ShellCommandRequest &request,
           amf interrupt_flag = nullptr) = 0;
};

namespace detail {
class SessionGatewayAdapter final
    : public AMApplication::ClientWorkflow::IClientSessionGateway {
public:
  explicit SessionGatewayAdapter(IFileSystemSessionGateway &gateway)
      : gateway_(gateway) {}

  ECM ConnectNickname(const std::string &nickname, bool force,
                      bool switch_client, amf interrupt_flag) override {
    return gateway_.ConnectNickname(nickname, force, switch_client,
                                    interrupt_flag);
  }

  ECM ChangeCurrentClient(const std::string &nickname,
                          amf interrupt_flag) override {
    return gateway_.ChangeCurrentClient(nickname, interrupt_flag);
  }

  ECM ConnectSftp(const std::string &nickname, const std::string &user_at_host,
                  int64_t port, const std::string &password,
                  const std::string &keyfile, amf interrupt_flag) override {
    return gateway_.ConnectProtocol(
        ClientProtocol::SFTP, AMDomain::filesystem::ProtocolConnectTarget{
                                  nickname, user_at_host},
        port, password, keyfile, interrupt_flag);
  }

  ECM ConnectFtp(const std::string &nickname, const std::string &user_at_host,
                 int64_t port, const std::string &password,
                 const std::string &keyfile, amf interrupt_flag) override {
    return gateway_.ConnectProtocol(
        ClientProtocol::FTP, AMDomain::filesystem::ProtocolConnectTarget{
                                 nickname, user_at_host},
        port, password, keyfile, interrupt_flag);
  }

  ECM ListClients(bool detail, amf interrupt_flag) override {
    return gateway_.ListClients(detail, interrupt_flag);
  }

  ECM DisconnectClients(const std::vector<std::string> &nicknames) override {
    return gateway_.DisconnectClients(nicknames);
  }

  ECM StatPaths(const std::vector<std::string> &paths,
                amf interrupt_flag) override {
    return gateway_.StatPaths(PathBatchRequest{paths, -1}, interrupt_flag);
  }

  ECM ListPath(const std::string &path, bool list_like, bool show_all,
               amf interrupt_flag) override {
    return gateway_.ListPath(ListPathRequest{path, list_like, show_all, -1},
                             interrupt_flag);
  }

private:
  IFileSystemSessionGateway &gateway_;
};

class CommandGatewayAdapter final
    : public AMApplication::FileCommandWorkflow::IFileCommandGateway {
public:
  explicit CommandGatewayAdapter(IFileSystemCommandGateway &gateway)
      : gateway_(gateway) {}

  ECM CheckClients(const std::vector<std::string> &nicknames, bool detail,
                   amf interrupt_flag, int timeout_ms = -1) override {
    (void)timeout_ms;
    return gateway_.CheckClients(nicknames, detail, interrupt_flag);
  }

  ECM GetSize(const std::vector<std::string> &paths, amf interrupt_flag,
              int timeout_ms = -1) override {
    return gateway_.GetSize(PathBatchRequest{paths, timeout_ms}, interrupt_flag);
  }

  ECM Find(const std::string &path, SearchType type, amf interrupt_flag,
           int timeout_ms = -1) override {
    return gateway_.Find(path, type, interrupt_flag, timeout_ms);
  }

  ECM Mkdir(const std::vector<std::string> &paths, amf interrupt_flag,
            int timeout_ms = -1) override {
    return gateway_.Mkdir(PathBatchRequest{paths, timeout_ms}, interrupt_flag);
  }

  ECM Remove(const std::vector<std::string> &paths, bool permanent, bool force,
             bool quiet, amf interrupt_flag, int timeout_ms = -1) override {
    RemoveRequest request{};
    request.paths = paths;
    request.timeout_ms = timeout_ms;
    request.policy.permanent = permanent;
    request.policy.force = force;
    request.policy.quiet = quiet;
    return gateway_.Remove(request, interrupt_flag);
  }

  ECM Walk(const std::string &path, bool only_file, bool only_dir,
           bool show_all, bool ignore_special_file, bool quiet,
           amf interrupt_flag, int timeout_ms = -1) override {
    WalkRequest request{};
    request.path = path;
    request.timeout_ms = timeout_ms;
    request.policy.only_file = only_file;
    request.policy.only_dir = only_dir;
    request.policy.show_all = show_all;
    request.policy.ignore_special_file = ignore_special_file;
    request.policy.quiet = quiet;
    return gateway_.Walk(request, interrupt_flag);
  }

  ECM Tree(const std::string &path, int max_depth, bool only_dir, bool show_all,
           bool ignore_special_file, bool quiet, amf interrupt_flag,
           int timeout_ms = -1) override {
    TreeRequest request{};
    request.path = path;
    request.timeout_ms = timeout_ms;
    request.policy.max_depth = max_depth;
    request.policy.only_dir = only_dir;
    request.policy.show_all = show_all;
    request.policy.ignore_special_file = ignore_special_file;
    request.policy.quiet = quiet;
    return gateway_.Tree(request, interrupt_flag);
  }

  ECM Realpath(const std::string &path, amf interrupt_flag,
               int timeout_ms = -1) override {
    return gateway_.Realpath(path, interrupt_flag, timeout_ms);
  }

  ECM TestRtt(int times, amf interrupt_flag) override {
    return gateway_.TestRtt(times, interrupt_flag);
  }

  ECM Cd(const std::string &path, amf interrupt_flag,
         bool from_history = false) override {
    return gateway_.Cd(path, interrupt_flag, from_history);
  }

  std::pair<ECM, std::pair<std::string, int>>
  ShellRun(const std::string &cmd, int max_time_ms, amf interrupt_flag) override {
    return gateway_.ShellRun(ShellCommandRequest{cmd, max_time_ms},
                             interrupt_flag);
  }

private:
  IFileSystemCommandGateway &gateway_;
};
} // namespace detail

AMSFTP_DEPRECATED_FS_WORKFLOW [[nodiscard]] inline bool
IsInteractiveMode(const SessionMode &mode) {
  return AMApplication::ClientWorkflow::IsInteractiveMode(mode);
}

inline ECM
ResolveProtocolConnectTarget(const ProtocolConnectRequest &request,
                             AMDomain::filesystem::ProtocolConnectTarget *out) {
  if (!out) {
    return Err(EC::InvalidArg, "null output target");
  }
  if (request.targets.size() == 1) {
    out->nickname = "";
    out->user_at_host = request.targets.front();
  } else if (request.targets.size() == 2) {
    out->nickname = request.targets.front();
    out->user_at_host = request.targets.back();
  } else {
    return Err(EC::InvalidArg, "protocol connect requires user@host");
  }
  if (out->user_at_host.find('@') == std::string::npos) {
    return Err(EC::InvalidArg, "Invalid user@host format");
  }
  return Ok();
}

AMSFTP_DEPRECATED_FS_WORKFLOW inline SessionWorkflowResult
ExecuteProtocolConnect(IFileSystemSessionGateway &gateway,
                       const ProtocolConnectRequest &request,
                       amf interrupt_flag = nullptr) {
  SessionWorkflowResult out = {};
  AMDomain::filesystem::ProtocolConnectTarget target{};
  out.rcm = ResolveProtocolConnectTarget(request, &target);
  if (!isok(out.rcm)) {
    return out;
  }
  out.rcm =
      gateway.ConnectProtocol(request.protocol, target, request.port,
                              request.password, request.keyfile, interrupt_flag);
  out.enter_interactive = isok(out.rcm);
  return out;
}

AMSFTP_DEPRECATED_FS_WORKFLOW inline SessionWorkflowResult
ExecuteConnectNicknames(IFileSystemSessionGateway &gateway,
                        const ConnectNicknamesRequest &request,
                        const SessionMode &mode,
                        amf interrupt_flag = nullptr) {
  detail::SessionGatewayAdapter adapter(gateway);
  return AMApplication::ClientWorkflow::ConnectNicknames(
      adapter, request.nicknames, request.force, mode, interrupt_flag);
}

AMSFTP_DEPRECATED_FS_WORKFLOW inline ECM
ExecuteCheckClients(IFileSystemCommandGateway &gateway,
                    const std::vector<std::string> &nicknames, bool detail,
                    amf interrupt_flag = nullptr) {
  detail::CommandGatewayAdapter adapter(gateway);
  return AMApplication::FileCommandWorkflow::ExecuteCheckClients(
      adapter, nicknames, detail, interrupt_flag);
}

AMSFTP_DEPRECATED_FS_WORKFLOW inline ECM
ExecuteStatPaths(IFileSystemCommandGateway &gateway,
                 const PathBatchRequest &request,
                 amf interrupt_flag = nullptr) {
  ECM status = Ok();
  for (const auto &path : request.paths) {
    const ECM rcm = gateway.StatPaths(PathBatchRequest{{path}, request.timeout_ms},
                                      interrupt_flag);
    if (!isok(rcm)) {
      status = rcm;
    }
  }
  return status;
}

AMSFTP_DEPRECATED_FS_WORKFLOW inline ECM
ExecuteListPath(IFileSystemCommandGateway &gateway,
                const ListPathRequest &request,
                amf interrupt_flag = nullptr) {
  return gateway.ListPath(request, interrupt_flag);
}

AMSFTP_DEPRECATED_FS_WORKFLOW inline ECM
ExecuteGetSize(IFileSystemCommandGateway &gateway,
               const PathBatchRequest &request,
               amf interrupt_flag = nullptr) {
  detail::CommandGatewayAdapter adapter(gateway);
  return AMApplication::FileCommandWorkflow::ExecuteGetSize(
      adapter, request.paths, interrupt_flag);
}

AMSFTP_DEPRECATED_FS_WORKFLOW inline ECM
ExecuteMkdir(IFileSystemCommandGateway &gateway,
             const PathBatchRequest &request, amf interrupt_flag = nullptr) {
  detail::CommandGatewayAdapter adapter(gateway);
  return AMApplication::FileCommandWorkflow::ExecuteMkdir(
      adapter, request.paths, interrupt_flag);
}

AMSFTP_DEPRECATED_FS_WORKFLOW inline ECM
ExecuteRemove(IFileSystemCommandGateway &gateway, const RemoveRequest &request,
              amf interrupt_flag = nullptr) {
  detail::CommandGatewayAdapter adapter(gateway);
  return AMApplication::FileCommandWorkflow::ExecuteRemove(
      adapter, request.paths, request.policy.permanent, request.policy.force,
      request.policy.quiet, interrupt_flag);
}

AMSFTP_DEPRECATED_FS_WORKFLOW inline ECM
ExecuteWalk(IFileSystemCommandGateway &gateway, const WalkRequest &request,
            amf interrupt_flag = nullptr) {
  detail::CommandGatewayAdapter adapter(gateway);
  return AMApplication::FileCommandWorkflow::ExecuteWalk(
      adapter, request.path, request.policy.only_file, request.policy.only_dir,
      request.policy.show_all, request.policy.ignore_special_file,
      request.policy.quiet, interrupt_flag);
}

AMSFTP_DEPRECATED_FS_WORKFLOW inline ECM
ExecuteTree(IFileSystemCommandGateway &gateway, const TreeRequest &request,
            amf interrupt_flag = nullptr) {
  detail::CommandGatewayAdapter adapter(gateway);
  return AMApplication::FileCommandWorkflow::ExecuteTree(
      adapter, request.path, request.policy.max_depth, request.policy.only_dir,
      request.policy.show_all, request.policy.ignore_special_file,
      request.policy.quiet, interrupt_flag);
}

AMSFTP_DEPRECATED_FS_WORKFLOW inline ECM
ExecuteRealpath(IFileSystemCommandGateway &gateway, const std::string &path,
                amf interrupt_flag = nullptr, int timeout_ms = -1) {
  detail::CommandGatewayAdapter adapter(gateway);
  return AMApplication::FileCommandWorkflow::ExecuteRealpath(
      adapter, path, interrupt_flag);
}

AMSFTP_DEPRECATED_FS_WORKFLOW inline ECM
ExecuteRtt(IFileSystemCommandGateway &gateway, int times,
           amf interrupt_flag = nullptr) {
  detail::CommandGatewayAdapter adapter(gateway);
  return AMApplication::FileCommandWorkflow::ExecuteRtt(adapter, times,
                                                        interrupt_flag);
}

AMSFTP_DEPRECATED_FS_WORKFLOW inline SessionWorkflowResult
ExecuteCd(IFileSystemCommandGateway &gateway, const std::string &path,
          amf interrupt_flag = nullptr, bool from_history = false) {
  detail::CommandGatewayAdapter adapter(gateway);
  return AMApplication::FileCommandWorkflow::ExecuteCd(adapter, path,
                                                       interrupt_flag,
                                                       from_history);
}

AMSFTP_DEPRECATED_FS_WORKFLOW inline ShellCommandResult
ExecuteShellCommand(IFileSystemCommandGateway &gateway,
                    const ShellCommandRequest &request,
                    amf interrupt_flag = nullptr) {
  detail::CommandGatewayAdapter adapter(gateway);
  return AMApplication::FileCommandWorkflow::ExecuteShellCommand(
      adapter, request.timeout_ms, request.cmd, interrupt_flag);
}
} // namespace AMApplication::filesystem

#undef AMSFTP_DEPRECATED_FS_WORKFLOW
