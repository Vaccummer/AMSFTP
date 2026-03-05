#pragma once

#include "foundation/DataClass.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace AMApplication::ClientWorkflow {
/**
 * @brief Session mode flags used by application-level client workflows.
 */
struct SessionMode {
  /**
   * @brief Force commands to behave as interactive operations.
   */
  bool enforce_interactive = false;

  /**
   * @brief Runtime interactive state from current session.
   */
  bool current_interactive = false;
};

/**
 * @brief Application result for workflows that may request interactive loop.
 */
struct SessionWorkflowResult {
  /**
   * @brief Status code and message.
   */
  ECM rcm = {EC::Success, ""};

  /**
   * @brief Whether caller should enter/keep interactive loop.
   */
  bool enter_interactive = false;
};

/**
 * @brief Parsed target for protocol connection commands.
 */
struct ProtocolConnectTarget {
  /**
   * @brief Optional persisted nickname.
   */
  std::string nickname;

  /**
   * @brief Raw `user@host` token.
   */
  std::string user_at_host;
};

/**
 * @brief Application port for client-session operations.
 */
class IClientSessionGateway {
public:
  /**
   * @brief Virtual destructor for polymorphic gateway.
   */
  virtual ~IClientSessionGateway() = default;

  /**
   * @brief Connect one configured nickname.
   */
  virtual ECM ConnectNickname(const std::string &nickname, bool force,
                              bool switch_client,
                              amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Change current active client nickname.
   */
  virtual ECM ChangeCurrentClient(const std::string &nickname,
                                  amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Connect one SFTP target.
   */
  virtual ECM ConnectSftp(const std::string &nickname,
                          const std::string &user_at_host, int64_t port,
                          const std::string &password,
                          const std::string &keyfile,
                          amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Connect one FTP target.
   */
  virtual ECM ConnectFtp(const std::string &nickname,
                         const std::string &user_at_host, int64_t port,
                         const std::string &password,
                         const std::string &keyfile,
                         amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Print current client table.
   */
  virtual ECM ListClients(bool detail, amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Remove one or more clients by nickname list.
   */
  virtual ECM DisconnectClients(const std::vector<std::string> &nicknames) = 0;

  /**
   * @brief Print stat info for one or more resolved paths.
   */
  virtual ECM StatPaths(const std::vector<std::string> &paths,
                        amf interrupt_flag = nullptr) = 0;

  /**
   * @brief List directory entries for one resolved path.
   */
  virtual ECM ListPath(const std::string &path, bool list_like, bool show_all,
                       amf interrupt_flag = nullptr) = 0;
};

/**
 * @brief Return true when caller should run interactive-only path.
 */
[[nodiscard]] bool IsInteractiveMode(const SessionMode &mode);

/**
 * @brief Parse protocol targets from `[user@host]` or `[nickname user@host]`.
 *
 * @param targets Raw positional target list.
 * @param protocol_name Protocol label used in validation error message.
 * @param out_target Parsed result.
 * @return Validation result.
 */
ECM ResolveProtocolTarget(const std::vector<std::string> &targets,
                          const std::string &protocol_name,
                          ProtocolConnectTarget *out_target);

/**
 * @brief Run `sftp`/`ftp` style connect workflow.
 *
 * @param gateway Session gateway port.
 * @param protocol Connection protocol.
 * @param targets One or two targets from CLI parser.
 * @param port Destination port.
 * @param password Optional password.
 * @param keyfile Optional key file.
 * @param interrupt_flag Optional task-control token.
 * @return Result and enter-interactive hint.
 */
SessionWorkflowResult
ConnectProtocolClient(IClientSessionGateway &gateway, ClientProtocol protocol,
                      const std::vector<std::string> &targets, int64_t port,
                      const std::string &password, const std::string &keyfile,
                      amf interrupt_flag = nullptr);

/**
 * @brief Run `ch` style workflow with interactive/non-interactive behavior.
 *
 * @param gateway Session gateway port.
 * @param nickname Target nickname.
 * @param mode Session mode flags.
 * @param interrupt_flag Optional task-control token.
 * @return Result and enter-interactive hint.
 */
SessionWorkflowResult ChangeClient(IClientSessionGateway &gateway,
                                   const std::string &nickname,
                                   const SessionMode &mode,
                                   amf interrupt_flag = nullptr);

/**
 * @brief Run multi-target `connect` orchestration.
 *
 * In non-interactive mode, this workflow switches back to local client after
 * successful pre-connect to keep command-mode semantics.
 *
 * @param gateway Session gateway port.
 * @param nicknames Target nicknames.
 * @param force Whether to rebuild existing clients.
 * @param mode Session mode flags.
 * @param interrupt_flag Optional task-control token.
 * @return Result and enter-interactive hint.
 */
SessionWorkflowResult
ConnectNicknames(IClientSessionGateway &gateway,
                 const std::vector<std::string> &nicknames, bool force,
                 const SessionMode &mode, amf interrupt_flag = nullptr);

/**
 * @brief Execute client-list workflow.
 */
ECM ExecuteClientList(IClientSessionGateway &gateway, bool detail,
                      amf interrupt_flag = nullptr);

/**
 * @brief Execute client-disconnect workflow.
 */
ECM ExecuteClientDisconnect(IClientSessionGateway &gateway,
                            const std::vector<std::string> &nicknames);

/**
 * @brief Execute path-stat workflow.
 */
ECM ExecuteStatPaths(IClientSessionGateway &gateway,
                     const std::vector<std::string> &paths,
                     amf interrupt_flag = nullptr);

/**
 * @brief Execute path-list workflow.
 */
ECM ExecuteListPath(IClientSessionGateway &gateway, const std::string &path,
                    bool list_like, bool show_all,
                    amf interrupt_flag = nullptr);
} // namespace AMApplication::ClientWorkflow
