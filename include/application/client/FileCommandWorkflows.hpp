#pragma once

#include "foundation/DataClass.hpp"
#include <string>
#include <utility>
#include <vector>

namespace AMApplication::FileCommandWorkflow {
/**
 * @brief Result payload for shell-command workflow execution.
 */
struct ShellCommandResult {
  /**
   * @brief Workflow status code and message.
   */
  ECM rcm = {EC::Success, ""};

  /**
   * @brief Command stdout/stderr text payload.
   */
  std::string output;

  /**
   * @brief Command process exit code.
   */
  int exit_code = 0;
};

/**
 * @brief Result payload for workflows that may request interactive loop.
 */
struct SessionWorkflowResult {
  /**
   * @brief Workflow status code and message.
   */
  ECM rcm = {EC::Success, ""};

  /**
   * @brief Whether caller should enter/keep interactive loop.
   */
  bool enter_interactive = false;
};

/**
 * @brief Application port for file/client command operations.
 */
class IFileCommandGateway {
public:
  /**
   * @brief Virtual destructor for polymorphic gateway.
   */
  virtual ~IFileCommandGateway() = default;

  /**
   * @brief Check clients by nickname list.
   */
  virtual ECM CheckClients(const std::vector<std::string> &nicknames,
                           bool detail, amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Print size for one or more paths.
   */
  virtual ECM GetSize(const std::vector<std::string> &paths,
                      amf interrupt_flag = nullptr, int timeout_ms = -1) = 0;

  /**
   * @brief Run find on one path.
   */
  virtual ECM Find(const std::string &path, SearchType type = SearchType::All,
                   amf interrupt_flag = nullptr, int timeout_ms = -1) = 0;

  /**
   * @brief Create directories for one or more paths.
   */
  virtual ECM Mkdir(const std::vector<std::string> &paths,
                    amf interrupt_flag = nullptr, int timeout_ms = -1) = 0;

  /**
   * @brief Remove one or more paths.
   */
  virtual ECM Remove(const std::vector<std::string> &paths, bool permanent,
                     bool force, bool quiet = false,
                     amf interrupt_flag = nullptr, int timeout_ms = -1) = 0;

  /**
   * @brief Walk one path.
   */
  virtual ECM Walk(const std::string &path, bool only_file = false,
                   bool only_dir = false, bool show_all = false,
                   bool ignore_special_file = true, bool quiet = false,
                   amf interrupt_flag = nullptr, int timeout_ms = -1) = 0;

  /**
   * @brief Print one path tree.
   */
  virtual ECM Tree(const std::string &path, int max_depth = -1,
                   bool only_dir = false, bool show_all = false,
                   bool ignore_special_file = true, bool quiet = false,
                   amf interrupt_flag = nullptr, int timeout_ms = -1) = 0;

  /**
   * @brief Resolve one real path.
   */
  virtual ECM Realpath(const std::string &path, amf interrupt_flag = nullptr,
                       int timeout_ms = -1) = 0;

  /**
   * @brief Measure RTT for current client.
   */
  virtual ECM TestRtt(int times = 1, amf interrupt_flag = nullptr) = 0;

  /**
   * @brief Change current workdir.
   */
  virtual ECM Cd(const std::string &path, amf interrupt_flag = nullptr,
                 bool from_history = false) = 0;

  /**
   * @brief Run one shell command.
   */
  virtual std::pair<ECM, std::pair<std::string, int>>
  ShellRun(const std::string &cmd, int max_time_ms = -1,
           amf interrupt_flag = nullptr) = 0;
};

/**
 * @brief Execute client-check workflow.
 */
ECM ExecuteCheckClients(IFileCommandGateway &gateway,
                        const std::vector<std::string> &nicknames, bool detail,
                        amf interrupt_flag = nullptr);

/**
 * @brief Execute size workflow.
 */
ECM ExecuteGetSize(IFileCommandGateway &gateway,
                   const std::vector<std::string> &paths,
                   amf interrupt_flag = nullptr);

/**
 * @brief Execute find workflow.
 */
ECM ExecuteFind(IFileCommandGateway &gateway, const std::string &path,
                SearchType type = SearchType::All,
                amf interrupt_flag = nullptr);

/**
 * @brief Execute mkdir workflow.
 */
ECM ExecuteMkdir(IFileCommandGateway &gateway,
                 const std::vector<std::string> &paths,
                 amf interrupt_flag = nullptr);

/**
 * @brief Execute remove workflow.
 */
ECM ExecuteRemove(IFileCommandGateway &gateway,
                  const std::vector<std::string> &paths, bool permanent,
                  bool force, bool quiet, amf interrupt_flag = nullptr);

/**
 * @brief Execute walk workflow.
 */
ECM ExecuteWalk(IFileCommandGateway &gateway, const std::string &path,
                bool only_file, bool only_dir, bool show_all,
                bool ignore_special_file, bool quiet,
                amf interrupt_flag = nullptr);

/**
 * @brief Execute tree workflow.
 */
ECM ExecuteTree(IFileCommandGateway &gateway, const std::string &path,
                int max_depth, bool only_dir, bool show_all,
                bool ignore_special_file, bool quiet,
                amf interrupt_flag = nullptr);

/**
 * @brief Execute realpath workflow.
 */
ECM ExecuteRealpath(IFileCommandGateway &gateway, const std::string &path,
                    amf interrupt_flag = nullptr);

/**
 * @brief Execute RTT workflow.
 */
ECM ExecuteRtt(IFileCommandGateway &gateway, int times,
               amf interrupt_flag = nullptr);

/**
 * @brief Execute cd workflow.
 */
SessionWorkflowResult ExecuteCd(IFileCommandGateway &gateway,
                                const std::string &path,
                                amf interrupt_flag = nullptr,
                                bool from_history = false);

/**
 * @brief Execute shell-command workflow.
 */
ShellCommandResult ExecuteShellCommand(IFileCommandGateway &gateway,
                                       int timeout_ms, const std::string &cmd,
                                       amf interrupt_flag = nullptr);
} // namespace AMApplication::FileCommandWorkflow
