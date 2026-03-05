#include "application/client/FileCommandWorkflows.hpp"
#include "foundation/tools/enum_related.hpp"
#include "foundation/tools/string.hpp"

namespace AMApplication::FileCommandWorkflow {
/**
 * @brief Execute client-check workflow.
 */
ECM ExecuteCheckClients(IFileCommandGateway &gateway,
                        const std::vector<std::string> &nicknames, bool detail,
                        amf interrupt_flag) {
  return gateway.CheckClients(nicknames, detail, interrupt_flag);
}

/**
 * @brief Execute size workflow.
 */
ECM ExecuteGetSize(IFileCommandGateway &gateway,
                   const std::vector<std::string> &paths,
                   amf interrupt_flag) {
  return gateway.GetSize(paths, interrupt_flag);
}

/**
 * @brief Execute find workflow.
 */
ECM ExecuteFind(IFileCommandGateway &gateway, const std::string &path,
                SearchType type, amf interrupt_flag) {
  return gateway.Find(path, type, interrupt_flag);
}

/**
 * @brief Execute mkdir workflow.
 */
ECM ExecuteMkdir(IFileCommandGateway &gateway,
                 const std::vector<std::string> &paths,
                 amf interrupt_flag) {
  return gateway.Mkdir(paths, interrupt_flag);
}

/**
 * @brief Execute remove workflow.
 */
ECM ExecuteRemove(IFileCommandGateway &gateway,
                  const std::vector<std::string> &paths, bool permanent,
                  bool force, bool quiet, amf interrupt_flag) {
  return gateway.Remove(paths, permanent, force, quiet, interrupt_flag);
}

/**
 * @brief Execute walk workflow.
 */
ECM ExecuteWalk(IFileCommandGateway &gateway, const std::string &path,
                bool only_file, bool only_dir, bool show_all,
                bool ignore_special_file, bool quiet, amf interrupt_flag) {
  return gateway.Walk(path, only_file, only_dir, show_all, ignore_special_file,
                      quiet, interrupt_flag);
}

/**
 * @brief Execute tree workflow.
 */
ECM ExecuteTree(IFileCommandGateway &gateway, const std::string &path,
                int max_depth, bool only_dir, bool show_all,
                bool ignore_special_file, bool quiet, amf interrupt_flag) {
  return gateway.Tree(path, max_depth, only_dir, show_all, ignore_special_file,
                      quiet, interrupt_flag);
}

/**
 * @brief Execute realpath workflow.
 */
ECM ExecuteRealpath(IFileCommandGateway &gateway, const std::string &path,
                    amf interrupt_flag) {
  return gateway.Realpath(path, interrupt_flag);
}

/**
 * @brief Execute RTT workflow.
 */
ECM ExecuteRtt(IFileCommandGateway &gateway, int times, amf interrupt_flag) {
  return gateway.TestRtt(times, interrupt_flag);
}

/**
 * @brief Execute cd workflow.
 */
SessionWorkflowResult ExecuteCd(IFileCommandGateway &gateway,
                                const std::string &path, amf interrupt_flag,
                                bool from_history) {
  SessionWorkflowResult out = {};
  out.rcm = gateway.Cd(path, interrupt_flag, from_history);
  out.enter_interactive = isok(out.rcm);
  return out;
}

/**
 * @brief Execute shell-command workflow.
 */
ShellCommandResult ExecuteShellCommand(IFileCommandGateway &gateway,
                                       int timeout_ms,
                                       const std::string &cmd,
                                       amf interrupt_flag) {
  ShellCommandResult out = {};
  if (timeout_ms <= 0) {
    out.rcm = Err(EC::InvalidArg, "timeout_ms must be > 0");
    return out;
  }

  const std::string command = AMStr::Strip(cmd);
  if (command.empty()) {
    out.rcm = Err(EC::InvalidArg, "cmd_str cannot be empty");
    return out;
  }

  const std::pair<ECM, std::pair<std::string, int>> shell_result =
      gateway.ShellRun(command, timeout_ms, interrupt_flag);
  out.rcm = shell_result.first;
  out.output = shell_result.second.first;
  out.exit_code = shell_result.second.second;
  return out;
}
} // namespace AMApplication::FileCommandWorkflow
