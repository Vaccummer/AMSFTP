#include "interface/cli/CLIBind.hpp"
#include "CLI/App.hpp"
#include "application/log/LoggerAppService.hpp"
#include "foundation/tools/string.hpp"
#include "foundation/tools/time.hpp"
#include "interface/parser/CommandTree.hpp"

#include <algorithm>
#include <atomic>
#include <iostream>
#include <string>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace AMInterface::cli {

using AMInterface::parser::AMCommandArgSemantic;
using AMInterface::parser::CommandNode;

namespace {
using TraceLevel = AMDomain::client::TraceLevel;

TraceLevel CommandTraceLevel_(const ECM &rcm) {
  if ((rcm)) {
    return TraceLevel::Info;
  }
  if (rcm.code == EC::Terminate || rcm.code == EC::OperationTimeout ||
      rcm.code == EC::ConfigCanceled) {
    return TraceLevel::Warning;
  }
  return TraceLevel::Error;
}

std::string CommandTraceMode_(const CliRunContext &ctx) {
  const bool interactive =
      ctx.is_interactive && ctx.is_interactive->load(std::memory_order_relaxed);
  return interactive ? std::string("interactive") : std::string("single");
}

void TraceProgramCommand_(const CLIServices &managers, TraceLevel level,
                          EC code, const std::string &command,
                          const std::string &action,
                          const std::string &message) {
  if (!managers.application.log_manager.IsReady()) {
    return;
  }
  const std::string target = command.empty() ? std::string("<none>") : command;
  (void)managers.application.log_manager->Trace(
      AMDomain::log::LoggerType::Program, level, code, "", target, action,
      message);
}

void TraceProgramCommand_(const CLIServices &managers, const ECM &rcm,
                          const std::string &command,
                          const std::string &action,
                          const std::string &message) {
  std::string detail = message;
  if (!(rcm)) {
    if (!detail.empty()) {
      detail += "; ";
    }
    detail += AMStr::fmt("result={} error={}", AMStr::ToString(rcm.code),
                         rcm.msg());
  }
  TraceProgramCommand_(managers, CommandTraceLevel_(rcm), rcm.code, command,
                       action, detail);
}

class ScopedConsoleProcessedInput_ {
public:
  ScopedConsoleProcessedInput_() {
#ifdef _WIN32
    input_ = GetStdHandle(STD_INPUT_HANDLE);
    if (input_ == nullptr || input_ == INVALID_HANDLE_VALUE) {
      return;
    }
    DWORD mode = 0;
    if (GetConsoleMode(input_, &mode) == 0) {
      return;
    }
    previous_mode_ = mode;
    const DWORD command_mode = mode | ENABLE_PROCESSED_INPUT;
    if (command_mode == mode) {
      return;
    }
    active_ = SetConsoleMode(input_, command_mode) != 0;
#endif
  }

  ~ScopedConsoleProcessedInput_() {
#ifdef _WIN32
    if (active_ && input_ != nullptr && input_ != INVALID_HANDLE_VALUE) {
      (void)SetConsoleMode(input_, previous_mode_);
    }
#endif
  }

  ScopedConsoleProcessedInput_(const ScopedConsoleProcessedInput_ &) = delete;
  ScopedConsoleProcessedInput_ &
  operator=(const ScopedConsoleProcessedInput_ &) = delete;

private:
#ifdef _WIN32
  HANDLE input_ = nullptr;
  DWORD previous_mode_ = 0;
  bool active_ = false;
#endif
};
} // namespace

/**
 * @brief Bind config-related CLI commands.
 */
void BindConfigCommands(CommandNode *root, CliArgsPool &args) {
  if (!root) {
    return;
  }

  CommandNode *config_node = root->AddFunction("config", "Config manager");
  if (!config_node) {
    return;
  }

  config_node->AddFunction("ls", "List project/config file paths", args,
                           &CliArgsPool::config, &CliConfigArgs::ls);
  config_node->AddFunction("save", "Save all config files", args,
                           &CliArgsPool::config, &CliConfigArgs::save);
  config_node->AddFunction("backup", "Backup all config files", args,
                           &CliArgsPool::config, &CliConfigArgs::backup);
  config_node->AddFunction(
      "export", "Export all config files to local directory", args,
      &CliArgsPool::config, &CliConfigArgs::export_config,
      [&args](CommandNode &node) {
        node.AddOption("path", args.config.export_config.path, 1, 1,
                       "Local directory path", true);
      });

  root->AddFunction(
      "decrypt", "Decrypt encrypted password and copy plain text to clipboard",
      args, &CliArgsPool::config, &CliConfigArgs::decrypt,
      [&args](CommandNode &node) {
        node.AddOption("password", args.config.decrypt.password, 1, 1,
                       "Encrypted password: enc:<HEX> or <HEX>", true);
        node.AddPositionalRule(0, AMCommandArgSemantic::None, false);
      });
}

/**
 * @brief Bind host-related CLI commands.
 */
void BindHostCommands(CommandNode *root, CliArgsPool &args) {
  using Sem = AMCommandArgSemantic;
  if (!root) {
    return;
  }

  CommandNode *host_node = root->AddFunction("host", "Host manager");
  if (!host_node) {
    return;
  }

  host_node->AddFunction("ls", "List hosts", args, &CliArgsPool::host,
                         &CliHostArgs::ls, [&args](CommandNode &node) {
                           node.AddOption("nicknames", args.host.ls.nicknames,
                                          0, static_cast<size_t>(-1),
                                          "Host nicknames");
                           node.AddFlag("-d", "--detail", args.host.ls.detail,
                                        "Show full host details");
                           node.AddFlag("-l", "--list", args.host.ls.list,
                                        "Show host list table");
                           node.AddPositionalRule(0, Sem::HostNickname, true);
                         });

  host_node->AddFunction("get", "Query host", args, &CliArgsPool::host,
                         &CliHostArgs::get, [&args](CommandNode &node) {
                           node.AddOption("nicknames", args.host.get.nicknames,
                                          1, static_cast<size_t>(-1),
                                          "Host nicknames");
                           node.AddPositionalRule(0, Sem::HostNickname, true);
                         });

  host_node->AddFunction("add", "Add host", args, &CliArgsPool::host,
                         &CliHostArgs::add, [&args](CommandNode &node) {
                           node.AddOption("nickname", args.host.add.nickname, 0,
                                          1, "Host nickname");
                           node.AddPositionalRule(0, Sem::HostNicknameNew,
                                                  false);
                         });

  host_node->AddFunction("edit", "Edit host", args, &CliArgsPool::host,
                         &CliHostArgs::edit, [&args](CommandNode &node) {
                           node.AddOption("nickname", args.host.edit.nickname,
                                          1, 1, "Host nickname", true);
                           node.AddPositionalRule(0, Sem::HostNickname, true);
                         });

  host_node->AddFunction("rn", "Rename host", args, &CliArgsPool::host,
                         &CliHostArgs::rn, [&args](CommandNode &node) {
                           node.AddOption("old", args.host.rn.old_name, 1, 1,
                                          "Old nickname", true);
                           node.AddOption("new", args.host.rn.new_name, 1, 1,
                                          "New nickname", true);
                           node.AddPositionalRule(0, Sem::HostNickname, false);
                           node.AddPositionalRule(1, Sem::HostNicknameNew,
                                                  false);
                         });

  host_node->AddFunction("rm", "Remove host", args, &CliArgsPool::host,
                         &CliHostArgs::rm, [&args](CommandNode &node) {
                           node.AddOption("nicknames", args.host.rm.names, 1,
                                          static_cast<size_t>(-1),
                                          "Host nicknames to remove");
                           node.AddPositionalRule(0, Sem::HostNickname, true);
                         });

  host_node->AddFunction("set", "Set host", args, &CliArgsPool::host,
                         &CliHostArgs::set, [&args](CommandNode &node) {
                           node.AddOption("nickname",
                                          args.host.set.request.nickname, 1, 1,
                                          "Host nickname", true);
                           node.AddOption("attrname",
                                          args.host.set.request.attrname, 1, 1,
                                          "Host property name", true);
                           node.AddOption("value", args.host.set.request.value,
                                          1, 1, "Host property value", true);
                           node.AddPositionalRule(0, Sem::HostNickname, false);
                           node.AddPositionalRule(1, Sem::HostAttr, false);
                           node.AddPositionalRule(2, Sem::HostAttrValue, false);
                         });

  host_node->AddFunction("keys", "List private keys", args, &CliArgsPool::host,
                         &CliHostArgs::keys);
}

/**
 * @brief Bind profile-related CLI commands.
 */
void BindProfileCommands(CommandNode *root, CliArgsPool &args) {
  using Sem = AMCommandArgSemantic;
  if (!root) {
    return;
  }

  CommandNode *profile_node = root->AddFunction("profile", "Profile manager");
  if (!profile_node) {
    return;
  }

  profile_node->AddFunction(
      "edit", "Edit host profile", args, &CliArgsPool::profile,
      &CliProfileArgs::edit, [&args](CommandNode &node) {
        node.AddOption("nickname", args.profile.edit.nickname, 1, 1,
                       "Host nickname", true);
        node.AddPositionalRule(0, Sem::HostNickname, false);
      });

  profile_node->AddFunction(
      "get", "Query host profile", args, &CliArgsPool::profile,
      &CliProfileArgs::get, [&args](CommandNode &node) {
        node.AddOption("nicknames", args.profile.get.nicknames, 1,
                       static_cast<size_t>(-1), "Host nicknames", true);
        node.AddPositionalRule(0, Sem::HostNickname, true);
      });

  profile_node->AddFunction("clean", "Clean profiles without hosts", args,
                            &CliArgsPool::profile, &CliProfileArgs::clean);
}

/**
 * @brief Bind client-related CLI commands.
 */
void BindClientCommands(CommandNode *root, CliArgsPool &args) {
  using Sem = AMCommandArgSemantic;
  if (!root) {
    return;
  }

  CommandNode *client_node = root->AddFunction("client", "Client manager");
  if (!client_node) {
    return;
  }

  client_node->AddFunction(
      "ls", "List client names", args, &CliArgsPool::client,
      &CliClientArgs::ls, [&args](CommandNode &node) {
        node.AddOption("nicknames", args.client.ls.request.nicknames, 0,
                       static_cast<size_t>(-1), "Client nicknames");
        node.AddFlag("-d", "--detail", args.client.ls.request.detail,
                     "Show full status details");
        node.AddFlag("-c", "--check", args.client.ls.request.check,
                     "Check client status");
        node.AddPositionalRule(0, Sem::ClientName, true);
      });

  client_node->AddFunction(
      "check", "Check client status", args, &CliArgsPool::client,
      &CliClientArgs::check, [&args](CommandNode &node) {
        node.AddOption("nicknames", args.client.check.request.nicknames, 0,
                       static_cast<size_t>(-1), "Client nicknames");
        node.AddFlag("-d", "--detail", args.client.check.request.detail,
                     "Show client details");
        node.AddPositionalRule(0, Sem::ClientName, true);
      });

  client_node->AddFunction(
      "clear", "Check and remove unhealthy clients", args,
      &CliArgsPool::client, &CliClientArgs::clear,
      [&args](CommandNode &node) {
        node.AddOption("-t", "--timeout",
                       args.client.clear.request.timeout_s, 1, 1, Sem::None,
                       "Per-client check timeout in seconds");
      });

  client_node->AddFunction(
      "rm", "Disconnect clients", args, &CliArgsPool::client,
      &CliClientArgs::disconnect, [&args](CommandNode &node) {
        node.AddOption("nicknames", args.client.disconnect.request.nicknames, 1,
                       static_cast<size_t>(-1),
                       "Client nicknames to disconnect");
        node.AddPositionalRule(0, Sem::ClientName, true);
      });
}

/**
 * @brief Bind pool-related CLI commands.
 */
void BindPoolCommands(CommandNode *root, CliArgsPool &args) {
  using Sem = AMCommandArgSemantic;
  if (!root) {
    return;
  }

  CommandNode *pool_node = root->AddFunction("pool", "Public pool manager");
  if (!pool_node) {
    return;
  }

  pool_node->AddFunction("ls", "List public-pool clients", args,
                         &CliArgsPool::pool, &CliPoolArgs::ls,
                         [&args](CommandNode &node) {
                           node.AddOption("nicknames",
                                          args.pool.ls.request.nicknames, 0,
                                          static_cast<size_t>(-1),
                                          "Pool nicknames");
                           node.AddFlag("-d", "--detail",
                                        args.pool.ls.request.detail,
                                        "Show full status details");
                           node.AddFlag("-c", "--check",
                                        args.pool.ls.request.check,
                                        "Check client status");
                           node.AddPositionalRule(0, Sem::PoolName, true);
                         });

  pool_node->AddFunction("check", "Check public-pool client status", args,
                         &CliArgsPool::pool, &CliPoolArgs::check,
                         [&args](CommandNode &node) {
                           node.AddOption("nicknames",
                                          args.pool.check.request.nicknames, 0,
                                          static_cast<size_t>(-1),
                                          "Pool nicknames");
                           node.AddFlag("-d", "--detail",
                                        args.pool.check.request.detail,
                                        "Show client details");
                           node.AddPositionalRule(0, Sem::PoolName, true);
                         });

  pool_node->AddFunction("rm", "Remove public-pool clients", args,
                         &CliArgsPool::pool, &CliPoolArgs::rm,
                         [&args](CommandNode &node) {
                           node.AddOption("nickname",
                                          args.pool.rm.request.nickname, 1, 1,
                                          "Pool nickname to remove", true);
                           node.AddPositionalRule(0, Sem::PoolName, false);
                         });
}

/**
 * @brief Bind variable-related CLI commands.
 */
void BindVarCommands(CommandNode *root, CliArgsPool &args) {
  using Sem = AMCommandArgSemantic;
  if (!root) {
    return;
  }
  CommandNode *var_node = root->AddFunction("var", "Variable manager");
  if (!var_node) {
    return;
  }

  var_node->AddFunction("get", "Query variable by name", args,
                        &CliArgsPool::var, &CliVarArgs::get,
                        [&args](CommandNode &node) {
                          node.AddOption("varname", args.var.get.varname, 1, 1,
                                         "$varname", true);
                          node.AddPositionalRule(0, Sem::VariableName, false);
                        });

  var_node->AddFunction("def", "Define variable", args, &CliArgsPool::var,
                        &CliVarArgs::def, [&args](CommandNode &node) {
                          node.AddFlag("-g", "--global", args.var.def.global,
                                       "Define in public section");
                          node.AddOption("varname", args.var.def.varname, 1, 1,
                                         "$varname", true);
                          node.AddOption("value", args.var.def.value, 1, 1,
                                         "varvalue", true);
                          node.AddPositionalRule(0, Sem::None, false);
                          node.AddPositionalRule(1, Sem::None, false);
                        });

  var_node->AddFunction("del", "Delete variable", args, &CliArgsPool::var,
                        &CliVarArgs::del, [&args](CommandNode &node) {
                          node.AddFlag("-a", "--all", args.var.del.all,
                                       "Delete from all sections");
                          node.AddOption("tokens", args.var.del.tokens, 1, 2,
                                         "[section] $varname", true);
                          node.AddPositionalRule(0, Sem::None, true);
                        });

  var_node->AddFunction("ls", "List variables by section", args,
                        &CliArgsPool::var, &CliVarArgs::ls,
                        [&args](CommandNode &node) {
                          node.AddOption("sections", args.var.ls.sections, 0,
                                         static_cast<size_t>(-1),
                                         "section names");
                          node.AddPositionalRule(0, Sem::VarZone, true);
                        });
}

/**
 * @brief Bind filesystem-related CLI commands.
 */
void BindFilesystemCommands(CommandNode *root, CliArgsPool &args) {
  using Sem = AMCommandArgSemantic;
  if (!root) {
    return;
  }

  root->AddFunction("stat", "Print path info", args, &CliArgsPool::fs,
                    &CliFilesystemArgs::stat, [&args](CommandNode &node) {
                      node.AddOption("paths", args.fs.stat.request.raw_paths, 1,
                                     static_cast<size_t>(-1), "Paths to stat");
                      node.AddFlag("-L", "--trace-link",
                                   args.fs.stat.request.trace_link,
                                   "Trace symlink target instead of link itself");
                      node.AddPositionalRule(0, Sem::Path, true);
                    });

  root->AddFunction("ls", "List directory", args, &CliArgsPool::fs,
                    &CliFilesystemArgs::ls, [&args](CommandNode &node) {
                      node.AddOption("path", args.fs.ls.request.raw_path, 0, 1,
                                     "Path to list");
                      node.AddFlag("-l", "", args.fs.ls.request.list_like,
                                   "List like");
                      node.AddFlag("-a", "", args.fs.ls.request.show_all,
                                   "Show all entries");
                      node.AddPositionalRule(0, Sem::Path, false);
                    });

  root->AddFunction("size", "Get total size", args, &CliArgsPool::fs,
                    &CliFilesystemArgs::size, [&args](CommandNode &node) {
                      node.AddOption("paths", args.fs.size.request.raw_paths, 1,
                                     static_cast<size_t>(-1), "Paths to size");
                      node.AddPositionalRule(0, Sem::Path, true);
                    });

  root->AddFunction("find", "Find paths", args, &CliArgsPool::fs,
                    &CliFilesystemArgs::find, [&args](CommandNode &node) {
                      node.AddOption("tokens", args.fs.find.tokens, 1, 2,
                                     "[path] pattern", true);
                      node.AddPositionalRule(0, Sem::Path, false);
                      node.AddPositionalRule(1, Sem::FindPattern, false);
                    });

  root->AddFunction("mkdir", "Create directories", args, &CliArgsPool::fs,
                    &CliFilesystemArgs::mkdir, [&args](CommandNode &node) {
                      node.AddOption("paths", args.fs.mkdir.request.raw_paths,
                                     1, static_cast<size_t>(-1),
                                     "Paths to create");
                      node.AddPositionalRule(0, Sem::Path, true);
                    });

  root->AddFunction("rm", "Remove paths", args, &CliArgsPool::fs,
                    &CliFilesystemArgs::rm, [&args](CommandNode &node) {
                      node.AddOption("paths", args.fs.rm.paths, 1,
                                     static_cast<size_t>(-1),
                                     "Paths to remove");
                      node.AddFlag("-p", "--permanent", args.fs.rm.permanent,
                                   "Delete permanently");
                      node.AddFlag("-q", "--quiet", args.fs.rm.quiet,
                                   "Suppress error output");
                      node.AddPositionalRule(0, Sem::Path, true);
                    });

  root->AddFunction("tree", "Print directory tree", args, &CliArgsPool::fs,
                    &CliFilesystemArgs::tree, [&args](CommandNode &node) {
                      node.AddOption("path", args.fs.tree.request.raw_path, 1,
                                     1, "Path to tree", true);
                      node.AddOption("-d", "--depth",
                                     args.fs.tree.request.max_depth, 1, 1,
                                     Sem::None, "Max depth (default: -1)");
                      node.AddFlag("-o", "--onlydir",
                                   args.fs.tree.request.only_dir,
                                   "Only show directories");
                      node.AddFlag("-a", "--all",
                                   args.fs.tree.request.show_all,
                                   "Show hidden entries");
                      node.AddFlag("-s", "--special",
                                   args.fs.tree.include_special,
                                   "Include special files");
                      node.AddFlag("-q", "--quiet", args.fs.tree.request.quiet,
                                   "Suppress error output");
                      node.AddPositionalRule(0, Sem::Path, false);
                    });

  root->AddFunction("realpath", "Print absolute path", args, &CliArgsPool::fs,
                    &CliFilesystemArgs::realpath,
                    [&args](CommandNode &node) {
                      node.AddOption("path", args.fs.realpath.path, 0, 1,
                                     "Path to resolve");
                      node.AddPositionalRule(0, Sem::Path, false);
                    });

  root->AddFunction("rtt", "Measure current client RTT", args, &CliArgsPool::fs,
                    &CliFilesystemArgs::rtt, [&args](CommandNode &node) {
                      node.AddOption("times", args.fs.rtt.request.times, 0, 1,
                                     "Samples (default: 1)");
                    });

  root->AddFunction("clear", "Clear screen", args, &CliArgsPool::fs,
                    &CliFilesystemArgs::clear, [&args](CommandNode &node) {
                      node.AddFlag("-a", "--all", args.fs.clear.all,
                                   "Clear scrollback buffer");
                    });

  root->AddFunction(
      "cp", "Transfer files/directories", args, &CliArgsPool::fs,
      &CliFilesystemArgs::cp, [&args](CommandNode &node) {
        node.AddOption("src", args.fs.cp.srcs, 1, static_cast<size_t>(-1),
                       "Source paths");
        node.AddOption("-o", "--output", args.fs.cp.output, 1, 1, Sem::Path,
                       "Destination path (optional)");
        node.AddOption("-t", "--timeout", args.fs.cp.timeout_ms, 1, 1,
                       Sem::None,
                       "Transfer timeout in milliseconds (<=0 means no timeout)");
        node.AddFlag("-f", "--force", args.fs.cp.overwrite,
                     "Overwrite existing targets");
        node.AddFlag("-n", "--no-mkdir", args.fs.cp.no_mkdir,
                     "Do not create missing directories");
        node.AddFlag("-c", "--clone", args.fs.cp.clone,
                     "Clone instead of transfer");
        node.AddFlag("-s", "--special", args.fs.cp.include_special,
                     "Include special files");
        node.AddFlag("-r", "--resume", args.fs.cp.resume,
                     "Resume from existing destination file");
        node.AddFlag("-q", "--quiet", args.fs.cp.quiet,
                     "Suppress transfer output");
        node.AddPositionalRule(0, Sem::Path, true);
      });

  root->AddFunction(
      "mv", "Move one source to destination directory", args,
      &CliArgsPool::fs, &CliFilesystemArgs::mv,
      [&args](CommandNode &node) {
        node.AddOption("src", args.fs.mv.src, 1, 1, "Source path", true);
        node.AddOption("dst", args.fs.mv.dst, 0, 1,
                       "Destination directory path");
        node.AddFlag("-f", "--force", args.fs.mv.force,
                     "Overwrite existing targets");
        node.AddPositionalRule(0, Sem::Path, false);
        node.AddPositionalRule(1, Sem::Path, false);
      });

  root->AddFunction(
      "clone", "Clone one source to one destination (cp -c)", args,
      &CliArgsPool::fs, &CliFilesystemArgs::clone,
      [&args](CommandNode &node) {
        node.AddOption("src", args.fs.clone.src, 1, 1, "Source path", true);
        node.AddOption("dst", args.fs.clone.dst, 1, 1, "Destination path",
                       true);
        node.AddOption("suffix", args.fs.clone.async_suffix, 0, 1,
                       "Optional async suffix (&)");
        node.AddFlag("-f", "--force", args.fs.clone.overwrite,
                     "Overwrite existing targets");
        node.AddFlag("-r", "--resume", args.fs.clone.resume,
                     "Resume from existing destination file");
        node.AddFlag("-q", "--quiet", args.fs.clone.quiet,
                     "Suppress transfer output");
        node.AddPositionalRule(0, Sem::Path, false);
        node.AddPositionalRule(1, Sem::Path, false);
        node.AddPositionalRule(2, Sem::None, false);
      });

  root->AddFunction(
      "wget", "Download one HTTP/HTTPS URL", args, &CliArgsPool::fs,
      &CliFilesystemArgs::wget, [&args](CommandNode &node) {
        node.AddOption("src", args.fs.wget.src, 1, 1,
                       "Source URL (http/https)", true);
        node.AddOption("dst", args.fs.wget.dst, 0, 1,
                       "Destination path target");
        node.AddOption("-t", "--timeout", args.fs.wget.timeout_ms, 1, 1,
                       Sem::None,
                       "Transfer timeout in milliseconds (<=0 means no timeout)");
        node.AddOption("-u", "--username", args.fs.wget.username, 1, 1,
                       Sem::None, "Basic auth username");
        node.AddOption("-P", "--password", args.fs.wget.password, 1, 1,
                       Sem::None, "Basic auth password");
        node.AddOption("-b", "--bear", args.fs.wget.bear_token, 1, 1,
                       Sem::None, "Bearer token");
        node.AddOption("-p", "--proxy", args.fs.wget.proxy, 1, 1, Sem::Url,
                       "HTTP proxy");
        node.AddOption("-s", "--sproxy", args.fs.wget.sproxy, 1, 1, Sem::Url,
                       "HTTPS proxy");
        node.AddOption("-R", "--redirect", args.fs.wget.redirect_times, 1, 1,
                       Sem::None,
                       "Max redirect hops (default from Options.FileSystem.wget_max_redirect)");
        node.AddFlag("-r", "--resume", args.fs.wget.resume,
                     "Resume from existing destination file when possible");
        node.AddFlag("-f", "--force", args.fs.wget.overwrite,
                     "Overwrite existing destination file");
        node.AddFlag("-q", "--quiet", args.fs.wget.quiet,
                     "Suppress transfer output");
        node.AddPositionalRule(0, Sem::Url, false);
        node.AddPositionalRule(1, Sem::Path, false);
      });

  root->AddFunction(
      "sftp", "Connect to SFTP host", args, &CliArgsPool::fs,
      &CliFilesystemArgs::sftp, [&args](CommandNode &node) {
        node.AddOption("targets", args.fs.sftp.targets, 1, 2,
                       "nickname user@host | user@host", true);
        node.AddOption("-P", "--port", args.fs.sftp.request.port, 1, 1,
                       Sem::None, "Port");
        node.AddOption("-p", "--password", args.fs.sftp.request.password, 1, 1,
                       Sem::None, "Password");
        node.AddOption("-k", "--keyfile", args.fs.sftp.request.keyfile, 1, 1,
                       Sem::None, "Keyfile");
        node.AddPositionalRule(0, Sem::HostNicknameNew, false);
      });

  root->AddFunction(
      "ftp", "Connect to FTP host", args, &CliArgsPool::fs,
      &CliFilesystemArgs::ftp, [&args](CommandNode &node) {
        node.AddOption("targets", args.fs.ftp.targets, 1, 2,
                       "nickname user@host | user@host", true);
        node.AddOption("-P", "--port", args.fs.ftp.request.port, 1, 1,
                       Sem::None, "Port");
        node.AddOption("-p", "--password", args.fs.ftp.request.password, 1, 1,
                       Sem::None, "Password");
        node.AddPositionalRule(0, Sem::HostNicknameNew, false);
      });

  root->AddFunction(
      "local", "Connect to LOCAL host", args, &CliArgsPool::fs,
      &CliFilesystemArgs::local, [&args](CommandNode &node) {
        node.AddOption("nickname", args.fs.local.targets, 0, 1, "nickname");
        node.AddPositionalRule(0, Sem::HostNicknameNew, false);
      });

  root->AddFunction(
      "ch", "Change current client", args, &CliArgsPool::client,
      &CliClientArgs::change, [&args](CommandNode &node) {
        node.AddOption("nickname", args.client.change.request.nickname, 0, 1,
                       "Client nickname");
        node.AddPositionalRule(0, Sem::ClientName, false);
      });

  root->AddFunction(
      "cd", "Change working directory", args, &CliArgsPool::fs,
      &CliFilesystemArgs::cd, [&args](CommandNode &node) {
        node.AddOption("path", args.fs.cd.request.raw_path, 0, 1,
                       "Target path");
        node.AddPositionalRule(0, Sem::Path, false);
      });

  root->AddFunction(
      "connect", "Connect to a host", args, &CliArgsPool::fs,
      &CliFilesystemArgs::connect, [&args](CommandNode &node) {
        node.AddOption("nicknames", args.fs.connect.request.nicknames, 1,
                       static_cast<size_t>(-1), "Host nicknames", true);
        node.AddFlag("-f", "--force", args.fs.connect.request.force,
                     "Rebuild and replace existing client");
        node.AddPositionalRule(0, Sem::HostNickname, true);
      });

  root->AddFunction(
      "cmd", "Execute one shell command on current client", args,
      &CliArgsPool::fs, &CliFilesystemArgs::cmd,
      [&args](CommandNode &node) {
        node.AddOption("command", args.fs.cmd.request.cmd, 1, 1,
                       "Shell command text", true);
        node.AddOption("-t", "--timeout", args.fs.cmd.timeout_ms, 1, 1,
                       Sem::None,
                       "Command timeout in milliseconds (<=0 means no timeout)");
        node.AddPositionalRule(0, Sem::ShellCmd, false);
      });

  root->AddFunction(
      "ssh",
      "Open an interactive terminal on the current client (local escape: Ctrl+])",
      args, &CliArgsPool::fs, &CliFilesystemArgs::ssh,
      [&args](CommandNode &node) {
        node.AddOption(
            "target", args.fs.ssh.request.target, 0, 1,
            "Optional terminal target spec: [nickname]@[channel] or channel");
        node.AddPositionalRule(0, Sem::SshChannelTarget, false);
      });

  CommandNode *term_module_node = root->AddFunction("term", "Terminal manager");
  if (term_module_node) {
    term_module_node->AddFunction(
        "add", "Add one terminal by nickname", args, &CliArgsPool::term,
        &CliTermArgs::add, [&args](CommandNode &node) {
          node.AddOption("nickname", args.term.add.request.nicknames, 1,
                         static_cast<size_t>(-1), "Target nicknames", true);
          node.AddFlag("-f", "--force", args.term.add.request.force,
                       "Recreate terminal if it already exists");
          node.AddPositionalRule(0, Sem::TerminalName, true);
        });

    term_module_node->AddFunction("ls", "List terminals", args,
                                  &CliArgsPool::term, &CliTermArgs::ls);

    term_module_node->AddFunction(
        "rm", "Remove one terminal by nickname", args, &CliArgsPool::term,
        &CliTermArgs::rm, [&args](CommandNode &node) {
          node.AddOption("nickname", args.term.rm.request.nicknames, 1,
                         static_cast<size_t>(-1), "Target nicknames", true);
          node.AddPositionalRule(0, Sem::TerminalName, true);
        });

    term_module_node->AddFunction(
        "clear", "Check and remove unhealthy terminals", args,
        &CliArgsPool::term, &CliTermArgs::clear,
        [&args](CommandNode &node) {
          node.AddOption("-t", "--timeout",
                         args.term.clear.request.timeout_s, 1, 1, Sem::None,
                         "Per-terminal check timeout in seconds");
        });
  }

  CommandNode *channel_module_node =
      root->AddFunction("channel", "Terminal channel manager");
  if (channel_module_node) {
    channel_module_node->AddFunction(
        "add", "Add one channel", args, &CliArgsPool::channel,
        &CliChannelArgs::add, [&args](CommandNode &node) {
          node.AddOption("target", args.channel.add.request.target, 1, 1,
                         "Channel target: [termname]@channel", true);
          node.AddPositionalRule(0, Sem::ChannelTargetNew, false);
        });

    channel_module_node->AddFunction(
        "ls", "List channels in one terminal", args, &CliArgsPool::channel,
        &CliChannelArgs::ls, [&args](CommandNode &node) {
          node.AddOption("nickname", args.channel.ls.request.nickname, 0, 1,
                         "Terminal nickname (optional, default current)");
          node.AddPositionalRule(0, Sem::TerminalName, false);
        });

    channel_module_node->AddFunction(
        "rm", "Remove one channel", args, &CliArgsPool::channel,
        &CliChannelArgs::rm, [&args](CommandNode &node) {
          node.AddOption("target", args.channel.rm.request.target, 1, 1,
                         "Channel target: [termname]@channel", true);
          node.AddFlag("-f", "--force", args.channel.rm.request.force,
                       "Force close channel");
          node.AddPositionalRule(0, Sem::ChannelTargetExisting, false);
        });

    channel_module_node->AddFunction(
        "rn", "Rename one channel inside one terminal", args,
        &CliArgsPool::channel, &CliChannelArgs::rn,
        [&args](CommandNode &node) {
          node.AddOption("src", args.channel.rn.request.src, 1, 1,
                         "Source: [termname]@channel", true);
          node.AddOption("dst", args.channel.rn.request.dst, 1, 1,
                         "Destination: [termname]@channel", true);
          node.AddPositionalRule(0, Sem::ChannelTargetExisting, false);
          node.AddPositionalRule(1, Sem::ChannelTargetNew, false);
        });

    channel_module_node->AddFunction(
        "export", "Append channel VT history to a local text file", args,
        &CliArgsPool::channel, &CliChannelArgs::export_history,
        [&args](CommandNode &node) {
          node.AddOption("target", args.channel.export_history.request.target,
                         1, 1, "Channel target: [termname]@channel", true);
          node.AddOption("path", args.channel.export_history.request.path, 1,
                         1, "Local text file path", true);
          node.AddPositionalRule(0, Sem::ChannelTargetExisting, false);
          node.AddPositionalRule(1, Sem::Path, false);
        });

    channel_module_node->AddFunction(
        "clear", "Check and remove unhealthy channels", args,
        &CliArgsPool::channel, &CliChannelArgs::clear,
        [&args](CommandNode &node) {
          node.AddOption("nickname", args.channel.clear.request.nickname, 0, 1,
                         "Terminal nickname (optional, default current)");
          node.AddOption("-t", "--timeout",
                         args.channel.clear.request.timeout_s, 1, 1,
                         Sem::None, "Per-channel check timeout in seconds");
          node.AddPositionalRule(0, Sem::TerminalName, false);
        });
  }

  root->AddFunction("bash", "Enter interactive mode", args, &CliArgsPool::fs,
                    &CliFilesystemArgs::bash);

  root->AddFunction("exit", "Exit interactive mode", args, &CliArgsPool::fs,
                    &CliFilesystemArgs::exit, [&args](CommandNode &node) {
                      node.AddFlag(
                          "-f", "--force", args.fs.exit.force,
                          "Exit immediately without interactive-loop exit callbacks");
                    });
}

/**
 * @brief Bind task-related CLI commands.
 */
void BindTaskCommands(CommandNode *root, CliArgsPool &args) {
  using Sem = AMCommandArgSemantic;
  if (!root) {
    return;
  }
  CommandNode *task_node = root->AddFunction("task", "Task manager");
  if (!task_node) {
    return;
  }

  task_node->AddFunction("ls", "List tasks", args, &CliArgsPool::task,
                         &CliTaskArgs::ls, [&args](CommandNode &node) {
                           node.AddFlag("-p", "--pending", args.task.ls.pending,
                                        "Show pending tasks");
                           node.AddFlag("-s", "--suspend", args.task.ls.suspend,
                                        "Show paused tasks");
                           node.AddFlag("-f", "--finished",
                                        args.task.ls.finished,
                                        "Show finished tasks");
                           node.AddFlag("-c", "--conducting",
                                        args.task.ls.conducting,
                                        "Show conducting tasks");
                         });

  task_node->AddFunction("show", "Show task status", args, &CliArgsPool::task,
                         &CliTaskArgs::show, [&args](CommandNode &node) {
                           node.AddOption("id", args.task.show.ids, 1,
                                          static_cast<size_t>(-1), "Task ID",
                                          true);
                           node.AddPositionalRule(0, Sem::TaskId, true);
                         });

  task_node->AddFunction(
      "thread", "Get or set thread count", args, &CliArgsPool::task,
      &CliTaskArgs::thread, [&args](CommandNode &node) {
        node.AddOption("num", args.task.thread.num, 0, 1,
                       "Thread count (optional)");
        node.AddPositionalRule(0, Sem::None, false);
      });

  task_node->AddFunction(
      "inspect", "Inspect a task", args, &CliArgsPool::task,
      &CliTaskArgs::inspect, [&args](CommandNode &node) {
        node.AddOption("id", args.task.inspect.id, 0, 1, "Task ID");
        node.AddFlag("-s", "--set", args.task.inspect.set,
                     "Show transfer sets");
        node.AddFlag("-e", "--entry", args.task.inspect.entry,
                     "Show task entries");
        node.AddPositionalRule(0, Sem::TaskId, true);
      });

  task_node->AddFunction(
      "query", "Inspect task entry", args, &CliArgsPool::task,
      &CliTaskArgs::entry, [&args](CommandNode &node) {
        node.AddOption("id", args.task.entry.ids, 1, static_cast<size_t>(-1),
                       "Entry ID", true);
      });

  task_node->AddFunction(
      "terminate", "Terminate task(s)", args, &CliArgsPool::task,
      &CliTaskArgs::terminate, [&args](CommandNode &node) {
        node.AddOption("id", args.task.terminate.ids, 1,
                       static_cast<size_t>(-1), "Task IDs");
        node.AddOption("-g", "--grace-period",
                       args.task.terminate.grace_period_ms, 1, 1, Sem::None,
                       "Grace period in milliseconds before hard terminate");
        node.AddPositionalRule(0, Sem::TaskId, true);
      });

  task_node->AddFunction(
      "pause", "Pause task(s)", args, &CliArgsPool::task, &CliTaskArgs::pause,
      [&args](CommandNode &node) {
        node.AddOption("id", args.task.pause.ids, 1,
                       static_cast<size_t>(-1), "Task IDs");
        node.AddOption("-g", "--grace-period", args.task.pause.grace_period_ms,
                       1, 1, Sem::None,
                       "Grace period in milliseconds before pausing active IO");
        node.AddPositionalRule(0, Sem::TaskId, true);
      });

  task_node->AddFunction(
      "resume", "Resume paused task(s)", args, &CliArgsPool::task,
      &CliTaskArgs::resume, [&args](CommandNode &node) {
        node.AddOption("id", args.task.resume.ids, 1,
                       static_cast<size_t>(-1), "Task IDs");
        node.AddPositionalRule(0, Sem::PausedTaskId, true);
      });

  task_node->AddFunction(
      "rm", "Remove finished task record(s)", args, &CliArgsPool::task,
      &CliTaskArgs::rm, [&args](CommandNode &node) {
        node.AddOption("id", args.task.rm.ids, 1, static_cast<size_t>(-1),
                       "Finished task IDs");
        node.AddPositionalRule(0, Sem::TaskId, true);
      });

  args.task.terminate.action = TaskControlArgs::Action::Terminate;
  args.task.pause.action = TaskControlArgs::Action::Pause;
  args.task.resume.action = TaskControlArgs::Action::Resume;
}

/**
 * @brief Bind all CLI options into the argument pool.
 */
CliCommands BindCliOptions(CLI::App &app, CliArgsPool &args,
                           CommandNode &tree) {
  app.require_subcommand(0, 1);
  tree.Init(app);
  CliCommands commands;
  commands.app = &app;
  commands.args = &args;
  BindConfigCommands(&tree, args);
  BindHostCommands(&tree, args);
  BindProfileCommands(&tree, args);
  BindClientCommands(&tree, args);
  BindPoolCommands(&tree, args);
  BindVarCommands(&tree, args);
  BindFilesystemCommands(&tree, args);
  BindTaskCommands(&tree, args);
  return commands;
}

/**
 * @brief Dispatch CLI commands based on parsed state.
 */
void DispatchCliCommands(const CliCommands &cli_commands,
                         const CLIServices &managers, CliRunContext &ctx) {
  ctx.rcm = OK;
  ctx.enter_interactive = false;
  ctx.request_exit = false;
  ctx.force_exit = false;
  ctx.command_name.clear();

  auto store_exit_code = [&ctx](int code) {
    if (ctx.exit_code) {
      ctx.exit_code->store(code, std::memory_order_relaxed);
    }
  };
  if (!cli_commands.args) {
    const std::string msg = "CLI args pool is not initialized";
    std::cerr << msg << std::endl;
    ctx.rcm = {EC::UnknownError, "", "", msg};
    TraceProgramCommand_(managers, ctx.rcm, "", "cli.dispatch.error", msg);
    store_exit_code(static_cast<int>(ctx.rcm.code));
    return;
  }
  if (!ctx.task_control_token) {
    const std::string msg = "CLI session task control token is not initialized";
    std::cerr << msg << std::endl;
    ctx.rcm = {EC::InvalidArg, "", "", msg};
    TraceProgramCommand_(managers, ctx.rcm, "", "cli.dispatch.error", msg);
    store_exit_code(static_cast<int>(ctx.rcm.code));
    if (cli_commands.args) {
      cli_commands.args->ClearActive();
    }
    return;
  }
  CliArgsPool &args = *cli_commands.args;
  bool any_parsed = false;
  std::string command_name = "";
  std::string top_level_name = "";
  if (cli_commands.app) {
    for (const auto *cmd : cli_commands.app->get_subcommands()) {
      if (cmd && cmd->parsed()) {
        any_parsed = true;
        if (top_level_name.empty()) {
          top_level_name = cmd->get_name();
        }
        command_name += cmd->get_name() + " ";
      }
    }
  }

  if (!any_parsed) {
    std::string msg = "No valid command provided";
    std::cerr << msg << std::endl;
    ctx.rcm = {EC::InvalidArg, "", "", msg};
    TraceProgramCommand_(managers, ctx.rcm, "", "cli.dispatch.error", msg);
    store_exit_code(static_cast<int>(ctx.rcm.code));
    args.ClearActive();
    return;
  }
  command_name = command_name.empty()
                     ? command_name
                     : command_name.substr(0, command_name.size() - 1);
  if (!args.GetActive()) {
    std::string msg = "No valid command provided";
    if (!top_level_name.empty()) {
      msg = "Invalid " + top_level_name + " command";
    }
    std::cerr << msg << std::endl;
    ctx.rcm = {EC::InvalidArg, "", "", msg};
    TraceProgramCommand_(managers, ctx.rcm, command_name,
                         "cli.dispatch.error", msg);
    store_exit_code(static_cast<int>(ctx.rcm.code));
    args.ClearActive();
    return;
  }

  ctx.command_name = command_name;

  BaseArgStruct *selected = args.GetActive();
  const ScopedConsoleProcessedInput_ processed_input_guard;
  const auto dispatch_begin = AMTime::SteadyNow();
  TraceProgramCommand_(
      managers, TraceLevel::Info, EC::Success, command_name,
      "cli.dispatch.start",
      AMStr::fmt("mode={} async={}", CommandTraceMode_(ctx),
                 ctx.async ? "true" : "false"));
  const ECM run_rcm = selected->Run(managers, ctx);
  const ECM sync_rcm =
      managers.application.config_service->FlushDirtyParticipants();
  ctx.rcm = run_rcm;
  if ((ctx.rcm) && !(sync_rcm)) {
    ctx.rcm = sync_rcm;
  }
  const int64_t duration_ms =
      std::max<int64_t>(0,
                        AMTime::IntervalMS(dispatch_begin, AMTime::SteadyNow()));
  TraceProgramCommand_(
      managers, ctx.rcm, command_name, "cli.dispatch.end",
      AMStr::fmt("duration_ms={} run={} sync={}", duration_ms,
                 AMStr::ToString(run_rcm.code),
                 AMStr::ToString(sync_rcm.code)));
  selected->reset();
  args.ClearActive();
  store_exit_code(static_cast<int>(ctx.rcm.code));
  return;
}

} // namespace AMInterface::cli
