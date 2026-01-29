#include "AMClientManager.hpp"
#include "AMConfigManager.hpp"
#include "AMFileSystem.hpp"
#include "CLI/CLI.hpp"
#include "base/AMPath.hpp"
#include <csignal>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_set>

namespace fs = std::filesystem;

/** Global interrupt flag for CLI operations. */
static amf gif = std::make_shared<InterruptFlag>();

/** Handle Ctrl-C to signal interruption. */
static void HandleCliSignal([[maybe_unused]] int signum) {
  if (gif) {
    gif->set(true);
  }
}

/** Install signal handlers for graceful termination. */
static void InstallCliSignalHandlers() {
  std::signal(SIGINT, HandleCliSignal);
#ifdef SIGTERM
  std::signal(SIGTERM, HandleCliSignal);
#endif
}

/** Resolve network timeout from settings with a 5-second default. */
static int ResolveTimeoutMs(AMConfigManager &cfg) {
  int timeout_ms = cfg.GetSettingInt({"client_manager", "timeout_ms"}, -1);
  if (timeout_ms <= 0) {
    timeout_ms = 5000;
  }
  return timeout_ms;
}

/** Parse nickname@path into nickname and path. */
static std::pair<std::string, std::string>
ParseAddress(const std::string &input) {
  auto pos = input.find('@');
  if (pos == std::string::npos) {
    return {"", input};
  }
  return {input.substr(0, pos), input.substr(pos + 1)};
}

/** Ensure a client exists and is connected; creates it if missing. */
static std::pair<ECM, std::shared_ptr<BaseClient>>
EnsureClient(AMClientManager &manager, const std::string &nickname,
             const amf &flag) {
  if (nickname.empty() || nickname == "local") {
    return {ECM{EC::Success, ""}, manager.LOCAL};
  }

  auto existing = manager.Clients().GetHost(nickname);
  if (!existing) {
    std::cout << "Connecting to " << nickname << "..." << std::endl;
    return manager.AddClient(nickname, nullptr, false, true, {}, flag);
  }

  ECM rcm = existing->Connect(false, flag);
  if (rcm.first != EC::Success) {
    return {rcm, existing};
  }
  return {ECM{EC::Success, ""}, existing};
}

/** Get or initialize the client workdir. */
static std::string GetOrInitWorkdir(const std::shared_ptr<BaseClient> &client) {
  if (!client) {
    return "";
  }
  {
    std::lock_guard<std::recursive_mutex> lock(client->public_kv_mtx);
    auto it = client->public_kv.find("workdir");
    if (it != client->public_kv.end()) {
      return it->second;
    }
  }
  std::string home = AMPathStr::UnifyPathSep(client->GetHomeDir(), "/");
  {
    std::lock_guard<std::recursive_mutex> lock(client->public_kv_mtx);
    client->public_kv["workdir"] = home;
  }
  return home;
}

/** Build an absolute path based on client home/workdir. */
static std::string BuildPath(const std::shared_ptr<BaseClient> &client,
                             const std::string &path) {
  if (!client) {
    return path;
  }
  if (path.empty()) {
    return GetOrInitWorkdir(client);
  }
  std::string cwd = GetOrInitWorkdir(client);
  std::string home = client->GetHomeDir();
  return AMFS::abspath(path, true, home, cwd, "/");
}

/** Format a size value to a human-readable string. */
static std::string FormatSize(uint64_t size) {
  const char *units[] = {"B", "KB", "MB", "GB", "TB"};
  double value = static_cast<double>(size);
  size_t idx = 0;
  while (value >= 1024.0 && idx < 4) {
    value /= 1024.0;
    ++idx;
  }
  std::ostringstream oss;
  if (value == static_cast<uint64_t>(value)) {
    oss << static_cast<uint64_t>(value);
  } else {
    oss << std::fixed << std::setprecision(1) << value;
  }
  oss << units[idx];
  return oss.str();
}

/** Entry point for AMSFTP CLI (non-interactive). */
int main(int argc, char **argv) {
  try {
    InstallCliSignalHandlers();

    auto &config_manager = AMConfigManager::Instance();
    auto init_status = config_manager.Init();
    if (init_status.first != EC::Success) {
      std::cerr << init_status.second << std::endl;
      return static_cast<int>(init_status.first);
    }

    auto &client_manager = AMClientManager::Instance(config_manager);
    auto &filesystem = AMFileSystem::Instance(client_manager, config_manager);
    AMClientManager::global_interrupt_flag = gif;
    AMFileSystem::global_interrupt_flag = gif;

    const int timeout_ms = ResolveTimeoutMs(config_manager);

    const std::string app_name =
        fs::path(argc > 0 ? argv[0] : "amsftp").filename().string();
    CLI::App app{"AMSFTP CLI", app_name};

    bool config_detail = false;
    std::string config_get_name;
    std::string config_edit_name;
    std::string config_rn_old;
    std::string config_rn_new;
    std::vector<std::string> config_rm_names;

    CLI::App *config_cmd = app.add_subcommand("config", "Config manager");
    CLI::App *config_ls = config_cmd->add_subcommand("ls", "List configs");
    config_ls->add_flag("-d,--detail", config_detail, "Show detailed list");
    CLI::App *config_keys = config_cmd->add_subcommand("keys", "List keys");
    CLI::App *config_data = config_cmd->add_subcommand("data", "Show config");
    CLI::App *config_get = config_cmd->add_subcommand("get", "Query host");
    CLI::App *config_add = config_cmd->add_subcommand("add", "Add host");
    CLI::App *config_edit = config_cmd->add_subcommand("edit", "Edit host");
    CLI::App *config_rn = config_cmd->add_subcommand("rn", "Rename host");
    CLI::App *config_rm = config_cmd->add_subcommand("rm", "Remove host");

    config_get->add_option("nickname", config_get_name, "Host nickname")
        ->required();
    config_edit->add_option("nickname", config_edit_name, "Host nickname")
        ->required();
    config_rn->add_option("old", config_rn_old, "Old nickname")->required();
    config_rn->add_option("new", config_rn_new, "New nickname")->required();
    config_rm
        ->add_option("nicknames", config_rm_names, "Host nicknames to remove")
        ->expected(1, -1);

    std::vector<std::string> stat_paths;
    std::string ls_path;
    bool ls_long = false;
    bool ls_all = false;
    std::vector<std::string> size_paths;
    std::string find_path;
    std::vector<std::string> mkdir_paths;
    std::vector<std::string> rm_paths;
    bool rm_permanent = false;

    CLI::App *stat_cmd = app.add_subcommand("stat", "Print path info");
    stat_cmd->add_option("paths", stat_paths, "Paths to stat")->expected(1, -1);

    CLI::App *ls_cmd = app.add_subcommand("ls", "List directory");
    ls_cmd->add_option("path", ls_path, "Path to list")->required();
    ls_cmd->add_flag("-l", ls_long, "List like");
    ls_cmd->add_flag("-a", ls_all, "Show all entries");

    CLI::App *size_cmd = app.add_subcommand("size", "Get total size");
    size_cmd->add_option("paths", size_paths, "Paths to size")->expected(1, -1);

    CLI::App *find_cmd = app.add_subcommand("find", "Find paths");
    find_cmd->add_option("path", find_path, "Path to find")->required();

    CLI::App *mkdir_cmd = app.add_subcommand("mkdir", "Create directories");
    mkdir_cmd->add_option("paths", mkdir_paths, "Paths to create")
        ->expected(1, -1);

    CLI::App *rm_cmd = app.add_subcommand("rm", "Remove paths");
    rm_cmd->add_option("paths", rm_paths, "Paths to remove")->expected(1, -1);
    rm_cmd->add_flag("-p,--permanent", rm_permanent, "Delete permanently");

    try {
      CLI11_PARSE(app, argc, argv);
    } catch (const CLI::ParseError &e) {
      return app.exit(e);
    }

    if (config_cmd->parsed()) {
      if (config_ls->parsed()) {
        auto status =
            config_detail ? config_manager.List() : config_manager.ListName();
        return static_cast<int>(status.first);
      }
      if (config_keys->parsed()) {
        auto result = config_manager.PrivateKeys(true);
        return static_cast<int>(result.first.first);
      }
      if (config_data->parsed()) {
        auto status = config_manager.Src();
        return static_cast<int>(status.first);
      }
      if (config_get->parsed()) {
        auto status = config_manager.Query(config_get_name);
        return static_cast<int>(status.first);
      }
      if (config_add->parsed()) {
        auto status = config_manager.Add();
        return static_cast<int>(status.first);
      }
      if (config_edit->parsed()) {
        auto status = config_manager.Modify(config_edit_name);
        return static_cast<int>(status.first);
      }
      if (config_rn->parsed()) {
        auto status = config_manager.Rename(config_rn_old, config_rn_new);
        return static_cast<int>(status.first);
      }
      if (config_rm->parsed()) {
        int exit_code = 0;
        for (const auto &name : config_rm_names) {
          auto status = config_manager.Delete(name);
          if (status.first != EC::Success) {
            exit_code = static_cast<int>(status.first);
          }
        }
        return exit_code;
      }
      std::cerr << "Invalid config command" << std::endl;
      return static_cast<int>(EC::InvalidArg);
    }

    auto ensure_clients = [&](const std::vector<std::string> &paths) -> ECM {
      std::unordered_set<std::string> seen;
      for (const auto &input : paths) {
        auto [nickname, subpath] = ParseAddress(input);
        if (nickname.empty()) {
          continue;
        }
        if (seen.find(nickname) != seen.end()) {
          continue;
        }
        seen.insert(nickname);
        auto [rcm, _client] = EnsureClient(client_manager, nickname, gif);
        if (rcm.first != EC::Success) {
          return rcm;
        }
        if (subpath.empty()) {
          return {EC::InvalidArg, "Empty path after nickname"};
        }
      }
      return {EC::Success, ""};
    };

    if (stat_cmd->parsed()) {
      ECM rcm = ensure_clients(stat_paths);
      if (rcm.first != EC::Success) {
        std::cerr << rcm.second << std::endl;
        return static_cast<int>(rcm.first);
      }
      int exit_code = 0;
      for (const auto &path : stat_paths) {
        rcm = filesystem.stat(path, gif, timeout_ms);
        if (rcm.first != EC::Success) {
          std::cerr << rcm.second << std::endl;
          exit_code = static_cast<int>(rcm.first);
        }
      }
      return exit_code;
    }

    if (ls_cmd->parsed()) {
      ECM rcm = ensure_clients({ls_path});
      if (rcm.first != EC::Success) {
        std::cerr << rcm.second << std::endl;
        return static_cast<int>(rcm.first);
      }
      rcm = filesystem.ls(ls_path, ls_long, ls_all, gif, timeout_ms);
      if (rcm.first != EC::Success) {
        std::cerr << rcm.second << std::endl;
      }
      return static_cast<int>(rcm.first);
    }

    if (size_cmd->parsed()) {
      ECM rcm = ensure_clients(size_paths);
      if (rcm.first != EC::Success) {
        std::cerr << rcm.second << std::endl;
        return static_cast<int>(rcm.first);
      }
      int exit_code = 0;
      for (const auto &input : size_paths) {
        auto [nickname, subpath] = ParseAddress(input);
        std::shared_ptr<BaseClient> client =
            nickname.empty() ? client_manager.CLIENT
                             : client_manager.Clients().GetHost(nickname);
        if (!client) {
          auto [rcm2, created] = EnsureClient(client_manager, nickname, gif);
          if (rcm2.first != EC::Success) {
            std::cerr << rcm2.second << std::endl;
            exit_code = static_cast<int>(rcm2.first);
            continue;
          }
          client = created;
        }
        std::string abs_path =
            BuildPath(client, subpath.empty() ? input : subpath);
        int64_t start_time = am_ms();
        int64_t size =
            client->getsize(abs_path, true, gif, timeout_ms, start_time);
        if (size < 0) {
          std::cerr << "Failed to get size: " << input << std::endl;
          exit_code = static_cast<int>(EC::UnknownError);
          continue;
        }
        std::cout << input << ": " << FormatSize(static_cast<uint64_t>(size))
                  << std::endl;
      }
      return exit_code;
    }

    if (find_cmd->parsed()) {
      ECM rcm = ensure_clients({find_path});
      if (rcm.first != EC::Success) {
        std::cerr << rcm.second << std::endl;
        return static_cast<int>(rcm.first);
      }
      rcm = filesystem.find(find_path, SearchType::All, gif, timeout_ms);
      if (rcm.first != EC::Success) {
        std::cerr << rcm.second << std::endl;
      }
      return static_cast<int>(rcm.first);
    }

    if (mkdir_cmd->parsed()) {
      ECM rcm = ensure_clients(mkdir_paths);
      if (rcm.first != EC::Success) {
        std::cerr << rcm.second << std::endl;
        return static_cast<int>(rcm.first);
      }
      int exit_code = 0;
      for (const auto &path : mkdir_paths) {
        rcm = filesystem.mkdir(path, gif, timeout_ms);
        if (rcm.first != EC::Success) {
          std::cout << "❌ " << static_cast<int>(rcm.first)
                    << ": Fail to mkdir " << path << " , " << rcm.second
                    << std::endl;
          exit_code = static_cast<int>(rcm.first);
        } else {
          std::cout << "✅ Success to mkdir " << path << std::endl;
        }
      }
      return exit_code;
    }

    if (rm_cmd->parsed()) {
      ECM rcm = ensure_clients(rm_paths);
      if (rcm.first != EC::Success) {
        std::cerr << rcm.second << std::endl;
        return static_cast<int>(rcm.first);
      }
      int exit_code = 0;
      for (const auto &input : rm_paths) {
        auto [nickname, subpath] = ParseAddress(input);
        std::shared_ptr<BaseClient> client =
            nickname.empty() ? client_manager.CLIENT
                             : client_manager.Clients().GetHost(nickname);
        if (!client) {
          auto [rcm2, created] = EnsureClient(client_manager, nickname, gif);
          if (rcm2.first != EC::Success) {
            std::cout << "❌ " << static_cast<int>(rcm2.first)
                      << ": Fail to rm " << input << " , " << rcm2.second
                      << std::endl;
            exit_code = static_cast<int>(rcm2.first);
            continue;
          }
          client = created;
        }
        std::string abs_path =
            BuildPath(client, subpath.empty() ? input : subpath);
        int64_t start_time = am_ms();
        if (rm_permanent) {
          auto result = client->remove(abs_path, gif, timeout_ms, start_time);
          rcm = result.first;
        } else {
          rcm = client->saferm(abs_path, gif, timeout_ms, start_time);
        }
        if (rcm.first != EC::Success) {
          std::cout << "❌ " << static_cast<int>(rcm.first) << ": Fail to rm "
                    << input << " , " << rcm.second << std::endl;
          exit_code = static_cast<int>(rcm.first);
        } else {
          std::cout << "✅ Success to rm " << input << std::endl;
        }
      }
      return exit_code;
    }

    std::cerr << "No valid command provided" << std::endl;
    return static_cast<int>(EC::InvalidArg);
  } catch (const std::exception &e) {
    std::cerr << "Unexpected error: " << e.what() << std::endl;
    return -13;
  }
}
