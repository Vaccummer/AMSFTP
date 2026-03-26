#pragma once
#include "application/client/ClientAppService.hpp"
#include "application/filesystem/FilesystemAppService.hpp"
#include "foundation/core/DataClass.hpp"
#include "foundation/core/Enum.hpp"
#include "interface/prompt/Prompt.hpp"
#include <optional>
#include <string>
#include <tuple>
#include <vector>

namespace AMInterface::filesystem {
using ClientPath = AMDomain::filesystem::ClientPath;

class FileSystemCliAdapter final {
public:
  FileSystemCliAdapter(
      AMApplication::client::ClientAppService &client_service,
      AMInterface::prompt::AMPromptIOManager &prompt_manager);

  ECM CheckClients(const std::vector<std::string> &nicknames, bool detail,
                   AMDomain::client::amf interrupt_flag = nullptr) const;
  ECM ListClients(bool detail,
                  AMDomain::client::amf interrupt_flag = nullptr) const;
  ECM DisconnectClients(const std::vector<std::string> &nicknames) const;
  ECM StatPaths(const std::vector<std::string> &paths,
                AMDomain::client::amf interrupt_flag = nullptr,
                int timeout_ms = -1) const;
  ECM ListPath(const std::string &path, bool list_like, bool show_all,
               AMDomain::client::amf interrupt_flag = nullptr,
               int timeout_ms = -1) const;
  ECM GetSize(const std::vector<std::string> &paths,
              AMDomain::client::amf interrupt_flag = nullptr,
              int timeout_ms = -1) const;
  ECM Find(const std::string &path, SearchType type,
           AMDomain::client::amf interrupt_flag = nullptr,
           int timeout_ms = -1) const;
  ECM Mkdir(const std::vector<std::string> &paths,
            AMDomain::client::amf interrupt_flag = nullptr,
            int timeout_ms = -1) const;
  ECM Remove(const std::vector<std::string> &paths, bool permanent, bool quiet,
             AMDomain::client::amf interrupt_flag = nullptr,
             int timeout_ms = -1) const;
  ECM Walk(const std::string &path, bool only_file, bool only_dir,
           bool show_all, bool ignore_special_file, bool quiet,
           AMDomain::client::amf interrupt_flag = nullptr,
           int timeout_ms = -1) const;
  ECM Tree(const std::string &path, int max_depth, bool only_dir,
           bool show_all, bool ignore_special_file, bool quiet,
           AMDomain::client::amf interrupt_flag = nullptr,
           int timeout_ms = -1) const;
  ECM Realpath(const std::string &path,
               AMDomain::client::amf interrupt_flag = nullptr,
               int timeout_ms = -1) const;
  ECM TestRtt(int times,
              AMDomain::client::amf interrupt_flag = nullptr) const;
  ECM Cd(const std::string &path,
         AMDomain::client::amf interrupt_flag = nullptr,
         bool from_history = false) const;
  std::pair<ECM, std::pair<std::string, int>>
  ShellRun(const std::string &cmd, int max_time_ms,
           AMDomain::client::amf interrupt_flag = nullptr) const;

private:
  std::tuple<ECM, AMDomain::client::ClientHandle, std::string>
  ResolveClientPath_(const std::string &raw_path,
                     AMDomain::client::amf interrupt_flag) const;

  AMApplication::client::ClientAppService &client_service_;
  AMInterface::prompt::AMPromptIOManager &prompt_io_manager_;
};

struct FilesystemStatArg {
  std::vector<std::string> raw_paths = {};
  bool trace_link = false;
};

class FilesystemInterfaceSerivce final : public NonCopyableNonMovable {
public:
  FilesystemInterfaceSerivce(
      AMApplication::filesystem::FilesystemAppService &filesystem_service,
      AMInterface::prompt::AMPromptIOManager &prompt_io_manager,
      AMDomain::client::amf default_interrupt_flag = nullptr);
  ~FilesystemInterfaceSerivce() override = default;

  [[nodiscard]] ECMData<ClientPath>
  SplitRawPath(const std::string &token) const;
  ECM Stat(
      const FilesystemStatArg &arg,
      const std::optional<AMDomain::client::ClientControlComponent>
          &control_opt = std::nullopt) const;

private:
  AMApplication::filesystem::FilesystemAppService &filesystem_service_;
  AMInterface::prompt::AMPromptIOManager &prompt_io_manager_;
  AMDomain::client::amf default_interrupt_flag_ = nullptr;
};
} // namespace AMInterface::filesystem

namespace AMInterface::ApplicationAdapters {
using FileSystemCliAdapter = AMInterface::filesystem::FileSystemCliAdapter;
using FilesystemInterfaceSerivce =
    AMInterface::filesystem::FilesystemInterfaceSerivce;
} // namespace AMInterface::ApplicationAdapters
