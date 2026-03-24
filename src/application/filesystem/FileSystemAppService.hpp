#pragma once
#include "application/filesystem/FilesystemAppBaseService.hpp"
#include "domain/filesystem/ClientIOPortInterfaceArgs.hpp"
#include "domain/transfer/TransferDomainModel.hpp"
#include <functional>
#include <map>

namespace AMApplication::filesystem {
using ClientPath = AMDomain::filesystem::ClientPath;
using ClientControlComponent = AMDomain::client::ClientControlComponent;
using FilesystemArg = AMDomain::filesystem::FilesystemArg;
using RunResult = AMDomain::filesystem::RunResult;
using TransferClientContainer = AMDomain::transfer::TransferClientContainer;
using TASKS = std::vector<AMDomain::transfer::TransferTask>;
struct PathStatItem {
  ClientPath target = {};
  ECM rcm = {EC::Success, ""};
  PathInfo info = {};
};

struct TransferPath {
  ClientPath target = {};
  ClientHandle client = nullptr;
  std::vector<PathInfo> raw_paths = {};
  std::vector<PathInfo> paths = {};
  ECM rcm = {EC::Success, ""};
};

struct SourceResolveResult {
  std::map<std::string, TransferPath> data = {};
  std::map<std::string, ClientPath> error_data = {};
  ECM rcm = {EC::Success, ""};
};

struct BuildTransferTaskOptions {
  bool clone = false;
  bool mkdir = true;
  bool ignore_special_file = true;
  bool resume = false;
};

struct BuildTransferTaskResult {
  struct WarningItem {
    std::string src = {};
    std::string dst = {};
    ECM rcm = {EC::Success, ""};
  };

  TASKS dir_tasks = {};
  TASKS file_tasks = {};
  std::vector<WarningItem> warnings = {};
};

class FilesystemAppService final : public FilesystemAppBaseService {
public:
  FilesystemAppService(FilesystemArg arg,
                       std::shared_ptr<HostAppService> host_service,
                       std::shared_ptr<ClientAppService> client_service);
  ~FilesystemAppService() override = default;

  [[nodiscard]] ECMData<ClientPath>
  GetCwd(const ClientControlComponent &control);
  ECM ChangeDir(ClientPath path, const ClientControlComponent &control,
                bool from_history = false);
  [[nodiscard]] ECMData<std::vector<PathStatItem>>
  Stat(std::vector<ClientPath> paths, const ClientControlComponent &control);
  [[nodiscard]] ECMData<std::vector<PathInfo>>
  Listdir(ClientPath path, const ClientControlComponent &control);
  [[nodiscard]] ECMData<std::vector<std::string>>
  ListNames(ClientPath path, const ClientControlComponent &control);
  ECM Mkdirs(ClientPath path, const ClientControlComponent &control);
  [[nodiscard]] ECMData<double> TestRTT(const std::string &nickname,
                                        const ClientControlComponent &control);
  ECM Rename(const ClientPath &src, const ClientPath &dst,
             const ClientControlComponent &control);
  [[nodiscard]] RunResult ShellRun(const std::string &nickname,
                                   const std::string &workdir,
                                   const std::string &cmd,
                                   const ClientControlComponent &control);
  [[nodiscard]] ECMData<std::vector<PathInfo>>
  find(const ClientPath &path, SearchType type,
       const ClientControlComponent &control,
       std::function<void(const ClientPath &)> on_enter_dir = {},
       std::function<void(const ClientPath &, ECM)> on_error = {});

  [[nodiscard]] ECMData<TransferPath>
  ResolveTransferDst(ClientPath dst, const ClientControlComponent &control);

  [[nodiscard]] ECMData<SourceResolveResult> ResolveTransferSrc(
      std::vector<ClientPath> srcs, TransferClientContainer *clients,
      const ClientControlComponent &control, bool error_stop = true);

  [[nodiscard]] ECMData<BuildTransferTaskResult>
  BuildTransferTasks(const SourceResolveResult &src, const TransferPath &dst,
                     const ClientControlComponent &control,
                     const BuildTransferTaskOptions &opt);
};
} // namespace AMApplication::filesystem
