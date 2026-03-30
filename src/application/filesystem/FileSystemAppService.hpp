#pragma once
#include "application/filesystem/FilesystemAppBaseService.hpp"
#include "domain/filesystem/ClientIOPortInterfaceArgs.hpp"
#include "domain/transfer/TransferDomainModel.hpp"
#include "foundation/core/Enum.hpp"
#include <functional>
#include <map>

namespace AMApplication::filesystem {
using ClientPath = AMDomain::filesystem::ClientPath;
using ClientControlComponent = AMDomain::client::ClientControlComponent;
using FilesystemArg = AMDomain::filesystem::FilesystemArg;
using RunResult = AMDomain::filesystem::RunResult;
using TransferClientContainer = AMDomain::transfer::TransferClientContainer;
using TASKS = std::vector<AMDomain::transfer::TransferTask>;
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

struct PermanentRemovePlan {
  std::map<std::string, std::vector<ClientPath>> grouped_display_paths = {};
  std::vector<ClientPath> ordered_delete_paths = {};
  std::vector<std::pair<ClientPath, ECM>> precheck_errors = {};
  ECM rcm = {EC::Success, ""};
};

struct RmfilePlan {
  std::map<std::string, std::vector<ClientPath>> grouped_display_paths = {};
  std::vector<ClientPath> validated_targets = {};
  std::vector<std::pair<ClientPath, ECM>> precheck_errors = {};
  ECM rcm = {EC::Success, ""};
};

[[nodiscard]] std::vector<PathInfo>
CompactMatchedPaths_(const std::vector<PathInfo> &raw);

class FilesystemAppService final : public FilesystemAppBaseService {
public:
  FilesystemAppService(FilesystemArg arg, HostAppService *host_service,
                       ClientAppService *client_service);
  ~FilesystemAppService() override = default;

  [[nodiscard]] ECMData<ClientPath>
  GetCwd(const ClientControlComponent &control);
  [[nodiscard]] ECMData<ClientPath> PeekCdHistory() const;
  ECM ChangeDir(ClientPath path, const ClientControlComponent &control,
                bool from_history = false);
  [[nodiscard]] ECMData<PathInfo> Stat(ClientPath path,
                                       const ClientControlComponent &control,
                                       bool trace_link = false);
  [[nodiscard]] ECMData<std::vector<PathInfo>>
  Listdir(ClientPath path, const ClientControlComponent &control);
  [[nodiscard]] ECMData<std::vector<std::string>>
  ListNames(ClientPath path, const ClientControlComponent &control);
  [[nodiscard]] ECMData<int64_t>
  GetSize(ClientPath path, const ClientControlComponent &control,
          std::function<bool(const ClientPath &, int64_t)> on_progress = {},
          std::function<void(const ClientPath &, ECM)> on_error = {});
  ECM Mkdirs(ClientPath path, const ClientControlComponent &control);
  [[nodiscard]] ECMData<double> TestRTT(const std::string &nickname,
                                        const ClientControlComponent &control,
                                        int times = 1);
  [[nodiscard]] ECMData<ClientPath>
  ResolveTrashDir(ClientPath source, const ClientControlComponent &control);
  ECM Rename(const ClientPath &src, const ClientPath &dst,
             const ClientControlComponent &control, bool mkdir = true,
             bool overwrite = false);
  [[nodiscard]] ECMData<RmfilePlan>
  PrepareRmfile(std::vector<ClientPath> targets,
                const ClientControlComponent &control);
  [[nodiscard]] ECMData<std::vector<std::pair<ClientPath, ECM>>>
  ExecuteRmfile(const RmfilePlan &plan, const ClientControlComponent &control,
                std::function<void(const ClientPath &, ECM)> on_error = {});
  [[nodiscard]] ECMData<std::vector<std::pair<ClientPath, ECM>>>
  Rmdir(std::vector<ClientPath> targets, const ClientControlComponent &control,
        std::function<void(const ClientPath &, ECM)> on_error = {});
  [[nodiscard]] ECMData<PermanentRemovePlan>
  PreparePermanentRemove(std::vector<ClientPath> targets,
                         const ClientControlComponent &control);
  [[nodiscard]] ECMData<std::vector<std::pair<ClientPath, ECM>>>
  ExecutePermanentRemove(
      const PermanentRemovePlan &plan, const ClientControlComponent &control,
      std::function<void(const ClientPath &)> on_progress = {},
      std::function<void(const ClientPath &, ECM)> on_error = {});
  [[nodiscard]] ECMData<std::vector<std::pair<ClientPath, ECM>>>
  Saferm(std::vector<ClientPath> targets,
         const ClientControlComponent &control);
  [[nodiscard]] RunResult ShellRun(const std::string &nickname,
                                   const std::string &workdir,
                                   const std::string &cmd,
                                   const ClientControlComponent &control,
                                   std::string *final_cmd_out = nullptr);
  [[nodiscard]] ECMData<std::vector<PathInfo>>
  find(const ClientPath &path, SearchType type,
       const ClientControlComponent &control,
       std::function<void(const ClientPath &)> on_enter_dir = {},
       std::function<void(const ClientPath &, ECM)> on_error = {},
       std::function<bool(const ClientPath &)> on_match = {});

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
