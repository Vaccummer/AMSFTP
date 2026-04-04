#pragma once
#include "application/filesystem/FilesystemAppBaseService.hpp"
#include "domain/filesystem/ClientIOPortInterfaceArgs.hpp"
#include "domain/transfer/TransferDomainModel.hpp"
#include "foundation/core/Enum.hpp"
#include <functional>
#include <map>
#include <optional>

namespace AMApplication::filesystem {
using PathTarget = AMDomain::filesystem::PathTarget;
using ResolvedPath = AMDomain::filesystem::ResolvedPath;
using PathEntry = AMDomain::filesystem::PathEntry;
using ClientControlComponent = AMDomain::client::ClientControlComponent;
using FilesystemArg = AMDomain::filesystem::FilesystemArg;
using RunResult = AMDomain::filesystem::RunResult;
using ClientHandle = AMDomain::client::ClientHandle;
using TransferClientContainer = AMDomain::transfer::TransferClientContainer;
using TASKS = std::vector<AMDomain::transfer::TransferTask>;
struct DstResolveResult {
  PathTarget target = {};
  ResolvedPath resolved_target = {};
  std::optional<PathInfo> dst_info = std::nullopt;
};

struct SourceHostResolveData {
  ResolvedPath resolved_target = {};
  std::vector<PathInfo> raw_paths = {};
  std::vector<PathInfo> paths = {};
};

struct SourceResolveResult {
  std::map<std::string, SourceHostResolveData> data = {};
  std::map<std::string, std::vector<std::pair<PathTarget, ECM>>> error_data =
      {};
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
    ECM rcm = OK;
  };

  TASKS dir_tasks = {};
  TASKS file_tasks = {};
  std::vector<WarningItem> warnings = {};
};

struct HttpDownloadPlan {
  PathTarget final_target = {};
  ResolvedPath resolved_target = {};
  std::optional<PathInfo> dst_info = std::nullopt;
};

struct PermanentRemovePlan {
  std::map<std::string, std::vector<PathTarget>> grouped_display_paths = {};
  std::vector<ResolvedPath> ordered_delete_paths = {};
  std::vector<std::pair<PathTarget, ECM>> precheck_errors = {};
  ECM rcm = OK;
};

struct RmfilePlan {
  std::map<std::string, std::vector<PathTarget>> grouped_display_paths = {};
  std::vector<ResolvedPath> validated_targets = {};
  std::vector<std::pair<PathTarget, ECM>> precheck_errors = {};
  ECM rcm = OK;
};

[[nodiscard]] std::vector<PathInfo>
CompactMatchedPaths_(const std::vector<PathInfo> &raw);

class FilesystemAppService final : public FilesystemAppBaseService {
public:
  FilesystemAppService(FilesystemArg arg, HostAppService *host_service,
                       ClientAppService *client_service);
  ~FilesystemAppService() override = default;

  [[nodiscard]] static ECMData<std::string>
  GetClientHome(ClientHandle client, const ClientControlComponent &control);
  [[nodiscard]] static ECMData<std::string>
  GetClientCwd(const ClientHandle &client,
               const ClientControlComponent &control);
  [[nodiscard]] static ECMData<std::string>
  ResolveAbsolutePath(ClientHandle client, const std::string &raw_path,
                      const ClientControlComponent &control);

  [[nodiscard]] ECMData<PathTarget>
  GetCwd(const ClientControlComponent &control);
  ECM EnsureClientWorkdir(ClientHandle client,
                          const ClientControlComponent &control);
  [[nodiscard]] ECMData<PathTarget> PeekCdHistory() const;
  ECM ChangeDir(PathTarget path, const ClientControlComponent &control,
                bool from_history = false);
  [[nodiscard]] ECMData<PathEntry>
  StatEntry(const PathTarget &target, const ClientControlComponent &control,
            bool trace_link = false, ClientHandle preferred_client = nullptr);
  [[nodiscard]] ECMData<PathInfo> Stat(const PathTarget &path,
                                       const ClientControlComponent &control,
                                       bool trace_link = false,
                                       ClientHandle preferred_client = nullptr);
  [[nodiscard]] ECMData<std::vector<PathInfo>>
  Listdir(const PathTarget &path, const ClientControlComponent &control,
          ClientHandle preferred_client = nullptr);
  [[nodiscard]] ECMData<std::vector<std::string>>
  ListNames(const PathTarget &path, const ClientControlComponent &control,
            ClientHandle preferred_client = nullptr);
  [[nodiscard]] ECMData<int64_t>
  GetSize(const PathTarget &path, const ClientControlComponent &control,
          std::function<bool(const PathTarget &, int64_t)> on_progress = {},
          std::function<void(const PathTarget &, ECM)> on_error = {});
  ECM Mkdirs(const PathTarget &path, const ClientControlComponent &control,
             ClientHandle preferred_client = nullptr);
  [[nodiscard]] ECMData<double> TestRTT(const std::string &nickname,
                                        const ClientControlComponent &control,
                                        int times = 1);
  [[nodiscard]] ECMData<PathTarget>
  ResolveTrashDir(const PathTarget &source,
                  const ClientControlComponent &control,
                  ClientHandle preferred_client = nullptr);
  ECM Rename(const PathTarget &src, const PathTarget &dst,
             const ClientControlComponent &control, bool mkdir = true,
             bool overwrite = false);
  [[nodiscard]] ECMData<RmfilePlan>
  PrepareRmfile(std::vector<PathTarget> targets,
                const ClientControlComponent &control);
  [[nodiscard]] ECMData<std::vector<std::pair<PathTarget, ECM>>>
  ExecuteRmfile(const RmfilePlan &plan, const ClientControlComponent &control,
                std::function<void(const PathTarget &, ECM)> on_error = {});
  [[nodiscard]] ECMData<std::vector<std::pair<PathTarget, ECM>>>
  Rmdir(std::vector<PathTarget> targets, const ClientControlComponent &control,
        std::function<void(const PathTarget &, ECM)> on_error = {});
  [[nodiscard]] ECMData<PermanentRemovePlan>
  PreparePermanentRemove(std::vector<PathTarget> targets,
                         const ClientControlComponent &control);
  [[nodiscard]] ECMData<std::vector<std::pair<PathTarget, ECM>>>
  ExecutePermanentRemove(
      const PermanentRemovePlan &plan, const ClientControlComponent &control,
      std::function<void(const PathTarget &)> on_progress = {},
      std::function<void(const PathTarget &, ECM)> on_error = {});
  [[nodiscard]] ECMData<std::vector<std::pair<PathTarget, ECM>>>
  Saferm(std::vector<PathTarget> targets,
         const ClientControlComponent &control);
  [[nodiscard]] ECMData<std::vector<PathInfo>>
  find(const PathTarget &path, SearchType type,
       const ClientControlComponent &control,
       std::function<void(const PathTarget &)> on_enter_dir = {},
       std::function<void(const PathTarget &, ECM)> on_error = {},
       std::function<bool(const PathTarget &)> on_match = {});

  [[nodiscard]] ECMData<DstResolveResult>
  ResolveTransferDst(PathTarget dst, TransferClientContainer *clients,
                     const ClientControlComponent &control);

  [[nodiscard]] ECMData<SourceResolveResult> ResolveTransferSrc(
      std::vector<PathTarget> srcs, TransferClientContainer *clients,
      const ClientControlComponent &control, bool error_stop = true);

  [[nodiscard]] ECMData<BuildTransferTaskResult>
  BuildTransferTasks(const SourceResolveResult &src,
                     const DstResolveResult &dst,
                     const ClientControlComponent &control,
                     const BuildTransferTaskOptions &opt);

  [[nodiscard]] ECMData<HttpDownloadPlan> BuildHttpDownloadPlan(
      const std::optional<PathTarget> &dst_target,
      const std::string &suggested_filename,
      const ClientControlComponent &control);
};
} // namespace AMApplication::filesystem
