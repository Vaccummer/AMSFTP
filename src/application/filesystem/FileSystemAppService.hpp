#pragma once
#include "application/filesystem/FilesystemAppBaseService.hpp"
#include "application/filesystem/FilesystemAppDTO.hpp"
#include "domain/filesystem/ClientIOPortInterfaceArgs.hpp"
#include "foundation/core/Enum.hpp"
#include <functional>
#include <optional>
#include <string>

namespace AMApplication::log {
class LoggerAppService;
}

namespace AMApplication::filesystem {
using PathTarget = AMDomain::filesystem::PathTarget;
using ResolvedPath = AMDomain::filesystem::ResolvedPath;
using PathEntry = AMDomain::filesystem::PathEntry;
using FilesystemArg = AMDomain::filesystem::FilesystemArg;
using RunResult = AMDomain::filesystem::RunResult;
using ClientHandle = AMDomain::client::ClientHandle;
using AMDomain::filesystem::SearchType;

class FilesystemAppService final : public FilesystemAppBaseService {
public:
  FilesystemAppService(FilesystemArg arg, ClientAppService *client_service,
                       AMApplication::log::LoggerAppService *logger = nullptr);
  ~FilesystemAppService() override = default;

  [[nodiscard]] static ECMData<std::string>
  GetClientHome(ClientHandle client, const ControlComponent &control);
  [[nodiscard]] static ECMData<std::string>
  GetClientCwd(const ClientHandle &client, const ControlComponent &control);
  [[nodiscard]] static ECMData<std::string>
  ResolveAbsolutePath(ClientHandle client, const std::string &raw_path,
                      const ControlComponent &control);
  void ClearCache();
  [[nodiscard]] ECMData<ClientHandle> GetClient(const std::string &nickname,
                                                const ControlComponent &control);

  [[nodiscard]] ECMData<PathTarget> GetCwd(const ControlComponent &control);
  ECM EnsureClientWorkdir(ClientHandle client, const ControlComponent &control);
  [[nodiscard]] ECMData<PathTarget> PeekCdHistory() const;
  ECM ChangeDir(PathTarget path, const ControlComponent &control,
                bool from_history = false);
  [[nodiscard]] ECMData<PathEntry>
  StatEntry(const PathTarget &target, const ControlComponent &control,
            bool trace_link = false, ClientHandle preferred_client = nullptr);
  [[nodiscard]] ECMData<PathInfo> Stat(const PathTarget &path,
                                       const ControlComponent &control,
                                       bool trace_link = false,
                                       ClientHandle preferred_client = nullptr);
  [[nodiscard]] ECMData<std::vector<PathInfo>>
  Listdir(const PathTarget &path, const ControlComponent &control,
          ClientHandle preferred_client = nullptr);
  [[nodiscard]] ECMData<std::vector<std::string>>
  ListNames(const PathTarget &path, const ControlComponent &control,
            ClientHandle preferred_client = nullptr);
  [[nodiscard]] ECMData<int64_t>
  GetSize(const PathTarget &path, const ControlComponent &control,
          std::function<bool(const PathTarget &, int64_t)> on_progress = {},
          std::function<void(const PathTarget &, ECM)> on_error = {});
  ECM Mkdirs(const PathTarget &path, const ControlComponent &control,
             ClientHandle preferred_client = nullptr);
  [[nodiscard]] ECMData<double> TestRTT(const std::string &nickname,
                                        const ControlComponent &control,
                                        int times = 1);
  [[nodiscard]] ECMData<PathTarget>
  ResolveTrashDir(const PathTarget &source, const ControlComponent &control,
                  ClientHandle preferred_client = nullptr);
  ECM Rename(const PathTarget &src, const PathTarget &dst,
             const ControlComponent &control, bool mkdir = true,
             bool overwrite = false);
  [[nodiscard]] ECMData<RmfilePlan>
  PrepareRmfile(std::vector<PathTarget> targets,
                const ControlComponent &control);
  [[nodiscard]] ECMData<std::vector<std::pair<PathTarget, ECM>>>
  ExecuteRmfile(const RmfilePlan &plan, const ControlComponent &control,
                std::function<void(const PathTarget &, ECM)> on_error = {});
  [[nodiscard]] ECMData<std::vector<std::pair<PathTarget, ECM>>>
  Rmdir(std::vector<PathTarget> targets, const ControlComponent &control,
        std::function<void(const PathTarget &, ECM)> on_error = {});
  [[nodiscard]] ECMData<PermanentRemovePlan>
  PreparePermanentRemove(std::vector<PathTarget> targets,
                         const ControlComponent &control);
  [[nodiscard]] ECMData<std::vector<std::pair<PathTarget, ECM>>>
  ExecutePermanentRemove(
      const PermanentRemovePlan &plan, const ControlComponent &control,
      std::function<void(const PathTarget &)> on_progress = {},
      std::function<void(const PathTarget &, ECM)> on_error = {});
  [[nodiscard]] ECMData<std::vector<std::pair<PathTarget, ECM>>>
  Saferm(std::vector<PathTarget> targets, const ControlComponent &control);
  [[nodiscard]] ECMData<std::vector<PathInfo>>
  find(const PathTarget &path, SearchType type, const ControlComponent &control,
       std::function<void(const PathTarget &)> on_enter_dir = {},
       std::function<void(const PathTarget &, ECM)> on_error = {},
       std::function<bool(const PathTarget &)> on_match = {});

private:
  [[nodiscard]] ECMData<ClientHandle>
  GetTransferClient_(const std::string &nickname);
  [[nodiscard]] ECMData<ResolvedPath>
  ResolvePath_(const PathTarget &target, const ControlComponent &control,
               ClientHandle preferred_client = nullptr);
  void TraceFs_(const ECM &rcm, const PathTarget &target,
                const std::string &action,
                const std::string &message = {}) const;
  void TraceFs_(const ECM &rcm, const std::string &target,
                const std::string &action,
                const std::string &message = {}) const;

private:
  AMApplication::log::LoggerAppService *logger_ = nullptr;
};
} // namespace AMApplication::filesystem
