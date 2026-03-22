#pragma once
#include "application/filesystem/FilesystemAppBaseService.hpp"

#include "domain/filesystem/ClientIOPortInterfaceArgs.hpp"

#include <functional>
#include <unordered_map>

namespace AMApplication::filesystem {
using ClientPath = AMDomain::filesystem::ClientPath;
using ClientControlComponent = AMDomain::client::ClientControlComponent;
using FilesystemArg = AMDomain::filesystem::FilesystemArg;
using RunResult = AMDomain::filesystem::RunResult;
struct PathStatItem {
  ClientPath target = {};
  ECM rcm = {EC::Success, ""};
  PathInfo info = {};
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

private:
  struct IOCache {
    struct KeyHash {
      size_t operator()(const ClientPath &key) const noexcept;
    };

    struct KeyEq {
      bool operator()(const ClientPath &lhs,
                      const ClientPath &rhs) const noexcept;
    };

    using StatCacheMap =
        std::unordered_map<ClientPath, ECMData<PathInfo>, KeyHash, KeyEq>;
    using ListdirCacheMap =
        std::unordered_map<ClientPath, ECMData<std::vector<PathInfo>>, KeyHash,
                           KeyEq>;
    using ListnamesCacheMap =
        std::unordered_map<ClientPath, ECMData<std::vector<std::string>>,
                           KeyHash, KeyEq>;

    AMAtomic<StatCacheMap> stat_cache = {};
    AMAtomic<ListdirCacheMap> listdir_cache = {};
    AMAtomic<ListnamesCacheMap> listnames_cache = {};
  };

  [[nodiscard]] ClientPath BuildCacheKey(ClientHandle client,
                                         const std::string &nickname,
                                         const std::string &abs_path) const;
  void InvalidateParentListCache(ClientHandle client,
                                 const std::string &nickname,
                                 const std::string &abs_path);
  void InvalidateClientCache(ClientHandle client);
  [[nodiscard]] static std::vector<std::string>
  BuildListNames(const std::vector<PathInfo> &entries);

  IOCache io_cache_ = {};
};
} // namespace AMApplication::filesystem
