#pragma once
#include "application/config/ConfigAppService.hpp"
#include "application/client/ClientAppService.hpp"
#include "application/host/HostAppService.hpp"
#include "domain/filesystem/FileSystemModel.hpp"
#include "foundation/core/DataClass.hpp"
#include <deque>
#include <string>
#include <unordered_map>
#include <vector>

namespace AMApplication::filesystem {
using FilesystemArg = AMDomain::filesystem::FilesystemArg;
using PathTarget = AMDomain::filesystem::PathTarget;
using ResolvedPath = AMDomain::filesystem::ResolvedPath;
using PathEntry = AMDomain::filesystem::PathEntry;
using ClientHandle = AMDomain::client::ClientHandle;
using ClientControlComponent = AMDomain::client::ClientControlComponent;
using HostAppService = AMApplication::host::HostAppService;
using ClientAppService = AMApplication::client::ClientAppService;

class FilesystemAppBaseService : public AMApplication::config::IConfigSyncPort {
public:
  FilesystemAppBaseService(FilesystemArg arg, HostAppService *host_service,
                           ClientAppService *client_service);
  ~FilesystemAppBaseService() override = default;

  ECM Init();

  [[nodiscard]] FilesystemArg GetInitArg() const;
  ECM FlushTo(AMApplication::config::ConfigAppService *config_service) override;
  [[nodiscard]] std::string CurrentNickname() const;

  [[nodiscard]] ECMData<ClientHandle>
  GetClient(const std::string &nickname, const ClientControlComponent &control,
            bool detach = false);
  [[nodiscard]] ECMData<ClientHandle>
  GetTransferClient(const std::string &nickname);

  [[nodiscard]] ECMData<ResolvedPath>
  ResolvePath(const PathTarget &target, const ClientControlComponent &control,
              ClientHandle preferred_client = nullptr);

  [[nodiscard]] std::vector<ECMData<ResolvedPath>>
  ResolvePath(const std::vector<PathTarget> &targets,
              const ClientControlComponent &control);

protected:
  struct BaseIOCache {
    struct KeyHash {
      size_t operator()(const PathTarget &key) const noexcept;
    };

    struct KeyEq {
      bool operator()(const PathTarget &lhs,
                      const PathTarget &rhs) const noexcept;
    };

    using StatCacheMap =
        std::unordered_map<PathTarget, ECMData<PathInfo>, KeyHash, KeyEq>;
    using ListdirCacheMap =
        std::unordered_map<PathTarget, ECMData<std::vector<PathInfo>>, KeyHash,
                           KeyEq>;
    using ListnamesCacheMap =
        std::unordered_map<PathTarget, ECMData<std::vector<std::string>>,
                           KeyHash, KeyEq>;

    AMAtomic<StatCacheMap> stat_cache = {};
    AMAtomic<ListdirCacheMap> listdir_cache = {};
    AMAtomic<ListnamesCacheMap> listnames_cache = {};
  };

  [[nodiscard]] ECMData<PathInfo>
  BaseStat(ClientHandle client, const std::string &nickname,
           const std::string &abs_path, const ClientControlComponent &control,
           bool trace_link = false);
  [[nodiscard]] ECMData<std::vector<PathInfo>>
  BaseListdir(ClientHandle client, const std::string &nickname,
              const std::string &abs_path,
              const ClientControlComponent &control);
  [[nodiscard]] ECMData<std::vector<std::string>>
  BaseListNames(ClientHandle client, const std::string &nickname,
                const std::string &abs_path,
                const ClientControlComponent &control);

  void ClearBaseIOCache();
  void ClearBaseIOCacheByNickname(const std::string &nickname);
  void ClearBaseIOCacheByPath(const std::string &nickname,
                              const std::string &abs_path);

  [[nodiscard]] PathTarget BuildBaseCacheKey(const std::string &nickname,
                                             const std::string &abs_path) const;

  [[nodiscard]] static std::vector<std::string>
  BuildBaseListNames(const std::vector<PathInfo> &entries);

  mutable AMAtomic<FilesystemArg> init_arg_ = {};
  HostAppService *host_service_ = nullptr;
  ClientAppService *client_service_ = nullptr;
  mutable AMAtomic<std::deque<PathTarget>> cd_history_ = {};
  BaseIOCache base_io_cache_ = {};
};
} // namespace AMApplication::filesystem
