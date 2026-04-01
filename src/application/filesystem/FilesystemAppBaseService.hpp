#pragma once
#include "application/client/ClientAppService.hpp"
#include "application/host/HostAppService.hpp"
#include "domain/filesystem/FileSystemModel.hpp"
#include "foundation/core/DataClass.hpp"
#include <list>
#include <string>
#include <unordered_map>
#include <vector>

namespace AMApplication::filesystem {
using FilesystemArg = AMDomain::filesystem::FilesystemArg;
using ClientPath = AMDomain::filesystem::ClientPath;
using ClientHandle = AMDomain::client::ClientHandle;
using ClientControlComponent = AMDomain::client::ClientControlComponent;
using HostAppService = AMApplication::host::HostAppService;
using ClientAppService = AMApplication::client::ClientAppService;

namespace ClientOperationHelper {
ECMData<std::string> GetClientHome(ClientHandle client,
                                   const ClientControlComponent &control);
ECMData<std::string> GetClientCwd(ClientHandle client,
                                  const ClientControlComponent &control);

ECM AbsolutePath(ClientPath &path);
} // namespace ClientOperationHelper

class FilesystemAppBaseService : public NonCopyableNonMovable {
public:
  FilesystemAppBaseService(FilesystemArg arg,
                           HostAppService *host_service,
                           ClientAppService *client_service);
  ~FilesystemAppBaseService() override = default;

  ECM Init();

  [[nodiscard]] FilesystemArg GetInitArg() const;
  [[nodiscard]] std::string CurrentNickname() const;

  [[nodiscard]] ECMData<ClientHandle>
  GetClient(const std::string &nickname, const ClientControlComponent &control);
  [[nodiscard]] ECMData<ClientHandle>
  GetTransferClient(const std::string &nickname);

  ECM ResolvePath(ClientPath &path, const ClientControlComponent &control);

  ECM ResolvePath(std::vector<ClientPath> &paths,
                  const ClientControlComponent &control,
                  bool error_stop = true);

protected:
  struct BaseIOCache {
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

  [[nodiscard]] AMAtomic<std::list<ClientPath>> &CdHistory();
  [[nodiscard]] const AMAtomic<std::list<ClientPath>> &CdHistory() const;

  [[nodiscard]] ClientPath BuildBaseCacheKey(ClientHandle client,
                                             const std::string &nickname,
                                             const std::string &abs_path) const;
  [[nodiscard]] static std::vector<std::string>
  BuildBaseListNames(const std::vector<PathInfo> &entries);

  mutable AMAtomic<FilesystemArg> init_arg_ = {};
  HostAppService *host_service_ = nullptr;
  ClientAppService *client_service_ = nullptr;
  mutable AMAtomic<std::list<ClientPath>> cd_history_ = {};
  BaseIOCache base_io_cache_ = {};
};
} // namespace AMApplication::filesystem
