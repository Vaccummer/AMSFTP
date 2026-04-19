#pragma once
#include "application/client/ClientAppService.hpp"
#include "domain/config/ConfigSyncPort.hpp"
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
using ClientAppService = AMApplication::client::ClientAppService;

class FilesystemAppBaseService : public AMDomain::config::IConfigSyncPort {
public:
  FilesystemAppBaseService(FilesystemArg arg, ClientAppService *client_service);
  ~FilesystemAppBaseService() override = default;

  ECM Init();

  [[nodiscard]] FilesystemArg GetInitArg() const;
  ECM FlushTo(AMDomain::config::IConfigStorePort *store) override;
  [[nodiscard]] std::string CurrentNickname() const;

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

    StatCacheMap stat_cache = {};
    ListdirCacheMap listdir_cache = {};
    ListnamesCacheMap listnames_cache = {};
  };

  [[nodiscard]] ECMData<PathInfo> BaseStat(ClientHandle client,
                                           const std::string &nickname,
                                           const std::string &abs_path,
                                           const ControlComponent &control,
                                           bool trace_link = false);
  [[nodiscard]] ECMData<std::vector<PathInfo>>
  BaseListdir(ClientHandle client, const std::string &nickname,
              const std::string &abs_path, const ControlComponent &control);
  [[nodiscard]] ECMData<std::vector<std::string>>
  BaseListNames(ClientHandle client, const std::string &nickname,
                const std::string &abs_path, const ControlComponent &control);

  void ClearBaseIOCache();
  void ClearBaseIOCacheByNickname(const std::string &nickname);
  void ClearBaseIOCacheByPath(const std::string &nickname,
                              const std::string &abs_path);

  [[nodiscard]] PathTarget BuildBaseCacheKey(const std::string &nickname,
                                             const std::string &abs_path) const;

  [[nodiscard]] static std::vector<std::string>
  BuildBaseListNames(const std::vector<PathInfo> &entries);

  mutable AMAtomic<FilesystemArg> init_arg_ = {};
  ClientAppService *client_service_ = nullptr;
  mutable AMAtomic<std::deque<PathTarget>> cd_history_ = {};
  mutable AMAtomic<BaseIOCache> base_io_cache_ = {};
};
} // namespace AMApplication::filesystem
