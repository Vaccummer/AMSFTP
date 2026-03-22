#pragma once
#include "application/client/ClientAppService.hpp"
#include "application/host/HostAppService.hpp"
#include "domain/filesystem/FileSystemModel.hpp"
#include "foundation/core/DataClass.hpp"
#include <list>
#include <memory>
#include <string>
#include <vector>

namespace AMApplication::filesystem {
using FilesystemArg = AMDomain::filesystem::FilesystemArg;
using ClientPath = AMDomain::filesystem::ClientPath;
using ClientHandle = AMDomain::client::ClientHandle;
using ClientControlComponent = AMDomain::client::ClientControlComponent;
using HostAppService = AMApplication::host::AMHostAppService;
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
                           std::shared_ptr<HostAppService> host_service,
                           std::shared_ptr<ClientAppService> client_service);
  ~FilesystemAppBaseService() override = default;

  ECM Init();

  [[nodiscard]] FilesystemArg GetInitArg() const;

  [[nodiscard]] ECMData<ClientPath>
  SplitRawPath(const std::string &token) const;

  [[nodiscard]] ECMData<ClientHandle>
  GetClient(const std::string &nickname, const ClientControlComponent &control);

  ECM ResolvePath(ClientPath &path, const ClientControlComponent &control);

  ECM ResolvePath(std::vector<ClientPath> &paths,
                  const ClientControlComponent &control,
                  bool error_stop = true);

protected:
  [[nodiscard]] AMAtomic<std::list<ClientPath>> &CdHistory();
  [[nodiscard]] const AMAtomic<std::list<ClientPath>> &CdHistory() const;
  mutable AMAtomic<FilesystemArg> init_arg_ = {};
  std::shared_ptr<HostAppService> host_service_ = nullptr;
  std::shared_ptr<ClientAppService> client_service_ = nullptr;
  AMAtomic<std::list<ClientPath>> cd_history_ = {};
};
} // namespace AMApplication::filesystem
