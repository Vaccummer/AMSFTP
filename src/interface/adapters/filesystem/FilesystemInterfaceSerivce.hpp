#pragma once
#include "application/client/ClientAppService.hpp"
#include "application/filesystem/FileSystemAppService.hpp"
#include "application/host/HostAppService.hpp"
#include "foundation/core/DataClass.hpp"
#include "foundation/core/Enum.hpp"
#include "interface/adapters/filesystem/FilesystemInterfaceDTO.hpp"
#include "interface/prompt/Prompt.hpp"
#include <optional>

namespace AMInterface::filesystem {
using PathTarget = AMDomain::filesystem::PathTarget;
using ResolvedPath = AMDomain::filesystem::ResolvedPath;
} // namespace AMInterface::filesystem

namespace AMInterface::style {
class AMStyleService;
}

namespace AMInterface::filesystem {

class FilesystemInterfaceSerivce final : public NonCopyableNonMovable {
public:
  FilesystemInterfaceSerivce(
      AMApplication::client::ClientAppService &client_service,
      AMApplication::host::HostAppService &host_service,
      AMApplication::filesystem::FilesystemAppService &filesystem_service,
      AMInterface::style::AMStyleService &style_service,
      AMInterface::prompt::PromptIOManager &prompt_io_manager);
  ~FilesystemInterfaceSerivce() override = default;

  void SetDefaultControlToken(const AMDomain::client::amf &token);
  [[nodiscard]] AMDomain::client::amf GetDefaultControlToken() const;

  [[nodiscard]] ECMData<PathTarget>
  SplitRawTarget(const std::string &token) const;

  [[nodiscard]] ECM Stat(
      const FilesystemStatArg &arg,
      const std::optional<ControlComponent> &control_opt = std::nullopt) const;

  [[nodiscard]] ECM Ls(
      const FilesystemLsArg &arg,
      const std::optional<ControlComponent> &control_opt = std::nullopt) const;

  [[nodiscard]] ECM Cd(
      const FilesystemCdArg &arg,
      const std::optional<ControlComponent> &control_opt = std::nullopt) const;

  [[nodiscard]] ECM Mkdirs(
      const FilesystemMkdirsArg &arg,
      const std::optional<ControlComponent> &control_opt = std::nullopt) const;

  [[nodiscard]] ECM GetSize(
      const FilesystemGetSizeArg &arg,
      const std::optional<ControlComponent> &control_opt = std::nullopt) const;

  [[nodiscard]] ECM Find(
      const FilesystemFindArg &arg,
      const std::optional<ControlComponent> &control_opt = std::nullopt) const;

  [[nodiscard]] ECM Realpath(
      const FilesystemRealpathArg &arg,
      const std::optional<ControlComponent> &control_opt = std::nullopt) const;

  [[nodiscard]] ECM Tree(
      const FilesystemTreeArg &arg,
      const std::optional<ControlComponent> &control_opt = std::nullopt) const;

  [[nodiscard]] ECM TestRTT(
      const FilesystemTestRTTArg &arg,
      const std::optional<ControlComponent> &control_opt = std::nullopt) const;

  [[nodiscard]] ECM Rename(
      const FilesystemRenameArg &arg,
      const std::optional<ControlComponent> &control_opt = std::nullopt) const;

  [[nodiscard]] ECM Move(
      const FilesystemMoveArg &arg,
      const std::optional<ControlComponent> &control_opt = std::nullopt) const;

  [[nodiscard]] ECM Saferm(
      const FilesystemSafermArg &arg,
      const std::optional<ControlComponent> &control_opt = std::nullopt) const;

  [[nodiscard]] ECM Rmfile(
      const FilesystemRmfileArg &arg,
      const std::optional<ControlComponent> &control_opt = std::nullopt) const;

  [[nodiscard]] ECM Rmdir(
      const FilesystemRmdirArg &arg,
      const std::optional<ControlComponent> &control_opt = std::nullopt) const;

  [[nodiscard]] ECM PermanentRemove(
      const FilesystemPermanentRemoveArg &arg,
      const std::optional<ControlComponent> &control_opt = std::nullopt) const;

private:
  [[nodiscard]] ECMData<PathTarget> MatchOne(const PathTarget &path) const;

  AMApplication::client::ClientAppService &client_service_;
  [[maybe_unused]] AMApplication::host::HostAppService &host_service_;
  AMApplication::filesystem::FilesystemAppService &filesystem_service_;
  AMInterface::style::AMStyleService &style_service_;
  AMInterface::prompt::PromptIOManager &prompt_io_manager_;
  AMDomain::client::amf default_interrupt_flag_ = nullptr;
};
} // namespace AMInterface::filesystem
