#pragma once
#include "application/client/ClientAppService.hpp"
#include "application/filesystem/FilesystemAppService.hpp"
#include "application/host/HostAppService.hpp"
#include "foundation/core/DataClass.hpp"
#include "foundation/core/Enum.hpp"
#include "interface/prompt/Prompt.hpp"
#include <optional>
#include <string>
#include <vector>

namespace AMInterface::filesystem {
using PathTarget = AMDomain::filesystem::PathTarget;
using ResolvedPath = AMDomain::filesystem::ResolvedPath;
} // namespace AMInterface::filesystem

namespace AMInterface::style {
class AMStyleService;
}

namespace AMInterface::filesystem {

struct FilesystemStatArg {
  std::vector<std::string> raw_paths = {};
  bool trace_link = false;
};

struct FilesystemLsArg {
  std::string raw_path = {};
  bool list_like = false;
  bool show_all = false;
};

struct FilesystemCdArg {
  std::string raw_path = {};
};

struct FilesystemMkdirsArg {
  std::vector<std::string> raw_paths = {};
};

struct FilesystemGetSizeArg {
  std::vector<std::string> raw_paths = {};
};

struct FilesystemFindArg {
  std::string raw_path = {};
};

struct FilesystemRealpathArg {
  std::string raw_path = {};
};

struct FilesystemTreeArg {
  std::string raw_path = {};
  int max_depth = -1;
  bool only_dir = false;
  bool show_all = false;
  bool ignore_special_file = true;
  bool quiet = false;
};

struct FilesystemTestRTTArg {
  int times = 1;
};

struct FilesystemRenameArg {
  std::string target = {};
  std::string dst = {};
  bool mkdir = true;
  bool overwrite = false;
};

struct FilesystemMoveArg {
  std::string target = {};
  std::string dst = {};
  bool mkdir = true;
  bool overwrite = false;
};

struct FilesystemSafermArg {
  std::vector<std::string> targets = {};
};

struct FilesystemRmfileArg {
  std::vector<std::string> targets = {};
};

struct FilesystemRmdirArg {
  std::vector<std::string> targets = {};
};

struct FilesystemPermanentRemoveArg {
  std::vector<std::string> targets = {};
  bool quiet = false;
};

class FilesystemInterfaceSerivce final : public NonCopyableNonMovable {
public:
  FilesystemInterfaceSerivce(
      AMApplication::client::ClientAppService &client_service,
      AMApplication::host::HostAppService &host_service,
      AMApplication::filesystem::FilesystemAppService &filesystem_service,
      AMInterface::style::AMStyleService &style_service,
      AMInterface::prompt::AMPromptIOManager &prompt_io_manager);
  ~FilesystemInterfaceSerivce() override = default;

  void SetDefaultControlToken(const AMDomain::client::amf &token);
  [[nodiscard]] AMDomain::client::amf GetDefaultControlToken() const;

  [[nodiscard]] ECMData<PathTarget>
  SplitRawTarget(const std::string &token) const;

  ECM Stat(const FilesystemStatArg &arg,
           const std::optional<AMDomain::client::ClientControlComponent>
               &control_opt = std::nullopt) const;

  ECM Ls(const FilesystemLsArg &arg,
         const std::optional<AMDomain::client::ClientControlComponent>
             &control_opt = std::nullopt) const;

  ECM Cd(const FilesystemCdArg &arg,
         const std::optional<AMDomain::client::ClientControlComponent>
             &control_opt = std::nullopt) const;

  ECM Mkdirs(const FilesystemMkdirsArg &arg,
             const std::optional<AMDomain::client::ClientControlComponent>
                 &control_opt = std::nullopt) const;

  ECM GetSize(const FilesystemGetSizeArg &arg,
              const std::optional<AMDomain::client::ClientControlComponent>
                  &control_opt = std::nullopt) const;

  ECM Find(const FilesystemFindArg &arg,
           const std::optional<AMDomain::client::ClientControlComponent>
               &control_opt = std::nullopt) const;

  ECM Realpath(const FilesystemRealpathArg &arg,
               const std::optional<AMDomain::client::ClientControlComponent>
                   &control_opt = std::nullopt) const;

  ECM Tree(const FilesystemTreeArg &arg,
           const std::optional<AMDomain::client::ClientControlComponent>
               &control_opt = std::nullopt) const;

  ECM TestRTT(const FilesystemTestRTTArg &arg,
              const std::optional<AMDomain::client::ClientControlComponent>
                  &control_opt = std::nullopt) const;

  ECM Rename(const FilesystemRenameArg &arg,
             const std::optional<AMDomain::client::ClientControlComponent>
                 &control_opt = std::nullopt) const;

  ECM Move(const FilesystemMoveArg &arg,
           const std::optional<AMDomain::client::ClientControlComponent>
               &control_opt = std::nullopt) const;

  ECM Saferm(const FilesystemSafermArg &arg,
             const std::optional<AMDomain::client::ClientControlComponent>
                 &control_opt = std::nullopt) const;

  ECM Rmfile(const FilesystemRmfileArg &arg,
             const std::optional<AMDomain::client::ClientControlComponent>
                 &control_opt = std::nullopt) const;

  ECM Rmdir(const FilesystemRmdirArg &arg,
            const std::optional<AMDomain::client::ClientControlComponent>
                &control_opt = std::nullopt) const;

  ECM PermanentRemove(
      const FilesystemPermanentRemoveArg &arg,
      const std::optional<AMDomain::client::ClientControlComponent>
          &control_opt = std::nullopt) const;

private:
  [[nodiscard]] ECMData<PathTarget> MatchOne(const PathTarget &path) const;

  AMApplication::client::ClientAppService &client_service_;
  AMApplication::host::HostAppService &host_service_;
  AMApplication::filesystem::FilesystemAppService &filesystem_service_;
  AMInterface::style::AMStyleService &style_service_;
  AMInterface::prompt::AMPromptIOManager &prompt_io_manager_;
  AMDomain::client::amf default_interrupt_flag_ = nullptr;
};
} // namespace AMInterface::filesystem
