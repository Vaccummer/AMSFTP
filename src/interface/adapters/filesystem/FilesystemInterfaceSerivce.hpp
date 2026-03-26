#pragma once
#include "application/client/ClientAppService.hpp"
#include "application/filesystem/FilesystemAppService.hpp"
#include "foundation/core/DataClass.hpp"
#include "foundation/core/Enum.hpp"
#include "interface/prompt/Prompt.hpp"
#include <optional>
#include <string>
#include <vector>

namespace AMInterface::filesystem {
using ClientPath = AMDomain::filesystem::ClientPath;
}

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
  bool from_history = false;
};

struct FilesystemMkdirsArg {
  std::vector<std::string> raw_paths = {};
};

class FilesystemInterfaceSerivce final : public NonCopyableNonMovable {
public:
  FilesystemInterfaceSerivce(
      AMApplication::client::ClientAppService &client_service,
      AMApplication::filesystem::FilesystemAppService &filesystem_service,
      AMInterface::style::AMStyleService &style_service,
      AMInterface::prompt::AMPromptIOManager &prompt_io_manager,
      AMDomain::client::amf default_interrupt_flag = nullptr);
  ~FilesystemInterfaceSerivce() override = default;

  [[nodiscard]] ECMData<ClientPath>
  SplitRawPath(const std::string &token) const;
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

private:
  AMApplication::client::ClientAppService &client_service_;
  AMApplication::filesystem::FilesystemAppService &filesystem_service_;
  AMInterface::style::AMStyleService &style_service_;
  AMInterface::prompt::AMPromptIOManager &prompt_io_manager_;
  AMDomain::client::amf default_interrupt_flag_ = nullptr;
};
} // namespace AMInterface::filesystem
