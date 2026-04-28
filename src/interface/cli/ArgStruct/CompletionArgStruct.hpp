#pragma once

#include "interface/cli/ArgStruct/BaseArgStruct.hpp"

#include <string>

namespace AMInterface::cli {

struct CompletionArgs final : BaseArgStruct {
  std::string shell_str;
  std::string out_dir;

  [[nodiscard]] ECM Run(const CLIServices &managers,
                        const CliRunContext &ctx) const override;
  void reset() override;
};

} // namespace AMInterface::cli
