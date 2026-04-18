#pragma once
#include "application/style/StyleAppService.hpp"

#include "domain/style/StyleDomainModel.hpp"
#include "foundation/core/DataClass.hpp"
#include "foundation/tools/bar.hpp"
#include "interface/style/StyleIndex.hpp"

#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace AMInterface::style {
using StyleConfigArg = AMDomain::style::StyleConfigArg;

class AMStyleService : public AMApplication::style::StyleConfigManager {
public:
  explicit AMStyleService(StyleConfigArg arg = {});
  ~AMStyleService() override = default;

  ECM Init() override;

  [[nodiscard]] std::string Format(const std::string &ori_str,
                                   StyleIndex style_index,
                                   const PathInfo *path_info = nullptr) const;
  [[nodiscard]] std::string
  FormatUtf8Table(const std::vector<std::string> &keys,
                  const std::vector<std::vector<std::string>> &rows) const;
  [[nodiscard]] std::unique_ptr<BaseProgressBar>
  CreateProgressBar(int64_t total_size, const std::string &prefix);

private:
  AMAtomic<std::optional<AMProgressBarStyle>> progress_bar_style_ = {};
};
} // namespace AMInterface::style
