#pragma once

#include "domain/style/StyleDomainModel.hpp"
#include "foundation/core/DataClass.hpp"
#include "foundation/tools/bar.hpp"
#include "interface/style/StyleIndex.hpp"

#include <optional>
#include <string>
#include <vector>

namespace AMInterface::style {
using StyleConfigArg = AMDomain::style::StyleConfigArg;

class AMStyleService : NonCopyableNonMovable {
public:
  explicit AMStyleService(StyleConfigArg arg = {});
  ~AMStyleService() override = default;

  ECM Init();
  [[nodiscard]] StyleConfigArg GetInitArg() const;

  [[nodiscard]] std::string Format(const std::string &ori_str,
                                   StyleIndex style_index,
                                   const PathInfo *path_info = nullptr) const;
  [[nodiscard]] std::string
  FormatUtf8Table(const std::vector<std::string> &keys,
                  const std::vector<std::vector<std::string>> &rows) const;
  [[nodiscard]] AMProgressBar CreateProgressBar(int64_t total_size,
                                                const std::string &prefix);

private:
  void SetInitArg(StyleConfigArg arg);
  mutable AMAtomic<StyleConfigArg> init_arg_ = {};
  AMAtomic<std::optional<AMProgressBarStyle>> progress_bar_style_ = {};
};
} // namespace AMInterface::style
