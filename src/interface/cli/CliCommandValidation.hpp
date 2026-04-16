#pragma once

#include "interface/parser/CommandTree.hpp"
#include "interface/style/StyleManager.hpp"

#include <optional>
#include <string>
#include <vector>

namespace AMInterface::cli {

[[nodiscard]] std::optional<std::string>
BuildUnknownCommandError(const std::vector<std::string> &tokens,
                         const AMInterface::parser::CommandNode &command_tree,
                         const AMInterface::style::AMStyleService &style_service);

} // namespace AMInterface::cli

