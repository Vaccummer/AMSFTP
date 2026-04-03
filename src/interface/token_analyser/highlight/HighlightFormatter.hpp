#pragma once

#include "interface/token_analyser/model/RawToken.hpp"
#include <memory>
#include <string>
#include <vector>

namespace AMInterface::parser {
class CommandNode;
class ITokenAnalyzerRuntime;
}

namespace AMInterface::parser::highlight {

void FormatHighlightedInput(
    const std::string &input,
    const std::vector<AMInterface::parser::model::RawToken> &tokens,
    const AMInterface::parser::CommandNode *command_tree,
    std::shared_ptr<AMInterface::parser::ITokenAnalyzerRuntime> runtime,
    std::string *formatted);

} // namespace AMInterface::parser::highlight


