#pragma once

#include <cstddef>
#include <string>

namespace AMInterface::parser::shared {

[[nodiscard]] bool IsQuotedChar(char c);

[[nodiscard]] size_t FindUnescapedChar(const std::string &text, char target);

[[nodiscard]] std::string UnescapeBackticks(const std::string &text,
                                            bool unescape_at_sign);

[[nodiscard]] bool IsPathLikeText(const std::string &text,
                                  bool include_dot_prefix);

[[nodiscard]] bool HasClearPathSign(const std::string &text,
                                    bool include_dot_prefix);

} // namespace AMInterface::parser::shared

