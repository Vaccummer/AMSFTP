#pragma once

#include "CLI/CLI.hpp"
#include "foundation/tools/string.hpp"

#include <sstream>
#include <string>

namespace AMInterface::cli {

inline size_t CountExtraArgs_(const std::string &args_text) {
  size_t count = 0;
  std::istringstream iss(args_text);
  std::string token = {};
  while (iss >> token) {
    ++count;
  }
  return count;
}

inline std::string ExtractExtrasArgText_(const std::string &raw_message) {
  static const std::string kSinglePrefix =
      "The following argument was not expected: ";
  static const std::string kMultiPrefix =
      "The following arguments were not expected: ";

  if (raw_message.rfind(kSinglePrefix, 0) == 0) {
    return AMStr::Strip(raw_message.substr(kSinglePrefix.size()));
  }
  if (raw_message.rfind(kMultiPrefix, 0) == 0) {
    return AMStr::Strip(raw_message.substr(kMultiPrefix.size()));
  }
  return AMStr::Strip(raw_message);
}

inline std::string FormatCliParseErrorMessage(const CLI::ParseError &error) {
  if (error.get_name() != "ExtrasError") {
    return error.what();
  }
  const std::string args_text = ExtractExtrasArgText_(error.what());
  const size_t invalid_arg_count = CountExtraArgs_(args_text);
  return AMStr::fmt("❌ Recieve {} invalid args: {}", invalid_arg_count,
                    args_text);
}

} // namespace AMInterface::cli

