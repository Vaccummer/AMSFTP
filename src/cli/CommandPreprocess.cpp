#include "AMCLI/CommandPreprocess.hpp"
#include "AMBase/CommonTools.hpp"
#include <vector>

using EC = ErrorCode;

/**
 * @brief Return true if a character is valid inside a variable name.
 */
static bool IsVarNameChar(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
         (c >= '0' && c <= '9') || c == '_';
}

/**
 * @brief Return true if a variable name is non-empty and valid.
 */
static bool IsValidVarName(const std::string &name) {
  if (name.empty()) {
    return false;
  }
  for (char c : name) {
    if (!IsVarNameChar(c)) {
      return false;
    }
  }
  return true;
}

/**
 * @brief Normalize a raw value by trimming and stripping paired quotes.
 */
static AMCommandPreprocessor::ECM ParseValue(const std::string &input,
                                             std::string *value) {
  if (!value) {
    return {EC::InvalidArg, "Null output pointer"};
  }
  std::string trimmed = AMStr::TrimWhitespaceCopy(input);
  if (trimmed.empty()) {
    *value = "";
    return {EC::Success, ""};
  }

  const char first = trimmed.front();
  const char last = trimmed.back();
  const bool starts_quote = first == '"' || first == '\'';
  const bool ends_quote = last == '"' || last == '\'';

  if (starts_quote || ends_quote) {
    if (trimmed.size() < 2 || first != last) {
      return {EC::InvalidArg, "Malformed quoted value"};
    }
    *value = trimmed.substr(1, trimmed.size() - 2);
    return {EC::Success, ""};
  }

  *value = trimmed;
  return {EC::Success, ""};
}

/**
 * @brief Parse a variable token like $name or ${ name }.
 */
static AMCommandPreprocessor::ECM ParseVarToken(const std::string &token,
                                                std::string *name) {
  if (!name) {
    return {EC::InvalidArg, "Null output pointer"};
  }
  std::string trimmed = AMStr::TrimWhitespaceCopy(token);
  if (trimmed.empty()) {
    return {EC::InvalidArg, "Empty variable token"};
  }
  if (trimmed.find('=') != std::string::npos) {
    return {EC::InvalidArg, "Invalid variable token"};
  }
  if (trimmed.front() != '$') {
    return {EC::InvalidArg, "Variable token must start with $"};
  }
  if (trimmed.size() < 2) {
    return {EC::InvalidArg, "Invalid variable token"};
  }

  if (trimmed[1] == '{') {
    if (trimmed.back() != '}') {
      return {EC::InvalidArg, "Unclosed ${...} expression"};
    }
    std::string inner =
        AMStr::TrimWhitespaceCopy(trimmed.substr(2, trimmed.size() - 3));
    if (!IsValidVarName(inner)) {
      return {EC::InvalidArg,
              "Invalid variable name: only letters, digits, and _ are allowed"};
    }
    *name = inner;
    return {EC::Success, ""};
  }

  std::string inner = trimmed.substr(1);
  if (!IsValidVarName(inner)) {
    return {EC::InvalidArg,
            "Invalid variable name: only letters, digits, and _ are allowed"};
  }
  *name = inner;
  return {EC::Success, ""};
}

/**
 * @brief Parse a persistent definition ($name= or ${name}=) from the text.
 */
static AMCommandPreprocessor::ECM
ParsePersistentDefinition(const std::string &text, std::string *name,
                          std::string *value) {
  if (!name || !value) {
    return {EC::InvalidArg, "Null output pointer"};
  }
  std::string trimmed = AMStr::TrimWhitespaceCopy(text);
  if (trimmed.size() < 2 || trimmed[0] != '$') {
    return {EC::InvalidArg, "Persistent definition must start with $"};
  }

  std::string name_part;
  size_t pos = 1;
  if (pos < trimmed.size() && trimmed[pos] == '{') {
    const size_t close = trimmed.find('}', pos + 1);
    if (close == std::string::npos) {
      return {EC::InvalidArg, "Unclosed ${...} expression"};
    }
    name_part =
        AMStr::TrimWhitespaceCopy(trimmed.substr(pos + 1, close - pos - 1));
    pos = close + 1;
  } else {
    const size_t start = pos;
    while (pos < trimmed.size() && IsVarNameChar(trimmed[pos])) {
      ++pos;
    }
    if (pos == start) {
      return {EC::InvalidArg,
              "Invalid variable name: only letters, digits, and _ are allowed"};
    }
    name_part = trimmed.substr(start, pos - start);
  }

  if (!IsValidVarName(name_part)) {
    return {EC::InvalidArg,
            "Invalid variable name: only letters, digits, and _ are allowed"};
  }

  while (pos < trimmed.size() && AMStr::IsWhitespace(trimmed[pos])) {
    ++pos;
  }
  if (pos >= trimmed.size() || trimmed[pos] != '=') {
    return {EC::InvalidArg, "Variable definition requires '='"};
  }
  ++pos;
  AMCommandPreprocessor::ECM rcm = ParseValue(trimmed.substr(pos), value);
  if (rcm.first != EC::Success) {
    return rcm;
  }
  *name = name_part;
  return {EC::Success, ""};
}

/**
 * @brief Detect and parse a $name=value definition if present.
 */
static AMCommandPreprocessor::ECM ParseMemoryDefinition(const std::string &text,
                                                        std::string *name,
                                                        std::string *value,
                                                        bool *is_definition) {
  if (!name || !value || !is_definition) {
    return {EC::InvalidArg, "Null output pointer"};
  }
  *is_definition = false;
  if (text.empty() || text.front() != '$') {
    return {EC::Success, ""};
  }

  const size_t eq_pos = text.find('=');
  if (eq_pos == std::string::npos) {
    return {EC::Success, ""};
  }

  size_t pos = 1;
  size_t start = pos;
  while (pos < eq_pos && IsVarNameChar(text[pos])) {
    ++pos;
  }

  if (start == pos) {
    *is_definition = true;
    return {EC::InvalidArg,
            "Invalid variable name: only letters, digits, and _ are allowed"};
  }

  for (size_t scan = pos; scan < eq_pos; ++scan) {
    if (!AMStr::IsWhitespace(text[scan])) {
      *is_definition = true;
      return {EC::InvalidArg,
              "Invalid variable name: only letters, digits, and _ are allowed"};
    }
  }

  std::string name_part = text.substr(start, pos - start);
  *is_definition = true;
  AMCommandPreprocessor::ECM rcm = ParseValue(text.substr(eq_pos + 1), value);
  if (rcm.first != EC::Success) {
    return rcm;
  }
  *name = name_part;
  return {EC::Success, ""};
}

/**
 * @brief Tokenize a command line, honoring simple quotes, up to max tokens.
 */
static std::vector<std::string> SplitTokens(const std::string &input,
                                            size_t max_tokens) {
  std::vector<std::string> tokens;
  std::string current;
  bool in_single = false;
  bool in_double = false;

  for (char c : input) {
    if (in_single) {
      if (c == '\'') {
        in_single = false;
      } else {
        current.push_back(c);
      }
      continue;
    }
    if (in_double) {
      if (c == '"') {
        in_double = false;
      } else {
        current.push_back(c);
      }
      continue;
    }

    if (AMStr::IsWhitespace(c)) {
      if (!current.empty()) {
        tokens.push_back(current);
        current.clear();
        if (tokens.size() >= max_tokens) {
          return tokens;
        }
      }
      continue;
    }

    if (c == '\'') {
      in_single = true;
      continue;
    }
    if (c == '"') {
      in_double = true;
      continue;
    }
    current.push_back(c);
  }

  if (!current.empty() && tokens.size() < max_tokens) {
    tokens.push_back(current);
  }
  return tokens;
}

/**
 * @brief Return true if the command supports async '&' suffix.
 */
static bool IsAsyncAllowed(const std::string &command) {
  std::vector<std::string> tokens = SplitTokens(command, 2);
  if (tokens.empty()) {
    return false;
  }
  const std::string head = AMStr::lowercase(tokens[0]);
  if (head == "cp") {
    return true;
  }
  if (head == "task" && tokens.size() >= 2 &&
      AMStr::lowercase(tokens[1]) == "submit") {
    return true;
  }
  return false;
}

/**
 * @brief Apply variable substitution with backtick escapes.
 */
static AMCommandPreprocessor::ECM SubstituteVariables(const std::string &input,
                                                      AMVarManager &var_manager,
                                                      std::string *output) {
  if (!output) {
    return {EC::InvalidArg, "Null output pointer"};
  }
  output->clear();
  for (size_t i = 0; i < input.size(); ++i) {
    const char c = input[i];
    if (c == '`' && i + 1 < input.size() && input[i + 1] == '$') {
      output->push_back('$');
      ++i;
      continue;
    }
    if (c != '$') {
      output->push_back(c);
      continue;
    }

    if (i + 1 >= input.size()) {
      output->push_back('$');
      continue;
    }

    if (input[i + 1] == '{') {
      const size_t close = input.find('}', i + 2);
      if (close == std::string::npos) {
        return {EC::InvalidArg, "Unclosed ${...} expression"};
      }
      const std::string name_raw = input.substr(i + 2, close - (i + 2));
      const std::string name = AMStr::TrimWhitespaceCopy(name_raw);
      if (!IsValidVarName(name)) {
        output->append(input.substr(i, close - i + 1));
        i = close;
        continue;
      }
      std::string value;
      if (var_manager.Resolve(name, &value)) {
        output->append(value);
      } else {
        output->append(input.substr(i, close - i + 1));
      }
      i = close;
      continue;
    }

    size_t start = i + 1;
    size_t pos = start;
    while (pos < input.size() && IsVarNameChar(input[pos])) {
      ++pos;
    }
    if (pos == start) {
      output->push_back('$');
      continue;
    }
    const std::string name = input.substr(start, pos - start);
    std::string value;
    if (var_manager.Resolve(name, &value)) {
      output->append(value);
    } else {
      output->append("$");
      output->append(name);
    }
    i = pos - 1;
  }
  return {EC::Success, ""};
}

/**
 * @brief Apply variable substitution after the first token only.
 */
static AMCommandPreprocessor::ECM
SubstituteAfterFirstToken(const std::string &input, AMVarManager &var_manager,
                          std::string *output) {
  if (!output) {
    return {EC::InvalidArg, "Null output pointer"};
  }
  *output = "";
  if (input.empty()) {
    return {EC::Success, ""};
  }

  size_t pos = 0;
  while (pos < input.size() && AMStr::IsWhitespace(input[pos])) {
    ++pos;
  }
  size_t start = pos;
  while (pos < input.size() && !AMStr::IsWhitespace(input[pos])) {
    ++pos;
  }
  const std::string head = input.substr(0, pos);
  const std::string tail = input.substr(pos);

  std::string substituted_tail;
  AMCommandPreprocessor::ECM rcm =
      SubstituteVariables(tail, var_manager, &substituted_tail);
  if (rcm.first != EC::Success) {
    return rcm;
  }
  *output = head + substituted_tail;
  return {EC::Success, ""};
}

/**
 * @brief Strip a trailing '&' token and mark async execution when allowed.
 */
static AMCommandPreprocessor::ECM HandleAsyncSuffix(const std::string &input,
                                                    std::string *command,
                                                    bool *async_flag) {
  if (!command || !async_flag) {
    return {EC::InvalidArg, "Null output pointer"};
  }
  *async_flag = false;
  std::string trimmed = AMStr::TrimWhitespaceCopy(input);
  if (trimmed.empty()) {
    *command = "";
    return {EC::Success, ""};
  }
  if (trimmed.back() != '&') {
    *command = trimmed;
    return {EC::Success, ""};
  }

  if (trimmed.size() < 2 ||
      !AMStr::IsWhitespace(trimmed[trimmed.size() - 2])) {
    *command = trimmed;
    return {EC::Success, ""};
  }

  std::string base =
      AMStr::TrimWhitespaceCopy(trimmed.substr(0, trimmed.size() - 1));
  if (base.empty()) {
    return {EC::InvalidArg, "Empty command before &"};
  }
  if (!IsAsyncAllowed(base)) {
    return {EC::InvalidArg,
            "& not permitted in functions except cp and task submit"};
  }

  *async_flag = true;
  *command = base;
  return {EC::Success, ""};
}

/**
 * @brief Construct a command preprocessor bound to a config manager.
 */
AMCommandPreprocessor::AMCommandPreprocessor(AMConfigManager &config_manager)
    : var_manager_(AMVarManager::Instance(config_manager)) {}

/**
 * @brief Preprocess a raw interactive command line according to rules.
 */
AMCommandPreprocessor::Result
AMCommandPreprocessor::Preprocess(const std::string &input) {
  Result result;
  std::string trimmed = AMStr::TrimWhitespaceCopy(input);
  if (trimmed.empty()) {
    return result;
  }

  if (!trimmed.empty() && trimmed.front() == '!') {
    std::string shell = AMStr::TrimWhitespaceCopy(trimmed.substr(1));
    if (shell.empty()) {
      result.rcm = {EC::InvalidArg, "Empty shell command"};
      return result;
    }
    result.action = Action::Shell;
    result.command = shell;
    return result;
  }

  if (trimmed.size() >= 3 && trimmed.compare(0, 3, "var") == 0 &&
      (trimmed.size() == 3 || AMStr::IsWhitespace(trimmed[3]))) {
    std::string remainder = AMStr::TrimWhitespaceCopy(trimmed.substr(3));
    if (remainder.empty()) {
      result.rcm = var_manager_.Enumerate();
      result.action = Action::Handled;
      return result;
    }

    const size_t eq_pos = remainder.find('=');
    if (eq_pos != std::string::npos) {
      const std::string left =
          AMStr::TrimWhitespaceCopy(remainder.substr(0, eq_pos));
      const std::string right = remainder.substr(eq_pos + 1);
      std::string name;
      result.rcm = ParseVarToken(left, &name);
      if (result.rcm.first != EC::Success) {
        return result;
      }
      std::string value;
      result.rcm = ParseValue(right, &value);
      if (result.rcm.first != EC::Success) {
        return result;
      }
      result.rcm = var_manager_.SetPersistentVar(name, value, true);
      result.action = Action::Handled;
      return result;
    }

    std::vector<std::string> tokens = SplitTokens(remainder, remainder.size());
    if (tokens.empty()) {
      result.rcm = {EC::InvalidArg, "var requires variable names"};
      return result;
    }
    std::vector<std::string> names;
    names.reserve(tokens.size());
    for (const auto &token : tokens) {
      std::string name;
      result.rcm = ParseVarToken(token, &name);
      if (result.rcm.first != EC::Success) {
        return result;
      }
      names.push_back(name);
    }
    result.rcm = var_manager_.Query(names);
    result.action = Action::Handled;
    return result;
  }

  if (trimmed.size() >= 3 && trimmed.compare(0, 3, "del") == 0 &&
      (trimmed.size() == 3 || AMStr::IsWhitespace(trimmed[3]))) {
    std::string remainder = AMStr::TrimWhitespaceCopy(trimmed.substr(3));
    if (remainder.empty()) {
      result.rcm = {EC::InvalidArg, "del requires variable names"};
      return result;
    }
    std::vector<std::string> tokens = SplitTokens(remainder, remainder.size());
    if (tokens.empty()) {
      result.rcm = {EC::InvalidArg, "del requires variable names"};
      return result;
    }
    std::vector<std::string> names;
    names.reserve(tokens.size());
    for (const auto &token : tokens) {
      std::string name;
      result.rcm = ParseVarToken(token, &name);
      if (result.rcm.first != EC::Success) {
        return result;
      }
      names.push_back(name);
    }
    result.rcm = var_manager_.Delete(names);
    result.action = Action::Handled;
    return result;
  }

  if (trimmed.size() >= 2 && trimmed[0] == '$' && trimmed[1] == '{') {
    size_t close = trimmed.find('}', 2);
    if (close != std::string::npos) {
      size_t pos = close + 1;
      while (pos < trimmed.size() && AMStr::IsWhitespace(trimmed[pos])) {
        ++pos;
      }
      if (pos < trimmed.size() && trimmed[pos] == '=') {
        std::string name;
        std::string value;
        result.rcm = ParsePersistentDefinition(trimmed, &name, &value);
        if (result.rcm.first != EC::Success) {
          return result;
        }
        result.rcm = var_manager_.SetPersistentVar(name, value, true);
        result.action = Action::Handled;
        return result;
      }
    }
  }

  {
    std::string name;
    std::string value;
    bool is_definition = false;
    result.rcm = ParseMemoryDefinition(trimmed, &name, &value, &is_definition);
    if (result.rcm.first != EC::Success) {
      return result;
    }
    if (is_definition) {
      result.rcm = var_manager_.SetMemoryVar(name, value, true);
      result.action = Action::Handled;
      return result;
    }
  }

  std::string substituted;
  result.rcm = SubstituteAfterFirstToken(trimmed, var_manager_, &substituted);
  if (result.rcm.first != EC::Success) {
    return result;
  }

  bool async_flag = false;
  std::string command;
  result.rcm = HandleAsyncSuffix(substituted, &command, &async_flag);
  if (result.rcm.first != EC::Success) {
    return result;
  }

  result.action = Action::Cli;
  result.command = command;
  result.async = async_flag;
  return result;
}
