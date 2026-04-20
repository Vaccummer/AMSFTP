#pragma once

#include "CLI/CLI.hpp"
#include "foundation/core/DataClass.hpp"
#include "interface/cli/ParseErrorFormatter.hpp"
#include "interface/parser/CommandTree.hpp"
#include "interface/style/StyleManager.hpp"

#include <algorithm>
#include <string>
#include <vector>

namespace AMInterface::cli {

enum class CliParseAction {
  Dispatch,
  ShowHelp,
  ShowAllHelp,
  ShowVersion,
  ParseFailed,
};

struct CliParseRequest {
  CLI::App *app = nullptr;
  const AMInterface::parser::CommandNode *command_tree = nullptr;
  const AMInterface::style::AMStyleService *style_service = nullptr;
  bool validate_unknown_command = true;
  bool require_command = false;
  bool show_all_help_when_no_command = false;
};

struct CliParseOutcome {
  CliParseAction action = CliParseAction::ParseFailed;
  ECM rcm = OK;
  int exit_code = 0;
  std::string message = {};

  [[nodiscard]] bool ShouldDispatch() const {
    return action == CliParseAction::Dispatch;
  }
};

inline std::string BuildUnknownCommandError(
    const std::vector<std::string> &tokens,
    const AMInterface::parser::CommandNode &command_tree,
    const AMInterface::style::AMStyleService &style_service) {
  std::string invalid_token = {};
  const auto *matched = AMInterface::parser::MatchSubcommand(
      tokens, command_tree, &invalid_token);
  if (invalid_token.empty()) {
    return {};
  }

  const std::string invalid = style_service.Format(
      invalid_token, AMInterface::style::StyleIndex::IllegalCommand);
  if (!matched) {
    return "❌ " + invalid + " is not a valid module or command";
  }

  const bool is_module = !matched->subcommands.empty();
  const auto kind_style = is_module ? AMInterface::style::StyleIndex::Module
                                    : AMInterface::style::StyleIndex::Command;
  const std::string kind_text = is_module ? "module" : "command";
  const std::string matched_name =
      style_service.Format(matched->name, kind_style);
  return "❌ " + invalid + " is not a valid module or command, did you mean " +
         kind_text + ": " + matched_name;
}

inline bool HasParsedCommand(const CLI::App &app) {
  for (const auto *sub : app.get_subcommands()) {
    if (sub && sub->parsed()) {
      return true;
    }
  }
  return false;
}

inline CliParseOutcome BuildParseErrorOutcome_(CLI::App &app,
                                               const CLI::CallForHelp &error) {
  return {
      CliParseAction::ShowHelp,
      OK,
      error.get_exit_code(),
      app.help(),
  };
}

inline CliParseOutcome BuildParseErrorOutcome_(CLI::App &app,
                                               const CLI::CallForAllHelp &error) {
  return {
      CliParseAction::ShowAllHelp,
      OK,
      error.get_exit_code(),
      app.help("", CLI::AppFormatMode::All),
  };
}

inline CliParseOutcome BuildParseErrorOutcome_(
    CLI::App &app, const CLI::CallForVersion &error) {
  return {
      CliParseAction::ShowVersion,
      OK,
      error.get_exit_code(),
      app.version(),
  };
}

inline CliParseOutcome BuildParseErrorOutcome_(CLI::App &,
                                               const CLI::ParseError &error) {
  const std::string parse_msg = FormatCliParseErrorMessage(error);
  return {
      CliParseAction::ParseFailed,
      {EC::InvalidArg, "", "", parse_msg},
      error.get_exit_code(),
      parse_msg,
  };
}

inline CliParseOutcome BuildMissingCommandOutcome_(
    const CliParseRequest &request) {
  if (!request.app) {
    return {
        CliParseAction::ParseFailed,
        {EC::InvalidHandle, "", "", "CLI app is not initialized"},
        static_cast<int>(EC::InvalidHandle),
        "CLI app is not initialized",
    };
  }

  const bool show_all_help = request.show_all_help_when_no_command;
  return {
      show_all_help ? CliParseAction::ShowAllHelp : CliParseAction::ShowHelp,
      {EC::InvalidArg, "", "", ""},
      static_cast<int>(EC::InvalidArg),
      show_all_help ? request.app->help("", CLI::AppFormatMode::All)
                    : request.app->help(),
  };
}

inline CliParseOutcome ValidateUnknownCommand_(
    const CliParseRequest &request, const std::vector<std::string> &tokens) {
  if (!request.validate_unknown_command || !request.command_tree ||
      !request.style_service || tokens.empty()) {
    return {
        CliParseAction::Dispatch,
        OK,
        0,
        {},
    };
  }

  const std::string invalid_command_error = BuildUnknownCommandError(
      tokens, *request.command_tree, *request.style_service);
  if (invalid_command_error.empty()) {
    return {
        CliParseAction::Dispatch,
        OK,
        0,
        {},
    };
  }

  return {
      CliParseAction::ParseFailed,
      {EC::InvalidArg, "", "", invalid_command_error},
      static_cast<int>(EC::InvalidArg),
      invalid_command_error,
  };
}

template <typename ParseFn>
inline CliParseOutcome ParseCliImpl_(const CliParseRequest &request,
                                     const std::vector<std::string> &tokens,
                                     ParseFn parse_fn) {
  if (!request.app) {
    return {
        CliParseAction::ParseFailed,
        {EC::InvalidHandle, "", "", "CLI app is not initialized"},
        static_cast<int>(EC::InvalidHandle),
        "CLI app is not initialized",
    };
  }

  const CliParseOutcome invalid_command =
      ValidateUnknownCommand_(request, tokens);
  if (!invalid_command.ShouldDispatch()) {
    return invalid_command;
  }

  try {
    request.app->clear();
    parse_fn();
  } catch (const CLI::CallForHelp &error) {
    return BuildParseErrorOutcome_(*request.app, error);
  } catch (const CLI::CallForAllHelp &error) {
    return BuildParseErrorOutcome_(*request.app, error);
  } catch (const CLI::CallForVersion &error) {
    return BuildParseErrorOutcome_(*request.app, error);
  } catch (const CLI::ParseError &error) {
    return BuildParseErrorOutcome_(*request.app, error);
  }

  if (request.require_command && !HasParsedCommand(*request.app)) {
    return BuildMissingCommandOutcome_(request);
  }

  return {
      CliParseAction::Dispatch,
      OK,
      0,
      {},
  };
}

inline CliParseOutcome ParseCliArgv(const CliParseRequest &request, int argc,
                                    char **argv) {
  std::vector<std::string> argv_tokens = {};
  if (argc > 1) {
    argv_tokens.reserve(static_cast<size_t>(argc - 1));
    for (int i = 1; i < argc; ++i) {
      argv_tokens.emplace_back(argv[i] ? argv[i] : "");
    }
  }

  return ParseCliImpl_(request, argv_tokens,
                       [&]() { request.app->parse(argc, argv); });
}

inline CliParseOutcome ParseCliTokens(const CliParseRequest &request,
                                      std::vector<std::string> cli_args) {
  std::vector<std::string> parse_args = cli_args;
  std::ranges::reverse(parse_args);
  return ParseCliImpl_(request, cli_args,
                       [&]() { request.app->parse(parse_args); });
}

} // namespace AMInterface::cli
