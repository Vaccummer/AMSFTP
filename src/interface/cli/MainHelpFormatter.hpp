#pragma once

#include "CLI/Formatter.hpp"
#include "domain/style/StyleDomainService.hpp"
#include "foundation/tools/string.hpp"
#include "interface/parser/CommandTree.hpp"
#include "interface/style/StyleManager.hpp"

#include <algorithm>
#include <iomanip>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

namespace AMInterface::cli {

class MainHelpFormatter final : public CLI::Formatter {
public:
  explicit MainHelpFormatter(const AMInterface::style::AMStyleService &style_service,
                             const AMInterface::parser::CommandNode *command_tree =
                                 nullptr)
      : command_tree_(command_tree) {
    const auto &style_cfg = style_service.GetInitArg().style;
    option_style_ = NormalizeStyleTag_(style_cfg.common.cli_option);
    module_style_ = NormalizeStyleTag_(style_cfg.common.cli_module);
    command_style_ = NormalizeStyleTag_(style_cfg.common.cli_command);
    comment_style_ = NormalizeStyleTag_(style_cfg.complete_menu.help_style);
    if (comment_style_.empty()) {
      comment_style_ = NormalizeStyleTag_(style_cfg.internal_style.inline_hint);
    }
  }

  [[nodiscard]] std::string make_option(const CLI::Option *opt,
                                        bool is_positional) const override {
    const std::string plain_name =
        CLI::Formatter::make_option_name(opt, is_positional) +
        CLI::Formatter::make_option_opts(opt);
    const std::string plain_desc = CLI::Formatter::make_option_desc(opt);
    return FormatHelpLine_(plain_name, ApplyStyleTag_(option_style_, plain_name),
                           ApplyStyleTag_(comment_style_, plain_desc));
  }

  [[nodiscard]] std::string make_subcommands(const CLI::App *app,
                                             CLI::AppFormatMode mode) const override {
    std::stringstream out;

    std::vector<const CLI::App *> subcommands = app->get_subcommands({});
    std::vector<std::string> subcmd_groups_seen = {};
    for (const CLI::App *sub : subcommands) {
      if (!sub) {
        continue;
      }
      if (sub->get_name().empty()) {
        if (!sub->get_group().empty()) {
          out << make_expanded(sub, mode);
        }
        continue;
      }

      const std::string group_key = sub->get_group();
      if (group_key.empty()) {
        continue;
      }
      const auto found = std::find_if(
          subcmd_groups_seen.begin(), subcmd_groups_seen.end(),
          [&group_key](const std::string &seen) {
            return AMStr::lowercase(seen) == AMStr::lowercase(group_key);
          });
      if (found == subcmd_groups_seen.end()) {
        subcmd_groups_seen.push_back(group_key);
      }
    }

    for (const std::string &group : subcmd_groups_seen) {
      out << "\n" << group << ":\n";
      std::vector<const CLI::App *> subcommands_group = app->get_subcommands(
          [&group](const CLI::App *sub) {
            return sub && AMStr::lowercase(sub->get_group()) ==
                              AMStr::lowercase(group);
          });
      SortSubcommands_(subcommands_group);
      for (const CLI::App *sub : subcommands_group) {
        if (!sub || sub->get_name().empty()) {
          continue;
        }
        if (mode != CLI::AppFormatMode::All) {
          out << make_subcommand(sub);
        } else {
          out << sub->help(sub->get_name(), CLI::AppFormatMode::Sub);
          out << "\n";
        }
      }
    }

    return out.str();
  }

  [[nodiscard]] std::string make_subcommand(const CLI::App *sub) const override {
    const std::string plain_name =
        sub->get_display_name(true) +
        (sub->get_required() ? " " + get_label("REQUIRED") : "");
    const std::string plain_desc = sub->get_description();
    const std::string styled_name =
        ApplyStyleTag_(ResolveCommandStyle_(sub), plain_name);
    const std::string styled_desc = ApplyStyleTag_(comment_style_, plain_desc);
    return FormatHelpLine_(plain_name, styled_name, styled_desc);
  }

  [[nodiscard]] std::string make_expanded(
      const CLI::App *sub, CLI::AppFormatMode mode) const override {
    return CLI::Formatter::make_expanded(sub, mode);
  }

private:
  [[nodiscard]] static std::string NormalizeStyleTag_(const std::string &raw_tag) {
    std::string trimmed = AMStr::Strip(raw_tag);
    if (trimmed.empty()) {
      return {};
    }
    if (trimmed.find("[/") != std::string::npos) {
      return {};
    }
    if (trimmed.front() != '[') {
      trimmed.insert(trimmed.begin(), '[');
    }
    if (trimmed.back() != ']') {
      trimmed.push_back(']');
    }
    if (!AMDomain::style::service::IsStyleString(trimmed)) {
      return {};
    }
    return trimmed;
  }

  [[nodiscard]] static std::string ApplyStyleTag_(const std::string &tag,
                                                  const std::string &text) {
    const std::string escaped = AMStr::BBCEscape(text);
    if (tag.empty()) {
      return escaped;
    }
    return tag + escaped + "[/]";
  }

  [[nodiscard]] std::string ResolveCommandStyle_(const CLI::App *sub) const {
    if (IsModule_(sub)) {
      return module_style_;
    }
    return command_style_;
  }

  [[nodiscard]] bool IsModule_(const CLI::App *sub) const {
    if (!sub) {
      return false;
    }
    if (command_tree_ && !sub->get_name().empty()) {
      return command_tree_->IsModule(sub->get_name());
    }
    const auto children = sub->get_subcommands(
        [](const CLI::App *child) { return child && !child->get_name().empty(); });
    return !children.empty();
  }

  void SortSubcommands_(std::vector<const CLI::App *> &subcommands) const {
    std::sort(subcommands.begin(), subcommands.end(),
              [this](const CLI::App *lhs, const CLI::App *rhs) {
                const bool lhs_is_module = IsModule_(lhs);
                const bool rhs_is_module = IsModule_(rhs);
                if (lhs_is_module != rhs_is_module) {
                  return lhs_is_module && !rhs_is_module;
                }
                const std::string lhs_name = lhs ? lhs->get_name() : std::string();
                const std::string rhs_name = rhs ? rhs->get_name() : std::string();
                return lhs_name < rhs_name;
              });
  }

  [[nodiscard]] std::string FormatHelpLine_(const std::string &plain_name,
                                            const std::string &rendered_name,
                                            const std::string &rendered_desc) const {
    std::stringstream out;
    const std::string padded_plain_name = " " + plain_name;
    const std::string padded_rendered_name = " " + rendered_name;
    const size_t column_width = get_column_width();

    out << padded_rendered_name;
    if (padded_plain_name.size() < column_width) {
      out << std::string(column_width - padded_plain_name.size(), ' ');
    }

    if (!rendered_desc.empty()) {
      if (padded_plain_name.size() >= column_width) {
        out << "\n" << std::setw(static_cast<int>(column_width)) << "";
      }
      for (char ch : rendered_desc) {
        out.put(ch);
        if (ch == '\n') {
          out << std::setw(static_cast<int>(column_width)) << "";
        }
      }
    }

    out << "\n";
    return out.str();
  }

  const AMInterface::parser::CommandNode *command_tree_ = nullptr;
  std::string option_style_ = {};
  std::string comment_style_ = {};
  std::string module_style_ = {};
  std::string command_style_ = {};
};

inline void InstallMainHelpFormatter(
    CLI::App &app, const AMInterface::style::AMStyleService &style_service,
    const AMInterface::parser::CommandNode *command_tree = nullptr) {
  auto formatter =
      std::make_shared<MainHelpFormatter>(style_service, command_tree);
  if (const auto existing = app.get_formatter(); existing) {
    formatter->column_width(existing->get_column_width());
    formatter->right_column_width(existing->get_right_column_width());
    formatter->description_paragraph_width(
        existing->get_description_paragraph_width());
    formatter->footer_paragraph_width(existing->get_footer_paragraph_width());
  }
  app.formatter(std::move(formatter));
}

} // namespace AMInterface::cli
