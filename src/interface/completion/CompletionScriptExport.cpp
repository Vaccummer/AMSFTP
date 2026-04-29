#include "interface/completion/CompletionScriptExport.hpp"

#include "domain/style/StyleDomainService.hpp"
#include "foundation/tools/string.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace AMInterface::completion {

namespace fs = std::filesystem;

using AMInterface::parser::CommandNode;

namespace {

struct SubInfo {
  std::string name;
  std::string help;
  bool is_module = false;
};

struct OptInfo {
  std::string display;
  std::string help;
  bool has_value = false;
};

struct FlatNode {
  std::vector<SubInfo> subs;
  std::vector<OptInfo> opts;
};

using FlatTree = std::unordered_map<std::string, FlatNode>;

bool OptionHasValue_(const CommandNode &node, const std::string &long_name,
                     char short_name) {
  for (const auto &rule : node.option_value_rules) {
    if (!long_name.empty() && rule.long_option == long_name)
      return true;
    if (short_name != '\0' && rule.short_option == short_name)
      return true;
  }
  return false;
}

void CollectFlat_(const CommandNode *node, const std::string &prefix,
                  FlatTree &out) {
  if (!node)
    return;

  FlatNode fn = {};
  for (const auto &[sub_name, sub_child] : node->subcommands) {
    if (!sub_child)
      continue;
    fn.subs.push_back(
        {sub_name, sub_child->help, !sub_child->subcommands.empty()});
  }
  for (const auto &[lname, lhelp] : node->long_options) {
    fn.opts.push_back({lname, lhelp, OptionHasValue_(*node, lname, '\0')});
  }
  for (const auto &[sname, shelp] : node->short_options) {
    fn.opts.push_back(
        {std::string("-") + sname, shelp, OptionHasValue_(*node, "", sname)});
  }
  out[prefix] = std::move(fn);

  for (const auto &[name, child] : node->subcommands) {
    if (!child)
      continue;
    const std::string path = prefix.empty() ? name : prefix + " " + name;
    CollectFlat_(child.get(), path, out);
  }
}

std::string EscapePS_(const std::string &s) {
  std::string out = {};
  out.reserve(s.size() + 8);
  for (char ch : s) {
    switch (ch) {
    case '`':
      out += "``";
      break;
    case '"':
      out += "`\"";
      break;
    case '$':
      out += "`$";
      break;
    case '\r':
      out += "`r";
      break;
    case '\n':
      out += "`n";
      break;
    case '\t':
      out += "`t";
      break;
    default:
      out.push_back(ch);
      break;
    }
  }
  return out;
}

std::string EscapeBash_(const std::string &s) {
  std::string out = {};
  out.reserve(s.size() + 8);
  for (char ch : s) {
    if (ch == '"' || ch == '\\' || ch == '$' || ch == '`')
      out.push_back('\\');
    out.push_back(ch);
  }
  return out;
}

std::string EscapeZsh_(const std::string &s) {
  std::string out = {};
  out.reserve(s.size() + 8);
  for (char ch : s) {
    if (ch == '"' || ch == '\\' || ch == '$' || ch == '`')
      out.push_back('\\');
    out.push_back(ch);
  }
  return out;
}

std::string NormalizeStyleTag_(const std::string &raw, const std::string &fallback) {
  auto normalize = [](const std::string &input) -> std::string {
    std::string trimmed = AMStr::Strip(input);
    if (trimmed.empty() || trimmed.find("[/") != std::string::npos) {
      return "";
    }
    if (trimmed.front() != '[') {
      trimmed.insert(trimmed.begin(), '[');
    }
    if (trimmed.back() != ']') {
      trimmed.push_back(']');
    }
    return trimmed;
  };

  std::string normalized = normalize(raw);
  if (!normalized.empty() && AMDomain::style::service::IsStyleString(normalized)) {
    return normalized;
  }
  normalized = normalize(fallback);
  if (!normalized.empty() && AMDomain::style::service::IsStyleString(normalized)) {
    return normalized;
  }
  return "";
}

int HexNibble_(char ch) {
  const unsigned char uch = static_cast<unsigned char>(ch);
  if (uch >= '0' && uch <= '9') {
    return static_cast<int>(uch - '0');
  }
  if (uch >= 'a' && uch <= 'f') {
    return static_cast<int>(uch - 'a' + 10);
  }
  if (uch >= 'A' && uch <= 'F') {
    return static_cast<int>(uch - 'A' + 10);
  }
  return -1;
}

int HexByte_(char hi, char lo) {
  const int h = HexNibble_(hi);
  const int l = HexNibble_(lo);
  if (h < 0 || l < 0) {
    return -1;
  }
  return h * 16 + l;
}

std::string HexToSgrRgb_(const std::string &hex, bool background) {
  if (!AMDomain::style::service::IsHexColorString(hex)) {
    return "";
  }
  const int r = HexByte_(hex[1], hex[2]);
  const int g = HexByte_(hex[3], hex[4]);
  const int b = HexByte_(hex[5], hex[6]);
  if (r < 0 || g < 0 || b < 0) {
    return "";
  }
  return std::to_string(background ? 48 : 38) + ";2;" + std::to_string(r) +
         ";" + std::to_string(g) + ";" + std::to_string(b);
}

std::string StyleTagToZshListColorCode_(const std::string &style_tag,
                                        const std::string &fallback_code) {
  if (style_tag.size() < 2 || style_tag.front() != '[' || style_tag.back() != ']') {
    return fallback_code;
  }
  const std::string body = AMStr::Strip(style_tag.substr(1, style_tag.size() - 2));
  if (body.empty()) {
    return fallback_code;
  }

  std::istringstream in(body);
  std::vector<std::string> tokens;
  for (std::string token; in >> token;) {
    tokens.push_back(std::move(token));
  }
  if (tokens.empty()) {
    return fallback_code;
  }

  std::vector<std::string> sgr = {};
  size_t i = 0;
  if (i < tokens.size() && AMDomain::style::service::IsHexColorString(tokens[i])) {
    const std::string fg = HexToSgrRgb_(tokens[i], false);
    if (!fg.empty()) {
      sgr.push_back(fg);
    }
    ++i;
  }
  if (i + 1 < tokens.size() && AMStr::lowercase(tokens[i]) == "on" &&
      AMDomain::style::service::IsHexColorString(tokens[i + 1])) {
    const std::string bg = HexToSgrRgb_(tokens[i + 1], true);
    if (!bg.empty()) {
      sgr.push_back(bg);
    }
    i += 2;
  }
  for (; i < tokens.size(); ++i) {
    if (tokens[i].size() != 1) {
      continue;
    }
    const char flag = static_cast<char>(
        std::tolower(static_cast<unsigned char>(tokens[i].front())));
    if (flag == 'b') {
      sgr.push_back("1");
    } else if (flag == 'i') {
      sgr.push_back("3");
    } else if (flag == 'u') {
      sgr.push_back("4");
    } else if (flag == 's') {
      sgr.push_back("9");
    }
  }
  if (sgr.empty()) {
    return fallback_code;
  }

  std::string out = {};
  for (size_t idx = 0; idx < sgr.size(); ++idx) {
    if (idx != 0) {
      out.push_back(';');
    }
    out += sgr[idx];
  }
  return out;
}

std::string EncodeZshTripletField_(const std::string &field) {
  std::string out = {};
  out.reserve(field.size() + 8);
  for (char ch : field) {
    switch (ch) {
    case '%':
      out += "%25";
      break;
    case ':':
      out += "%3A";
      break;
    case '\n':
      out += "%0A";
      break;
    default:
      out.push_back(ch);
      break;
    }
  }
  return out;
}

std::string ToPSIdentifier_(const std::string &s) {
  std::string out = {};
  out.reserve(s.size());
  for (char ch : s) {
    const unsigned char uch = static_cast<unsigned char>(ch);
    if (std::isalnum(uch) || ch == '_') {
      out.push_back(ch);
    } else {
      out.push_back('_');
    }
  }
  if (out.empty())
    out = "app";
  if (std::isdigit(static_cast<unsigned char>(out.front()))) {
    out.insert(out.begin(), '_');
  }
  return out;
}

std::string NormalizeAppName_(const std::string &raw_app_name) {
  std::string app = raw_app_name;
  constexpr std::string_view exe_suffix = ".exe";
  if (app.size() > exe_suffix.size() &&
      AMStr::lowercase(app.substr(app.size() - exe_suffix.size())) ==
          exe_suffix) {
    app.resize(app.size() - exe_suffix.size());
  }
  return app;
}

std::string GeneratePowerShell_(const CommandNode &tree,
                                const std::string &app_name) {
  FlatTree flat = {};
  CollectFlat_(&tree, "", flat);
  const std::string ps_tree_var = ToPSIdentifier_(app_name) + "_tree";

  std::ostringstream s;
  s << "# " << app_name << " completion (PowerShell)\n";
  s << "# Usage: . " << app_name << ".ps1  (dot-source to register)\n\n";

  s << "$script:" << ps_tree_var << " = @(\n";
  for (const auto &[path, fn] : flat) {
    std::vector<SubInfo> modules = {};
    std::vector<SubInfo> commands = {};
    modules.reserve(fn.subs.size());
    commands.reserve(fn.subs.size());
    for (const auto &sub : fn.subs) {
      if (sub.is_module) {
        modules.push_back(sub);
      } else {
        commands.push_back(sub);
      }
    }
    auto sort_sub = [](const SubInfo &a, const SubInfo &b) {
      return a.name < b.name;
    };
    std::sort(modules.begin(), modules.end(), sort_sub);
    std::sort(commands.begin(), commands.end(), sort_sub);

    std::vector<OptInfo> options = fn.opts;
    std::sort(options.begin(), options.end(),
              [](const OptInfo &a, const OptInfo &b) {
                return a.display < b.display;
              });

    s << "  [pscustomobject]@{\n";
    s << "    path = \"" << EscapePS_(path) << "\"\n";
    s << "    subs = @(\n";
    for (const auto &si : modules) {
      s << "      [pscustomobject]@{ name = \"" << EscapePS_(si.name)
        << "\"; kind = \"module\"; info = \"" << EscapePS_(si.help)
        << "\" }\n";
    }
    for (const auto &si : commands) {
      s << "      [pscustomobject]@{ name = \"" << EscapePS_(si.name)
        << "\"; kind = \"command\"; info = \"" << EscapePS_(si.help)
        << "\" }\n";
    }
    s << "    )\n";
    s << "    opts = @(\n";
    for (const auto &oi : options) {
      s << "      [pscustomobject]@{ name = \"" << EscapePS_(oi.display)
        << "\"; info = \"" << EscapePS_(oi.help) << "\" }\n";
    }
    s << "    )\n";
    s << "  }\n";
  }
  s << ")\n\n";

  s << "Register-ArgumentCompleter -CommandName \"" << EscapePS_(app_name)
    << "\" -ScriptBlock {\n";
  s << "  param($wordToComplete, $commandAst, $cursorPosition)\n";
  s << "  $words = @(); $i = 0\n";
  s << "  foreach ($el in $commandAst.CommandElements) {\n";
  s << "    if ($i -eq 0) { $i++; continue }\n";
  s << "    $val = if ($el -is [string]) { $el } else { $el.Extent.Text }\n";
  s << "    if ($val -eq $wordToComplete -and "
       "$el.Extent.EndOffset -ge $cursorPosition) { break }\n";
  s << "    $words += $val; $i++\n";
  s << "  }\n";
  s << "  $nodes = $script:" << ps_tree_var << "\n";
  s << "  $findNode = {\n";
  s << "    param($allNodes, $path)\n";
  s << "    foreach ($n in $allNodes) {\n";
  s << "      if ($n.path -ceq $path) { return $n }\n";
  s << "    }\n";
  s << "    return $null\n";
  s << "  }\n";
  s << "  $cmdPath = \"\"\n";
  s << "  foreach ($w in $words) {\n";
  s << "    if ($w.StartsWith('-')) { break }\n";
  s << "    $testPath = if ($cmdPath) { \"$cmdPath $w\" } else { $w }\n";
  s << "    $testNode = & $findNode $nodes $testPath\n";
  s << "    if ($null -ne $testNode) {\n";
  s << "      $cmdPath = $testPath\n";
  s << "      continue\n";
  s << "    }\n";
  s << "    break\n";
  s << "  }\n";
  s << "  $curNode = & $findNode $nodes $cmdPath\n";
  s << "  if ($null -eq $curNode) { return @() }\n";
  s << "  $match = $wordToComplete + \"*\"\n";
  s << "  $items = @()\n";
  s << "  foreach ($sub in $curNode.subs) {\n";
  s << "    if ($sub.kind -cne 'module') { continue }\n";
  s << "    if ($sub.name -cnotlike $match) { continue }\n";
  s << "    $items += [pscustomobject]@{ name = $sub.name; icon = '🧩'; info = "
       "$sub.info; rt = 'ParameterValue' }\n";
  s << "  }\n";
  s << "  foreach ($sub in $curNode.subs) {\n";
  s << "    if ($sub.kind -cne 'command') { continue }\n";
  s << "    if ($sub.name -cnotlike $match) { continue }\n";
  s << "    $items += [pscustomobject]@{ name = $sub.name; icon = '🚀'; info = "
       "$sub.info; rt = 'ParameterValue' }\n";
  s << "  }\n";
  s << "  foreach ($opt in $curNode.opts) {\n";
  s << "    if ($opt.name -cnotlike $match) { continue }\n";
  s << "    $items += [pscustomobject]@{ name = $opt.name; icon = '⚙️'; info = "
       "$opt.info; rt = 'ParameterName' }\n";
  s << "  }\n";
  s << "  $completions = @()\n";
  s << "  foreach ($it in $items) {\n";
  s << "    $name = if ($null -eq $it.name) { '' } else { $it.name }\n";
  s << "    $info = if ([string]::IsNullOrWhiteSpace($it.info)) { '' } else { "
       "$it.info }\n";
  s << "    $completions += [System.Management.Automation.CompletionResult]"
       "::new($name, $name, $it.rt, $info)\n";
  s << "  }\n";
  s << "  $completions\n";
  s << "}\n";

  return s.str();
}

std::string GenerateBash_(const CommandNode &tree,
                          const std::string &app_name) {
  FlatTree flat = {};
  CollectFlat_(&tree, "", flat);

  std::ostringstream s;
  s << "# " << app_name << " completion (Bash)\n";
  s << "# Usage: source " << app_name << ".bash\n\n";

  s << "_" << app_name << "_complete() {\n";
  s << "  local cur prev words cword\n";
  s << "  _init_completion 2>/dev/null || {\n";
  s << "    cur=\"${COMP_WORDS[COMP_CWORD]}\"\n";
  s << "    prev=\"${COMP_WORDS[COMP_CWORD-1]}\"\n";
  s << "  }\n\n";

  s << "  local cmd_path=\"\"\n";
  s << "  local i w\n";
  s << "  for ((i=1; i<COMP_CWORD; i++)); do\n";
  s << "    w=\"${COMP_WORDS[i]}\"\n";
  s << "    [[ \"$w\" == -* ]] && break\n";
  s << "    local test_path=\"$w\"\n";
  s << "    [[ -n \"$cmd_path\" ]] && test_path=\"$cmd_path $w\"\n";
  s << "    case \"$test_path\" in\n";
  for (const auto &[path, fn] : flat) {
    (void)fn;
    s << "      \"" << EscapeBash_(path) << "\") cmd_path=\"$test_path\" ;;\n";
  }
  s << "      *) break ;;\n";
  s << "    esac\n";
  s << "  done\n\n";

  s << "  case \"$cmd_path\" in\n";
  for (const auto &[path, fn] : flat) {
    s << "    \"" << EscapeBash_(path) << "\")\n";
    s << "      COMPREPLY=($(compgen -W \"";
    bool need_space = false;
    for (const auto &si : fn.subs) {
      if (need_space)
        s << " ";
      s << si.name;
      need_space = true;
    }
    for (const auto &oi : fn.opts) {
      if (need_space)
        s << " ";
      s << oi.display;
      need_space = true;
    }
    s << "\" -- \"$cur\"))\n";
    s << "      ;;\n";
  }
  s << "  esac\n";
  s << "}\n\n";
  s << "complete -F _" << app_name << "_complete " << app_name << "\n";

  return s.str();
}

std::string GenerateZsh_(const CommandNode &tree, const std::string &app_name,
                         const CompletionScriptExportRequest &request) {
  FlatTree flat = {};
  CollectFlat_(&tree, "", flat);
  const std::string module_style =
      NormalizeStyleTag_(request.style_cli_module, "[#00b8a9]");
  const std::string command_style =
      NormalizeStyleTag_(request.style_cli_command, "[#FFC66C]");
  const std::string option_style =
      NormalizeStyleTag_(request.style_cli_option, "[#b8b0b0]");
  const std::string comment_style =
      NormalizeStyleTag_(request.style_complete_help, "[#928a97]");
  const std::string module_color =
      StyleTagToZshListColorCode_(module_style, "38;2;0;184;169");
  const std::string command_color =
      StyleTagToZshListColorCode_(command_style, "38;2;255;198;108");
  const std::string option_color =
      StyleTagToZshListColorCode_(option_style, "38;2;184;176;176");
  const std::string help_color =
      StyleTagToZshListColorCode_(comment_style, "38;2;146;138;151");

  std::ostringstream s;
  s << "#compdef " << app_name << "\n\n";
  s << "# Generated from BBCode style config via zstyle list-colors.\n";
  s << "_" << app_name << "_completion_styles() {\n";
  s << "  zmodload zsh/complist 2>/dev/null\n";
  s << "  local -a ams_colors=(\n";
  s << "    \"(ams-module)==(#b)([^[:space:]]##)([[:space:]]##)(*)=0="
    << module_color << "=0=" << help_color << "\"\n";
  s << "    \"(ams-module)=*=" << module_color << "\"\n";
  s << "    \"(ams-command)==(#b)([^[:space:]]##)([[:space:]]##)(*)=0="
    << command_color << "=0=" << help_color << "\"\n";
  s << "    \"(ams-command)=*=" << command_color << "\"\n";
  s << "    \"(ams-option)==(#b)([^[:space:]]##)([[:space:]]##)(*)=0="
    << option_color << "=0=" << help_color << "\"\n";
  s << "    \"(ams-option)=*=" << option_color << "\"\n";
  s << "  )\n";
  s << "  zstyle ':completion:*:*:" << app_name << ":*' group-name ''\n";
  s << "  zstyle ':completion:*:*:" << app_name
    << ":*' list-colors \"${ams_colors[@]}\"\n";
  s << "  zstyle ':completion:*:*:" << app_name
    << ":*:default' list-colors \"${ams_colors[@]}\"\n";
  s << "}\n";
  s << "_" << app_name << "_completion_styles\n\n";

  auto emitTriplets = [&](const std::vector<SubInfo> &subs,
                          const std::vector<OptInfo> &opts) {
    auto emit_item = [&](const std::string &target, const std::string &display,
                         const std::string &comment) {
      s << "        \"" << EscapeZsh_(EncodeZshTripletField_(target)) << ":"
        << EscapeZsh_(EncodeZshTripletField_(display)) << ":"
        << EscapeZsh_(EncodeZshTripletField_(comment)) << "\"\n";
    };
    for (const auto &si : subs) {
      emit_item(si.name, si.name, si.help);
    }
    for (const auto &oi : opts) {
      emit_item(oi.display, oi.display, oi.help);
    }
  };

  auto emitZshCaseItems = [&](const FlatNode &fn) {
    std::vector<SubInfo> modules = {};
    std::vector<SubInfo> commands = {};
    modules.reserve(fn.subs.size());
    commands.reserve(fn.subs.size());
    for (const auto &sub : fn.subs) {
      if (sub.is_module) {
        modules.push_back(sub);
      } else {
        commands.push_back(sub);
      }
    }
    auto sort_sub = [](const SubInfo &a, const SubInfo &b) {
      return a.name < b.name;
    };
    std::sort(modules.begin(), modules.end(), sort_sub);
    std::sort(commands.begin(), commands.end(), sort_sub);

    std::vector<OptInfo> options = fn.opts;
    std::sort(options.begin(), options.end(),
              [](const OptInfo &a, const OptInfo &b) {
                return a.display < b.display;
              });

    s << "      module_items=(\n";
    emitTriplets(modules, {});
    s << "      )\n";
    s << "      command_items=(\n";
    emitTriplets(commands, {});
    s << "      )\n";
    s << "      option_items=(\n";
    emitTriplets({}, options);
    s << "      )\n";
  };

  s << "_" << app_name << "() {\n";
  s << "  local context state line\n";
  s << "  typeset -A opt_args\n\n";
  s << "  _" << app_name << "_completion_styles\n\n";

  s << "  local cmd_path=\"\"\n";
  s << "  local i w\n";
  s << "  for ((i=2; i < CURRENT; i++)); do\n";
  s << "    w=\"${words[i]}\"\n";
  s << "    [[ \"$w\" == -* ]] && break\n";
  s << "    local test_path=\"$w\"\n";
  s << "    [[ -n \"$cmd_path\" ]] && test_path=\"$cmd_path $w\"\n";
  s << "    case \"$test_path\" in\n";
  for (const auto &[path, fn] : flat) {
    (void)fn;
    s << "      \"" << EscapeZsh_(path) << "\") cmd_path=\"$test_path\" ;;\n";
  }
  s << "      *) break ;;\n";
  s << "    esac\n";
  s << "  done\n\n";

  s << "  local -a module_items=()\n";
  s << "  local -a command_items=()\n";
  s << "  local -a option_items=()\n";
  s << "  case \"$cmd_path\" in\n";
  for (const auto &[path, fn] : flat) {
    s << "    \"" << EscapeZsh_(path) << "\")\n";
    emitZshCaseItems(fn);
    s << "      ;;\n";
  }
  s << "  esac\n\n";

  s << "  _ams_add_group() {\n";
  s << "    local tag=\"$1\"\n";
  s << "    local group=\"$2\"\n";
  s << "    local source_name=\"$3\"\n";
  s << "    local -a source=(\"${(@P)source_name}\")\n";
  s << "    (( ${#source} )) || return 0\n";
  s << "    local -a targets=()\n";
  s << "    local -a displays=()\n";
  s << "    local item target rest display\n";
  s << "    for item in \"${source[@]}\"; do\n";
  s << "      target=\"${item%%:*}\"\n";
  s << "      rest=\"${item#*:}\"\n";
  s << "      display=\"${rest%%:*}\"\n";
  s << "      target=\"${target//%0A/$'\\n'}\"\n";
  s << "      target=\"${target//%3A/:}\"\n";
  s << "      target=\"${target//%25/%}\"\n";
  s << "      display=\"${display//%0A/$'\\n'}\"\n";
  s << "      display=\"${display//%3A/:}\"\n";
  s << "      display=\"${display//%25/%}\"\n";
  s << "      targets+=(\"$target\")\n";
  s << "      displays+=(\"$display\")\n";
  s << "    done\n";
  s << "    local expl\n";
  s << "    _description \"$tag\" expl \"$group\"\n";
  s << "    compadd \"${expl[@]}\" -Q -J \"$group\" -d displays -a targets\n";
  s << "  }\n\n";
  s << "  _ams_add_group ams-module ams-module module_items\n";
  s << "  _ams_add_group ams-command ams-command command_items\n";
  s << "  _ams_add_group ams-option ams-option option_items\n";
  s << "}\n\n";
  s << "_" << app_name << " \"$@\"\n";

  return s.str();
}

ECMData<std::string>
BuildScriptContent_(const CompletionScriptExportRequest &request,
                    const std::string &app_name) {
  const CommandNode &tree = *request.command_tree;
  switch (request.shell) {
  case CompletionScriptShell::Powershell5:
  case CompletionScriptShell::Powershell7:
    return {GeneratePowerShell_(tree, app_name), OK};
  case CompletionScriptShell::Bash:
    return {GenerateBash_(tree, app_name), OK};
  case CompletionScriptShell::Zsh:
    return {GenerateZsh_(tree, app_name, request), OK};
  }
  return {{EC::InvalidArg, "completion.export", "", "unsupported shell"}, ""};
}

fs::path BuildOutputPath_(CompletionScriptShell shell,
                          const std::string &app_name, const std::string &cwd,
                          const std::string &out_dir) {
  fs::path dir = out_dir.empty() ? fs::path(cwd) : fs::path(out_dir);
  if (dir.is_relative()) {
    dir = fs::path(cwd) / dir;
  }
  dir = fs::absolute(dir).lexically_normal();

  switch (shell) {
  case CompletionScriptShell::Powershell5:
  case CompletionScriptShell::Powershell7:
    return dir / (app_name + ".ps1");
  case CompletionScriptShell::Bash:
    return dir / (app_name + ".bash");
  case CompletionScriptShell::Zsh:
    return dir / ("_" + app_name);
  }
  return dir / (app_name + ".bash");
}

} // namespace

CompletionScriptShell ParseCompletionScriptShell(const std::string &shell) {
  const std::string lower = AMStr::lowercase(AMStr::Strip(shell));
  if (lower == "powershell5" || lower == "ps5") {
    return CompletionScriptShell::Powershell5;
  }
  if (lower == "powershell7" || lower == "ps7") {
    return CompletionScriptShell::Powershell7;
  }
  if (lower == "zsh") {
    return CompletionScriptShell::Zsh;
  }
  return CompletionScriptShell::Bash;
}

ECMData<CompletionScriptExportResult>
ExportCompletionScript(const CompletionScriptExportRequest &request) {
  if (!request.command_tree) {
    return {{EC::InvalidHandle, "completion.export", "<command-tree>",
             "command tree is null"},
            {}};
  }

  const std::string app_name = NormalizeAppName_(request.app_name);
  if (app_name.empty()) {
    return {
        {EC::InvalidArg, "completion.export", "app_name", "app name is empty"},
        {}};
  }

  const fs::path out_path =
      BuildOutputPath_(request.shell, app_name, request.cwd, request.out_dir);
  std::error_code create_ec = {};
  fs::create_directories(out_path.parent_path(), create_ec);
  if (create_ec && !fs::exists(out_path.parent_path())) {
    return {{EC::FilesystemNoSpace, "completion.export",
             out_path.parent_path().string(),
             "failed to create output directory"},
            {}};
  }

  auto content_result = BuildScriptContent_(request, app_name);
  if (!content_result.rcm) {
    return content_result.rcm;
  }

  std::ofstream ofs(out_path, std::ios::binary | std::ios::trunc);
  if (!ofs.is_open()) {
    return {{EC::FilesystemNoSpace, "completion.export", out_path.string(),
             "failed to open output file"},
            {}};
  }
  ofs << content_result.data;
  ofs.close();
  if (ofs.fail()) {
    return {{EC::FilesystemNoSpace, "completion.export", out_path.string(),
             "write failed"},
            {}};
  }

  CompletionScriptExportResult result = {};
  result.output_path = out_path.string();
  result.display_uri = result.output_path;
  for (char &ch : result.display_uri) {
    if (ch == '\\')
      ch = '/';
  }
  result.bytes = content_result.data.size();
  return {result, OK};
}

} // namespace AMInterface::completion
