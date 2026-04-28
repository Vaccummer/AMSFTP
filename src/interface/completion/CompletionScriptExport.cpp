#include "interface/completion/CompletionScriptExport.hpp"

#include "foundation/tools/string.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
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
    if (ch == '\'' || ch == '\\')
      out.push_back('\\');
    out.push_back(ch);
  }
  return out;
}

std::string BBCodeToAnsi_(const std::string &s) {
  std::string out = {};
  out.reserve(s.size() + 32);
  for (size_t i = 0; i < s.size(); ++i) {
    if (s[i] != '[' || i + 1 >= s.size()) {
      out.push_back(s[i]);
      continue;
    }
    const size_t close = s.find(']', i + 1);
    if (close == std::string::npos) {
      out.push_back(s[i]);
      continue;
    }
    const std::string tag = s.substr(i + 1, close - i - 1);
    if (tag == "b") {
      out += "\033[1m";
      i = close;
      continue;
    }
    if (tag == "/b") {
      out += "\033[22m";
      i = close;
      continue;
    }
    if (tag == "dim") {
      out += "\033[2m";
      i = close;
      continue;
    }
    if (tag == "/dim") {
      out += "\033[22m";
      i = close;
      continue;
    }
    if (tag == "cyan") {
      out += "\033[36m";
      i = close;
      continue;
    }
    if (tag == "yellow") {
      out += "\033[33m";
      i = close;
      continue;
    }
    if (tag == "green") {
      out += "\033[32m";
      i = close;
      continue;
    }
    if (tag == "/cyan" || tag == "/yellow" || tag == "/green") {
      out += "\033[39m";
      i = close;
      continue;
    }
    out.push_back(s[i]);
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
  s << "  $maxNameLen = 0\n";
  s << "  foreach ($it in $items) {\n";
  s << "    $nameLen = if ($null -eq $it.name) { 0 } else { $it.name.Length }\n";
  s << "    if ($nameLen -gt $maxNameLen) { $maxNameLen = $nameLen }\n";
  s << "  }\n";
  s << "  $completions = @()\n";
  s << "  foreach ($it in $items) {\n";
  s << "    $name = if ($null -eq $it.name) { '' } else { $it.name }\n";
  s << "    $info = if ([string]::IsNullOrWhiteSpace($it.info)) { '' } else { "
       "$it.info }\n";
  s << "    $nameBlock = $name.PadRight($maxNameLen)\n";
  s << "    $display = if ($info.Length -gt 0) { \"$nameBlock $($it.icon) "
       "$info\" } else { \"$nameBlock $($it.icon)\" }\n";
  s << "      $completions += [System.Management.Automation.CompletionResult]"
       "::new($name, $display, $it.rt, $info)\n";
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

std::string GenerateZsh_(const CommandNode &tree, const std::string &app_name) {
  FlatTree flat = {};
  CollectFlat_(&tree, "", flat);

  std::ostringstream s;
  s << "#compdef " << app_name << "\n\n";

  auto emitZshDescribed = [&](const FlatNode &fn) {
    for (const auto &si : fn.subs) {
      const char *tag = si.is_module ? "[b]Module[/b]" : "[dim]Command[/dim]";
      s << "    \"" << EscapeZsh_(si.name) << ":"
        << EscapeZsh_(si.name + " " + BBCodeToAnsi_(tag)) << "\"\n";
    }
    for (const auto &oi : fn.opts) {
      const char *tag =
          oi.has_value ? "[yellow]Option[/yellow]" : "[cyan]Flag[/cyan]";
      s << "    \"" << EscapeZsh_(oi.display) << ":"
        << EscapeZsh_(oi.display + " " + BBCodeToAnsi_(tag)) << "\"\n";
    }
  };

  s << "_" << app_name << "() {\n";
  s << "  local context state line\n";
  s << "  typeset -A opt_args\n\n";

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

  s << "  local -a completions=()\n";
  s << "  case \"$cmd_path\" in\n";
  for (const auto &[path, fn] : flat) {
    s << "    \"" << EscapeZsh_(path) << "\")\n";
    s << "      completions=(\n";
    emitZshDescribed(fn);
    s << "      )\n";
    s << "      ;;\n";
  }
  s << "  esac\n\n";

  s << "  if (( ${#completions} )); then\n";
  s << "    _describe -t commands '' completions\n";
  s << "  fi\n";
  s << "}\n\n";
  s << "_" << app_name << " \"$@\"\n";

  return s.str();
}

ECMData<std::string> BuildScriptContent_(const CommandNode &tree,
                                         CompletionScriptShell shell,
                                         const std::string &app_name) {
  switch (shell) {
  case CompletionScriptShell::Powershell5:
  case CompletionScriptShell::Powershell7:
    return {GeneratePowerShell_(tree, app_name), OK};
  case CompletionScriptShell::Bash:
    return {GenerateBash_(tree, app_name), OK};
  case CompletionScriptShell::Zsh:
    return {GenerateZsh_(tree, app_name), OK};
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

  auto content_result =
      BuildScriptContent_(*request.command_tree, request.shell, app_name);
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
