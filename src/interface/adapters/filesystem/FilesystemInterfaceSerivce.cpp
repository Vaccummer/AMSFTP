#include "interface/adapters/filesystem/FilesystemInterfaceSerivce.hpp"
#include "domain/filesystem/FileSystemDomainService.hpp"
#include "domain/host/HostDomainService.hpp"
#include "foundation/tools/path.hpp"
#include "foundation/tools/string.hpp"
#include "foundation/tools/time.hpp"
#include "interface/parser/CommandPreprocess.hpp"
#include "interface/style/StyleManager.hpp"
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <functional>
#include <iomanip>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

#ifdef _WIN32
#include <windows.h>
#else
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>
#endif

namespace AMInterface::filesystem {
namespace {
using AMDomain::filesystem::SearchType;
using AMDomain::filesystem::service::NormalizePath;
using AMDomain::host::HostService::NormalizeNickname;
ECM MergeStatus_(const ECM &current, const ECM &next) {
  return (next) ? current : next;
}

ControlComponent
ResolveControl_(AMDomain::client::amf default_interrupt_flag,
                const std::optional<ControlComponent> &control_opt) {
  return control_opt.has_value() ? control_opt.value()
                                 : ControlComponent(default_interrupt_flag);
}

std::string MakePathKey_(const PathTarget &path) {
  return path.nickname + "@" + path.path;
}

bool IsHiddenName_(const std::string &name) {
  return !name.empty() && name.front() == '.';
}

int TypeRank_(PathType type) {
  switch (type) {
  case PathType::FILE:
    return 0;
  case PathType::DIR:
    return 1;
  case PathType::SYMLINK:
    return 2;
  default:
    return 3;
  }
}

bool HasExplicitNickname_(const std::string &token) {
  return token.find('@') != std::string::npos;
}

bool IsValidNicknameToken_(const std::string &nickname_token) {
  const std::string nickname = AMStr::Strip(nickname_token);
  if (nickname.empty()) {
    return false;
  }
  return AMDomain::host::HostService::ValidateNickname(nickname);
}

size_t FindFirstNonEscapedAt_(
    const AMInterface::parser::ResolvedStringMeta &resolved) {
  for (size_t i = 0; i < resolved.value.size(); ++i) {
    if (resolved.value[i] != '@') {
      continue;
    }
    if (i < resolved.chars.size() && resolved.chars[i].escaped) {
      continue;
    }
    return i;
  }
  return std::string::npos;
}

bool IsAlreadyExistsError_(ErrorCode ec) {
  return ec == ErrorCode::PathAlreadyExists ||
         ec == ErrorCode::TargetAlreadyExists;
}

struct TreeNode_ {
  std::vector<PathInfo> dirs = {};
  std::vector<PathInfo> files = {};
};

namespace interface_print {
std::string FormatStatTime(double value) {
  if (value <= 0.0) {
    return "-";
  }
  return FormatTime(static_cast<size_t>(value), "%Y/%m/%d %H:%M:%S");
}

std::string BuildPathLabel(const PathTarget &path) {
  const std::string display_path = path.path.empty() ? "." : path.path;
  if (path.nickname.empty()) {
    return display_path;
  }
  return AMStr::fmt("{}@{}", path.nickname, display_path);
}

std::string
BuildStyledPathLabel(AMInterface::style::AMStyleService &style_service,
                     const PathTarget &path,
                     const PathInfo *path_info = nullptr) {
  const std::string display_path = path.path.empty() ? "." : path.path;
  const std::string styled_path = style_service.Format(
      display_path, AMInterface::style::StyleIndex::None, path_info);

  const std::string nickname = path.nickname;
  if (nickname.empty()) {
    return styled_path;
  }
  const std::string styled_nickname =
      style_service.Format(nickname, AMInterface::style::StyleIndex::Nickname);
  const std::string styled_at =
      style_service.Format("@", AMInterface::style::StyleIndex::AtSign);
  return styled_nickname + styled_at + styled_path;
}

std::string FormatStatBlock(const PathInfo &info) {
  constexpr int kWidth = 11;
  std::ostringstream out;
  out << std::left << std::setw(kWidth) << "path"
      << " : " << info.path << "\n";
  out << std::left << std::setw(kWidth) << "type"
      << " : " << AMStr::ToString(info.type) << "\n";
  out << std::left << std::setw(kWidth) << "owner"
      << " : " << info.owner << "\n";
  out << std::left << std::setw(kWidth) << "mode"
      << " : " << info.mode_str << "\n";
  out << std::left << std::setw(kWidth) << "size"
      << " : " << AMStr::FormatSize(info.size) << "\n";
  out << std::left << std::setw(kWidth) << "create_time"
      << " : " << FormatStatTime(info.create_time) << "\n";
  out << std::left << std::setw(kWidth) << "modify_time"
      << " : " << FormatStatTime(info.modify_time) << "\n";
  out << std::left << std::setw(kWidth) << "access_time"
      << " : " << FormatStatTime(info.access_time);
  return out.str();
}

void PrintStatBlock(AMInterface::prompt::PromptIOManager &prompt_io_manager,
                    const PathInfo &info) {
  prompt_io_manager.Print(FormatStatBlock(info));
}

void PrintLsNamesGrid(AMInterface::prompt::PromptIOManager &prompt_io_manager,
                      AMInterface::style::AMStyleService &style_service,
                      const std::vector<PathInfo> &entries) {
  constexpr size_t kMaxWidth = 80;
  size_t max_len = 0;
  std::vector<std::string> styled_names = {};
  styled_names.reserve(entries.size());
  for (const auto &entry : entries) {
    max_len = std::max(max_len, entry.name.size());
    styled_names.push_back(style_service.Format(
        entry.name, AMInterface::style::StyleIndex::None, &entry));
  }
  const size_t col_width = (max_len == 0 ? 1 : max_len + 2);
  const size_t columns =
      std::max<size_t>(1, kMaxWidth / (col_width == 0 ? 1 : col_width));
  const size_t rows = (entries.size() + columns - 1) / columns;

  for (size_t row = 0; row < rows; ++row) {
    std::ostringstream line;
    for (size_t col = 0; col < columns; ++col) {
      const size_t idx = row + col * rows;
      if (idx >= entries.size()) {
        continue;
      }
      line << styled_names[idx];
      if (col + 1 < columns && idx + rows < entries.size()) {
        const size_t pad = col_width > entries[idx].name.size()
                               ? col_width - entries[idx].name.size()
                               : 1;
        line << std::string(pad, ' ');
      }
    }
    prompt_io_manager.Print(line.str());
  }
}

void PrintLsLongEntries(
    AMInterface::prompt::PromptIOManager &prompt_io_manager,
    AMInterface::style::AMStyleService &style_service,
    const std::vector<PathInfo> &entries) {
  size_t mode_width = 0;
  size_t owner_width = 0;
  size_t size_width = 0;
  size_t time_width = 0;
  std::vector<std::string> time_values = {};
  time_values.reserve(entries.size());

  for (const auto &info : entries) {
    const char type_char = info.type == PathType::DIR
                               ? 'd'
                               : (info.type == PathType::SYMLINK ? 'l' : '-');
    const std::string mode = std::string(1, type_char) + info.mode_str;
    const std::string size_str = AMStr::FormatSize(info.size);
    const std::string time_str = FormatStatTime(info.modify_time);

    mode_width = std::max(mode_width, mode.size());
    owner_width = std::max(owner_width, info.owner.size());
    size_width = std::max(size_width, size_str.size());
    time_width = std::max(time_width, time_str.size());
    time_values.push_back(time_str);
  }

  for (size_t i = 0; i < entries.size(); ++i) {
    const auto &info = entries[i];
    const char type_char = info.type == PathType::DIR
                               ? 'd'
                               : (info.type == PathType::SYMLINK ? 'l' : '-');
    const std::string mode = std::string(1, type_char) + info.mode_str;
    const std::string size_str = AMStr::FormatSize(info.size);
    const std::string styled_name = style_service.Format(
        info.name, AMInterface::style::StyleIndex::None, &info);

    std::ostringstream line;
    line << std::left << std::setw(static_cast<int>(mode_width)) << mode << "  "
         << std::left << std::setw(static_cast<int>(owner_width)) << info.owner
         << "  " << std::right << std::setw(static_cast<int>(size_width))
         << size_str << "  " << std::left
         << std::setw(static_cast<int>(time_width)) << time_values[i] << "  "
         << styled_name;
    prompt_io_manager.Print(line.str());
  }
}

std::string FormatTreeName(AMInterface::style::AMStyleService &style_service,
                           const PathInfo &info, const std::string &name) {
  return style_service.Format(name, AMInterface::style::StyleIndex::None,
                              &info);
}

void SortTreeNode_(TreeNode_ *node) {
  if (node == nullptr) {
    return;
  }
  std::sort(node->dirs.begin(), node->dirs.end(),
            [](const PathInfo &lhs, const PathInfo &rhs) {
              return AMStr::lowercase(lhs.name) < AMStr::lowercase(rhs.name);
            });
  std::sort(node->files.begin(), node->files.end(),
            [](const PathInfo &lhs, const PathInfo &rhs) {
              return AMStr::lowercase(lhs.name) < AMStr::lowercase(rhs.name);
            });
}

void PrintTreeLines(
    AMInterface::prompt::PromptIOManager &prompt_io_manager,
    AMInterface::style::AMStyleService &style_service,
    const std::string &root_key, const std::string &root_line,
    const std::unordered_map<std::string, TreeNode_> &tree_nodes) {
  prompt_io_manager.Print(root_line);

  std::function<void(const std::string &, const std::string &)> render_dir =
      [&](const std::string &dir_key, const std::string &prefix) {
        auto it = tree_nodes.find(dir_key);
        if (it == tree_nodes.end()) {
          return;
        }

        const auto &dirs = it->second.dirs;
        const auto &files = it->second.files;
        const size_t total_items = dirs.size() + files.size();
        size_t index = 0;

        for (const auto &dir_info : dirs) {
          const bool is_last = (++index == total_items);
          const std::string connector = is_last ? "└── " : "├── ";
          const std::string line =
              prefix + connector +
              FormatTreeName(style_service, dir_info,
                             AMStr::BBCEscape(dir_info.name));
          prompt_io_manager.Print(line);

          const std::string child_prefix = prefix + (is_last ? "    " : "│   ");
          render_dir(dir_info.path, child_prefix);
        }

        for (const auto &file_info : files) {
          const bool is_last = (++index == total_items);
          const std::string connector = is_last ? "└── " : "├── ";
          const std::string line =
              prefix + connector +
              FormatTreeName(style_service, file_info,
                             AMStr::BBCEscape(file_info.name));
          prompt_io_manager.Print(line);
        }
      };

  render_dir(root_key, "");
}

void PrintPermanentRemovePlan(
    AMInterface::prompt::PromptIOManager &prompt_io_manager,
    const AMApplication::filesystem::PermanentRemovePlan &plan) {
  for (const auto &[nickname, paths] : plan.grouped_display_paths) {
    prompt_io_manager.Print(AMStr::fmt("{}:", nickname));
    for (const auto &path : paths) {
      prompt_io_manager.Print(path.path);
    }
  }
}

void PrintGroupedClientPaths(
    AMInterface::prompt::PromptIOManager &prompt_io_manager,
    const std::map<std::string, std::vector<PathTarget>> &grouped_paths) {
  for (const auto &[nickname, paths] : grouped_paths) {
    prompt_io_manager.Print(AMStr::fmt("{}:", nickname));
    for (const auto &path : paths) {
      prompt_io_manager.Print(path.path);
    }
  }
}
} // namespace interface_print
} // namespace

FilesystemInterfaceSerivce::FilesystemInterfaceSerivce(
    AMApplication::client::ClientAppService &client_service,
    AMApplication::host::HostAppService &host_service,
    AMApplication::filesystem::FilesystemAppService &filesystem_service,
    AMInterface::style::AMStyleService &style_service,
    AMInterface::prompt::PromptIOManager &prompt_io_manager)
    : client_service_(client_service), host_service_(host_service),
      filesystem_service_(filesystem_service), style_service_(style_service),
      prompt_io_manager_(prompt_io_manager), default_interrupt_flag_(nullptr) {}

void FilesystemInterfaceSerivce::SetDefaultControlToken(
    const AMDomain::client::amf &token) {
  default_interrupt_flag_ = token;
}

AMDomain::client::amf
FilesystemInterfaceSerivce::GetDefaultControlToken() const {
  return default_interrupt_flag_;
}

ECMData<PathTarget>
FilesystemInterfaceSerivce::SplitRawTarget(const std::string &token) const {
  PathTarget out = {};
  const std::string stripped_token = AMStr::Strip(token);
  auto resolved_result =
      AMInterface::parser::AMInputPreprocess::ResolveStringMeta(stripped_token);
  if (!(resolved_result.rcm)) {
    prompt_io_manager_.ErrorFormat(
        Err(resolved_result.rcm.code, "split.raw_target",
            stripped_token.empty() ? "<empty>" : stripped_token,
            resolved_result.rcm.error.empty()
                ? std::string(AMStr::ToString(resolved_result.rcm.code))
                : resolved_result.rcm.error));
    return {PathTarget{}, resolved_result.rcm};
  }

  const auto &resolved = resolved_result.data;
  const size_t at_pos = FindFirstNonEscapedAt_(resolved);
  if (at_pos == std::string::npos) {
    // Rule 1: no '@' -> current nickname + full token as path.
    out.nickname = filesystem_service_.CurrentNickname();
    out.path = resolved.value;
  } else if (resolved.value == "@") {
    // Rule 5: only '@' -> local@.
    out.nickname = "local";
    out.path = ".";
  } else if (at_pos == 0) {
    // Rule 4: '@' at head -> local + remaining path.
    out.nickname = "local";
    out.path = resolved.value.substr(1);
  } else {
    const std::string nickname_part = resolved.value.substr(0, at_pos);
    if (!IsValidNicknameToken_(nickname_part)) {
      // Rule 2.1 / 3.1 fallback to rule 1 when nickname is invalid.
      out.nickname = filesystem_service_.CurrentNickname();
      out.path = resolved.value;
    } else {
      // Rule 2.2 / 3.2: split at first '@'; trailing '@' means path='.'.
      out.nickname = nickname_part;
      out.path = resolved.value.substr(at_pos + 1);
      if (out.path.empty()) {
        out.path = ".";
      }
    }
  }

  // Final strip + normalize.
  out.nickname = NormalizeNickname(AMStr::Strip(out.nickname));
  if (out.nickname.empty()) {
    out.nickname =
        NormalizeNickname(AMStr::Strip(filesystem_service_.CurrentNickname()));
  }
  if (out.nickname.empty()) {
    out.nickname = "local";
  }
  out.path = NormalizePath(AMStr::Strip(out.path));
  if (out.path.empty()) {
    out.path = ".";
  }

  return {std::move(out), OK};
}

ECMData<PathTarget>
FilesystemInterfaceSerivce::MatchOne(const PathTarget &path) const {
  size_t matched_count = 0;
  PathTarget first_matched_path = {};
  auto control = ControlComponent(default_interrupt_flag_);
  auto find_result = filesystem_service_.find(
      path, SearchType::All, control, {}, {},
      [&matched_count, &first_matched_path](const PathTarget &matched) -> bool {
        ++matched_count;
        if (matched_count == 1) {
          first_matched_path = matched;
        }
        return matched_count <= 1;
      });

  if (matched_count == 1) {
    return {std::move(first_matched_path), OK};
  }
  if (matched_count > 1) {
    return {PathTarget{},
            Err(EC::InvalidArg, "", "",
                AMStr::fmt("Wildcard path must match exactly one target: {}@{}",
                           path.nickname, path.path))};
  }
  if (!find_result.rcm) {
    return {PathTarget{}, find_result.rcm};
  }
  return {PathTarget{}, Err(EC::InvalidArg, "", "",
                            AMStr::fmt("Wildcard path matched no target: {}@{}",
                                       path.nickname, path.path))};
}

ECM FilesystemInterfaceSerivce::Stat(
    const FilesystemStatArg &arg,
    const std::optional<ControlComponent> &control_opt) const {
  if (arg.raw_paths.empty()) {
    const ECM rcm = Err(EC::InvalidArg, "", "", "No path is given");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  std::vector<PathTarget> split_paths = {};
  split_paths.reserve(arg.raw_paths.size());
  std::unordered_set<std::string> seen_split_error = {};
  ECM status = OK;
  for (const auto &raw_path : arg.raw_paths) {
    if (control.IsInterrupted()) {
      return Err(EC::Terminate, "", "", "Interrupted by user");
    }
    auto split_result = SplitRawTarget(raw_path);
    if (!(split_result.rcm)) {
      if (seen_split_error.insert(raw_path).second) {
        prompt_io_manager_.ErrorFormat(split_result.rcm);
      }
      status = MergeStatus_(status, split_result.rcm);
      continue;
    }
    split_paths.push_back(std::move(split_result.data));
  }
  const auto valid_paths =
      AMDomain::filesystem::service::DedupPathTargets(split_paths);

  for (const auto &path : valid_paths) {
    if (control.IsInterrupted()) {
      return Err(EC::Terminate, "", "", "Interrupted by user");
    }

    auto stat_result = filesystem_service_.Stat(path, control, arg.trace_link);
    if (!(stat_result.rcm)) {
      prompt_io_manager_.ErrorFormat(stat_result.rcm);
      status = MergeStatus_(status, stat_result.rcm);
      continue;
    }
    interface_print::PrintStatBlock(prompt_io_manager_, stat_result.data);
  }

  return status;
}

ECM FilesystemInterfaceSerivce::GetSize(
    const FilesystemGetSizeArg &arg,
    const std::optional<ControlComponent> &control_opt) const {
  if (arg.raw_paths.empty()) {
    const ECM rcm = Err(EC::InvalidArg, "", "", "No path is given");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  std::vector<PathTarget> split_paths = {};
  split_paths.reserve(arg.raw_paths.size());
  std::unordered_set<std::string> seen_split_error = {};
  ECM status = OK;
  for (const auto &raw_path : arg.raw_paths) {
    if (control.IsInterrupted()) {
      return Err(EC::Terminate, "", "", "Interrupted by user");
    }
    auto split_result = SplitRawTarget(raw_path);
    if (!(split_result.rcm)) {
      if (seen_split_error.insert(raw_path).second) {
        prompt_io_manager_.ErrorFormat(split_result.rcm);
      }
      status = MergeStatus_(status, split_result.rcm);
      continue;
    }
    split_paths.push_back(std::move(split_result.data));
  }
  const auto valid_paths =
      AMDomain::filesystem::service::DedupPathTargets(split_paths);

  for (const auto &path : valid_paths) {
    if (control.IsInterrupted()) {
      return Err(EC::Terminate, "", "", "Interrupted by user");
    }
    if (control.IsTimeout()) {
      return Err(EC::OperationTimeout, "", "", "Operation timed out");
    }

    PathTarget target = path;
    if (AMDomain::filesystem::service::HasWildcard(target.path)) {
      auto match_result = MatchOne(target);
      if (!(match_result.rcm)) {
        prompt_io_manager_.ErrorFormat(match_result.rcm);
        status = MergeStatus_(status, match_result.rcm);
        continue;
      }
      target = std::move(match_result.data);
    }

    auto pre_stat = filesystem_service_.Stat(target, control, false);
    if (!pre_stat.rcm) {
      const std::string label = interface_print::BuildPathLabel(target);
      prompt_io_manager_.ErrorFormat(pre_stat.rcm);
      status = MergeStatus_(status, pre_stat.rcm);
      continue;
    }
    PathTarget display_target = target;
    if (!pre_stat.data.path.empty()) {
      display_target.path = pre_stat.data.path;
    } else {
      display_target.path = display_target.path;
    }
    if (display_target.path.empty()) {
      display_target.path = ".";
    }
    const std::string styled_label = interface_print::BuildStyledPathLabel(
        style_service_, display_target, &pre_stat.data);

    if (pre_stat.data.type != PathType::DIR) {
      prompt_io_manager_.Print(AMStr::fmt(
          "{} {}", styled_label, AMStr::FormatSize(pre_stat.data.size)));
      continue;
    }

    std::string latest_size = "0KB";
    bool has_progress = false;
    bool refresh_started = false;
    bool cursor_hidden = false;
    prompt_io_manager_.SetCursorVisible(false);
    cursor_hidden = true;
    prompt_io_manager_.RefreshBegin();
    refresh_started = true;

    auto size_result = filesystem_service_.GetSize(
        target, control,
        [this, &styled_label, &latest_size,
         &has_progress](const PathTarget &, int64_t current_size) -> bool {
          const std::string formatted = AMStr::FormatSize(current_size);
          if (has_progress && formatted == latest_size) {
            return true;
          }
          has_progress = true;
          latest_size = formatted;
          prompt_io_manager_.RefreshRender(
              {AMStr::fmt("{} {}", styled_label, latest_size)});
          return true;
        },
        [this](const PathTarget &, ECM rcm) {
          prompt_io_manager_.ErrorFormat(rcm);
        });

    if (refresh_started) {
      prompt_io_manager_.RefreshEnd();
    }
    if (cursor_hidden) {
      prompt_io_manager_.SetCursorVisible(true);
    }
    if (size_result.rcm) {
      latest_size = AMStr::FormatSize(size_result.data);
    }
    prompt_io_manager_.Print(AMStr::fmt("{} {}", styled_label, latest_size));

    if (!size_result.rcm) {
      status = MergeStatus_(status, size_result.rcm);
      if (size_result.rcm.code == EC::Terminate ||
          size_result.rcm.code == EC::OperationTimeout) {
        return size_result.rcm;
      }
    }
  }

  return status;
}

ECM FilesystemInterfaceSerivce::Find(
    const FilesystemFindArg &arg,
    const std::optional<ControlComponent> &control_opt) const {
  const std::string raw_path = AMStr::Strip(arg.raw_path);
  if (raw_path.empty()) {
    const ECM rcm = Err(EC::InvalidArg, "", "", "No find target is given");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  auto split_result = SplitRawTarget(raw_path);
  if (!(split_result.rcm)) {
    prompt_io_manager_.ErrorFormat(split_result.rcm);
    return split_result.rcm;
  }
  PathTarget target = std::move(split_result.data);
  const std::string raw_pattern = AMStr::Strip(arg.raw_pattern);
  const bool recursive_pattern_mode = !raw_pattern.empty();
  if (recursive_pattern_mode) {
    target.path = AMPath::join(target.path.empty() ? "." : target.path, "**",
                               raw_pattern, SepType::Unix);
  }

  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  ECM status = OK;
  auto result = filesystem_service_.find(
      target, SearchType::All, control, {},
      [this, &status](const PathTarget &, ECM rcm) {
        prompt_io_manager_.ErrorFormat(rcm);
        status = MergeStatus_(status, rcm);
      });

  if (!(result.rcm)) {
    if (result.rcm.code == EC::Terminate ||
        result.rcm.code == EC::OperationTimeout) {
      return result.rcm;
    }
    status = MergeStatus_(status, result.rcm);
  }

  const std::string pattern_label =
      recursive_pattern_mode ? raw_pattern : raw_path;
  prompt_io_manager_.FmtPrint("Find {} Result for pattern \"{}\"",
                              result.data.size(), pattern_label);
  for (const auto &entry : result.data) {
    prompt_io_manager_.Print(style_service_.Format(
        entry.path, AMInterface::style::StyleIndex::None, &entry));
  }

  return status;
}

ECM FilesystemInterfaceSerivce::Realpath(
    const FilesystemRealpathArg &arg,
    const std::optional<ControlComponent> &control_opt) const {
  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  std::string raw_path = AMStr::Strip(arg.raw_path);
  if (raw_path.empty()) {
    raw_path = ".";
  }

  auto split_result = SplitRawTarget(raw_path);
  if (!(split_result.rcm)) {
    prompt_io_manager_.ErrorFormat(split_result.rcm);
    return split_result.rcm;
  }

  auto client_result =
      filesystem_service_.GetClient(split_result.data.nickname, control);
  if (!(client_result.rcm) || !client_result.data) {
    const ECM rcm = !(client_result.rcm)
                        ? client_result.rcm
                        : Err(EC::ClientNotFound, "",
                              split_result.data.nickname, "Client not found");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  auto abs_result =
      AMApplication::filesystem::FilesystemAppService::ResolveAbsolutePath(
          client_result.data, split_result.data.path, control);
  if (!(abs_result.rcm)) {
    prompt_io_manager_.ErrorFormat(abs_result.rcm);
    return abs_result.rcm;
  }

  std::string npath = AMStr::Strip(abs_result.data);
  if (npath.empty()) {
    npath = ".";
  }

  const PathTarget print_target = {split_result.data.nickname, npath};
  auto stat_result = filesystem_service_.Stat(print_target, control, false,
                                              client_result.data);
  if ((stat_result.rcm)) {
    PathInfo info = stat_result.data;
    if (AMStr::Strip(info.path).empty()) {
      info.path = npath;
    }
    PathTarget styled_target = print_target;
    styled_target.path = info.path;
    const std::string type_text = AMStr::ToString(info.type);
    const std::string styled_label = interface_print::BuildStyledPathLabel(
        style_service_, styled_target, &info);
    prompt_io_manager_.Print(
        AMStr::fmt("\\[{}] {}", AMStr::Strip(type_text), styled_label));
    return OK;
  }

  if (AMDomain::filesystem::service::IsPathNotExistError(
          stat_result.rcm.code)) {
    const std::string styled_label =
        interface_print::BuildStyledPathLabel(style_service_, print_target);
    prompt_io_manager_.Print(AMStr::fmt("⚠️ {}", styled_label));
    return OK;
  }

  prompt_io_manager_.ErrorFormat(stat_result.rcm);
  return stat_result.rcm;
}

ECM FilesystemInterfaceSerivce::Tree(
    const FilesystemTreeArg &arg,
    const std::optional<ControlComponent> &control_opt) const {
  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  const auto print_error = [&](const std::string &, const ECM &rcm) {
    if (!arg.quiet) {
      prompt_io_manager_.ErrorFormat(rcm);
    }
  };
  const auto stop_error = [&control]() -> ECM {
    if (control.IsInterrupted()) {
      return Err(EC::Terminate, "", "", "Interrupted by user");
    }
    if (control.IsTimeout()) {
      return Err(EC::OperationTimeout, "", "", "Operation timed out");
    }
    return OK;
  };

  auto split_result = SplitRawTarget(arg.raw_path);
  if (!(split_result.rcm)) {
    print_error(arg.raw_path, split_result.rcm);
    return split_result.rcm;
  }
  PathTarget target = std::move(split_result.data);

  if (AMDomain::filesystem::service::HasWildcard(target.path)) {
    auto match_result = MatchOne(target);
    if (!(match_result.rcm)) {
      print_error(interface_print::BuildPathLabel(target), match_result.rcm);
      return match_result.rcm;
    }
    target = std::move(match_result.data);
  }

  auto root_stat = filesystem_service_.Stat(target, control, false);
  if (!(root_stat.rcm)) {
    print_error(interface_print::BuildPathLabel(target), root_stat.rcm);
    return root_stat.rcm;
  }
  if (arg.only_dir && root_stat.data.type != PathType::DIR) {
    const ECM rcm = Err(EC::NotADirectory, "", "",
                        AMStr::fmt("Not a directory: {}",
                                   interface_print::BuildPathLabel(target)));
    print_error(interface_print::BuildPathLabel(target), rcm);
    return rcm;
  }

  std::string root_key = root_stat.data.path;
  if (root_key.empty()) {
    root_key = target.path.empty() ? "." : target.path;
  }

  std::unordered_map<std::string, TreeNode_> tree_nodes = {};
  tree_nodes[root_key] = {};
  std::deque<std::pair<std::string, int>> pending = {};
  pending.emplace_back(root_key, 0);
  std::unordered_set<std::string> visited = {};
  visited.insert(root_key);
  std::vector<std::pair<std::string, ECM>> traversal_errors = {};
  ECM status = OK;

  while (!pending.empty()) {
    const ECM check_rcm = stop_error();
    if (!(check_rcm)) {
      print_error(interface_print::BuildPathLabel(target), check_rcm);
      return check_rcm;
    }

    const auto [current_dir, depth] = pending.front();
    pending.pop_front();

    if (arg.max_depth >= 0 && depth >= arg.max_depth) {
      continue;
    }

    PathTarget current = {};
    current.nickname = target.nickname;
    current.path = current_dir;
    auto list_result = filesystem_service_.Listdir(current, control);
    if (!(list_result.rcm)) {
      traversal_errors.emplace_back(interface_print::BuildPathLabel(current),
                                    list_result.rcm);
      status = MergeStatus_(status, list_result.rcm);
      continue;
    }

    auto &node = tree_nodes[current_dir];
    for (const auto &entry : list_result.data) {
      const ECM item_check_rcm = stop_error();
      if (!(item_check_rcm)) {
        print_error(interface_print::BuildPathLabel(current), item_check_rcm);
        return item_check_rcm;
      }

      if (!arg.show_all && IsHiddenName_(entry.name)) {
        continue;
      }
      if (arg.ignore_special_file && entry.type != PathType::DIR &&
          entry.type != PathType::FILE) {
        continue;
      }

      if (entry.type == PathType::DIR) {
        PathInfo dir_info = entry;
        if (dir_info.path.empty()) {
          dir_info.path = AMPath::join(current_dir, dir_info.name);
        }
        node.dirs.push_back(dir_info);
        tree_nodes.try_emplace(dir_info.path);
        if (visited.insert(dir_info.path).second) {
          pending.emplace_back(dir_info.path, depth + 1);
        }
        continue;
      }

      if (arg.only_dir) {
        continue;
      }

      PathInfo file_info = entry;
      if (file_info.path.empty()) {
        file_info.path = AMPath::join(current_dir, file_info.name);
      }
      node.files.push_back(std::move(file_info));
    }
  }

  if (!arg.quiet) {
    for (const auto &item : traversal_errors) {
      prompt_io_manager_.ErrorFormat(item.second);
    }
  }

  for (auto &entry : tree_nodes) {
    interface_print::SortTreeNode_(&entry.second);
  }

  PathInfo root_info = root_stat.data;
  root_info.path = root_key;
  const std::string root_line =
      style_service_.Format(interface_print::BuildPathLabel(target),
                            AMInterface::style::StyleIndex::None, &root_info);
  interface_print::PrintTreeLines(prompt_io_manager_, style_service_, root_key,
                                  root_line, tree_nodes);
  return status;
}

ECM FilesystemInterfaceSerivce::TestRTT(
    const FilesystemTestRTTArg &arg,
    const std::optional<ControlComponent> &control_opt) const {
  if (arg.times <= 0) {
    const ECM rcm = Err(EC::InvalidArg, "", "", "times must be > 0");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  std::string nickname = filesystem_service_.CurrentNickname();

  auto rtt_result = filesystem_service_.TestRTT(nickname, control, arg.times);
  if (!(rtt_result.rcm)) {
    prompt_io_manager_.ErrorFormat(rtt_result.rcm);
    return rtt_result.rcm;
  }

  std::ostringstream out;
  out << std::fixed << std::setprecision(2) << rtt_result.data;
  prompt_io_manager_.FmtPrint("RTT: {} ms", out.str());
  return OK;
}

ECM FilesystemInterfaceSerivce::Rename(
    const FilesystemRenameArg &arg,
    const std::optional<ControlComponent> &control_opt) const {
  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  auto src_split = SplitRawTarget(arg.target);
  if (!(src_split.rcm)) {
    prompt_io_manager_.ErrorFormat(src_split.rcm);
    return src_split.rcm;
  }
  PathTarget src = std::move(src_split.data);
  if (AMDomain::filesystem::service::HasWildcard(src.path)) {
    auto match_result = MatchOne(src);
    if (!(match_result.rcm)) {
      prompt_io_manager_.ErrorFormat(match_result.rcm);
      return match_result.rcm;
    }
    src = std::move(match_result.data);
  }

  auto dst_split = SplitRawTarget(arg.dst);
  if (!(dst_split.rcm)) {
    prompt_io_manager_.ErrorFormat(dst_split.rcm);
    return dst_split.rcm;
  }
  PathTarget dst = std::move(dst_split.data);
  if (AMDomain::filesystem::service::HasWildcard(dst.path)) {
    const ECM rcm =
        Err(EC::InvalidArg, "", "", "Destination wildcard is not supported");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }
  if (!HasExplicitNickname_(arg.dst)) {
    dst.nickname = src.nickname;
  }

  auto run_rename = [&](bool overwrite) {
    return filesystem_service_.Rename(src, dst, control, arg.mkdir, overwrite);
  };

  ECM rename_rcm = run_rename(arg.overwrite);
  if (!(rename_rcm) && !arg.overwrite &&
      IsAlreadyExistsError_(rename_rcm.code)) {
    bool canceled = false;
    const std::string prompt =
        AMStr::fmt("Destination exists [{}], overwrite? (y/N): ",
                   interface_print::BuildPathLabel(dst));
    const bool approved = prompt_io_manager_.PromptYesNo(prompt, &canceled);
    if (!approved) {
      const ECM cancel_rcm = Err(EC::ConfigCanceled, "", "", "Rename canceled");
      prompt_io_manager_.ErrorFormat(cancel_rcm);
      return cancel_rcm;
    }
    rename_rcm = run_rename(true);
  }

  if (!(rename_rcm)) {
    prompt_io_manager_.ErrorFormat(rename_rcm);
  }
  return rename_rcm;
}

ECM FilesystemInterfaceSerivce::Move(
    const FilesystemMoveArg &arg,
    const std::optional<ControlComponent> &control_opt) const {
  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  const std::string raw_src = AMStr::Strip(arg.target);
  if (raw_src.empty()) {
    const ECM rcm = Err(EC::InvalidArg, "Move", "src", "Source path is empty");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  auto src_split = SplitRawTarget(raw_src);
  if (!(src_split.rcm)) {
    prompt_io_manager_.ErrorFormat(src_split.rcm);
    return src_split.rcm;
  }

  ECM status = OK;
  std::vector<PathTarget> sources = {};
  PathTarget src_pattern = std::move(src_split.data);
  const bool src_is_wildcard =
      AMDomain::filesystem::service::HasWildcard(src_pattern.path);
  if (src_is_wildcard) {
    auto find_result = filesystem_service_.find(
        src_pattern, SearchType::All, control, {},
        [this, &status](const PathTarget &error_path, ECM rcm) {
          (void)error_path;
          prompt_io_manager_.ErrorFormat(rcm);
          status = MergeStatus_(status, rcm);
        });

    if (!(find_result.rcm)) {
      if (find_result.rcm.code == EC::Terminate ||
          find_result.rcm.code == EC::OperationTimeout) {
        prompt_io_manager_.ErrorFormat(find_result.rcm);
        return find_result.rcm;
      }
      status = MergeStatus_(status, find_result.rcm);
    }

    for (const auto &entry : find_result.data) {
      PathTarget one = {};
      one.nickname = src_pattern.nickname;
      one.path = entry.path;
      sources.push_back(std::move(one));
    }
    sources = AMDomain::filesystem::service::DedupPathTargets(sources);

    if (sources.empty()) {
      const ECM rcm = Err(EC::PathNotExist, "Move", raw_src,
                          "Wildcard source matched no target");
      prompt_io_manager_.ErrorFormat(rcm);
      return MergeStatus_(status, rcm);
    }

    prompt_io_manager_.FmtPrint("Matched {} source path(s):", sources.size());
    for (const auto &source : sources) {
      const std::string styled =
          interface_print::BuildStyledPathLabel(style_service_, source);
      prompt_io_manager_.Print(AMStr::fmt("  {}", styled));
    }
    bool canceled = false;
    const bool approved = prompt_io_manager_.PromptYesNo(
        "Move all matched paths? (y/N): ", &canceled);
    if (!approved || canceled) {
      return Err(EC::ConfigCanceled, "Move", raw_src, "Move canceled");
    }
  } else {
    sources.push_back(std::move(src_pattern));
  }

  const std::string raw_dst =
      AMStr::Strip(arg.dst).empty() ? "." : AMStr::Strip(arg.dst);
  auto dst_split = SplitRawTarget(raw_dst);
  if (!(dst_split.rcm)) {
    prompt_io_manager_.ErrorFormat(dst_split.rcm);
    return MergeStatus_(status, dst_split.rcm);
  }
  PathTarget dst_dir = std::move(dst_split.data);
  if (AMDomain::filesystem::service::HasWildcard(dst_dir.path)) {
    const ECM rcm = Err(EC::InvalidArg, "Move", raw_dst,
                        "Destination wildcard is not supported");
    prompt_io_manager_.ErrorFormat(rcm);
    return MergeStatus_(status, rcm);
  }

  auto dst_stat = filesystem_service_.Stat(dst_dir, control, false);
  if (!(dst_stat.rcm)) {
    if (AMDomain::filesystem::service::IsPathNotExistError(dst_stat.rcm.code)) {
      if (!arg.mkdir) {
        const ECM rcm = Err(EC::PathNotExist, "Move",
                            interface_print::BuildPathLabel(dst_dir),
                            "Destination directory not found");
        prompt_io_manager_.ErrorFormat(rcm);
        return MergeStatus_(status, rcm);
      }
      ECM mkdir_rcm = filesystem_service_.Mkdirs(dst_dir, control);
      if (!(mkdir_rcm)) {
        prompt_io_manager_.ErrorFormat(mkdir_rcm);
        return MergeStatus_(status, mkdir_rcm);
      }
      dst_stat = filesystem_service_.Stat(dst_dir, control, false);
      if (!(dst_stat.rcm)) {
        prompt_io_manager_.ErrorFormat(dst_stat.rcm);
        return MergeStatus_(status, dst_stat.rcm);
      }
    } else {
      prompt_io_manager_.ErrorFormat(dst_stat.rcm);
      return MergeStatus_(status, dst_stat.rcm);
    }
  }
  if (dst_stat.data.type != PathType::DIR) {
    const ECM rcm =
        Err(EC::NotADirectory, "Move", interface_print::BuildPathLabel(dst_dir),
            "Destination path is not a directory");
    prompt_io_manager_.ErrorFormat(rcm);
    return MergeStatus_(status, rcm);
  }

  struct MoveEntry_ {
    PathTarget src = {};
    PathTarget dst = {};
    bool dst_exists = false;
  };
  std::vector<MoveEntry_> plan = {};
  std::vector<PathTarget> collisions = {};
  plan.reserve(sources.size());

  for (const auto &source : sources) {
    if (control.IsInterrupted()) {
      const ECM rcm =
          Err(EC::Terminate, "Move", interface_print::BuildPathLabel(source),
              "Operation interrupted");
      prompt_io_manager_.ErrorFormat(rcm);
      return MergeStatus_(status, rcm);
    }
    if (control.IsTimeout()) {
      const ECM rcm =
          Err(EC::OperationTimeout, "Move",
              interface_print::BuildPathLabel(source), "Operation timed out");
      prompt_io_manager_.ErrorFormat(rcm);
      return MergeStatus_(status, rcm);
    }

    MoveEntry_ entry = {};
    entry.src = source;
    entry.dst = dst_dir;
    entry.dst.path = AMPath::join(dst_dir.path, AMPath::basename(source.path));

    auto precheck = filesystem_service_.Stat(entry.dst, control, false);
    if ((precheck.rcm)) {
      entry.dst_exists = true;
      collisions.push_back(entry.dst);
    } else if (AMDomain::filesystem::service::IsPathNotExistError(
                   precheck.rcm.code)) {
      entry.dst_exists = false;
    } else {
      prompt_io_manager_.ErrorFormat(precheck.rcm);
      status = MergeStatus_(status, precheck.rcm);
      continue;
    }
    plan.push_back(std::move(entry));
  }

  if (plan.empty()) {
    if (!(status)) {
      return status;
    }
    const ECM rcm =
        Err(EC::PathNotExist, "Move", raw_src, "No source path can be moved");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  bool overwrite = arg.overwrite;
  if (!collisions.empty()) {
    prompt_io_manager_.Print("Destination collision(s):");
    for (const auto &collision : collisions) {
      const std::string styled =
          interface_print::BuildStyledPathLabel(style_service_, collision);
      prompt_io_manager_.Print(AMStr::fmt("  {}", styled));
    }
    prompt_io_manager_.Print(
        AMStr::fmt("Overwrite enabled: {}", overwrite ? "true" : "false"));
    if (!overwrite) {
      bool canceled = false;
      const bool approved = prompt_io_manager_.PromptYesNo(
          "Continue and overwrite existing destination file(s)? (y/N): ",
          &canceled);
      if (!approved || canceled) {
        return Err(EC::ConfigCanceled, "Move",
                   interface_print::BuildPathLabel(dst_dir), "Move canceled");
      }
      overwrite = true;
    }
  }

  for (const auto &entry : plan) {
    if (control.IsInterrupted()) {
      const ECM rcm =
          Err(EC::Terminate, "Move", interface_print::BuildPathLabel(entry.src),
              "Operation interrupted");
      prompt_io_manager_.ErrorFormat(rcm);
      return MergeStatus_(status, rcm);
    }
    if (control.IsTimeout()) {
      const ECM rcm = Err(EC::OperationTimeout, "Move",
                          interface_print::BuildPathLabel(entry.src),
                          "Operation timed out");
      prompt_io_manager_.ErrorFormat(rcm);
      return MergeStatus_(status, rcm);
    }

    ECM rename_rcm = filesystem_service_.Rename(entry.src, entry.dst, control,
                                                arg.mkdir, overwrite);
    if (!(rename_rcm)) {
      prompt_io_manager_.ErrorFormat(rename_rcm);
    }
    status = MergeStatus_(status, rename_rcm);
  }

  return status;
}

ECM FilesystemInterfaceSerivce::Saferm(
    const FilesystemSafermArg &arg,
    const std::optional<ControlComponent> &control_opt) const {
  if (arg.targets.empty()) {
    const ECM rcm = Err(EC::InvalidArg, "", "", "No target is given");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  std::vector<PathTarget> targets = {};
  targets.reserve(arg.targets.size());
  ECM status = OK;
  for (const auto &token : arg.targets) {
    if (control.IsInterrupted()) {
      return Err(EC::Terminate, "", "", "Interrupted by user");
    }
    if (control.IsTimeout()) {
      return Err(EC::OperationTimeout, "", "", "Operation timed out");
    }

    auto split_result = SplitRawTarget(token);
    if (!split_result.rcm) {
      prompt_io_manager_.ErrorFormat(split_result.rcm);
      status = MergeStatus_(status, split_result.rcm);
      continue;
    }
    targets.push_back(std::move(split_result.data));
  }

  auto saferm_result = filesystem_service_.Saferm(std::move(targets), control);
  for (const auto &entry : saferm_result.data) {
    prompt_io_manager_.ErrorFormat(entry.second);
  }
  return MergeStatus_(status, saferm_result.rcm);
}

ECM FilesystemInterfaceSerivce::Rmfile(
    const FilesystemRmfileArg &arg,
    const std::optional<ControlComponent> &control_opt) const {
  if (arg.targets.empty()) {
    const ECM rcm = Err(EC::InvalidArg, "", "", "No target is given");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  std::vector<PathTarget> targets = {};
  targets.reserve(arg.targets.size());
  std::unordered_set<std::string> seen = {};
  ECM status = OK;

  for (const auto &token : arg.targets) {
    if (control.IsInterrupted()) {
      return Err(EC::Terminate, "", "", "Interrupted by user");
    }
    if (control.IsTimeout()) {
      return Err(EC::OperationTimeout, "", "", "Operation timed out");
    }

    auto split_result = SplitRawTarget(token);
    if (!(split_result.rcm)) {
      prompt_io_manager_.ErrorFormat(split_result.rcm);
      status = MergeStatus_(status, split_result.rcm);
      continue;
    }

    PathTarget target = std::move(split_result.data);
    if (AMDomain::filesystem::service::HasWildcard(target.path)) {
      auto match_result = MatchOne(target);
      if (!(match_result.rcm)) {
        prompt_io_manager_.ErrorFormat(match_result.rcm);
        status = MergeStatus_(status, match_result.rcm);
        continue;
      }
      target = std::move(match_result.data);
    }

    const std::string key = MakePathKey_(target);
    if (!seen.insert(key).second) {
      continue;
    }
    targets.push_back(std::move(target));
  }

  auto prepare_result =
      filesystem_service_.PrepareRmfile(std::move(targets), control);
  for (const auto &entry : prepare_result.data.precheck_errors) {
    prompt_io_manager_.ErrorFormat(entry.second);
  }

  status = MergeStatus_(status, prepare_result.rcm);
  if (!(prepare_result.rcm) &&
      (prepare_result.rcm.code == EC::Terminate ||
       prepare_result.rcm.code == EC::OperationTimeout)) {
    return status;
  }
  if (prepare_result.data.grouped_display_paths.empty()) {
    return status;
  }

  interface_print::PrintGroupedClientPaths(
      prompt_io_manager_, prepare_result.data.grouped_display_paths);
  bool canceled = false;
  const bool confirmed = prompt_io_manager_.PromptYesNo(
      "Are you sure to remove these file paths? (y/n): ", &canceled);
  if (canceled || !confirmed) {
    return Err(EC::ConfigCanceled, "", "", "rmfile canceled");
  }

  auto execute_result = filesystem_service_.ExecuteRmfile(
      prepare_result.data, control, [this](const PathTarget &, ECM rcm) {
        prompt_io_manager_.ErrorFormat(rcm);
      });
  return MergeStatus_(status, execute_result.rcm);
}

ECM FilesystemInterfaceSerivce::Rmdir(
    const FilesystemRmdirArg &arg,
    const std::optional<ControlComponent> &control_opt) const {
  if (arg.targets.empty()) {
    const ECM rcm = Err(EC::InvalidArg, "", "", "No target is given");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  std::vector<PathTarget> targets = {};
  targets.reserve(arg.targets.size());
  std::unordered_set<std::string> seen = {};
  ECM status = OK;

  for (const auto &token : arg.targets) {
    if (control.IsInterrupted()) {
      return Err(EC::Terminate, "", "", "Interrupted by user");
    }
    if (control.IsTimeout()) {
      return Err(EC::OperationTimeout, "", "", "Operation timed out");
    }

    auto split_result = SplitRawTarget(token);
    if (!(split_result.rcm)) {
      prompt_io_manager_.ErrorFormat(split_result.rcm);
      status = MergeStatus_(status, split_result.rcm);
      continue;
    }

    PathTarget target = std::move(split_result.data);
    if (AMDomain::filesystem::service::HasWildcard(target.path)) {
      auto match_result = MatchOne(target);
      if (!(match_result.rcm)) {
        prompt_io_manager_.ErrorFormat(match_result.rcm);
        status = MergeStatus_(status, match_result.rcm);
        continue;
      }
      target = std::move(match_result.data);
    }

    const std::string key = MakePathKey_(target);
    if (!seen.insert(key).second) {
      continue;
    }
    targets.push_back(std::move(target));
  }

  auto rmdir_result = filesystem_service_.Rmdir(
      std::move(targets), control, [this](const PathTarget &, ECM rcm) {
        prompt_io_manager_.ErrorFormat(rcm);
      });
  return MergeStatus_(status, rmdir_result.rcm);
}

ECM FilesystemInterfaceSerivce::PermanentRemove(
    const FilesystemPermanentRemoveArg &arg,
    const std::optional<ControlComponent> &control_opt) const {
  if (arg.targets.empty()) {
    const ECM rcm = Err(EC::InvalidArg, "", "", "No target is given");
    if (!arg.quiet) {
      prompt_io_manager_.ErrorFormat(rcm);
    }
    return rcm;
  }

  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  std::vector<PathTarget> targets = {};
  targets.reserve(arg.targets.size());
  ECM status = OK;

  for (const auto &token : arg.targets) {
    if (control.IsInterrupted()) {
      return Err(EC::Terminate, "", "", "Interrupted by user");
    }
    if (control.IsTimeout()) {
      return Err(EC::OperationTimeout, "", "", "Operation timed out");
    }

    auto split_result = SplitRawTarget(token);
    if (!(split_result.rcm)) {
      if (!arg.quiet) {
        prompt_io_manager_.ErrorFormat(split_result.rcm);
      }
      status = MergeStatus_(status, split_result.rcm);
      continue;
    }
    targets.push_back(std::move(split_result.data));
  }

  auto prepare_result =
      filesystem_service_.PreparePermanentRemove(std::move(targets), control);
  if (!arg.quiet) {
    for (const auto &entry : prepare_result.data.precheck_errors) {
      prompt_io_manager_.ErrorFormat(entry.second);
    }
  }

  status = MergeStatus_(status, prepare_result.rcm);
  if (!(prepare_result.rcm) &&
      (prepare_result.rcm.code == EC::Terminate ||
       prepare_result.rcm.code == EC::OperationTimeout)) {
    return MergeStatus_(status, prepare_result.rcm);
  }

  if (prepare_result.data.grouped_display_paths.empty()) {
    return status;
  }

  interface_print::PrintPermanentRemovePlan(prompt_io_manager_,
                                            prepare_result.data);
  bool canceled = false;
  const bool confirmed = prompt_io_manager_.PromptYesNo(
      "Are you sure to permanantly remove these paths? (y/n): ", &canceled);
  if (canceled || !confirmed) {
    return Err(EC::ConfigCanceled, "", "", "permanent remove canceled");
  }

  bool cursor_hidden = false;
  prompt_io_manager_.SetCursorVisible(false);
  cursor_hidden = true;
  prompt_io_manager_.RefreshBegin();
  auto execute_result = filesystem_service_.ExecutePermanentRemove(
      prepare_result.data, control,
      [this](const PathTarget &path) {
        prompt_io_manager_.RefreshRender(
            {AMStr::fmt("Removing {}", interface_print::BuildPathLabel(path))});
      },
      [this, &arg](const PathTarget &, ECM rcm) {
        if (!arg.quiet) {
          prompt_io_manager_.ErrorFormat(rcm);
        }
      });
  prompt_io_manager_.RefreshEnd();
  if (cursor_hidden) {
    prompt_io_manager_.SetCursorVisible(true);
  }

  return MergeStatus_(status, execute_result.rcm);
}

ECM FilesystemInterfaceSerivce::Ls(
    const FilesystemLsArg &arg,
    const std::optional<ControlComponent> &control_opt) const {
  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  PathTarget target = {};
  if (AMStr::Strip(arg.raw_path).empty()) {
    auto cwd_result = filesystem_service_.GetCwd(control);
    if ((cwd_result.rcm) && !cwd_result.data.path.empty()) {
      target = cwd_result.data;
      if (target.nickname.empty()) {
        target.nickname = filesystem_service_.CurrentNickname();
      }
      if (target.path.empty()) {
        target.path = ".";
      }
    } else {
      auto split_result = SplitRawTarget("/");
      if (!(split_result.rcm)) {
        prompt_io_manager_.ErrorFormat(split_result.rcm);
        return split_result.rcm;
      }
      target = std::move(split_result.data);
    }
  } else {
    auto split_result = SplitRawTarget(arg.raw_path);
    if (!(split_result.rcm)) {
      prompt_io_manager_.ErrorFormat(split_result.rcm);
      return split_result.rcm;
    }
    target = std::move(split_result.data);
  }
  if (AMDomain::filesystem::service::HasWildcard(target.path)) {
    auto match_result = MatchOne(target);
    if (!(match_result.rcm)) {
      prompt_io_manager_.ErrorFormat(match_result.rcm);
      return match_result.rcm;
    }
    target = std::move(match_result.data);
  }
  if (target.path.empty()) {
    target.path = ".";
  }

  if (!arg.list_like) {
    auto list_result = filesystem_service_.Listdir(target, control);
    if (!(list_result.rcm)) {
      prompt_io_manager_.ErrorFormat(list_result.rcm);
      return list_result.rcm;
    }

    std::vector<PathInfo> entries = {};
    entries.reserve(list_result.data.size());
    for (const auto &entry : list_result.data) {
      if (!arg.show_all && IsHiddenName_(entry.name)) {
        continue;
      }
      entries.push_back(entry);
    }
    std::sort(entries.begin(), entries.end(),
              [](const PathInfo &lhs, const PathInfo &rhs) {
                const int lhs_rank = TypeRank_(lhs.type);
                const int rhs_rank = TypeRank_(rhs.type);
                if (lhs_rank != rhs_rank) {
                  return lhs_rank < rhs_rank;
                }
                return AMStr::lowercase(lhs.name) < AMStr::lowercase(rhs.name);
              });
    interface_print::PrintLsNamesGrid(prompt_io_manager_, style_service_,
                                      entries);
    return OK;
  }

  auto list_result = filesystem_service_.Listdir(target, control);
  if (!(list_result.rcm)) {
    prompt_io_manager_.ErrorFormat(list_result.rcm);
    return list_result.rcm;
  }

  std::vector<PathInfo> entries = {};
  entries.reserve(list_result.data.size());
  for (const auto &entry : list_result.data) {
    if (!arg.show_all && IsHiddenName_(entry.name)) {
      continue;
    }
    entries.push_back(entry);
  }
  std::sort(entries.begin(), entries.end(),
            [](const PathInfo &lhs, const PathInfo &rhs) {
              const int lhs_rank = TypeRank_(lhs.type);
              const int rhs_rank = TypeRank_(rhs.type);
              if (lhs_rank != rhs_rank) {
                return lhs_rank < rhs_rank;
              }
              return AMStr::lowercase(lhs.name) < AMStr::lowercase(rhs.name);
            });
  interface_print::PrintLsLongEntries(prompt_io_manager_, style_service_,
                                      entries);
  return OK;
}

ECM FilesystemInterfaceSerivce::Cd(
    const FilesystemCdArg &arg,
    const std::optional<ControlComponent> &control_opt) const {
  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  const std::string raw_path = AMStr::Strip(arg.raw_path);
  const bool from_history = (raw_path == "-");

  PathTarget target = {};
  if (from_history) {
    auto history_result = filesystem_service_.PeekCdHistory();
    if (!(history_result.rcm)) {
      prompt_io_manager_.ErrorFormat(history_result.rcm);
      return history_result.rcm;
    }
    target = std::move(history_result.data);
  } else {
    auto split_result = SplitRawTarget(arg.raw_path);
    if (!(split_result.rcm)) {
      prompt_io_manager_.ErrorFormat(split_result.rcm);
      return split_result.rcm;
    }
    target = split_result.data;
    if (AMDomain::filesystem::service::HasWildcard(target.path)) {
      auto match_result = MatchOne(target);
      if (!(match_result.rcm)) {
        prompt_io_manager_.ErrorFormat(match_result.rcm);
        return match_result.rcm;
      }
      target = std::move(match_result.data);
    }
  }
  if (target.path.empty()) {
    target.path = ".";
  }

  std::string current_nickname = filesystem_service_.CurrentNickname();

  if (target.nickname == current_nickname) {
    ECM rcm = filesystem_service_.ChangeDir(target, control, from_history);
    if (!(rcm)) {
      prompt_io_manager_.ErrorFormat(rcm);
    }
    return rcm;
  }

  auto ensure_result =
      client_service_.EnsureClient(target.nickname, control, false, true);
  if (!ensure_result.rcm || !ensure_result.data) {
    prompt_io_manager_.ErrorFormat(ensure_result.rcm);
    return ensure_result.rcm;
  }

  ECM change_dir_rcm =
      filesystem_service_.ChangeDir(target, control, from_history);
  if (!change_dir_rcm) {
    prompt_io_manager_.ErrorFormat(change_dir_rcm);
    return change_dir_rcm;
  }

  client_service_.SetCurrentClient(ensure_result.data);
  ECM prompt_change_rcm = prompt_io_manager_.ChangeClient(
      ensure_result.data->ConfigPort().GetNickname());
  if (!prompt_change_rcm) {
    prompt_io_manager_.ErrorFormat(prompt_change_rcm);
  }
  return prompt_change_rcm;
}

ECM FilesystemInterfaceSerivce::Mkdirs(
    const FilesystemMkdirsArg &arg,
    const std::optional<ControlComponent> &control_opt) const {
  if (arg.raw_paths.empty()) {
    const ECM rcm = Err(EC::InvalidArg, "", "", "No path is given");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  std::vector<PathTarget> split_paths = {};
  split_paths.reserve(arg.raw_paths.size());
  std::unordered_set<std::string> seen_split_error = {};
  ECM status = OK;
  for (const auto &raw_path : arg.raw_paths) {
    if (control.IsInterrupted()) {
      return {EC::Terminate, "", "", "Interrupted by user"};
    }
    auto split_result = SplitRawTarget(raw_path);
    if (!(split_result.rcm)) {
      if (seen_split_error.insert(raw_path).second) {
        prompt_io_manager_.ErrorFormat(split_result.rcm);
      }
      status = MergeStatus_(status, split_result.rcm);
      continue;
    }
    split_paths.push_back(std::move(split_result.data));
  }
  const auto valid_paths =
      AMDomain::filesystem::service::DedupPathTargets(split_paths);

  for (const auto &path : valid_paths) {
    if (control.IsInterrupted()) {
      return {EC::Terminate, "", "", "Interrupted by user"};
    }
    ECM rcm = filesystem_service_.Mkdirs(path, control);
    if (!(rcm)) {
      prompt_io_manager_.ErrorFormat(rcm);
      status = MergeStatus_(status, rcm);
    }
  }
  return status;
}
} // namespace AMInterface::filesystem
