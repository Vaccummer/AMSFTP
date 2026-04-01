#include "interface/adapters/filesystem/FilesystemInterfaceSerivce.hpp"
#include "domain/filesystem/FileSystemDomainService.hpp"
#include "domain/host/HostDomainService.hpp"
#include "foundation/tools/path.hpp"
#include "foundation/tools/enum_related.hpp"
#include "foundation/tools/string.hpp"
#include "foundation/tools/time.hpp"
#include "interface/style/StyleManager.hpp"
#include <algorithm>
#include <cstdint>
#include <deque>
#include <functional>
#include <iomanip>
#include <limits>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace AMInterface::filesystem {
namespace {
ECM MergeStatus_(const ECM &current, const ECM &next) {
  return isok(next) ? current : next;
}

std::string NormalizeNickname_(const std::string &nickname) {
  return AMDomain::host::HostService::NormalizeNickname(nickname);
}

std::string NormalizePath_(const std::string &path) {
  return AMDomain::filesystem::services::NormalizePath(path);
}

AMDomain::client::ClientControlComponent
ResolveControl_(AMDomain::client::amf default_interrupt_flag,
                const std::optional<AMDomain::client::ClientControlComponent>
                    &control_opt) {
  return control_opt.has_value() ? control_opt.value()
                                 : AMDomain::client::ClientControlComponent(
                                       default_interrupt_flag, -1);
}

std::string MakePathKey_(const PathTarget &path) {
  return NormalizeNickname_(path.nickname) + "@" + NormalizePath_(path.path);
}

bool IsHiddenName_(const std::string &name) {
  return !name.empty() && name.front() == '.';
}

int TypeRank_(PathType type) {
  switch (type) {
  case PathType::FILE:
    return 0;
  case PathType::SYMLINK:
    return 1;
  case PathType::DIR:
    return 2;
  default:
    return 3;
  }
}

bool HasExplicitNickname_(const std::string &token) {
  return token.find('@') != std::string::npos;
}

bool IsAlreadyExistsError_(ErrorCode ec) {
  return ec == ErrorCode::PathAlreadyExists ||
         ec == ErrorCode::TargetAlreadyExists;
}

struct SplitPathsResult_ {
  std::vector<PathTarget> valid_paths = {};
  ECM status = Ok();
};

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
  const std::string normalized_path = NormalizePath_(path.path);
  const std::string display_path =
      normalized_path.empty() ? path.path : normalized_path;
  if (path.nickname.empty()) {
    return display_path;
  }
  return AMStr::fmt("{}@{}", NormalizeNickname_(path.nickname), display_path);
}

void PrintPathError(AMInterface::prompt::AMPromptIOManager &prompt_io_manager,
                    const std::string &label, const ECM &rcm) {
  if (label.empty()) {
    prompt_io_manager.ErrorFormat(rcm);
    return;
  }
  const std::string detail =
      rcm.second.empty() ? AMStr::ToString(rcm.first) : rcm.second;
  prompt_io_manager.ErrorFormat(
      Err(rcm.first, AMStr::fmt("{}: {}", label, detail)));
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

void PrintStatBlock(AMInterface::prompt::AMPromptIOManager &prompt_io_manager,
                    const PathInfo &info) {
  prompt_io_manager.Print(FormatStatBlock(info));
}

void PrintLsNamesGrid(AMInterface::prompt::AMPromptIOManager &prompt_io_manager,
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
        const size_t pad =
            col_width > entries[idx].name.size()
                ? col_width - entries[idx].name.size()
                : 1;
        line << std::string(pad, ' ');
      }
    }
    prompt_io_manager.Print(line.str());
  }
}

void PrintLsLongEntries(
    AMInterface::prompt::AMPromptIOManager &prompt_io_manager,
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
    AMInterface::prompt::AMPromptIOManager &prompt_io_manager,
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
    AMInterface::prompt::AMPromptIOManager &prompt_io_manager,
    const AMApplication::filesystem::PermanentRemovePlan &plan) {
  for (const auto &[nickname, paths] : plan.grouped_display_paths) {
    prompt_io_manager.Print(AMStr::fmt("{}:", nickname));
    for (const auto &path : paths) {
      prompt_io_manager.Print(path.path);
    }
  }
}

void PrintGroupedClientPaths(
    AMInterface::prompt::AMPromptIOManager &prompt_io_manager,
    const std::map<std::string, std::vector<PathTarget>> &grouped_paths) {
  for (const auto &[nickname, paths] : grouped_paths) {
    prompt_io_manager.Print(AMStr::fmt("{}:", nickname));
    for (const auto &path : paths) {
      prompt_io_manager.Print(path.path);
    }
  }
}
} // namespace interface_print

SplitPathsResult_ CollectUniqueSplitPaths_(
    const std::vector<std::string> &raw_paths,
    const std::function<ECMData<PathTarget>(const std::string &)> &splitter,
    const AMDomain::client::ClientControlComponent &control,
    AMInterface::prompt::AMPromptIOManager &prompt_io_manager) {
  SplitPathsResult_ out = {};
  out.valid_paths.reserve(raw_paths.size());
  std::unordered_set<std::string> seen_valid = {};
  std::unordered_set<std::string> seen_error = {};

  for (const auto &raw_path : raw_paths) {
    if (control.IsInterrupted()) {
      out.status = Err(EC::Terminate, "Interrupted by user");
      out.valid_paths.clear();
      return out;
    }

    auto split_result = splitter(raw_path);
    if (!isok(split_result.rcm)) {
      if (seen_error.insert(raw_path).second) {
        interface_print::PrintPathError(prompt_io_manager, raw_path,
                                        split_result.rcm);
      }
      out.status = MergeStatus_(out.status, split_result.rcm);
      continue;
    }

    const std::string key = MakePathKey_(split_result.data);
    if (!seen_valid.insert(key).second) {
      continue;
    }
    out.valid_paths.push_back(std::move(split_result.data));
  }

  return out;
}
} // namespace

FilesystemInterfaceSerivce::FilesystemInterfaceSerivce(
    AMApplication::client::ClientAppService &client_service,
    AMApplication::filesystem::FilesystemAppService &filesystem_service,
    AMInterface::style::AMStyleService &style_service,
    AMInterface::prompt::AMPromptIOManager &prompt_io_manager,
    AMDomain::client::amf default_interrupt_flag)
    : client_service_(client_service), filesystem_service_(filesystem_service),
      style_service_(style_service), prompt_io_manager_(prompt_io_manager),
      default_interrupt_flag_(std::move(default_interrupt_flag)) {}

ECMData<PathTarget>
FilesystemInterfaceSerivce::SplitRawTarget(const std::string &token) const {
  PathTarget out = {};
  const std::string normalized_token = AMStr::Strip(token);
  const size_t at_pos = normalized_token.find('@');
  if (!normalized_token.empty() && normalized_token.front() == '@') {
    out.nickname = "local";
    out.path = normalized_token.substr(1);
  } else if (at_pos == std::string::npos) {
    out.nickname = filesystem_service_.CurrentNickname();
    out.path = normalized_token;
  } else {
    out.nickname = normalized_token.substr(0, at_pos);
    out.path = normalized_token.substr(at_pos + 1);
  }

  out.nickname = NormalizeNickname_(out.nickname);
  out.path = NormalizePath_(out.path);
  if (out.path.empty()) {
    out.path = ".";
  }

  return {std::move(out), Ok()};
}

ECMData<PathTarget>
FilesystemInterfaceSerivce::MatchOne(const PathTarget &path) const {
  size_t matched_count = 0;
  PathTarget first_matched_path = {};
  auto control =
      AMDomain::client::ClientControlComponent(default_interrupt_flag_, -1);
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
    first_matched_path.nickname =
        NormalizeNickname_(first_matched_path.nickname);
    first_matched_path.path = NormalizePath_(first_matched_path.path);
    return {std::move(first_matched_path), Ok()};
  }
  if (matched_count > 1) {
    return {PathTarget{},
            Err(EC::InvalidArg,
                AMStr::fmt("Wildcard path must match exactly one target: {}@{}",
                           path.nickname, path.path))};
  }
  if (!find_result.rcm) {
    return {PathTarget{}, find_result.rcm};
  }
  return {PathTarget{}, Err(EC::InvalidArg,
                            AMStr::fmt("Wildcard path matched no target: {}@{}",
                                       path.nickname, path.path))};
}

ECM FilesystemInterfaceSerivce::Stat(
    const FilesystemStatArg &arg,
    const std::optional<AMDomain::client::ClientControlComponent> &control_opt)
    const {
  if (arg.raw_paths.empty()) {
    const ECM rcm = Err(EC::InvalidArg, "No path is given");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  auto split_paths = CollectUniqueSplitPaths_(
      arg.raw_paths,
      [this](const std::string &raw_path) { return SplitRawTarget(raw_path); },
      control, prompt_io_manager_);
  if (split_paths.status.first == EC::Terminate) {
    return split_paths.status;
  }
  ECM status = split_paths.status;

  for (const auto &path : split_paths.valid_paths) {
    if (control.IsInterrupted()) {
      return Err(EC::Terminate, "Interrupted by user");
    }

    auto stat_result = filesystem_service_.Stat(path, control, arg.trace_link);
    if (!isok(stat_result.rcm)) {
      interface_print::PrintPathError(prompt_io_manager_,
                                      interface_print::BuildPathLabel(path),
                                      stat_result.rcm);
      status = MergeStatus_(status, stat_result.rcm);
      continue;
    }
    interface_print::PrintStatBlock(prompt_io_manager_, stat_result.data);
  }

  return status;
}

ECM FilesystemInterfaceSerivce::GetSize(
    const FilesystemGetSizeArg &arg,
    const std::optional<AMDomain::client::ClientControlComponent> &control_opt)
    const {
  if (arg.raw_paths.empty()) {
    const ECM rcm = Err(EC::InvalidArg, "No path is given");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  auto split_paths = CollectUniqueSplitPaths_(
      arg.raw_paths,
      [this](const std::string &raw_path) { return SplitRawTarget(raw_path); },
      control, prompt_io_manager_);
  if (split_paths.status.first == EC::Terminate) {
    return split_paths.status;
  }
  ECM status = split_paths.status;

  for (const auto &path : split_paths.valid_paths) {
    if (control.IsInterrupted()) {
      return Err(EC::Terminate, "Interrupted by user");
    }
    if (control.IsTimeout()) {
      return Err(EC::OperationTimeout, "Operation timed out");
    }

    PathTarget target = path;
    if (AMDomain::filesystem::services::HasWildcard(target.path)) {
      auto match_result = MatchOne(target);
      if (!isok(match_result.rcm)) {
        interface_print::PrintPathError(prompt_io_manager_,
                                        interface_print::BuildPathLabel(target),
                                        match_result.rcm);
        status = MergeStatus_(status, match_result.rcm);
        continue;
      }
      target = std::move(match_result.data);
    }

    auto pre_stat = filesystem_service_.Stat(target, control, false);
    if (!pre_stat.rcm) {
      const std::string label = interface_print::BuildPathLabel(target);
      interface_print::PrintPathError(prompt_io_manager_, label, pre_stat.rcm);
      status = MergeStatus_(status, pre_stat.rcm);
      continue;
    }
    PathTarget display_target = target;
    display_target.nickname = NormalizeNickname_(display_target.nickname);
    if (!pre_stat.data.path.empty()) {
      display_target.path = NormalizePath_(pre_stat.data.path);
    } else {
      display_target.path = NormalizePath_(display_target.path);
    }
    if (display_target.path.empty()) {
      display_target.path = ".";
    }
    const std::string label = interface_print::BuildPathLabel(display_target);

    if (pre_stat.data.type != PathType::DIR) {
      prompt_io_manager_.Print(
          AMStr::fmt("{} {}", label, AMStr::FormatSize(pre_stat.data.size)));
      continue;
    }

    std::string latest_size = "0KB";
    bool has_progress = false;
    bool refresh_started = false;
    prompt_io_manager_.RefreshBegin(1);
    refresh_started = true;
    prompt_io_manager_.RefreshRender({AMStr::fmt("{} {}", label, latest_size)});

    auto size_result = filesystem_service_.GetSize(
        target, control,
        [this, &label, &latest_size,
         &has_progress](const PathTarget &, int64_t current_size) -> bool {
          const std::string formatted = AMStr::FormatSize(current_size);
          if (has_progress && formatted == latest_size) {
            return true;
          }
          has_progress = true;
          latest_size = formatted;
          prompt_io_manager_.RefreshRender(
              {AMStr::fmt("{} {}", label, latest_size)});
          return true;
        },
        [this](const PathTarget &error_path, ECM rcm) {
          interface_print::PrintPathError(
              prompt_io_manager_, interface_print::BuildPathLabel(error_path),
              rcm);
        });

    if (refresh_started) {
      prompt_io_manager_.RefreshEnd();
    }
    if (!has_progress && isok(size_result.rcm)) {
      latest_size = AMStr::FormatSize(size_result.data);
    }
    prompt_io_manager_.Print(AMStr::fmt("{} {}", label, latest_size));

    if (!size_result.rcm) {
      status = MergeStatus_(status, size_result.rcm);
      if (size_result.rcm.first == EC::Terminate ||
          size_result.rcm.first == EC::OperationTimeout) {
        return size_result.rcm;
      }
    }
  }

  return status;
}

ECM FilesystemInterfaceSerivce::Find(
    const FilesystemFindArg &arg,
    const std::optional<AMDomain::client::ClientControlComponent> &control_opt)
    const {
  auto split_result = SplitRawTarget(arg.raw_path);
  if (!isok(split_result.rcm)) {
    interface_print::PrintPathError(prompt_io_manager_, arg.raw_path,
                                    split_result.rcm);
    return split_result.rcm;
  }

  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  ECM status = Ok();
  auto result = filesystem_service_.find(
      split_result.data, SearchType::All, control, {},
      [this, &status](const PathTarget &error_path, ECM rcm) {
        interface_print::PrintPathError(
            prompt_io_manager_, interface_print::BuildPathLabel(error_path),
            rcm);
        status = MergeStatus_(status, rcm);
      });

  if (!isok(result.rcm)) {
    if (result.rcm.first == EC::Terminate ||
        result.rcm.first == EC::OperationTimeout) {
      return result.rcm;
    }
    status = MergeStatus_(status, result.rcm);
  }

  const std::string pattern = AMStr::Strip(arg.raw_path).empty()
                                  ? split_result.data.path
                                  : AMStr::Strip(arg.raw_path);
  prompt_io_manager_.FmtPrint("Find Result for pattern {}", pattern);
  for (const auto &entry : result.data) {
    prompt_io_manager_.Print(entry.path);
  }

  return status;
}

ECM FilesystemInterfaceSerivce::Realpath(
    const FilesystemRealpathArg &arg,
    const std::optional<AMDomain::client::ClientControlComponent> &control_opt)
    const {
  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  std::string raw_path = AMStr::Strip(arg.raw_path);
  if (raw_path.empty()) {
    raw_path = ".";
  }

  auto split_result = SplitRawTarget(raw_path);
  if (!isok(split_result.rcm)) {
    interface_print::PrintPathError(prompt_io_manager_, raw_path,
                                    split_result.rcm);
    return split_result.rcm;
  }
  if (AMDomain::filesystem::services::HasWildcard(split_result.data.path)) {
    const ECM rcm = Err(EC::InvalidArg, "realpath does not accept wildcard path");
    interface_print::PrintPathError(
        prompt_io_manager_, interface_print::BuildPathLabel(split_result.data),
        rcm);
    return rcm;
  }

  auto resolve_result = filesystem_service_.ResolvePath(split_result.data, control);
  if (!isok(resolve_result.rcm)) {
    interface_print::PrintPathError(
        prompt_io_manager_, interface_print::BuildPathLabel(split_result.data),
        resolve_result.rcm);
    return resolve_result.rcm;
  }

  std::string nickname = NormalizeNickname_(resolve_result.data.target.nickname);
  std::string npath = NormalizePath_(AMStr::Strip(resolve_result.data.abs_path));
  if (npath.empty()) {
    npath = ".";
  }
  prompt_io_manager_.FmtPrint("{}@{}", nickname, npath);
  return Ok();
}

ECM FilesystemInterfaceSerivce::Tree(
    const FilesystemTreeArg &arg,
    const std::optional<AMDomain::client::ClientControlComponent> &control_opt)
    const {
  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  const auto print_error = [&](const std::string &label, const ECM &rcm) {
    if (!arg.quiet) {
      interface_print::PrintPathError(prompt_io_manager_, label, rcm);
    }
  };
  const auto stop_error = [&control]() -> ECM {
    if (control.IsInterrupted()) {
      return Err(EC::Terminate, "Interrupted by user");
    }
    if (control.IsTimeout()) {
      return Err(EC::OperationTimeout, "Operation timed out");
    }
    return Ok();
  };

  auto split_result = SplitRawTarget(arg.raw_path);
  if (!isok(split_result.rcm)) {
    print_error(arg.raw_path, split_result.rcm);
    return split_result.rcm;
  }
  PathTarget target = std::move(split_result.data);

  if (AMDomain::filesystem::services::HasWildcard(target.path)) {
    auto match_result = MatchOne(target);
    if (!isok(match_result.rcm)) {
      print_error(interface_print::BuildPathLabel(target), match_result.rcm);
      return match_result.rcm;
    }
    target = std::move(match_result.data);
  }

  auto root_stat = filesystem_service_.Stat(target, control, false);
  if (!isok(root_stat.rcm)) {
    print_error(interface_print::BuildPathLabel(target), root_stat.rcm);
    return root_stat.rcm;
  }
  if (arg.only_dir && root_stat.data.type != PathType::DIR) {
    const ECM rcm = Err(EC::NotADirectory,
                        AMStr::fmt("Not a directory: {}",
                                   interface_print::BuildPathLabel(target)));
    print_error(interface_print::BuildPathLabel(target), rcm);
    return rcm;
  }

  std::string root_key = NormalizePath_(root_stat.data.path);
  if (root_key.empty()) {
    root_key = target.path.empty() ? "." : NormalizePath_(target.path);
  }

  std::unordered_map<std::string, TreeNode_> tree_nodes = {};
  tree_nodes[root_key] = {};
  std::deque<std::pair<std::string, int>> pending = {};
  pending.emplace_back(root_key, 0);
  std::unordered_set<std::string> visited = {};
  visited.insert(root_key);
  std::vector<std::pair<std::string, ECM>> traversal_errors = {};
  ECM status = Ok();

  while (!pending.empty()) {
    const ECM check_rcm = stop_error();
    if (!isok(check_rcm)) {
      return check_rcm;
    }

    const auto [current_dir, depth] = pending.front();
    pending.pop_front();

    if (arg.max_depth >= 0 && depth >= arg.max_depth) {
      continue;
    }

    PathTarget current = {};
    current.nickname = NormalizeNickname_(target.nickname);
    current.path = NormalizePath_(current_dir);
    auto list_result = filesystem_service_.Listdir(current, control);
    if (!isok(list_result.rcm)) {
      traversal_errors.emplace_back(interface_print::BuildPathLabel(current),
                                    list_result.rcm);
      status = MergeStatus_(status, list_result.rcm);
      continue;
    }

    auto &node = tree_nodes[current_dir];
    for (const auto &entry : list_result.data) {
      const ECM item_check_rcm = stop_error();
      if (!isok(item_check_rcm)) {
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
          dir_info.path = NormalizePath_(AMPath::join(current_dir, dir_info.name));
        } else {
          dir_info.path = NormalizePath_(dir_info.path);
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
        file_info.path =
            NormalizePath_(AMPath::join(current_dir, file_info.name));
      } else {
        file_info.path = NormalizePath_(file_info.path);
      }
      node.files.push_back(std::move(file_info));
    }
  }

  if (!arg.quiet) {
    for (const auto &item : traversal_errors) {
      interface_print::PrintPathError(prompt_io_manager_, item.first,
                                      item.second);
    }
  }

  for (auto &entry : tree_nodes) {
    interface_print::SortTreeNode_(&entry.second);
  }

  PathInfo root_info = root_stat.data;
  root_info.path = NormalizePath_(root_key);
  const std::string root_line =
      style_service_.Format(interface_print::BuildPathLabel(target),
                            AMInterface::style::StyleIndex::None, &root_info);
  interface_print::PrintTreeLines(prompt_io_manager_, style_service_, root_key,
                                  root_line, tree_nodes);
  return status;
}

ECM FilesystemInterfaceSerivce::TestRTT(
    const FilesystemTestRTTArg &arg,
    const std::optional<AMDomain::client::ClientControlComponent> &control_opt)
    const {
  if (arg.times <= 0) {
    const ECM rcm = Err(EC::InvalidArg, "times must be > 0");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  std::string nickname = NormalizeNickname_(filesystem_service_.CurrentNickname());

  auto rtt_result = filesystem_service_.TestRTT(nickname, control, arg.times);
  if (!isok(rtt_result.rcm)) {
    prompt_io_manager_.ErrorFormat(rtt_result.rcm);
    return rtt_result.rcm;
  }

  std::ostringstream out;
  out << std::fixed << std::setprecision(2) << rtt_result.data;
  prompt_io_manager_.FmtPrint("RTT: {} ms", out.str());
  return Ok();
}

ECM FilesystemInterfaceSerivce::ShellRun(
    const FilesystemShellRunArg &arg,
    const std::optional<AMDomain::client::ClientControlComponent> &control_opt)
    const {
  const std::string command = AMStr::Strip(arg.cmd);
  if (command.empty()) {
    const ECM rcm = Err(EC::InvalidArg, "cmd cannot be empty");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }
  if (arg.max_time_s < -1) {
    const ECM rcm = Err(EC::InvalidArg, "max_time_s must be >= -1");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  const auto base_control =
      ResolveControl_(default_interrupt_flag_, control_opt);
  AMDomain::client::ClientControlComponent run_control = base_control;
  if (arg.max_time_s >= 0) {
    constexpr int kMaxSafeSeconds = std::numeric_limits<int>::max() / 1000;
    const int safe_seconds = std::min(arg.max_time_s, kMaxSafeSeconds);
    run_control = AMDomain::client::ClientControlComponent(
        base_control.ControlToken(), safe_seconds * 1000);
  }

  std::string nickname = NormalizeNickname_(filesystem_service_.CurrentNickname());

  std::string final_cmd = {};
  auto shell_result = filesystem_service_.ShellRun(nickname, "", command,
                                                   run_control, &final_cmd);

  if (!final_cmd.empty()) {
    prompt_io_manager_.FmtPrint("Final cmd: {}", final_cmd);
  }
  if (!shell_result.output.empty()) {
    prompt_io_manager_.Print(shell_result.output);
  }
  prompt_io_manager_.FmtPrint("Exit with code {}", shell_result.exit_code);

  if (!isok(shell_result.rcm)) {
    prompt_io_manager_.ErrorFormat(shell_result.rcm);
    return shell_result.rcm;
  }
  return Ok();
}

ECM FilesystemInterfaceSerivce::Rename(
    const FilesystemRenameArg &arg,
    const std::optional<AMDomain::client::ClientControlComponent> &control_opt)
    const {
  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  auto src_split = SplitRawTarget(arg.target);
  if (!isok(src_split.rcm)) {
    interface_print::PrintPathError(prompt_io_manager_, arg.target,
                                    src_split.rcm);
    return src_split.rcm;
  }
  PathTarget src = std::move(src_split.data);
  if (AMDomain::filesystem::services::HasWildcard(src.path)) {
    auto match_result = MatchOne(src);
    if (!isok(match_result.rcm)) {
      interface_print::PrintPathError(prompt_io_manager_,
                                      interface_print::BuildPathLabel(src),
                                      match_result.rcm);
      return match_result.rcm;
    }
    src = std::move(match_result.data);
  }

  auto dst_split = SplitRawTarget(arg.dst);
  if (!isok(dst_split.rcm)) {
    interface_print::PrintPathError(prompt_io_manager_, arg.dst, dst_split.rcm);
    return dst_split.rcm;
  }
  PathTarget dst = std::move(dst_split.data);
  if (AMDomain::filesystem::services::HasWildcard(dst.path)) {
    const ECM rcm =
        Err(EC::InvalidArg, "Destination wildcard is not supported");
    interface_print::PrintPathError(prompt_io_manager_, arg.dst, rcm);
    return rcm;
  }
  if (!HasExplicitNickname_(arg.dst)) {
    dst.nickname = src.nickname;
  }

  auto run_rename = [&](bool overwrite) {
    return filesystem_service_.Rename(src, dst, control, arg.mkdir, overwrite);
  };

  ECM rename_rcm = run_rename(arg.overwrite);
  if (!isok(rename_rcm) && !arg.overwrite &&
      IsAlreadyExistsError_(rename_rcm.first)) {
    bool canceled = false;
    const std::string prompt =
        AMStr::fmt("Destination exists [{}], overwrite? (y/N): ",
                   interface_print::BuildPathLabel(dst));
    const bool approved = prompt_io_manager_.PromptYesNo(prompt, &canceled);
    if (!approved) {
      const ECM cancel_rcm = Err(EC::ConfigCanceled, "Rename canceled");
      interface_print::PrintPathError(
          prompt_io_manager_, interface_print::BuildPathLabel(src), cancel_rcm);
      return cancel_rcm;
    }
    rename_rcm = run_rename(true);
  }

  if (!isok(rename_rcm)) {
    interface_print::PrintPathError(
        prompt_io_manager_, interface_print::BuildPathLabel(src), rename_rcm);
  }
  return rename_rcm;
}

ECM FilesystemInterfaceSerivce::Move(
    const FilesystemMoveArg &arg,
    const std::optional<AMDomain::client::ClientControlComponent> &control_opt)
    const {
  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  auto src_split = SplitRawTarget(arg.target);
  if (!src_split.rcm) {
    interface_print::PrintPathError(prompt_io_manager_, arg.target,
                                    src_split.rcm);
    return src_split.rcm;
  }
  PathTarget src = std::move(src_split.data);
  if (AMDomain::filesystem::services::HasWildcard(src.path)) {
    auto match_result = MatchOne(src);
    if (!isok(match_result.rcm)) {
      interface_print::PrintPathError(prompt_io_manager_,
                                      interface_print::BuildPathLabel(src),
                                      match_result.rcm);
      return match_result.rcm;
    }
    src = std::move(match_result.data);
  }

  auto dst_split = SplitRawTarget(arg.dst);
  if (!isok(dst_split.rcm)) {
    interface_print::PrintPathError(prompt_io_manager_, arg.dst, dst_split.rcm);
    return dst_split.rcm;
  }
  PathTarget dst_dir = std::move(dst_split.data);
  if (AMDomain::filesystem::services::HasWildcard(dst_dir.path)) {
    const ECM rcm =
        Err(EC::InvalidArg, "Destination wildcard is not supported");
    interface_print::PrintPathError(prompt_io_manager_, arg.dst, rcm);
    return rcm;
  }
  if (!HasExplicitNickname_(arg.dst)) {
    dst_dir.nickname = src.nickname;
  }

  auto dst_stat = filesystem_service_.Stat(dst_dir, control, false);
  if (!isok(dst_stat.rcm)) {
    if (AMDomain::filesystem::services::IsPathNotExistError(
            dst_stat.rcm.first)) {
      if (!arg.mkdir) {
        const ECM rcm =
            Err(EC::PathNotExist,
                AMStr::fmt("Destination directory not found: {}",
                           interface_print::BuildPathLabel(dst_dir)));
        interface_print::PrintPathError(
            prompt_io_manager_, interface_print::BuildPathLabel(dst_dir), rcm);
        return rcm;
      }
      ECM mkdir_rcm = filesystem_service_.Mkdirs(dst_dir, control);
      if (!isok(mkdir_rcm)) {
        interface_print::PrintPathError(
            prompt_io_manager_, interface_print::BuildPathLabel(dst_dir),
            mkdir_rcm);
        return mkdir_rcm;
      }
    } else {
      interface_print::PrintPathError(prompt_io_manager_,
                                      interface_print::BuildPathLabel(dst_dir),
                                      dst_stat.rcm);
      return dst_stat.rcm;
    }
  } else if (dst_stat.data.type != PathType::DIR) {
    const ECM rcm = Err(EC::NotADirectory,
                        AMStr::fmt("Not a directory: {}", dst_stat.data.path));
    interface_print::PrintPathError(
        prompt_io_manager_, interface_print::BuildPathLabel(dst_dir), rcm);
    return rcm;
  }

  PathTarget final_dst = dst_dir;
  final_dst.path =
      NormalizePath_(AMPath::join(dst_dir.path, AMPath::basename(src.path)));
  FilesystemRenameArg rename_arg = {};
  rename_arg.target = interface_print::BuildPathLabel(src);
  rename_arg.dst = interface_print::BuildPathLabel(final_dst);
  rename_arg.mkdir = arg.mkdir;
  rename_arg.overwrite = arg.overwrite;
  return Rename(rename_arg, control_opt);
}

ECM FilesystemInterfaceSerivce::Saferm(
    const FilesystemSafermArg &arg,
    const std::optional<AMDomain::client::ClientControlComponent> &control_opt)
    const {
  if (arg.targets.empty()) {
    const ECM rcm = Err(EC::InvalidArg, "No target is given");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  std::vector<PathTarget> targets = {};
  targets.reserve(arg.targets.size());
  ECM status = Ok();
  for (const auto &token : arg.targets) {
    if (control.IsInterrupted()) {
      return Err(EC::Terminate, "Interrupted by user");
    }
    if (control.IsTimeout()) {
      return Err(EC::OperationTimeout, "Operation timed out");
    }

    auto split_result = SplitRawTarget(token);
    if (!split_result.rcm) {
      interface_print::PrintPathError(prompt_io_manager_, token,
                                      split_result.rcm);
      status = MergeStatus_(status, split_result.rcm);
      continue;
    }
    targets.push_back(std::move(split_result.data));
  }

  auto saferm_result = filesystem_service_.Saferm(std::move(targets), control);
  for (const auto &entry : saferm_result.data) {
    interface_print::PrintPathError(
        prompt_io_manager_, interface_print::BuildPathLabel(entry.first),
        entry.second);
  }
  return MergeStatus_(status, saferm_result.rcm);
}

ECM FilesystemInterfaceSerivce::Rmfile(
    const FilesystemRmfileArg &arg,
    const std::optional<AMDomain::client::ClientControlComponent> &control_opt)
    const {
  if (arg.targets.empty()) {
    const ECM rcm = Err(EC::InvalidArg, "No target is given");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  std::vector<PathTarget> targets = {};
  targets.reserve(arg.targets.size());
  std::unordered_set<std::string> seen = {};
  ECM status = Ok();

  for (const auto &token : arg.targets) {
    if (control.IsInterrupted()) {
      return Err(EC::Terminate, "Interrupted by user");
    }
    if (control.IsTimeout()) {
      return Err(EC::OperationTimeout, "Operation timed out");
    }

    auto split_result = SplitRawTarget(token);
    if (!isok(split_result.rcm)) {
      interface_print::PrintPathError(prompt_io_manager_, token,
                                      split_result.rcm);
      status = MergeStatus_(status, split_result.rcm);
      continue;
    }

    PathTarget target = std::move(split_result.data);
    if (AMDomain::filesystem::services::HasWildcard(target.path)) {
      auto match_result = MatchOne(target);
      if (!isok(match_result.rcm)) {
        interface_print::PrintPathError(prompt_io_manager_,
                                        interface_print::BuildPathLabel(target),
                                        match_result.rcm);
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
    interface_print::PrintPathError(
        prompt_io_manager_, interface_print::BuildPathLabel(entry.first),
        entry.second);
  }

  status = MergeStatus_(status, prepare_result.rcm);
  if (!isok(prepare_result.rcm) &&
      (prepare_result.rcm.first == EC::Terminate ||
       prepare_result.rcm.first == EC::OperationTimeout)) {
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
    return Err(EC::ConfigCanceled, "rmfile canceled");
  }

  auto execute_result = filesystem_service_.ExecuteRmfile(
      prepare_result.data, control, [this](const PathTarget &path, ECM rcm) {
        interface_print::PrintPathError(
            prompt_io_manager_, interface_print::BuildPathLabel(path), rcm);
      });
  return MergeStatus_(status, execute_result.rcm);
}

ECM FilesystemInterfaceSerivce::Rmdir(
    const FilesystemRmdirArg &arg,
    const std::optional<AMDomain::client::ClientControlComponent> &control_opt)
    const {
  if (arg.targets.empty()) {
    const ECM rcm = Err(EC::InvalidArg, "No target is given");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  std::vector<PathTarget> targets = {};
  targets.reserve(arg.targets.size());
  std::unordered_set<std::string> seen = {};
  ECM status = Ok();

  for (const auto &token : arg.targets) {
    if (control.IsInterrupted()) {
      return Err(EC::Terminate, "Interrupted by user");
    }
    if (control.IsTimeout()) {
      return Err(EC::OperationTimeout, "Operation timed out");
    }

    auto split_result = SplitRawTarget(token);
    if (!isok(split_result.rcm)) {
      interface_print::PrintPathError(prompt_io_manager_, token,
                                      split_result.rcm);
      status = MergeStatus_(status, split_result.rcm);
      continue;
    }

    PathTarget target = std::move(split_result.data);
    if (AMDomain::filesystem::services::HasWildcard(target.path)) {
      auto match_result = MatchOne(target);
      if (!isok(match_result.rcm)) {
        interface_print::PrintPathError(prompt_io_manager_,
                                        interface_print::BuildPathLabel(target),
                                        match_result.rcm);
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
      std::move(targets), control, [this](const PathTarget &path, ECM rcm) {
        interface_print::PrintPathError(
            prompt_io_manager_, interface_print::BuildPathLabel(path), rcm);
      });
  return MergeStatus_(status, rmdir_result.rcm);
}

ECM FilesystemInterfaceSerivce::PermanentRemove(
    const FilesystemPermanentRemoveArg &arg,
    const std::optional<AMDomain::client::ClientControlComponent> &control_opt)
    const {
  if (arg.targets.empty()) {
    const ECM rcm = Err(EC::InvalidArg, "No target is given");
    if (!arg.quiet) {
      prompt_io_manager_.ErrorFormat(rcm);
    }
    return rcm;
  }

  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  std::vector<PathTarget> targets = {};
  targets.reserve(arg.targets.size());
  ECM status = Ok();

  for (const auto &token : arg.targets) {
    if (control.IsInterrupted()) {
      return Err(EC::Terminate, "Interrupted by user");
    }
    if (control.IsTimeout()) {
      return Err(EC::OperationTimeout, "Operation timed out");
    }

    auto split_result = SplitRawTarget(token);
    if (!isok(split_result.rcm)) {
      if (!arg.quiet) {
        interface_print::PrintPathError(prompt_io_manager_, token,
                                        split_result.rcm);
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
      interface_print::PrintPathError(
          prompt_io_manager_, interface_print::BuildPathLabel(entry.first),
          entry.second);
    }
  }

  status = MergeStatus_(status, prepare_result.rcm);
  if (!isok(prepare_result.rcm) &&
      (prepare_result.rcm.first == EC::Terminate ||
       prepare_result.rcm.first == EC::OperationTimeout)) {
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
    return Err(EC::ConfigCanceled, "permanent remove canceled");
  }

  prompt_io_manager_.RefreshBegin(1);
  auto execute_result = filesystem_service_.ExecutePermanentRemove(
      prepare_result.data, control,
      [this](const PathTarget &path) {
        prompt_io_manager_.RefreshRender(
            {AMStr::fmt("Removing {}", interface_print::BuildPathLabel(path))});
      },
      [this, &arg](const PathTarget &path, ECM rcm) {
        if (!arg.quiet) {
          interface_print::PrintPathError(
              prompt_io_manager_, interface_print::BuildPathLabel(path), rcm);
        }
      });
  prompt_io_manager_.RefreshEnd();

  return MergeStatus_(status, execute_result.rcm);
}

ECM FilesystemInterfaceSerivce::Ls(
    const FilesystemLsArg &arg,
    const std::optional<AMDomain::client::ClientControlComponent> &control_opt)
    const {
  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  PathTarget target = {};
  if (AMStr::Strip(arg.raw_path).empty()) {
    auto cwd_result = filesystem_service_.GetCwd(control);
    if (isok(cwd_result.rcm) && !cwd_result.data.path.empty()) {
      target = cwd_result.data;
      if (target.nickname.empty()) {
        target.nickname = filesystem_service_.CurrentNickname();
      }
      target.nickname = NormalizeNickname_(target.nickname);
      target.path = NormalizePath_(target.path);
      if (target.path.empty()) {
        target.path = ".";
      }
    } else {
      auto split_result = SplitRawTarget("/");
      if (!isok(split_result.rcm)) {
        interface_print::PrintPathError(prompt_io_manager_, "/",
                                        split_result.rcm);
        return split_result.rcm;
      }
      target = std::move(split_result.data);
    }
  } else {
    auto split_result = SplitRawTarget(arg.raw_path);
    if (!isok(split_result.rcm)) {
      interface_print::PrintPathError(prompt_io_manager_, arg.raw_path,
                                      split_result.rcm);
      return split_result.rcm;
    }
    target = std::move(split_result.data);
  }
  if (AMDomain::filesystem::services::HasWildcard(target.path)) {
    auto match_result = MatchOne(target);
    if (!isok(match_result.rcm)) {
      interface_print::PrintPathError(prompt_io_manager_,
                                      interface_print::BuildPathLabel(target),
                                      match_result.rcm);
      return match_result.rcm;
    }
    target = std::move(match_result.data);
  }
  target.nickname = NormalizeNickname_(target.nickname);
  target.path = NormalizePath_(target.path);
  if (target.path.empty()) {
    target.path = ".";
  }

  if (!arg.list_like) {
    auto list_result = filesystem_service_.Listdir(target, control);
    if (!isok(list_result.rcm)) {
      interface_print::PrintPathError(prompt_io_manager_,
                                      interface_print::BuildPathLabel(target),
                                      list_result.rcm);
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
                return AMStr::lowercase(lhs.name) < AMStr::lowercase(rhs.name);
              });
    interface_print::PrintLsNamesGrid(prompt_io_manager_, style_service_,
                                      entries);
    return Ok();
  }

  auto list_result = filesystem_service_.Listdir(target, control);
  if (!isok(list_result.rcm)) {
    interface_print::PrintPathError(prompt_io_manager_,
                                    interface_print::BuildPathLabel(target),
                                    list_result.rcm);
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
  return Ok();
}

ECM FilesystemInterfaceSerivce::Cd(
    const FilesystemCdArg &arg,
    const std::optional<AMDomain::client::ClientControlComponent> &control_opt)
    const {
  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  const std::string raw_path = AMStr::Strip(arg.raw_path);
  const bool from_history = (raw_path == "-");

  PathTarget target = {};
  if (from_history) {
    auto history_result = filesystem_service_.PeekCdHistory();
    if (!isok(history_result.rcm)) {
      interface_print::PrintPathError(prompt_io_manager_, "-",
                                      history_result.rcm);
      return history_result.rcm;
    }
    target = std::move(history_result.data);
  } else {
    auto split_result = SplitRawTarget(arg.raw_path);
    if (!isok(split_result.rcm)) {
      interface_print::PrintPathError(prompt_io_manager_, arg.raw_path,
                                      split_result.rcm);
      return split_result.rcm;
    }
    target = split_result.data;
    if (AMDomain::filesystem::services::HasWildcard(target.path)) {
      auto match_result = MatchOne(target);
      if (!isok(match_result.rcm)) {
        interface_print::PrintPathError(prompt_io_manager_,
                                        interface_print::BuildPathLabel(target),
                                        match_result.rcm);
        return match_result.rcm;
      }
      target = std::move(match_result.data);
    }
  }
  target.nickname = NormalizeNickname_(target.nickname);
  target.path = NormalizePath_(target.path);
  if (target.path.empty()) {
    target.path = ".";
  }

  std::string current_nickname =
      NormalizeNickname_(filesystem_service_.CurrentNickname());

  if (target.nickname == current_nickname) {
    ECM rcm = filesystem_service_.ChangeDir(target, control, from_history);
    if (!isok(rcm)) {
      interface_print::PrintPathError(
          prompt_io_manager_, interface_print::BuildPathLabel(target), rcm);
    }
    return rcm;
  }

  auto ensure_result =
      client_service_.EnsureClient(target.nickname, control, false, true);
  if (!ensure_result.rcm || !ensure_result.data) {
    interface_print::PrintPathError(prompt_io_manager_, target.nickname,
                                    ensure_result.rcm);
    return ensure_result.rcm;
  }

  ECM change_dir_rcm =
      filesystem_service_.ChangeDir(target, control, from_history);
  if (!change_dir_rcm) {
    interface_print::PrintPathError(prompt_io_manager_,
                                    interface_print::BuildPathLabel(target),
                                    change_dir_rcm);
    return change_dir_rcm;
  }

  client_service_.SetCurrentClient(ensure_result.data);
  ECM prompt_change_rcm = prompt_io_manager_.ChangeClient(
      ensure_result.data->ConfigPort().GetNickname());
  if (!prompt_change_rcm) {
    interface_print::PrintPathError(prompt_io_manager_, target.nickname,
                                    prompt_change_rcm);
  }
  return prompt_change_rcm;
}

ECM FilesystemInterfaceSerivce::Mkdirs(
    const FilesystemMkdirsArg &arg,
    const std::optional<AMDomain::client::ClientControlComponent> &control_opt)
    const {
  if (arg.raw_paths.empty()) {
    const ECM rcm = Err(EC::InvalidArg, "No path is given");
    prompt_io_manager_.ErrorFormat(rcm);
    return rcm;
  }

  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  auto split_paths = CollectUniqueSplitPaths_(
      arg.raw_paths,
      [this](const std::string &raw_path) { return SplitRawTarget(raw_path); },
      control, prompt_io_manager_);
  if (split_paths.status.first == EC::Terminate) {
    return split_paths.status;
  }
  ECM status = split_paths.status;

  for (const auto &path : split_paths.valid_paths) {
    if (control.IsInterrupted()) {
      return Err(EC::Terminate, "Interrupted by user");
    }
    ECM rcm = filesystem_service_.Mkdirs(path, control);
    if (!isok(rcm)) {
      interface_print::PrintPathError(
          prompt_io_manager_, interface_print::BuildPathLabel(path), rcm);
      status = MergeStatus_(status, rcm);
    }
  }
  return status;
}
} // namespace AMInterface::filesystem
