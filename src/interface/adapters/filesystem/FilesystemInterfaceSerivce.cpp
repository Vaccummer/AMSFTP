#include "interface/adapters/filesystem/FilesystemInterfaceSerivce.hpp"
#include "domain/filesystem/FileSystemDomainService.hpp"
#include "foundation/tools/enum_related.hpp"
#include "foundation/tools/string.hpp"
#include "foundation/tools/time.hpp"
#include "interface/style/StyleManager.hpp"

#include <algorithm>
#include <cctype>
#include <functional>
#include <iomanip>
#include <sstream>
#include <unordered_set>

namespace AMInterface::filesystem {
namespace {
ECM MergeStatus_(const ECM &current, const ECM &next) {
  return isok(next) ? current : next;
}

AMDomain::client::ClientControlComponent
ResolveControl_(AMDomain::client::amf default_interrupt_flag,
                const std::optional<AMDomain::client::ClientControlComponent>
                    &control_opt) {
  return control_opt.has_value() ? control_opt.value()
                                 : AMDomain::client::MakeClientControlComponent(
                                       default_interrupt_flag, -1);
}

std::string MakePathKey_(const ClientPath &path) {
  return path.nickname + "@" + path.path;
}

std::string Lowercase_(std::string text) {
  std::transform(text.begin(), text.end(), text.begin(), [](unsigned char ch) {
    return static_cast<char>(std::tolower(ch));
  });
  return text;
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

struct SplitPathsResult_ {
  std::vector<ClientPath> valid_paths = {};
  ECM status = Ok();
};

namespace interface_print {
std::string FormatStatTime(double value) {
  if (value <= 0.0) {
    return "-";
  }
  return FormatTime(static_cast<size_t>(value), "%Y/%m/%d %H:%M:%S");
}

std::string BuildPathLabel(const ClientPath &path) {
  if (path.nickname.empty()) {
    return path.path;
  }
  return AMStr::fmt("{}@{}", path.nickname, path.path);
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
                      const std::vector<std::string> &names) {
  constexpr size_t kMaxWidth = 80;
  size_t max_len = 0;
  for (const auto &name : names) {
    max_len = std::max(max_len, name.size());
  }
  const size_t col_width = (max_len == 0 ? 1 : max_len + 2);
  const size_t columns =
      std::max<size_t>(1, kMaxWidth / (col_width == 0 ? 1 : col_width));
  const size_t rows = (names.size() + columns - 1) / columns;

  for (size_t row = 0; row < rows; ++row) {
    std::ostringstream line;
    for (size_t col = 0; col < columns; ++col) {
      const size_t idx = row + col * rows;
      if (idx >= names.size()) {
        continue;
      }
      line << names[idx];
      if (col + 1 < columns && idx + rows < names.size()) {
        const size_t pad =
            col_width > names[idx].size() ? col_width - names[idx].size() : 1;
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
    const std::string styled_name =
        style_service.Format(info.name, AMInterface::style::StyleIndex::None,
                             &info);

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
} // namespace interface_print

SplitPathsResult_ CollectUniqueSplitPaths_(
    const std::vector<std::string> &raw_paths,
    const std::function<ECMData<ClientPath>(const std::string &)> &splitter,
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
    AMApplication::filesystem::FilesystemAppService &filesystem_service,
    AMInterface::style::AMStyleService &style_service,
    AMInterface::prompt::AMPromptIOManager &prompt_io_manager,
    AMDomain::client::amf default_interrupt_flag)
    : filesystem_service_(filesystem_service),
      style_service_(style_service),
      prompt_io_manager_(prompt_io_manager),
      default_interrupt_flag_(std::move(default_interrupt_flag)) {}

ECMData<ClientPath>
FilesystemInterfaceSerivce::SplitRawPath(const std::string &token) const {
  ClientPath out = {};
  const size_t at_pos = token.find('@');
  if (!token.empty() && token.front() == '@') {
    out.nickname = "local";
    out.path = token.substr(1);
  } else if (at_pos == std::string::npos) {
    out.nickname = filesystem_service_.CurrentNickname();
    out.path = token;
  } else {
    out.nickname = token.substr(0, at_pos);
    out.path = token.substr(at_pos + 1);
  }

  if (out.nickname.empty()) {
    out.nickname = "local";
  }
  if (out.path.empty()) {
    out.path = ".";
  }

  out.is_wildcard = AMDomain::filesystem::services::HasWildcard(out.path);
  out.userpath = !out.path.empty() && out.path.front() == '~';
  out.rcm = Ok();
  return {std::move(out), Ok()};
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
      [this](const std::string &raw_path) { return SplitRawPath(raw_path); },
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

ECM FilesystemInterfaceSerivce::Ls(
    const FilesystemLsArg &arg,
    const std::optional<AMDomain::client::ClientControlComponent> &control_opt)
    const {
  const auto control = ResolveControl_(default_interrupt_flag_, control_opt);
  ClientPath target = {};
  if (AMStr::Strip(arg.raw_path).empty()) {
    auto cwd_result = filesystem_service_.GetCwd(control);
    if (isok(cwd_result.rcm) && !cwd_result.data.path.empty()) {
      target = cwd_result.data;
      if (target.nickname.empty() && target.client) {
        target.nickname = target.client->ConfigPort().GetNickname();
      }
      if (target.nickname.empty()) {
        target.nickname = filesystem_service_.CurrentNickname();
      }
      if (target.nickname.empty()) {
        target.nickname = "local";
      }
    } else {
      auto split_result = SplitRawPath("/");
      if (!isok(split_result.rcm)) {
        interface_print::PrintPathError(prompt_io_manager_, "/",
                                        split_result.rcm);
        return split_result.rcm;
      }
      target = std::move(split_result.data);
    }
  } else {
    auto split_result = SplitRawPath(arg.raw_path);
    if (!isok(split_result.rcm)) {
      interface_print::PrintPathError(prompt_io_manager_, arg.raw_path,
                                      split_result.rcm);
      return split_result.rcm;
    }
    target = std::move(split_result.data);
  }

  if (!arg.list_like) {
    auto list_result = filesystem_service_.ListNames(target, control);
    if (!isok(list_result.rcm)) {
      interface_print::PrintPathError(prompt_io_manager_,
                                      interface_print::BuildPathLabel(target),
                                      list_result.rcm);
      return list_result.rcm;
    }

    std::vector<std::string> names = {};
    names.reserve(list_result.data.size());
    for (const auto &name : list_result.data) {
      if (!arg.show_all && IsHiddenName_(name)) {
        continue;
      }
      names.push_back(name);
    }
    std::sort(names.begin(), names.end(),
              [](const std::string &lhs, const std::string &rhs) {
                return Lowercase_(lhs) < Lowercase_(rhs);
              });
    interface_print::PrintLsNamesGrid(prompt_io_manager_, names);
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
              return Lowercase_(lhs.name) < Lowercase_(rhs.name);
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
  auto split_result = SplitRawPath(arg.raw_path);
  if (!isok(split_result.rcm)) {
    interface_print::PrintPathError(prompt_io_manager_, arg.raw_path,
                                    split_result.rcm);
    return split_result.rcm;
  }
  ECM rcm = filesystem_service_.ChangeDir(split_result.data, control,
                                          arg.from_history);
  if (!isok(rcm)) {
    interface_print::PrintPathError(
        prompt_io_manager_, interface_print::BuildPathLabel(split_result.data),
        rcm);
  }
  return rcm;
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
      [this](const std::string &raw_path) { return SplitRawPath(raw_path); },
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
