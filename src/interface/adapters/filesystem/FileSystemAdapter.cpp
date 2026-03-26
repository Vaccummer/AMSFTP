#include "interface/adapters/filesystem/FileSystemAdapter.hpp"

#include "domain/filesystem/FileSystemDomainService.hpp"
#include "foundation/tools/enum_related.hpp"
#include "foundation/tools/string.hpp"
#include "foundation/tools/time.hpp"

#include <iomanip>
#include <sstream>
#include <unordered_set>

namespace AMInterface::filesystem {
namespace {
ECM MergeStatus_(const ECM &current, const ECM &next) {
  return isok(next) ? current : next;
}

std::string MakePathKey_(const ClientPath &path) {
  return path.nickname + "@" + path.path;
}

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

void PrintStatError(AMInterface::prompt::AMPromptIOManager &prompt_io_manager,
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

void PrintStatBlock(AMInterface::prompt::AMPromptIOManager &prompt_io_manager,
                    const PathInfo &info) {
  prompt_io_manager.Print(FormatStatBlock(info));
}
} // namespace interface_print
} // namespace

FilesystemInterfaceSerivce::FilesystemInterfaceSerivce(
    AMApplication::filesystem::FilesystemAppService &filesystem_service,
    AMInterface::prompt::AMPromptIOManager &prompt_io_manager,
    AMDomain::client::amf default_interrupt_flag)
    : filesystem_service_(filesystem_service),
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

  const AMDomain::client::ClientControlComponent fallback_control =
      AMDomain::client::MakeClientControlComponent(default_interrupt_flag_, -1);
  const AMDomain::client::ClientControlComponent &control =
      control_opt.has_value() ? control_opt.value() : fallback_control;
  ECM status = Ok();
  std::vector<ClientPath> valid_paths = {};
  valid_paths.reserve(arg.raw_paths.size());
  std::unordered_set<std::string> seen_valid = {};
  std::unordered_set<std::string> seen_error = {};

  for (const auto &raw_path : arg.raw_paths) {
    if (control.IsInterrupted()) {
      return Err(EC::Terminate, "Interrupted by user");
    }

    auto split_result = SplitRawPath(raw_path);
    if (!isok(split_result.rcm)) {
      if (seen_error.insert(raw_path).second) {
        interface_print::PrintStatError(prompt_io_manager_, raw_path,
                                        split_result.rcm);
      }
      status = MergeStatus_(status, split_result.rcm);
      continue;
    }

    const std::string key = MakePathKey_(split_result.data);
    if (!seen_valid.insert(key).second) {
      continue;
    }
    valid_paths.push_back(std::move(split_result.data));
  }

  for (const auto &path : valid_paths) {
    if (control.IsInterrupted()) {
      return Err(EC::Terminate, "Interrupted by user");
    }

    auto stat_result = filesystem_service_.Stat(path, control, arg.trace_link);
    if (!isok(stat_result.rcm)) {
      interface_print::PrintStatError(prompt_io_manager_,
                                      interface_print::BuildPathLabel(path),
                                      stat_result.rcm);
      status = MergeStatus_(status, stat_result.rcm);
      continue;
    }
    interface_print::PrintStatBlock(prompt_io_manager_, stat_result.data);
  }

  return status;
}
} // namespace AMInterface::filesystem
