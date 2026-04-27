#include "application/prompt/PromptHistoryManager.hpp"
#include "domain/host/HostDomainService.hpp"
#include "domain/host/HostModel.hpp"
#include "foundation/tools/string.hpp"

#include <algorithm>
#include <deque>
#include <filesystem>
#include <fstream>
#include <optional>

namespace AMApplication::prompt {
namespace {
using EC = ErrorCode;
using AMDomain::host::HostService::IsLocalNickname;
using AMDomain::prompt::kPromptProfileDefault;

std::string NormalizeHistoryZone_(const std::string &zone) {
  const std::string stripped = AMStr::Strip(zone);
  if (stripped.empty() || stripped == kPromptProfileDefault ||
      IsLocalNickname(stripped)) {
    return AMDomain::host::klocalname;
  }
  return stripped;
}

void NormalizePromptHistoryArg_(PromptHistoryArg *arg) {
  if (arg == nullptr) {
    return;
  }
  if (AMStr::Strip(arg->history_dir).empty()) {
    arg->history_dir = "./history";
  }
  arg->max_count = std::clamp(arg->max_count, 1, 200);
}

std::vector<std::string>
DedupContinuousHistory_(const std::vector<std::string> &history) {
  std::vector<std::string> deduped = {};
  deduped.reserve(history.size());
  for (const auto &entry : history) {
    if (!deduped.empty() && deduped.back() == entry) {
      continue;
    }
    deduped.push_back(entry);
  }
  return deduped;
}

std::optional<std::string>
ReadLastHistoryRecord_(const std::filesystem::path &history_path) {
  std::ifstream in(history_path, std::ios::in | std::ios::binary);
  if (!in.is_open()) {
    return std::nullopt;
  }
  std::string line = {};
  std::string last = {};
  bool has_record = false;
  while (std::getline(in, line)) {
    last = line;
    has_record = true;
  }
  if (!has_record) {
    return std::nullopt;
  }
  return last;
}
} // namespace

PromptHistoryManager::PromptHistoryManager(PromptHistoryArg arg,
                                           std::filesystem::path project_root)
    : init_arg_([&arg]() {
        NormalizePromptHistoryArg_(&arg);
        return std::move(arg);
      }()),
      project_root_(std::move(project_root)) {}

ECM PromptHistoryManager::Init() { return OK; }

PromptHistoryArg PromptHistoryManager::GetInitArg() const {
  return init_arg_.lock().load();
}

void PromptHistoryManager::SetInitArg(PromptHistoryArg arg) {
  NormalizePromptHistoryArg_(&arg);
  init_arg_.lock().store(std::move(arg));
}

std::filesystem::path
PromptHistoryManager::ResolveHistoryPath_(const std::string &zone) const {
  PromptHistoryArg arg = GetInitArg();
  NormalizePromptHistoryArg_(&arg);
  std::filesystem::path dir = arg.history_dir;
  if (dir.is_relative() && !project_root_.empty()) {
    dir = project_root_ / dir;
  }
  return dir / NormalizeHistoryZone_(zone);
}

ECMData<PromptHistoryQueryResult>
PromptHistoryManager::GetZoneHistory(const std::string &zone) const {
  PromptHistoryArg arg = GetInitArg();
  NormalizePromptHistoryArg_(&arg);
  const std::string normalized_zone = NormalizeHistoryZone_(zone);
  const std::filesystem::path history_path = ResolveHistoryPath_(zone);

  std::ifstream in(history_path, std::ios::in | std::ios::binary);
  if (!in.is_open()) {
    PromptHistoryQueryResult out = {};
    out.request_zone = zone;
    out.resolved_zone = normalized_zone;
    out.from_fallback = (normalized_zone != AMStr::Strip(zone));
    out.allow_continuous_duplicates = arg.allow_continuous_duplicates;
    out.max_count = arg.max_count;
    return {std::move(out), OK};
  }

  std::deque<std::string> tail = {};
  std::string line = {};
  const size_t limit = static_cast<size_t>(std::max(1, arg.max_count));
  while (std::getline(in, line)) {
    tail.push_back(line);
    while (tail.size() > limit) {
      tail.pop_front();
    }
  }

  PromptHistoryQueryResult out = {};
  out.request_zone = zone;
  out.resolved_zone = normalized_zone;
  out.from_fallback = (normalized_zone != AMStr::Strip(zone));
  out.allow_continuous_duplicates = arg.allow_continuous_duplicates;
  out.max_count = arg.max_count;
  out.history.assign(tail.begin(), tail.end());
  if (!arg.allow_continuous_duplicates) {
    out.history = DedupContinuousHistory_(out.history);
  }
  return {std::move(out), OK};
}

ECM PromptHistoryManager::SetZoneHistory(const std::string &zone,
                                         std::vector<std::string> history) {
  PromptHistoryArg arg = GetInitArg();
  NormalizePromptHistoryArg_(&arg);
  if (!arg.allow_continuous_duplicates) {
    history = DedupContinuousHistory_(history);
  }

  const std::filesystem::path history_path = ResolveHistoryPath_(zone);
  std::error_code ec = {};
  std::filesystem::create_directories(history_path.parent_path(), ec);
  if (ec) {
    return Err(EC::ConfigDumpFailed, "", history_path.string(), ec.message());
  }

  std::ofstream out(history_path, std::ios::out | std::ios::binary |
                                      std::ios::trunc);
  if (!out.is_open()) {
    return Err(EC::LocalFileOpenError, "", history_path.string(),
               "failed to open prompt history file");
  }
  const size_t limit = static_cast<size_t>(std::max(1, arg.max_count));
  const size_t begin = history.size() > limit ? history.size() - limit : 0;
  for (size_t i = begin; i < history.size(); ++i) {
    out << history[i] << '\n';
  }
  return OK;
}

ECM PromptHistoryManager::AppendZoneHistory(const std::string &zone,
                                            const std::string &entry) {
  if (entry.empty()) {
    return Err(EC::InvalidArg, "", "", "Prompt history entry is empty");
  }

  PromptHistoryArg arg = GetInitArg();
  NormalizePromptHistoryArg_(&arg);
  const std::filesystem::path history_path = ResolveHistoryPath_(zone);
  if (!arg.allow_continuous_duplicates) {
    const std::optional<std::string> last_record =
        ReadLastHistoryRecord_(history_path);
    if (last_record.has_value() && *last_record == entry) {
      return OK;
    }
  }

  std::error_code ec = {};
  std::filesystem::create_directories(history_path.parent_path(), ec);
  if (ec) {
    return Err(EC::ConfigDumpFailed, "", history_path.string(), ec.message());
  }

  std::ofstream out(history_path,
                    std::ios::out | std::ios::binary | std::ios::app);
  if (!out.is_open()) {
    return Err(EC::LocalFileOpenError, "", history_path.string(),
               "failed to open prompt history file");
  }
  out << entry << '\n';
  return OK;
}

ECM PromptHistoryManager::ClearZoneHistory(const std::string &zone) {
  const std::filesystem::path history_path = ResolveHistoryPath_(zone);
  std::error_code ec = {};
  if (!std::filesystem::exists(history_path, ec) || ec) {
    return Err(EC::PathNotExist, "", "",
               AMStr::fmt("Prompt history zone not found: {}",
                          NormalizeHistoryZone_(zone)));
  }
  std::ofstream out(history_path,
                    std::ios::out | std::ios::binary | std::ios::trunc);
  if (!out.is_open()) {
    return Err(EC::LocalFileOpenError, "", history_path.string(),
               "failed to open prompt history file");
  }
  return OK;
}

} // namespace AMApplication::prompt
