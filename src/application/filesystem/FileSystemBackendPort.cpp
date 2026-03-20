#include "application/filesystem/FileSystemBackendPort.hpp"

#include "domain/client/ClientPort.hpp"
#include "foundation/tools/enum_related.hpp"

#include <algorithm>
#include <memory>
#include <tuple>
#include <utility>
#include <vector>

namespace AMApplication::filesystem::runtime {
namespace {
using ECM = std::pair<ErrorCode, std::string>;
using EC = ErrorCode;
using ClientHandle = AMDomain::client::ClientHandle;
using RemoveResult = AMDomain::filesystem::RemoveResult;
using StatPathResult = AMDomain::filesystem::StatPathResult;
using ListPathResult = AMDomain::filesystem::ListPathResult;
using GetSizeEntryResult = AMDomain::filesystem::GetSizeEntryResult;
using FindResult = AMDomain::filesystem::FindResult;
using WalkQueryResult = AMDomain::filesystem::WalkQueryResult;
using RealpathQueryResult = AMDomain::filesystem::RealpathQueryResult;
using RttQueryResult = AMDomain::filesystem::RttQueryResult;
using WalkPayload = AMDomain::filesystem::WalkPayload;
using ListPathPayload = AMDomain::filesystem::ListPathPayload;
using SizeEntry = AMDomain::filesystem::SizeEntry;
using RealpathEntry = AMDomain::filesystem::RealpathEntry;
using amf = AMApplication::filesystem::amf;

/**
 * @brief Return true when the external interrupt flag is terminated.
 */
bool IsInterrupted_(amf interrupt_flag) {
  return interrupt_flag && interrupt_flag->IsInterrupted();
}

/**
 * @brief Adapt task-level interrupt token into client control token.
 */
AMDomain::client::amf ToClientInterrupt_(amf interrupt_flag) {
  return interrupt_flag;
}

AMDomain::filesystem::ClientIOControlArgs
MakeControlArgs_(amf interrupt_flag, int timeout_ms = -1,
                 int64_t start_time = -1) {
  return AMDomain::client::MakeClientIOControlArgs(
      ToClientInterrupt_(interrupt_flag), timeout_ms, start_time);
}

/**
 * @brief Port-driven filesystem backend implementation.
 */
class DefaultFileSystemBackend final : public IFileSystemBackendPort {
public:
  /**
   * @brief Construct backend from split runtime/lifecycle/path client ports.
   */
  DefaultFileSystemBackend(AMDomain::client::IClientRuntimePort &runtime_port,
                           AMDomain::client::IClientPathPort &path_port)
      : runtime_port_(runtime_port), path_port_(path_port) {}

  /**
   * @brief Query RTT for current client with typed payload.
   */
  RttQueryResult QueryRtt(int times, amf interrupt_flag) override {
    if (IsInterrupted_(interrupt_flag)) {
      return {Err(EC::Terminate, "Interrupted by user"), 0.0};
    }
    auto client = runtime_port_.GetCurrentClient();
    if (!client) {
      return {Err(EC::ClientNotFound, "Current client not found"), 0.0};
    }
    const auto rtt_res = client->IOPort().GetRTT({times, MakeControlArgs_(
                                                             interrupt_flag)});
    if (!isok(rtt_res.rcm)) {
      return {rtt_res.rcm, 0.0};
    }
    return {Ok(), rtt_res.rtt_ms};
  }

  /**
   * @brief Create directory for explicit client target.
   */
  ECM MkdirForClient(const std::string &nickname, const std::string &path,
                     amf interrupt_flag, int timeout_ms) override {
    auto [parse_rcm, client, abs_path] =
        ResolvePathForClient_(nickname, path, interrupt_flag);
    if (!isok(parse_rcm) || !client) {
      return parse_rcm;
    }
    return client->IOPort().mkdirs(
        {abs_path, MakeControlArgs_(interrupt_flag, timeout_ms, -1)});
  }

  /**
   * @brief Remove one path for explicit client target.
   */
  RemoveResult ExecuteRemoveForClient(const std::string &nickname,
                                      const std::string &path, bool permanent,
                                      bool quiet, amf interrupt_flag,
                                      int timeout_ms) override {
    (void)quiet;
    auto [parse_rcm, client, abs_path] =
        ResolvePathForClient_(nickname, path, interrupt_flag);
    if (!isok(parse_rcm) || !client) {
      return {parse_rcm, {}};
    }
    if (permanent) {
      auto remove_res = client->IOPort().remove(
          {abs_path, nullptr, MakeControlArgs_(interrupt_flag, timeout_ms, -1)});
      return {remove_res.rcm, {}};
    }
    return {client->IOPort().saferm(
                {abs_path, MakeControlArgs_(interrupt_flag, timeout_ms, -1)}),
            {}};
  }

  /**
   * @brief Query stat for explicit client target.
   */
  StatPathResult QueryStatPath(const std::string &nickname,
                               const std::string &path, amf interrupt_flag,
                               int timeout_ms) override {
    auto [parse_rcm, client, abs_path] =
        ResolvePathForClient_(nickname, path, interrupt_flag);
    if (!isok(parse_rcm) || !client) {
      return {parse_rcm, {}};
    }
    auto stat_res = client->IOPort().stat(
        {abs_path, false, MakeControlArgs_(interrupt_flag, timeout_ms, -1)});
    if (!isok(stat_res.rcm)) {
      return {stat_res.rcm, {}};
    }
    return {Ok(), std::move(stat_res.info)};
  }

  /**
   * @brief Query list payload for explicit client target.
   */
  ListPathResult QueryListPathForClient(const std::string &nickname,
                                        const std::string &path, bool list_like,
                                        bool show_all, amf interrupt_flag,
                                        int timeout_ms) override {
    (void)list_like;
    auto [parse_rcm, client, abs_path] =
        ResolvePathForClient_(nickname, path.empty() ? "." : path, interrupt_flag);
    if (!isok(parse_rcm) || !client) {
      return {parse_rcm, {}};
    }

    auto stat_res = client->IOPort().stat(
        {abs_path, false, MakeControlArgs_(interrupt_flag, timeout_ms, -1)});
    if (!isok(stat_res.rcm)) {
      return {stat_res.rcm, {}};
    }
    ListPathPayload payload = {};
    payload.target = stat_res.info;
    if (stat_res.info.type != PathType::DIR) {
      return {Ok(), std::move(payload)};
    }
    auto list_res = client->IOPort().listdir(
        {abs_path, MakeControlArgs_(interrupt_flag, timeout_ms, -1)});
    if (!isok(list_res.rcm)) {
      return {list_res.rcm, std::move(payload)};
    }
    auto entries = std::move(list_res.entries);
    if (!show_all) {
      entries.erase(
          std::remove_if(entries.begin(), entries.end(),
                         [](const PathInfo &item) {
                           return item.name == "." || item.name == "..";
                         }),
          entries.end());
    }
    payload.entries = std::move(entries);
    return {Ok(), std::move(payload)};
  }

  /**
   * @brief Query size for explicit client target.
   */
  GetSizeEntryResult QueryGetSizeForClient(const std::string &nickname,
                                           const std::string &path,
                                           amf interrupt_flag,
                                           int timeout_ms) override {
    auto [parse_rcm, client, abs_path] =
        ResolvePathForClient_(nickname, path, interrupt_flag);
    if (!isok(parse_rcm) || !client) {
      return {parse_rcm, {}};
    }
    auto stat_res = client->IOPort().stat(
        {abs_path, false, MakeControlArgs_(interrupt_flag, timeout_ms, -1)});
    if (!isok(stat_res.rcm)) {
      return {stat_res.rcm, {}};
    }
    SizeEntry item = {};
    item.raw = path;
    item.abs_path = abs_path;
    auto size_res = client->IOPort().getsize(
        {abs_path, true, MakeControlArgs_(interrupt_flag, timeout_ms, -1)});
    if (!isok(size_res.rcm)) {
      return {size_res.rcm, {}};
    }
    item.size = size_res.size;
    return {Ok(), std::move(item)};
  }

  /**
   * @brief Query find for explicit client target.
   */
  FindResult QueryFindForClient(const std::string &nickname,
                                const std::string &path, SearchType type,
                                amf interrupt_flag, int timeout_ms) override {
    auto [parse_rcm, client, abs_path] =
        ResolvePathForClient_(nickname, path, interrupt_flag);
    if (!isok(parse_rcm) || !client) {
      return {parse_rcm, {}};
    }
    auto stat_res = client->IOPort().stat(
        {abs_path, false, MakeControlArgs_(interrupt_flag, timeout_ms, -1)});
    if (!isok(stat_res.rcm)) {
      return {stat_res.rcm, {}};
    }
    auto find_res = client->IOPort().find(
        {abs_path, type, MakeControlArgs_(interrupt_flag, timeout_ms, -1)});
    if (!isok(find_res.rcm)) {
      return {find_res.rcm, {}};
    }
    return {Ok(), std::move(find_res.entries)};
  }

  /**
   * @brief Query walk for explicit client target.
   */
  WalkQueryResult QueryWalkForClient(
      const std::string &nickname, const std::string &path, bool only_file,
      bool only_dir, bool show_all, bool ignore_special_file, bool quiet,
      amf interrupt_flag, int timeout_ms) override {
    (void)quiet;
    auto [parse_rcm, client, abs_path] =
        ResolvePathForClient_(nickname, path, interrupt_flag);
    if (!isok(parse_rcm) || !client) {
      return {parse_rcm, {}};
    }

    auto walk_res = client->IOPort().iwalk(
        {abs_path, show_all, ignore_special_file, nullptr,
         MakeControlArgs_(interrupt_flag, timeout_ms, -1)});
    WalkPayload payload = {};
    payload.errors = walk_res.errors;
    for (const auto &info : walk_res.entries) {
      if (only_file && info.type != PathType::FILE) {
        continue;
      }
      if (only_dir && info.type != PathType::DIR) {
        continue;
      }
      payload.items.emplace_back(info);
    }
    return {walk_res.rcm, std::move(payload)};
  }

  /**
   * @brief Query realpath for explicit client target.
   */
  RealpathQueryResult QueryRealpathForClient(const std::string &nickname,
                                             const std::string &path,
                                             amf interrupt_flag,
                                             int timeout_ms) override {
    auto [parse_rcm, client, abs_path] =
        ResolvePathForClient_(nickname, path, interrupt_flag);
    if (!isok(parse_rcm) || !client) {
      return {parse_rcm, {}};
    }
    auto real_res = client->IOPort().realpath(
        {abs_path, MakeControlArgs_(interrupt_flag, timeout_ms, -1)});
    if (!isok(real_res.rcm)) {
      return {real_res.rcm, {}};
    }
    RealpathEntry entry = {};
    entry.raw = path;
    entry.abs_path = real_res.path;
    return {Ok(), std::move(entry)};
  }

  /**
   * @brief Change workdir for explicit client target.
   */
  ECM CdForClient(const std::string &nickname, const std::string &path,
                  amf interrupt_flag, bool from_history) override {
    (void)from_history;
    auto [parse_rcm, client, abs_path] = ResolvePathForClient_(
        nickname, path.empty() ? "." : path, interrupt_flag);
    if (!isok(parse_rcm) || !client) {
      return parse_rcm;
    }
    auto stat_res =
        client->IOPort().stat({abs_path, false, MakeControlArgs_(interrupt_flag)});
    if (!isok(stat_res.rcm)) {
      return stat_res.rcm;
    }
    if (stat_res.info.type != PathType::DIR) {
      return Err(EC::NotADirectory, "Target is not a directory");
    }

    const std::string key = nickname.empty() ? client->ConfigPort().GetNickname()
                                             : nickname;
    auto state = path_port_.GetWorkdirState(key);
    state.cwd = abs_path;
    auto set_rcm = path_port_.SetWorkdirState(key, state);
    if (!isok(set_rcm)) {
      return set_rcm;
    }
    runtime_port_.SetCurrentClient(client);
    return Ok();
  }

  std::pair<ECM, std::pair<std::string, int>>
  ShellRun(const std::string &cmd, int max_time_ms,
           amf interrupt_flag) override {
    if (IsInterrupted_(interrupt_flag)) {
      return {Err(EC::Terminate, "Interrupted by user"), {"", -1}};
    }
    auto client = runtime_port_.GetCurrentClient();
    if (!client) {
      return {Err(EC::ClientNotFound, "Current client not found"), {"", -1}};
    }
    auto run_res = client->IOPort().ConductCmd(
        {cmd, max_time_ms, MakeControlArgs_(interrupt_flag)});
    return {run_res.rcm, {run_res.output, run_res.exit_code}};
  }

private:
  /**
   * @brief Resolve explicit client target into client handle + absolute path.
   */
  std::tuple<ECM, ClientHandle, std::string>
  ResolvePathForClient_(const std::string &nickname, const std::string &path,
                        amf interrupt_flag) {
    if (IsInterrupted_(interrupt_flag)) {
      return {Err(EC::Terminate, "Interrupted by user"), nullptr, ""};
    }

    ClientHandle client = nullptr;
    if (nickname.empty()) {
      client = runtime_port_.GetCurrentClient();
      if (!client) {
        client = runtime_port_.GetLocalClient();
      }
    } else {
      client = runtime_port_.GetClient(nickname);
    }
    if (!client) {
      return {Err(EC::ClientNotFound, "Resolved client is null"), nullptr,
              ""};
    }

    const std::string relative = path.empty() ? "." : path;
    const std::string abs_path = path_port_.BuildAbsolutePath(client, relative);
    return {Ok(), client, abs_path};
  }

  AMDomain::client::IClientRuntimePort &runtime_port_;
  AMDomain::client::IClientPathPort &path_port_;
};
} // namespace

std::shared_ptr<IFileSystemBackendPort> CreateDefaultFileSystemBackend(
    AMDomain::client::IClientRuntimePort &runtime_port,
    AMDomain::client::IClientPathPort &path_port) {
  return std::make_shared<DefaultFileSystemBackend>(runtime_port, path_port);
}
} // namespace AMApplication::filesystem::runtime



