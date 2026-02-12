#include "AMCLI/CompleteSources.hpp"
#include "AMBase/CommonTools.hpp"
#include "AMCLI/CLIBind.hpp"
#include "AMManager/Config.hpp"
#include "AMManager/Host.hpp"
#include "AMManager/Var.hpp"
#include "CLI/CLI.hpp"
#include <algorithm>
#include <utility>

namespace {
/**
 * @brief Escape bbcode special characters in display text.
 */
std::string EscapeBbcodeText_(const std::string &text) {
  std::string escaped;
  escaped.reserve(text.size() * 2);
  for (char c : text) {
    if (c == '\\') {
      escaped.append("\\\\");
    } else if (c == '[') {
      escaped.append("\\[");
    } else {
      escaped.push_back(c);
    }
  }
  return escaped;
}

/**
 * @brief Static host configuration fields for completion.
 */
const std::vector<std::string> kHostConfigFields = {
    "hostname",  "username", "port",        "keyfile",  "password",
    "trash_dir", "protocol", "buffer_size", "login_dir"};
} // namespace

/**
 * @brief Construct completion sources with required managers.
 */
AMCompleteSources::AMCompleteSources(AMCompleteEngine *engine,
                                     AMConfigManager &config_manager,
                                     AMClientManage::Manager &client_manager,
                                     AMFileSystem &filesystem,
                                     AMTransferManager &transfer_manager)
    : engine_(engine),
      config_manager_(config_manager),
      client_manager_(client_manager),
      filesystem_(filesystem),
      transfer_manager_(transfer_manager) {
  StartAsyncWorker();
}

/**
 * @brief Default destructor.
 */
AMCompleteSources::~AMCompleteSources() { StopAsyncWorker(); }

/**
 * @brief Clear completion caches.
 */
void AMCompleteSources::ClearCache() {
  {
    std::lock_guard<std::mutex> lock(cache_mtx_);
    cache_.clear();
  }
  {
    std::lock_guard<std::mutex> lock(async_result_mtx_);
    async_result_.reset();
  }
}

/**
 * @brief Reset async results for a new request.
 */
void AMCompleteSources::ResetAsyncResult() {
  std::lock_guard<std::mutex> lock(async_result_mtx_);
  async_result_.reset();
}

/**
 * @brief Return true when name is a top-level command.
 */
bool AMCompleteSources::IsTopCommand(const std::string &name) const {
  return command_tree_.IsTopCommand(name);
}

/**
 * @brief Return true when name is a module (has subcommands).
 */
bool AMCompleteSources::IsModule(const std::string &name) const {
  return command_tree_.IsModule(name);
}

/**
 * @brief Find a command node by its path.
 */
const AMCompleteEngine::CommandNode *
AMCompleteSources::FindNode(const std::string &path) const {
  return command_tree_.FindNode(path);
}

/**
 * @brief Collect command/option candidates.
 */
void AMCompleteSources::CollectCommandCandidates_(
    const AMCompleteEngine::CompletionContext &ctx,
    std::vector<AMCompleteEngine::CompletionCandidate> &out) {
  const std::string prefix = ctx.token_prefix;

  if (ctx.target == AMCompleteEngine::CompletionTarget::TopCommand) {
    struct ItemInfo {
      std::string name;
      std::string help;
      bool is_module = false;
    };
    std::vector<ItemInfo> items;
    auto tops = command_tree_.ListTopCommands();
    for (const auto &item : tops) {
      if (!prefix.empty() && item.first.rfind(prefix, 0) != 0) {
        continue;
      }
      items.push_back(
          {item.first, item.second, command_tree_.IsModule(item.first)});
    }
    if (items.empty()) {
      return;
    }
    size_t max_len = 0;
    for (const auto &item : items) {
      max_len = std::max(max_len, item.name.size());
    }
    for (const auto &item : items) {
      AMCompleteEngine::CompletionCandidate cand;
      cand.insert_text = item.name;
      cand.display = FormatCommandDisplay_(
          item.name, item.is_module ? "module" : "command", max_len);
      cand.help = item.help;
      cand.kind = item.is_module ? AMCompleteEngine::CompletionKind::Module
                                 : AMCompleteEngine::CompletionKind::Command;
      cand.score = item.is_module ? 0 : 1;
      out.push_back(std::move(cand));
    }
    return;
  }

  if (ctx.target == AMCompleteEngine::CompletionTarget::Subcommand) {
    struct ItemInfo {
      std::string name;
      std::string help;
    };
    std::vector<ItemInfo> items;
    auto subs = command_tree_.ListSubcommands(ctx.command_path);
    for (const auto &item : subs) {
      if (!prefix.empty() && item.first.rfind(prefix, 0) != 0) {
        continue;
      }
      items.push_back({item.first, item.second});
    }
    if (items.empty()) {
      return;
    }
    size_t max_len = 0;
    for (const auto &item : items) {
      max_len = std::max(max_len, item.name.size());
    }
    for (const auto &item : items) {
      AMCompleteEngine::CompletionCandidate cand;
      cand.insert_text = item.name;
      cand.display = FormatCommandDisplay_(item.name, "command", max_len);
      cand.help = item.help;
      cand.kind = AMCompleteEngine::CompletionKind::Command;
      out.push_back(std::move(cand));
    }
    return;
  }

  if (ctx.target == AMCompleteEngine::CompletionTarget::LongOption) {
    auto longs = command_tree_.ListLongOptions(ctx.command_path);
    for (const auto &item : longs) {
      if (!prefix.empty() && item.first.rfind(prefix, 0) != 0) {
        continue;
      }
      AMCompleteEngine::CompletionCandidate cand;
      cand.insert_text = item.first;
      cand.display = item.first;
      cand.help = item.second;
      cand.kind = AMCompleteEngine::CompletionKind::Option;
      out.push_back(std::move(cand));
    }
    return;
  }

  if (ctx.target == AMCompleteEngine::CompletionTarget::ShortOption) {
    auto shorts = command_tree_.ListShortOptions(ctx.command_path);
    for (const auto &item : shorts) {
      const std::string name = std::string("-") + item.first;
      if (!prefix.empty() && name.rfind(prefix, 0) != 0) {
        continue;
      }
      AMCompleteEngine::CompletionCandidate cand;
      cand.insert_text = name;
      cand.display = name;
      cand.help = item.second;
      cand.kind = AMCompleteEngine::CompletionKind::Option;
      out.push_back(std::move(cand));
    }
  }
}

/**
 * @brief Collect internal candidates (vars, hosts, clients, tasks).
 */
void AMCompleteSources::CollectInternalCandidates_(
    const AMCompleteEngine::CompletionContext &ctx,
    std::vector<AMCompleteEngine::CompletionCandidate> &out) {
  const std::string prefix = ctx.token_prefix;

  if (ctx.target == AMCompleteEngine::CompletionTarget::VariableName) {
    AMVarManager &var_manager = AMVarManager::Instance(config_manager_);
    auto names = var_manager.ListNames();
    for (const auto &name : names) {
      const std::string full = "$" + name;
      if (!prefix.empty() && full.rfind(prefix, 0) != 0) {
        continue;
      }
      AMCompleteEngine::CompletionCandidate cand;
      cand.insert_text = full;
      cand.display = full;
      cand.kind = AMCompleteEngine::CompletionKind::VariableName;
      out.push_back(std::move(cand));
    }
    return;
  }

  if (ctx.target == AMCompleteEngine::CompletionTarget::ClientName) {
    auto names = client_manager_.GetClientNames();
    for (const auto &name : names) {
      if (!prefix.empty() && name.rfind(prefix, 0) != 0) {
        continue;
      }
      AMCompleteEngine::CompletionCandidate cand;
      cand.insert_text = name;
      cand.display = name;
      cand.kind = AMCompleteEngine::CompletionKind::ClientName;
      out.push_back(std::move(cand));
    }
    return;
  }

  if (ctx.target == AMCompleteEngine::CompletionTarget::HostNickname) {
    auto names = config_manager_.ListHostnames();
    for (const auto &name : names) {
      if (!prefix.empty() && name.rfind(prefix, 0) != 0) {
        continue;
      }
      AMCompleteEngine::CompletionCandidate cand;
      cand.insert_text = name;
      cand.display = name;
      cand.kind = AMCompleteEngine::CompletionKind::HostNickname;
      out.push_back(std::move(cand));
    }
    return;
  }

  if (ctx.target == AMCompleteEngine::CompletionTarget::HostAttr) {
    for (const auto &field : kHostConfigFields) {
      if (!prefix.empty() && field.rfind(prefix, 0) != 0) {
        continue;
      }
      AMCompleteEngine::CompletionCandidate cand;
      cand.insert_text = field;
      cand.display = field;
      cand.kind = AMCompleteEngine::CompletionKind::HostAttr;
      out.push_back(std::move(cand));
    }
    return;
  }

  if (ctx.target == AMCompleteEngine::CompletionTarget::TaskId) {
    auto ids = transfer_manager_.ListTaskIds();
    for (const auto &id : ids) {
      if (!prefix.empty() && id.rfind(prefix, 0) != 0) {
        continue;
      }
      AMCompleteEngine::CompletionCandidate cand;
      cand.insert_text = id;
      cand.display = id;
      cand.kind = AMCompleteEngine::CompletionKind::TaskId;
      out.push_back(std::move(cand));
    }
  }
}

/**
 * @brief Build a styled and padded command/module display string.
 */
std::string AMCompleteSources::FormatCommandDisplay_(
    const std::string &name, const std::string &style_key,
    size_t pad_width) const {
  const auto &args = engine_->GetArgs();
  const std::string tag = style_key == "module" ? args.input_tag_module
                                                 : args.input_tag_command;
  const std::string escaped = EscapeBbcodeText_(name);
  std::string display = tag.empty() ? escaped : tag + escaped + "[/]";
  if (pad_width > name.size()) {
    display.append(pad_width - name.size(), ' ');
  }
  return display;
}

/**
 * @brief Style a path entry for display.
 */
std::string AMCompleteSources::FormatPathDisplay_(const PathInfo &info,
                                                  const std::string &name) const {
  auto wrap_pre = [&](const std::string &styled,
                      const std::string &raw) -> std::string {
    if (styled == raw) {
      return styled;
    }
    if (raw.empty()) {
      return styled;
    }
    if (styled.find("[/") == std::string::npos) {
      return styled;
    }
    const size_t pos = styled.find(raw);
    if (pos == std::string::npos) {
      return styled;
    }
    std::string result = styled;
    result.replace(pos, raw.size(), "[!pre]" + raw + "[/pre]");
    return result;
  };

  switch (info.type) {
  case PathType::DIR: {
    const std::string styled = filesystem_.StylePath(info, name);
    return wrap_pre(styled, name);
  }
  case PathType::SYMLINK: {
    const std::string styled = filesystem_.StylePath(info, name);
    return wrap_pre(styled, name);
  }
  case PathType::FILE: {
    const std::string styled = filesystem_.StylePath(info, name);
    return wrap_pre(styled, name);
  }
  default: {
    const std::string styled = filesystem_.StylePath(info, name);
    return wrap_pre(styled, name);
  }
  }
}

/**
 * @brief Filter and append path candidates from a list.
 */
void AMCompleteSources::AppendPathCandidates_(
    const AMCompleteEngine::CompletionContext &ctx,
    const std::vector<PathInfo> &items,
    std::vector<AMCompleteEngine::CompletionCandidate> &out) {
  const std::string &prefix = ctx.path.leaf_prefix;
  bool has_case_match = false;
  if (!prefix.empty()) {
    for (const auto &info : items) {
      if (info.name.rfind(prefix, 0) == 0) {
        has_case_match = true;
        break;
      }
    }
  }

  const std::string prefix_lower =
      prefix.empty() ? std::string() : AMStr::lowercase(prefix);

  for (const auto &info : items) {
    std::string name = info.name;
    if (!prefix.empty()) {
      if (has_case_match) {
        if (name.rfind(prefix, 0) != 0) {
          continue;
        }
      } else {
        if (AMStr::lowercase(name).rfind(prefix_lower, 0) != 0) {
          continue;
        }
      }
    }
    AMCompleteEngine::CompletionCandidate cand;
    const bool is_dir = info.type == PathType::DIR;
    cand.insert_text = ctx.path.base + name;
    if (is_dir) {
      cand.insert_text.push_back(ctx.path.sep);
    }
    const std::string display_name = is_dir ? name + ctx.path.sep : name;
    cand.display = FormatPathDisplay_(info, display_name);
    cand.kind = ctx.path.remote ? AMCompleteEngine::CompletionKind::PathRemote
                                : AMCompleteEngine::CompletionKind::PathLocal;
    cand.path_type = info.type;
    out.push_back(std::move(cand));
  }
}

/**
 * @brief Lookup cache entries for a path key.
 */
bool AMCompleteSources::LookupCache_(const CacheKey &key,
                                    std::vector<PathInfo> *items) {
  std::lock_guard<std::mutex> lock(cache_mtx_);
  auto it = cache_.find(key);
  if (it == cache_.end()) {
    return false;
  }
  if (items) {
    *items = it->second.items;
  }
  return true;
}

/**
 * @brief Store cache entries and prune if needed.
 */
void AMCompleteSources::StoreCache_(const CacheKey &key,
                                   const std::vector<PathInfo> &items) {
  std::lock_guard<std::mutex> lock(cache_mtx_);
  cache_[key] = CacheEntry{items, std::chrono::steady_clock::now()};
  const size_t max_entries = engine_->GetArgs().cache_max_entries;
  if (cache_.size() <= max_entries) {
    return;
  }
  while (cache_.size() > max_entries) {
    auto oldest = cache_.begin();
    for (auto it = cache_.begin(); it != cache_.end(); ++it) {
      if (it->second.timestamp < oldest->second.timestamp) {
        oldest = it;
      }
    }
    cache_.erase(oldest);
  }
}

/**
 * @brief Attempt to use async results for the current request.
 */
bool AMCompleteSources::TryConsumeAsyncResult_(
    const AMCompleteEngine::CompletionContext &ctx,
    std::vector<PathInfo> *items) {
  std::lock_guard<std::mutex> lock(async_result_mtx_);
  if (!async_result_ || async_result_->request_id != ctx.request_id) {
    return false;
  }
  if (async_result_->key.nickname != ctx.path.nickname ||
      async_result_->key.dir != ctx.path.dir_abs ||
      async_result_->base != ctx.path.base ||
      async_result_->leaf_prefix != ctx.path.leaf_prefix ||
      async_result_->sep != ctx.path.sep) {
    return false;
  }
  if (items) {
    *items = async_result_->items;
  }
  async_result_.reset();
  return true;
}

/**
 * @brief Collect path candidates.
 */
void AMCompleteSources::CollectPathCandidates_(
    const AMCompleteEngine::CompletionContext &ctx,
    std::vector<AMCompleteEngine::CompletionCandidate> &out) {
  if (!ctx.path.valid) {
    return;
  }

  CacheKey key{ctx.path.nickname, ctx.path.dir_abs};
  std::vector<PathInfo> items;
  if (ctx.path.remote) {
    if (LookupCache_(key, &items)) {
      AppendPathCandidates_(ctx, items, out);
      return;
    }
    if (TryConsumeAsyncResult_(ctx, &items)) {
      const size_t cache_min = engine_->GetArgs().cache_min_items;
      if (items.size() >= cache_min) {
        StoreCache_(key, items);
      }
      AppendPathCandidates_(ctx, items, out);
      return;
    }
    ScheduleAsyncRequest_(ctx);
    return;
  }

  if (LookupCache_(key, &items)) {
    AppendPathCandidates_(ctx, items, out);
    return;
  }

  auto client = client_manager_.LocalClientBase();
  if (!client) {
    return;
  }
  const int timeout_ms = config_manager_.ResolveArg<int>(
      DocumentKind::Settings, {"CompleteOption", "timeout_ms"}, 5000,
      [](int v) { return v > 0 ? v : 5000; });
  auto [rcm, listed] =
      client->listdir(ctx.path.dir_abs, nullptr, timeout_ms, am_ms());
  if (rcm.first != EC::Success) {
    return;
  }
  const size_t cache_min = engine_->GetArgs().cache_min_items;
  if (listed.size() >= cache_min) {
    StoreCache_(key, listed);
  }
  AppendPathCandidates_(ctx, listed, out);
}

/**
 * @brief Schedule a remote async completion request.
 */
void AMCompleteSources::ScheduleAsyncRequest_(
    const AMCompleteEngine::CompletionContext &ctx) {
  AMCompleteEngine::AsyncRequest req;
  req.request_id = ctx.request_id;
  req.cancel_token = std::make_shared<std::atomic<bool>>(false);

  const uint64_t request_id = ctx.request_id;
  const std::string nickname = ctx.path.nickname;
  const std::string dir_abs = ctx.path.dir_abs;
  const std::string base = ctx.path.base;
  const std::string leaf_prefix = ctx.path.leaf_prefix;
  const char sep = ctx.path.sep;
  const bool remote = ctx.path.remote;

  req.search = [this, request_id, nickname, dir_abs, base, leaf_prefix, sep,
                remote](AMCompleteEngine::AsyncResult *out) -> bool {
    auto client = client_manager_.Clients().GetHost(nickname);
    if (!client) {
      return false;
    }
    const int timeout_ms = config_manager_.ResolveArg<int>(
        DocumentKind::Settings, {"CompleteOption", "timeout_ms"}, 5000,
        [](int v) { return v > 0 ? v : 5000; });
    auto [rcm, listed] =
        client->listdir(dir_abs, nullptr, timeout_ms, am_ms());
    if (rcm.first != EC::Success) {
      return false;
    }
    if (out) {
      out->request_id = request_id;
      out->nickname = nickname;
      out->dir = dir_abs;
      out->base = base;
      out->leaf_prefix = leaf_prefix;
      out->sep = sep;
      out->remote = remote;
      out->items = std::move(listed);
    }
    return true;
  };

  {
    std::lock_guard<std::mutex> lock(async_mtx_);
    pending_request_ = req;
  }
  async_cv_.notify_all();
}

/**
 * @brief Start the async worker thread.
 */
void AMCompleteSources::StartAsyncWorker() {
  async_stop_.store(false, std::memory_order_relaxed);
  async_thread_ = std::thread([this]() { AsyncWorkerLoop_(); });
}

/**
 * @brief Stop the async worker thread.
 */
void AMCompleteSources::StopAsyncWorker() {
  async_stop_.store(true, std::memory_order_relaxed);
  async_cv_.notify_all();
  if (async_thread_.joinable()) {
    async_thread_.join();
  }
}

/**
 * @brief Run the async worker loop.
 */
void AMCompleteSources::AsyncWorkerLoop_() {
  while (true) {
    AMCompleteEngine::AsyncRequest request;
    {
      std::unique_lock<std::mutex> lock(async_mtx_);
      async_cv_.wait(lock, [this]() {
        return async_stop_.load(std::memory_order_relaxed) ||
               pending_request_.has_value();
      });
      if (async_stop_.load(std::memory_order_relaxed)) {
        break;
      }
      request = *pending_request_;
      pending_request_.reset();

      const int delay_ms = engine_->GetArgs().complete_delay_ms;
      if (delay_ms > 0) {
        auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::milliseconds(delay_ms);
        while (!async_stop_.load(std::memory_order_relaxed)) {
          if (async_cv_.wait_until(lock, deadline, [this]() {
                return async_stop_.load(std::memory_order_relaxed) ||
                       pending_request_.has_value();
              })) {
            if (async_stop_.load(std::memory_order_relaxed)) {
              break;
            }
            request = *pending_request_;
            pending_request_.reset();
            deadline = std::chrono::steady_clock::now() +
                       std::chrono::milliseconds(delay_ms);
            continue;
          }
          break;
        }
      }
      if (async_stop_.load(std::memory_order_relaxed)) {
        break;
      }
    }

    if (request.request_id != engine_->CurrentRequestId()) {
      continue;
    }

    if (!request.search) {
      continue;
    }
    AMCompleteEngine::AsyncResult result;
    if (!request.search(&result)) {
      continue;
    }
    result.request_id = request.request_id;

    {
      std::lock_guard<std::mutex> lock(async_result_mtx_);
      async_result_ = AsyncResult{result.request_id,
                                  {result.nickname, result.dir},
                                  result.base,
                                  result.leaf_prefix,
                                  result.sep,
                                  result.remote,
                                  std::move(result.items)};
    }

    if (request.request_id != engine_->CurrentRequestId()) {
      continue;
    }

    /* Completion menu is opened explicitly via Tab; do not auto-open here. */
  }
}

/**
 * @brief Construct and build the command tree.
 */
AMCompleteSources::CommandTree::CommandTree() { Build(); }

/**
 * @brief Return true when name is a top-level command.
 */
bool AMCompleteSources::CommandTree::IsTopCommand(
    const std::string &name) const {
  return top_commands_.find(name) != top_commands_.end();
}

/**
 * @brief Return true when name is a module (has subcommands).
 */
bool AMCompleteSources::CommandTree::IsModule(const std::string &name) const {
  return modules_.find(name) != modules_.end();
}

/**
 * @brief Find a node by its command path.
 */
const AMCompleteEngine::CommandNode *
AMCompleteSources::CommandTree::FindNode(const std::string &path) const {
  auto it = nodes_.find(path);
  if (it == nodes_.end()) {
    return nullptr;
  }
  return &it->second;
}

/**
 * @brief List top-level commands with help text.
 */
std::vector<std::pair<std::string, std::string>>
AMCompleteSources::CommandTree::ListTopCommands() const {
  std::vector<std::pair<std::string, std::string>> out;
  out.reserve(top_commands_.size());
  for (const auto &item : top_commands_) {
    auto it = top_help_.find(item);
    out.emplace_back(item, it == top_help_.end() ? "" : it->second);
  }
  std::sort(out.begin(), out.end(),
            [](const auto &a, const auto &b) { return a.first < b.first; });
  return out;
}

/**
 * @brief List subcommands for a command path.
 */
std::vector<std::pair<std::string, std::string>>
AMCompleteSources::CommandTree::ListSubcommands(const std::string &path) const {
  std::vector<std::pair<std::string, std::string>> out;
  const auto *node = FindNode(path);
  if (!node) {
    return out;
  }
  out.reserve(node->subcommands.size());
  for (const auto &item : node->subcommands) {
    out.emplace_back(item.first, item.second);
  }
  std::sort(out.begin(), out.end(),
            [](const auto &a, const auto &b) { return a.first < b.first; });
  return out;
}

/**
 * @brief List long options for a command path.
 */
std::vector<std::pair<std::string, std::string>>
AMCompleteSources::CommandTree::ListLongOptions(const std::string &path) const {
  std::vector<std::pair<std::string, std::string>> out;
  const auto *node = FindNode(path);
  if (!node) {
    return out;
  }
  out.reserve(node->long_options.size());
  for (const auto &item : node->long_options) {
    out.emplace_back(item.first, item.second);
  }
  std::sort(out.begin(), out.end(),
            [](const auto &a, const auto &b) { return a.first < b.first; });
  return out;
}

/**
 * @brief List short options for a command path.
 */
std::vector<std::pair<char, std::string>>
AMCompleteSources::CommandTree::ListShortOptions(const std::string &path) const {
  std::vector<std::pair<char, std::string>> out;
  const auto *node = FindNode(path);
  if (!node) {
    return out;
  }
  out.reserve(node->short_options.size());
  for (const auto &item : node->short_options) {
    out.emplace_back(item.first, item.second);
  }
  std::sort(out.begin(), out.end(),
            [](const auto &a, const auto &b) { return a.first < b.first; });
  return out;
}

/**
 * @brief Build the command tree from CLI metadata.
 */
void AMCompleteSources::CommandTree::Build() {
  CLI::App app;
  CliArgsPool args_pool;
  (void)BindCliOptions(app, args_pool);

  auto build_node = [&](auto &&self, CLI::App *node,
                        const std::string &path) -> void {
    AMCompleteEngine::CommandNode info;
    auto options = node->get_options();
    for (auto *opt : options) {
      const std::string desc = opt ? opt->get_description() : "";
      for (const auto &lname : opt->get_lnames()) {
        if (!lname.empty()) {
          info.long_options["--" + lname] = desc;
        }
      }
      for (const auto &sname : opt->get_snames()) {
        if (!sname.empty()) {
          info.short_options[sname[0]] = desc;
        }
      }
    }

    auto subs = node->get_subcommands([](CLI::App *) { return true; });
    for (auto *sub : subs) {
      if (sub) {
        info.subcommands[sub->get_name()] = sub->get_description();
      }
    }

    nodes_[path] = info;
    if (path.find(' ') == std::string::npos && !info.subcommands.empty()) {
      modules_.insert(path);
    }

    for (auto *sub : subs) {
      if (!sub) {
        continue;
      }
      const std::string next =
          path.empty() ? sub->get_name() : path + " " + sub->get_name();
      self(self, sub, next);
    }
  };

  auto subs = app.get_subcommands([](CLI::App *) { return true; });
  for (auto *sub : subs) {
    if (!sub) {
      continue;
    }
    const std::string name = sub->get_name();
    RegisterCommand_(name, sub->get_description());
    build_node(build_node, sub, name);
  }
}

/**
 * @brief Merge command metadata into a node.
 */
void AMCompleteSources::CommandTree::MergeCommand_(
    const std::string &path, const std::string &help,
    const std::vector<std::string> &commands,
    const std::vector<std::string> &long_opts,
    const std::vector<std::string> &short_opts) {
  AMCompleteEngine::CommandNode &node = nodes_[path];
  for (const auto &cmd : commands) {
    if (!cmd.empty()) {
      node.subcommands[cmd] = help;
    }
  }
  for (const auto &opt : long_opts) {
    if (!opt.empty()) {
      node.long_options[opt] = help;
    }
  }
  for (const auto &opt : short_opts) {
    if (!opt.empty()) {
      node.short_options[opt[0]] = help;
    }
  }
}

/**
 * @brief Register a command path as a top-level command.
 */
void AMCompleteSources::CommandTree::RegisterCommand_(
    const std::string &path, const std::string &help) {
  if (path.empty()) {
    return;
  }
  top_commands_.insert(path);
  if (!help.empty()) {
    top_help_[path] = help;
  }
}
