#include "AMCLI/CompleteEngine.hpp"
#include "AMCLI/CompleteSources.hpp"
#include "AMBase/CommonTools.hpp"
#include "AMBase/Path.hpp"
#include "AMManager/Client.hpp"
#include "Isocline/isocline.h"
#include <algorithm>
#include <cctype>

namespace {
/**
 * @brief Return true if character is a quote.
 */
bool IsQuoteChar(char c) { return c == '"' || c == '\''; }

/**
 * @brief Unescape backtick-escaped sequences.
 */
std::string UnescapeBackticks(const std::string &text) {
  if (text.empty()) {
    return text;
  }
  std::string out;
  out.reserve(text.size());
  for (size_t i = 0; i < text.size(); ++i) {
    if (text[i] == '`' && i + 1 < text.size()) {
      const char next = text[i + 1];
      if (next == '$' || next == '"' || next == '\'' || next == '`') {
        out.push_back(next);
        ++i;
        continue;
      }
    }
    out.push_back(text[i]);
  }
  return out;
}

/**
 * @brief Return true if string begins with an unescaped '$'.
 */
bool StartsWithUnescapedDollar(const std::string &raw_prefix,
                               const std::string &raw_token) {
  const std::string &text = raw_prefix.empty() ? raw_token : raw_prefix;
  if (text.size() >= 2 && text[0] == '`' && text[1] == '$') {
    return false;
  }
  return !text.empty() && text[0] == '$';
}

/**
 * @brief Return true if string begins with "--".
 */
bool StartsWithLongOption(const std::string &text) {
  return text.size() >= 2 && text[0] == '-' && text[1] == '-';
}

/**
 * @brief Return true if string begins with "-" but not "--".
 */
bool StartsWithShortOption(const std::string &text) {
  return text.size() >= 1 && text[0] == '-' &&
         !(text.size() >= 2 && text[1] == '-');
}

/**
 * @brief Return true if text looks like a path input.
 */
bool IsPathLikeText(const std::string &text) {
  if (text.empty()) {
    return false;
  }
  if (text[0] == '/' || text[0] == '\\') {
    return true;
  }
  if (text[0] == '~') {
    return true;
  }
  if (text.size() >= 2 && std::isalpha(static_cast<unsigned char>(text[0])) &&
      text[1] == ':') {
    return true;
  }
  if (text.find('/') != std::string::npos ||
      text.find('\\') != std::string::npos) {
    return true;
  }
  return false;
}

/**
 * @brief Return true if a command expects path input at the given arg index.
 */
bool IsPathArgumentCommand(const std::string &command_path, size_t arg_index) {
  if (command_path == "cd" || command_path == "ls" ||
      command_path == "realpath") {
    return arg_index == 0;
  }
  if (command_path == "find" || command_path == "walk" ||
      command_path == "tree") {
    return arg_index == 0;
  }
  if (command_path == "stat" || command_path == "size" ||
      command_path == "mkdir" || command_path == "rm" ||
      command_path == "cp") {
    return true;
  }
  return false;
}

/**
 * @brief Detect path separator for completion output.
 */
char DetectPathSep(const std::string &path, bool remote) {
  (void)path;
  (void)remote;
  return '/';
}

/**
 * @brief Split path into directory and leaf prefix components.
 */
void SplitPath(const std::string &path, std::string *dir, std::string *leaf,
               bool *trailing_sep) {
  if (dir) {
    dir->clear();
  }
  if (leaf) {
    leaf->clear();
  }
  if (trailing_sep) {
    *trailing_sep = false;
  }
  if (path.empty()) {
    return;
  }

  const size_t last_sep = path.find_last_of("/\\");
  if (last_sep == std::string::npos) {
    if (leaf) {
      *leaf = path;
    }
    return;
  }

  if (dir) {
    *dir = path.substr(0, last_sep + 1);
  }
  if (leaf) {
    if (last_sep + 1 < path.size()) {
      *leaf = path.substr(last_sep + 1);
    }
  }
  if (trailing_sep) {
    *trailing_sep = (last_sep + 1 == path.size());
  }
}

/**
 * @brief Order path types per completion sorting rules.
 */
int PathTypeOrder(PathType type) {
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

/**
 * @brief Return true when candidate is a path type.
 */
bool IsPathCandidate(AMCompleteEngine::CompletionKind kind) {
  return kind == AMCompleteEngine::CompletionKind::PathLocal ||
         kind == AMCompleteEngine::CompletionKind::PathRemote;
}
} // namespace

/**
 * @brief Tokenize input into completion tokens.
 */
std::vector<AMCompleteEngine::CompletionToken>
AMCompleteEngine::TokenizeInput_(const std::string &input) const {
  std::vector<CompletionToken> tokens;
  size_t i = 0;
  while (i < input.size()) {
    while (i < input.size() &&
           std::isspace(static_cast<unsigned char>(input[i])) != 0) {
      ++i;
    }
    if (i >= input.size()) {
      break;
    }
    const size_t start = i;
    if (IsQuoteChar(input[i])) {
      const char quote = input[i];
      ++i;
      const size_t content_start = i;
      while (i < input.size()) {
        if (input[i] == '`' && i + 1 < input.size() && input[i + 1] == quote) {
          i += 2;
          continue;
        }
        if (input[i] == quote) {
          break;
        }
        ++i;
      }
      const size_t content_end = i;
      if (i < input.size() && input[i] == quote) {
        ++i;
      }
      const size_t end = i;
      tokens.push_back({start, end, content_start, content_end, true});
      continue;
    }
    while (i < input.size() &&
           std::isspace(static_cast<unsigned char>(input[i])) == 0) {
      ++i;
    }
    const size_t end = i;
    tokens.push_back({start, end, start, end, false});
  }
  return tokens;
}

/**
 * @brief Find the token that owns the cursor.
 */
bool AMCompleteEngine::FindTokenAtCursor_(
    const std::vector<CompletionToken> &tokens, size_t cursor,
    CompletionToken *out, size_t *out_index) const {
  for (size_t i = 0; i < tokens.size(); ++i) {
    const auto &tok = tokens[i];
    const size_t begin = tok.quoted ? tok.content_start : tok.start;
    const size_t end = tok.quoted ? tok.content_end : tok.end;
    if (cursor >= begin && cursor <= end) {
      if (out) {
        *out = tok;
      }
      if (out_index) {
        *out_index = i;
      }
      return true;
    }
  }
  return false;
}

/**
 * @brief Parse the command path from tokens before the cursor.
 */
void AMCompleteEngine::ParseCommandPath_(
    const std::vector<CompletionToken> &tokens, const std::string &input,
    size_t current_index, std::string *out_path, const CommandNode **out_node,
    size_t *out_consumed) const {
  std::string path;
  const CommandNode *node = nullptr;
  size_t consumed = 0;

  for (size_t i = 0; i < tokens.size() && i < current_index; ++i) {
    const auto &token = tokens[i];
    if (token.quoted) {
      break;
    }
    if (token.content_end <= token.content_start) {
      break;
    }
    const std::string raw =
        input.substr(token.content_start, token.content_end - token.content_start);
    const std::string text = UnescapeBackticks(raw);
    if (text.empty()) {
      break;
    }

    if (path.empty()) {
      if (sources_ && sources_->IsModule(text)) {
        path = text;
        node = sources_->FindNode(path);
        consumed = i + 1;
        continue;
      }
      if (sources_ && sources_->IsTopCommand(text)) {
        path = text;
        node = sources_->FindNode(path);
        consumed = i + 1;
        continue;
      }
      break;
    }

    if (node && node->subcommands.find(text) != node->subcommands.end()) {
      path += " " + text;
      node = sources_ ? sources_->FindNode(path) : nullptr;
      consumed = i + 1;
      continue;
    }
    break;
  }

  if (out_path) {
    *out_path = path;
  }
  if (out_node) {
    *out_node = node;
  }
  if (out_consumed) {
    *out_consumed = consumed;
  }
}

/**
 * @brief Compute positional argument index for the current token.
 */
size_t AMCompleteEngine::ComputeArgIndex_(
    const std::vector<CompletionToken> &tokens, const std::string &input,
    size_t command_tokens, size_t current_index) const {
  size_t index = 0;
  for (size_t i = command_tokens; i < tokens.size() && i < current_index; ++i) {
    const auto &token = tokens[i];
    if (token.content_end <= token.content_start) {
      continue;
    }
    const std::string raw =
        input.substr(token.content_start, token.content_end - token.content_start);
    const std::string text = UnescapeBackticks(raw);
    if (StartsWithLongOption(text) || StartsWithShortOption(text)) {
      continue;
    }
    index++;
  }
  return index;
}

/**
 * @brief Build the completion context for the current input.
 */
AMCompleteEngine::CompletionContext
AMCompleteEngine::BuildContext_(const CompletionRequest &request) const {
  CompletionContext ctx;
  ctx.input = request.input;
  ctx.cursor = request.cursor;
  ctx.request_id = request.request_id;

  const std::string &input = request.input;
  const size_t cursor = request.cursor;
  std::string trimmed = AMStr::Strip(input);
  if (!trimmed.empty() && trimmed.front() == '!') {
    ctx.target = CompletionTarget::Disabled;
    return ctx;
  }

  std::vector<CompletionToken> tokens = TokenizeInput_(input);
  CompletionToken token;
  size_t token_index = tokens.size();
  ctx.has_token = FindTokenAtCursor_(tokens, cursor, &token, &token_index);
  if (!ctx.has_token) {
    token = {cursor, cursor, cursor, cursor, false};
  }
  ctx.token = token;
  ctx.token_quoted = token.quoted;

  if (token.content_end >= token.content_start &&
      token.content_end <= input.size() &&
      token.content_start <= input.size()) {
    ctx.token_raw =
        input.substr(token.content_start, token.content_end - token.content_start);
  }
  if (cursor >= token.content_start && cursor <= token.content_end &&
      token.content_start <= input.size()) {
    ctx.token_prefix_raw =
        input.substr(token.content_start, cursor - token.content_start);
  }
  ctx.token_text = UnescapeBackticks(ctx.token_raw);
  ctx.token_prefix = UnescapeBackticks(ctx.token_prefix_raw);

  const CommandNode *node = nullptr;
  size_t command_tokens = 0;
  ParseCommandPath_(tokens, input, token_index, &ctx.command_path, &node,
                    &command_tokens);
  ctx.command_node = node;
  ctx.command_tokens = command_tokens;
  ctx.arg_index = ComputeArgIndex_(tokens, input, command_tokens, token_index);

  if (ctx.command_path.empty()) {
    if (token_index == 0 || tokens.empty()) {
      ctx.target = CompletionTarget::TopCommand;
    } else {
      ctx.target = CompletionTarget::None;
    }
    return ctx;
  }

  if (node && !node->subcommands.empty() && token_index == command_tokens) {
    ctx.target = CompletionTarget::Subcommand;
    return ctx;
  }

  if (StartsWithUnescapedDollar(ctx.token_prefix_raw, ctx.token_raw)) {
    ctx.target = CompletionTarget::VariableName;
    return ctx;
  }

  if (StartsWithLongOption(ctx.token_prefix)) {
    ctx.target = CompletionTarget::LongOption;
    return ctx;
  }
  if (StartsWithShortOption(ctx.token_prefix)) {
    ctx.target = CompletionTarget::ShortOption;
    return ctx;
  }

  if (ctx.command_path == "config get" || ctx.command_path == "config edit" ||
      ctx.command_path == "config rm") {
    ctx.target = CompletionTarget::HostNickname;
    return ctx;
  }
  if (ctx.command_path == "config rn") {
    if (ctx.arg_index == 0) {
      ctx.target = CompletionTarget::HostNickname;
      return ctx;
    }
  }
  if (ctx.command_path == "config set") {
    if (ctx.arg_index == 0) {
      ctx.target = CompletionTarget::HostNickname;
      return ctx;
    }
    if (ctx.arg_index == 1) {
      ctx.target = CompletionTarget::HostAttr;
      return ctx;
    }
  }
  if (ctx.command_path == "connect") {
    if (ctx.arg_index == 0) {
      ctx.target = CompletionTarget::HostNickname;
      return ctx;
    }
  }
  if (ctx.command_path == "client check" || ctx.command_path == "client rm") {
    ctx.target = CompletionTarget::ClientName;
    return ctx;
  }
  if (ctx.command_path == "ch") {
    if (ctx.arg_index == 0) {
      ctx.target = CompletionTarget::ClientName;
      return ctx;
    }
  }
  if (ctx.command_path == "task show" || ctx.command_path == "task inspect" ||
      ctx.command_path == "task terminate" ||
      ctx.command_path == "task pause") {
    ctx.target = CompletionTarget::TaskId;
    return ctx;
  }
  if (ctx.command_path == "task retry" || ctx.command_path == "retry") {
    if (ctx.arg_index == 0) {
      ctx.target = CompletionTarget::TaskId;
      return ctx;
    }
  }

  if (IsPathArgumentCommand(ctx.command_path, ctx.arg_index)) {
    const std::string &text = ctx.token_prefix;
    const bool has_at = (text.find('@') != std::string::npos);
    if (text.empty()) {
      ctx.path = BuildPathContext_(ctx, true);
      if (ctx.path.valid) {
        ctx.target = CompletionTarget::Path;
        return ctx;
      }
      ctx.target = CompletionTarget::None;
      return ctx;
    }
    if (has_at) {
      ctx.path = BuildPathContext_(ctx, true);
      if (ctx.path.valid) {
        ctx.target = CompletionTarget::Path;
      } else {
        ctx.target = CompletionTarget::None;
      }
      return ctx;
    }
    if (!IsPathLikeText(text)) {
      if (HasClientPrefixMatch_(text)) {
        ctx.target = CompletionTarget::ClientName;
        return ctx;
      }
      ctx.path = BuildPathContext_(ctx, true);
      if (ctx.path.valid) {
        ctx.target = CompletionTarget::Path;
        return ctx;
      }
      ctx.target = CompletionTarget::None;
      return ctx;
    }
    ctx.path = BuildPathContext_(ctx, true);
    if (ctx.path.valid) {
      ctx.target = CompletionTarget::Path;
      return ctx;
    }
    ctx.target = CompletionTarget::None;
    return ctx;
  }

  ctx.path = BuildPathContext_(ctx, false);
  if (ctx.path.valid) {
    ctx.target = CompletionTarget::Path;
    return ctx;
  }

  ctx.target = CompletionTarget::None;
  return ctx;
}

/**
 * @brief Build path-specific context from the token.
 */
AMCompleteEngine::PathContext
AMCompleteEngine::BuildPathContext_(const CompletionContext &ctx,
                                    bool force_path) const {
  PathContext path;
  const std::string text = ctx.token_prefix;
  if (text.empty() && !force_path) {
    return path;
  }

  const auto current_client =
      client_manager_.CurrentClient() ? client_manager_.CurrentClient()
                                      : client_manager_.LocalClientBase();
  const bool current_remote =
      current_client &&
      current_client->GetProtocol() != ClientProtocol::LOCAL;

  bool force_local = false;
  std::string nickname;
  std::string path_part;
  std::string header;

  if (!text.empty() && text.front() == '@') {
    force_local = true;
    nickname = "local";
    path_part = text.substr(1);
    header = "@";
  } else {
    const size_t at_pos = text.find('@');
    if (at_pos != std::string::npos) {
      nickname = text.substr(0, at_pos);
      path_part = text.substr(at_pos + 1);
      header = nickname + "@";
      if (nickname.empty() || AMStr::lowercase(nickname) == "local") {
        force_local = true;
        nickname = "local";
      }
    } else {
      path_part = text;
      if (current_remote && current_client) {
        nickname = current_client->GetNickname();
      } else {
        nickname = "local";
      }
    }
  }

  if (header.empty() && !force_path && !IsPathLikeText(path_part)) {
    return path;
  }

  path.remote = (!force_local && current_remote && header.empty()) ||
                (!force_local && !header.empty() &&
                 AMStr::lowercase(nickname) != "local");
  path.nickname = nickname.empty() ? "local" : nickname;
  path.header = header;
  path.raw_path = path_part;
  path.sep = DetectPathSep(path_part, path.remote);

  SplitPath(path_part, &path.dir_raw, &path.leaf_prefix, &path.trailing_sep);

  if (path_part.size() == 2 &&
      std::isalpha(static_cast<unsigned char>(path_part[0])) &&
      path_part[1] == ':') {
    path.dir_raw = path_part + path.sep;
    path.leaf_prefix.clear();
    path.trailing_sep = true;
  }

  path.base = path.header + path.dir_raw;

  std::shared_ptr<BaseClient> client;
  if (path.remote) {
    client = client_manager_.Clients().GetHost(path.nickname);
  } else {
    client = client_manager_.LocalClientBase();
  }
  if (!client) {
    return path;
  }

  path.dir_abs = client_manager_.BuildPath(client, path.dir_raw);
  path.valid = true;
  return path;
}

/**
 * @brief Dispatch completion requests to their sources.
 */
void AMCompleteEngine::DispatchCandidates_(
    const CompletionContext &ctx, std::vector<CompletionCandidate> &out) {
  if (!sources_) {
    return;
  }
  switch (ctx.target) {
  case CompletionTarget::TopCommand:
  case CompletionTarget::Subcommand:
  case CompletionTarget::LongOption:
  case CompletionTarget::ShortOption:
    sources_->CollectCommandCandidates_(ctx, out);
    break;
  case CompletionTarget::VariableName:
  case CompletionTarget::ClientName:
  case CompletionTarget::HostNickname:
  case CompletionTarget::HostAttr:
  case CompletionTarget::TaskId:
    sources_->CollectInternalCandidates_(ctx, out);
    break;
  case CompletionTarget::Path:
    sources_->CollectPathCandidates_(ctx, out);
    break;
  default:
    break;
  }
}

/**
 * @brief Sort candidates by prefix and path type rules.
 */
void AMCompleteEngine::SortCandidates_(
    std::vector<CompletionCandidate> &items) {
  std::stable_sort(
      items.begin(), items.end(),
      [](const CompletionCandidate &a, const CompletionCandidate &b) {
        if (a.score != b.score) {
          return a.score < b.score;
        }
        const bool a_path = IsPathCandidate(a.kind);
        const bool b_path = IsPathCandidate(b.kind);
        if (a_path && b_path) {
          const int ao = PathTypeOrder(a.path_type);
          const int bo = PathTypeOrder(b.path_type);
          if (ao != bo) {
            return ao < bo;
          }
        }
        return a.insert_text < b.insert_text;
      });
}

/**
 * @brief Emit candidates to isocline with delete ranges.
 */
void AMCompleteEngine::EmitCandidates_(
    ic_completion_env_t *cenv, const CompletionContext &ctx,
    const std::vector<CompletionCandidate> &items) {
  if (!cenv) {
    return;
  }
  long delete_before = 0;
  long delete_after = 0;
  if (ctx.has_token && ctx.cursor >= ctx.token.content_start &&
      ctx.cursor <= ctx.token.content_end) {
    delete_before = static_cast<long>(ctx.cursor - ctx.token.content_start);
    delete_after = static_cast<long>(ctx.token.content_end - ctx.cursor);
  }

  for (const auto &cand : items) {
    const char *display = cand.display.empty() ? nullptr : cand.display.c_str();
    const char *help = cand.help.empty() ? nullptr : cand.help.c_str();
    ic_add_completion_prim(cenv, cand.insert_text.c_str(), display, help,
                           delete_before, delete_after);
  }
}
