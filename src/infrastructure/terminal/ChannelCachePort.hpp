#pragma once

#include "domain/terminal/ChannelPort.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace AMInfra::terminal {
namespace AMT = AMDomain::terminal;

class ChannelCacheStore {

private:
  static constexpr size_t kSoftLimitBytes = 32U * 1024U * 1024U;
  static constexpr size_t kHardLimitBytes = 128U * 1024U * 1024U;
  static constexpr size_t kMaxEscapeTailBytes = 16U;

  struct TerminalCache_ {
    std::vector<AMT::OutputBlock> blocks = {};
    bool in_alternate_screen = false;
  };

  struct RuntimeState_ {
    TerminalCache_ cache = {};
    std::string pending_escape_tail = {};
    std::string latest_output = {};
    size_t cached_bytes = 0;

    bool attached = false;
    bool closed = false;
    bool soft_limit_hit = false;
    bool hard_limit_hit = false;

    std::uint64_t attach_epoch = 0;
    std::uint64_t soft_warn_epoch = 0;

    AMT::ChannelOutputProcessor consumer = {};
    ECM last_error = OK;
  };

  struct ScreenToggleMatch_ {
    bool matched = false;
    bool partial = false;
    bool to_alternate = false;
    size_t length = 0;
  };

  struct ParsedScreenChunk_ {
    std::vector<AMT::OutputBlock> blocks = {};
    bool in_alternate_screen = false;
    std::string pending_escape_tail = {};
    size_t appended_bytes = 0;
  };

public:
  explicit ChannelCacheStore(std::string channel_name)
      : channel_name_(std::move(channel_name)) {}

  ~ChannelCacheStore() { (void)DetachConsumer(); }

  [[nodiscard]] ECMData<AMT::ChannelCacheReplayResult>
  AttachConsumer(AMT::ChannelOutputProcessor processor) {
    ECMData<AMT::ChannelCacheReplayResult> out = {};
    if (!processor) {
      out.rcm = Err(ErrorCode::InvalidArg, "terminal.channel.attach",
                    channel_name_, "Output processor is empty");
      return out;
    }

    std::vector<AMT::OutputBlock> replay_blocks = {};
    std::string fallback_output = {};
    {
      std::lock_guard<std::mutex> lock(mutex_);
      ++state_.attach_epoch;
      replay_blocks = state_.cache.blocks;
      fallback_output = state_.latest_output;
      out.data.in_alternate_screen = state_.cache.in_alternate_screen;
      out.data.soft_limit_hit = state_.soft_limit_hit;
      out.data.hard_limit_hit = state_.hard_limit_hit;
      out.data.closed = state_.closed;
      out.data.last_error = state_.last_error;
      state_.attached = false;
      state_.consumer = {};
      if (state_.soft_limit_hit) {
        state_.soft_warn_epoch = state_.attach_epoch;
      }
    }

    std::string main_content = {};
    std::string latest_alt = {};
    for (auto const &block : replay_blocks) {
      if (block.data.empty()) {
        continue;
      }
      if (block.screen == AMT::ScreenKind::Main) {
        main_content.append(block.data);
      } else {
        latest_alt = block.data;
      }
    }

    if (!main_content.empty()) {
      try {
        processor(main_content);
      } catch (...) {
      }
      out.data.replayed_bytes += main_content.size();
    }
    if (out.data.in_alternate_screen) {
      try {
        processor("\x1b[?1049h");
      } catch (...) {
      }
      if (!latest_alt.empty()) {
        try {
          processor(latest_alt);
        } catch (...) {
        }
        out.data.replayed_bytes += latest_alt.size();
      }
    }

    if (out.data.replayed_bytes == 0 && !fallback_output.empty()) {
      try {
        processor(fallback_output);
      } catch (...) {
      }
      out.data.fallback_bytes = fallback_output.size();
    }

    {
      std::lock_guard<std::mutex> lock(mutex_);
      state_.attached = true;
      state_.consumer = std::move(processor);
    }

    out.rcm = OK;
    return out;
  }

  ECM DetachConsumer() {
    std::lock_guard<std::mutex> lock(mutex_);
    state_.attached = false;
    state_.consumer = {};
    return OK;
  }

  [[nodiscard]] AMT::ChannelPortState GetState() const {
    std::lock_guard<std::mutex> lock(mutex_);
    AMT::ChannelPortState out = {};
    out.attached = state_.attached;
    out.closed = state_.closed;
    out.in_alternate_screen = state_.cache.in_alternate_screen;
    out.soft_limit_hit = state_.soft_limit_hit;
    out.hard_limit_hit = state_.hard_limit_hit;
    out.cached_bytes = state_.cached_bytes;
    out.last_error = state_.last_error;
    return out;
  }

  [[nodiscard]] ECMData<AMT::ChannelCacheCopyResult>
  GetCacheCopy() const {
    ECMData<AMT::ChannelCacheCopyResult> out = {};
    std::lock_guard<std::mutex> lock(mutex_);
    out.data.blocks = state_.cache.blocks;
    out.data.in_alternate_screen = state_.cache.in_alternate_screen;
    out.data.latest_output = state_.latest_output;
    out.data.cached_bytes = state_.cached_bytes;
    out.rcm = OK;
    return out;
  }

  ECM ClearCache() {
    std::lock_guard<std::mutex> lock(mutex_);
    state_.cache.blocks.clear();
    state_.cache.in_alternate_screen = false;
    state_.pending_escape_tail.clear();
    state_.latest_output.clear();
    state_.cached_bytes = 0;
    state_.soft_limit_hit = false;
    state_.hard_limit_hit = false;
    state_.soft_warn_epoch = state_.attach_epoch;
    return OK;
  }

  [[nodiscard]] ECMData<AMT::ChannelCacheTruncateResult>
  TruncateCache(const AMT::ChannelCacheTruncateArgs &truncate_args) {
    ECMData<AMT::ChannelCacheTruncateResult> out = {};

    std::lock_guard<std::mutex> lock(mutex_);
    size_t const desired = truncate_args.desired_size;
    if (desired >= state_.cached_bytes) {
      out.data.cached_bytes = state_.cached_bytes;
      out.rcm = OK;
      return out;
    }

    size_t remove_bytes = state_.cached_bytes - desired;
    if (truncate_args.truncate_at_newline) {
      size_t const newline_cut =
          FindCutAtNextNewline_(state_.cache.blocks, remove_bytes);
      if (newline_cut > remove_bytes) {
        remove_bytes = newline_cut;
      }
    }

    if (remove_bytes > 0U) {
      RemovePrefixFromBlocks_(remove_bytes, &(state_.cache.blocks));
      out.data.removed_bytes = remove_bytes;
      out.data.truncated = true;
      state_.cached_bytes = state_.cached_bytes > remove_bytes
                                ? state_.cached_bytes - remove_bytes
                                : 0U;
      while (!state_.cache.blocks.empty() &&
             state_.cache.blocks.front().data.empty()) {
        state_.cache.blocks.erase(state_.cache.blocks.begin());
      }
      if (state_.cache.blocks.empty()) {
        state_.cache.in_alternate_screen = false;
      }
      if (state_.cached_bytes < kSoftLimitBytes) {
        state_.soft_limit_hit = false;
      }
      if (state_.cached_bytes < kHardLimitBytes) {
        state_.hard_limit_hit = false;
      }
    }

    out.data.cached_bytes = state_.cached_bytes;
    out.rcm = OK;
    return out;
  }

  [[nodiscard]] ECMData<AMT::ChannelReadWrappedResult>
  WrapReadResultFromRaw(ECMData<AMT::ChannelReadResult> const &read_result) {
    ECMData<AMT::ChannelReadWrappedResult> out = {};
    out.data.channel_name = channel_name_;

    if (!(read_result.rcm)) {
      std::lock_guard<std::mutex> lock(mutex_);
      state_.last_error = read_result.rcm;
      if (IsConnectionBrokenCode_(read_result.rcm.code)) {
        state_.closed = true;
      }
      out.data.eof = true;
      out.data.in_alternate_screen = state_.cache.in_alternate_screen;
      out.data.last_error = state_.last_error;
      out.rcm = read_result.rcm;
      return out;
    }

    out.data.output = read_result.data.output;
    out.data.eof = read_result.data.eof;

    AMT::ChannelOutputProcessor consumer = {};
    bool hard_limit_hit_now = false;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (!read_result.data.output.empty()) {
        state_.latest_output = read_result.data.output;
        auto parsed = ParseScreenChunk_(state_.cache.in_alternate_screen,
                                        state_.pending_escape_tail,
                                        read_result.data.output);
        state_.cache.in_alternate_screen = parsed.in_alternate_screen;
        state_.pending_escape_tail = std::move(parsed.pending_escape_tail);

        for (auto &block : parsed.blocks) {
          if (block.data.empty()) {
            continue;
          }
          if (!state_.cache.blocks.empty() &&
              state_.cache.blocks.back().screen == block.screen) {
            state_.cache.blocks.back().data.append(block.data);
          } else {
            state_.cache.blocks.push_back(std::move(block));
          }
        }

        state_.cached_bytes += parsed.appended_bytes;
        if (!state_.soft_limit_hit && state_.cached_bytes >= kSoftLimitBytes) {
          state_.soft_limit_hit = true;
          if (state_.soft_warn_epoch != state_.attach_epoch) {
            out.data.soft_limit_hit_now = true;
            state_.soft_warn_epoch = state_.attach_epoch;
          }
        }

        if (state_.cached_bytes >= kHardLimitBytes) {
          state_.hard_limit_hit = true;
          hard_limit_hit_now = true;
          state_.last_error = Err(ErrorCode::FilesystemNoSpace,
                                  "terminal.channel.cache.limit", channel_name_,
                                  "Terminal output cache hard limit exceeded "
                                  "(128MB); channel closed");
          state_.closed = true;
        }

        if (state_.attached && state_.consumer) {
          consumer = state_.consumer;
        }
      }

      if (read_result.data.eof) {
        state_.closed = true;
      }

      out.data.in_alternate_screen = state_.cache.in_alternate_screen;
      out.data.hard_limit_hit = state_.hard_limit_hit;
      out.data.last_error = state_.last_error;
    }

    if (!out.data.output.empty() && consumer) {
      try {
        consumer(out.data.output);
      } catch (...) {
      }
    }

    if (hard_limit_hit_now) {
      out.data.eof = true;
      out.data.hard_limit_hit = true;
      out.data.last_error = Err(
          ErrorCode::FilesystemNoSpace, "terminal.channel.cache.limit",
          channel_name_,
          "Terminal output cache hard limit exceeded (128MB); channel closed");
      out.rcm = out.data.last_error;
      return out;
    }

    out.rcm = OK;
    return out;
  }

  void MarkChannelClosed(ECM const &reason) {
    std::lock_guard<std::mutex> lock(mutex_);
    state_.closed = true;
    if (!(reason)) {
      state_.last_error = reason;
    }
  }

private:
  [[nodiscard]] static bool StartsWith_(std::string_view full,
                                        std::string_view prefix) {
    return full.size() >= prefix.size() &&
           full.compare(0, prefix.size(), prefix.data(), prefix.size()) == 0;
  }

  [[nodiscard]] static ScreenToggleMatch_
  TryMatchScreenToggle_(std::string_view data, size_t pos) {
    static constexpr std::array<std::pair<std::string_view, bool>, 6>
        kScreenToggles = {{{"\x1b[?1049h", true},
                           {"\x1b[?1049l", false},
                           {"\x1b[?1047h", true},
                           {"\x1b[?1047l", false},
                           {"\x1b[?47h", true},
                           {"\x1b[?47l", false}}};

    if (pos >= data.size() || data[pos] != '\x1b') {
      return {};
    }

    std::string_view const remain = data.substr(pos);
    ScreenToggleMatch_ out = {};
    for (auto const &entry : kScreenToggles) {
      std::string_view const seq = entry.first;
      if (remain.size() >= seq.size()) {
        if (remain.compare(0, seq.size(), seq.data(), seq.size()) == 0) {
          out.matched = true;
          out.to_alternate = entry.second;
          out.length = seq.size();
          return out;
        }
        continue;
      }
      if (StartsWith_(seq, remain)) {
        out.partial = true;
        return out;
      }
    }
    return out;
  }

  [[nodiscard]] static ParsedScreenChunk_
  ParseScreenChunk_(bool in_alternate_screen, std::string_view pending_tail,
                    std::string_view chunk) {
    ParsedScreenChunk_ out = {};
    out.in_alternate_screen = in_alternate_screen;

    std::string combined = {};
    combined.reserve(pending_tail.size() + chunk.size());
    combined.append(pending_tail.data(), pending_tail.size());
    combined.append(chunk.data(), chunk.size());
    std::string_view const data(combined);

    auto append_block = [&](AMT::ScreenKind screen,
                            std::string const &payload) {
      if (payload.empty()) {
        return;
      }
      if (!out.blocks.empty() && out.blocks.back().screen == screen) {
        out.blocks.back().data.append(payload);
      } else {
        out.blocks.push_back(AMT::OutputBlock{screen, payload});
      }
      out.appended_bytes += payload.size();
    };

    AMT::ScreenKind current_screen = out.in_alternate_screen
                                         ? AMT::ScreenKind::Alternate
                                         : AMT::ScreenKind::Main;
    std::string payload = {};
    payload.reserve(data.size());

    size_t i = 0;
    bool ended_with_partial = false;
    while (i < data.size()) {
      char const ch = data[i];
      if (ch != '\x1b') {
        payload.push_back(ch);
        ++i;
        continue;
      }

      ScreenToggleMatch_ const match = TryMatchScreenToggle_(data, i);
      if (match.partial) {
        ended_with_partial = true;
        break;
      }
      if (!match.matched) {
        payload.push_back(ch);
        ++i;
        continue;
      }

      append_block(current_screen, payload);
      payload.clear();
      out.in_alternate_screen = match.to_alternate;
      current_screen = out.in_alternate_screen ? AMT::ScreenKind::Alternate
                                               : AMT::ScreenKind::Main;
      i += match.length;
    }

    append_block(current_screen, payload);
    if (ended_with_partial) {
      size_t const tail_size = std::min(kMaxEscapeTailBytes, data.size() - i);
      out.pending_escape_tail.assign(data.substr(data.size() - tail_size));
    } else {
      out.pending_escape_tail.clear();
    }
    return out;
  }

  [[nodiscard]] static bool IsConnectionBrokenCode_(ErrorCode code) {
    return code == ErrorCode::NoConnection ||
           code == ErrorCode::ConnectionLost || code == ErrorCode::NoSession ||
           code == ErrorCode::ClientNotFound;
  }

  static void RemovePrefixFromBlocks_(size_t remove_bytes,
                                      std::vector<AMT::OutputBlock> *blocks) {
    if (!blocks || remove_bytes == 0U) {
      return;
    }
    size_t left = remove_bytes;
    for (auto it = blocks->begin(); it != blocks->end() && left > 0U;) {
      if (it->data.size() <= left) {
        left -= it->data.size();
        it = blocks->erase(it);
      } else {
        it->data.erase(0, left);
        left = 0U;
      }
    }
  }

  [[nodiscard]] static size_t
  FindCutAtNextNewline_(std::vector<AMT::OutputBlock> const &blocks,
                        size_t min_remove_bytes) {
    if (min_remove_bytes == 0U) {
      return 0U;
    }

    size_t scanned = 0U;
    for (auto const &block : blocks) {
      for (char c : block.data) {
        ++scanned;
        if (scanned < min_remove_bytes) {
          continue;
        }
        if (c == '\n') {
          return scanned;
        }
      }
    }
    return min_remove_bytes;
  }

  void SetChannelName(std::string channel_name) {
    std::lock_guard<std::mutex> lock(mutex_);
    channel_name_ = std::move(channel_name);
  }

private:
  std::string channel_name_ = {};

  mutable std::mutex mutex_ = {};
  RuntimeState_ state_ = {};
};

} // namespace AMInfra::terminal
