#pragma once

#include "domain/terminal/ChannelPort.hpp"
#include "foundation/tools/string.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifdef AMSFTP_VT_STATIC
#include "AmsVt.h"
#endif

namespace AMInfra::terminal {
namespace AMT = AMDomain::terminal;

class ChannelCacheStore {

private:
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

#ifdef AMSFTP_VT_STATIC
    AmsVtHandle *vt = nullptr;
    int vt_rows = 24;
    int vt_cols = 80;
#endif
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

#ifdef AMSFTP_VT_STATIC
  struct VtRenderCache_ {
    bool valid = false;
    uint64_t damage_serial = 0;
    uint64_t viewport_offset = 0;
    bool in_alternate_screen = false;
    std::string main_replay_ansi = {};
    std::string visible_frame_ansi = {};
  };
#endif

public:
  explicit ChannelCacheStore(
      std::string terminal_key, std::string channel_name,
      AMT::BufferExceedCallback buffer_exceed_callback = {},
      AMT::TerminalManagerArg terminal_manager_arg = {})
      : terminal_key_(std::move(terminal_key)),
        channel_name_(std::move(channel_name)),
        buffer_exceed_callback_(std::move(buffer_exceed_callback)),
        terminal_manager_arg_(std::move(terminal_manager_arg)) {
    AMT::NormalizeTerminalManagerArg(&terminal_manager_arg_);
  }

  ~ChannelCacheStore() {
    (void)DetachConsumer();
#ifdef AMSFTP_VT_STATIC
    std::lock_guard<std::mutex> lock(mutex_);
    ResetVtUnlocked_();
#endif
  }

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
    std::optional<std::string> vt_main_replay = std::nullopt;
    std::optional<std::string> vt_visible_frame = std::nullopt;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      ++state_.attach_epoch;
      replay_blocks = state_.cache.blocks;
      fallback_output = state_.latest_output;
      const AMT::ChannelVtSnapshot vt_snapshot = BuildVtSnapshotUnlocked_();
      auto vt_render_bundle = BuildVtRenderBundleUnlocked_(vt_snapshot);
      vt_main_replay = std::move(vt_render_bundle.main_replay_ansi);
      vt_visible_frame = std::move(vt_render_bundle.visible_frame_ansi);
      out.data.soft_limit_threshold_bytes =
          terminal_manager_arg_.channel_cache_threshold_bytes.warning;
      out.data.hard_limit_threshold_bytes =
          terminal_manager_arg_.channel_cache_threshold_bytes.terminate;
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
    if (!out.data.in_alternate_screen && vt_main_replay.has_value()) {
      main_content = std::move(*vt_main_replay);
    } else {
      for (auto const &block : replay_blocks) {
        if (block.data.empty() || block.screen != AMT::ScreenKind::Main) {
          continue;
        }
        main_content.append(block.data);
      }
    }

    if (!main_content.empty()) {
      try {
        processor(main_content);
      } catch (...) {
      }
      out.data.replayed_bytes += main_content.size();
    }

    std::string latest_alt = {};
    for (auto const &block : replay_blocks) {
      if (block.screen == AMT::ScreenKind::Alternate && !block.data.empty()) {
        latest_alt = block.data;
      }
    }
    if (out.data.in_alternate_screen) {
      try {
        processor("\x1b[?1049h");
      } catch (...) {
      }
      if (vt_visible_frame.has_value()) {
        try {
          processor(*vt_visible_frame);
        } catch (...) {
        }
        out.data.replayed_bytes += vt_visible_frame->size();
      } else if (!latest_alt.empty()) {
        try {
          processor(latest_alt);
        } catch (...) {
        }
        out.data.replayed_bytes += latest_alt.size();
      }
    }

    if (!vt_main_replay.has_value() && out.data.replayed_bytes == 0 &&
        !fallback_output.empty()) {
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

  [[nodiscard]] ECMData<AMT::ChannelCacheCopyResult> GetCacheCopy() const {
    ECMData<AMT::ChannelCacheCopyResult> out = {};
    std::lock_guard<std::mutex> lock(mutex_);
    out.data.blocks = state_.cache.blocks;
    out.data.in_alternate_screen = state_.cache.in_alternate_screen;
    out.data.latest_output = state_.latest_output;
    out.data.cached_bytes = state_.cached_bytes;
    out.data.vt_snapshot = BuildVtSnapshotUnlocked_();
    auto vt_render_bundle = BuildVtRenderBundleUnlocked_(out.data.vt_snapshot);
    out.data.vt_main_replay_ansi =
        std::move(vt_render_bundle.main_replay_ansi).value_or("");
    out.data.vt_visible_frame_ansi =
        std::move(vt_render_bundle.visible_frame_ansi).value_or("");
    out.rcm = OK;
    return out;
  }

  [[nodiscard]] ECMData<AMT::ChannelRenderFrameResult>
  GetRenderFrame(
      const AMT::ChannelRenderFrameArgs &render_args = {}) const {
    ECMData<AMT::ChannelRenderFrameResult> out = {};
    std::lock_guard<std::mutex> lock(mutex_);
    out.data.in_alternate_screen = state_.cache.in_alternate_screen;
    out.data.vt_snapshot = BuildVtSnapshotUnlocked_();
    auto vt_render_bundle =
        BuildVtRenderBundleUnlocked_(out.data.vt_snapshot,
                                     render_args.viewport_offset);
    out.data.vt_main_replay_ansi =
        std::move(vt_render_bundle.main_replay_ansi).value_or("");
    out.data.vt_visible_frame_ansi =
        std::move(vt_render_bundle.visible_frame_ansi).value_or("");
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
#ifdef AMSFTP_VT_STATIC
    ResetVtUnlocked_();
    EnsureVtUnlocked_(state_.vt_cols, state_.vt_rows);
#endif
    return OK;
  }

  void ResizeViewport(int cols, int rows) {
    std::lock_guard<std::mutex> lock(mutex_);
    EnsureVtUnlocked_(cols, rows);
    ResizeVtUnlocked_(cols, rows);
  }

  [[nodiscard]] ECMData<AMT::ChannelCacheTruncateResult>
  TruncateCache(const AMT::ChannelCacheTruncateArgs &truncate_args) {
    ECMData<AMT::ChannelCacheTruncateResult> out = {};
    const size_t soft_limit_bytes =
        terminal_manager_arg_.channel_cache_threshold_bytes.warning;
    const size_t hard_limit_bytes =
        terminal_manager_arg_.channel_cache_threshold_bytes.terminate;

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
      RebuildVtFromCacheUnlocked_();
      if (state_.cached_bytes < soft_limit_bytes) {
        state_.soft_limit_hit = false;
      }
      if (state_.cached_bytes < hard_limit_bytes) {
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
    const size_t soft_limit_bytes =
        terminal_manager_arg_.channel_cache_threshold_bytes.warning;
    const size_t hard_limit_bytes =
        terminal_manager_arg_.channel_cache_threshold_bytes.terminate;

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
    AMT::BufferExceedCallback buffer_exceed_callback = {};
    std::optional<AMT::BufferExceedEvent> soft_limit_event = std::nullopt;
    std::optional<AMT::BufferExceedEvent> hard_limit_event = std::nullopt;
    bool hard_limit_hit_now = false;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (!read_result.data.output.empty()) {
        state_.latest_output = read_result.data.output;
        FeedRawOutputToVtUnlocked_(read_result.data.output);
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
        if (!state_.soft_limit_hit && state_.cached_bytes >= soft_limit_bytes) {
          state_.soft_limit_hit = true;
          soft_limit_event =
              AMT::BufferExceedEvent{terminal_key_,
                                     channel_name_,
                                     AMT::BufferExceedThresholdKind::Soft,
                                     state_.cached_bytes,
                                     soft_limit_bytes,
                                     state_.cache.in_alternate_screen,
                                     state_.last_error};
          if (state_.soft_warn_epoch != state_.attach_epoch) {
            out.data.soft_limit_hit_now = true;
            state_.soft_warn_epoch = state_.attach_epoch;
          }
        }

        if (!state_.hard_limit_hit && state_.cached_bytes >= hard_limit_bytes) {
          state_.hard_limit_hit = true;
          hard_limit_hit_now = true;
          state_.last_error =
              Err(ErrorCode::FilesystemNoSpace, "terminal.channel.cache.limit",
                  channel_name_,
                  AMStr::fmt("Terminal output cache hard limit "
                             "exceeded ({}); channel closed",
                             AMStr::FormatSize(hard_limit_bytes)));
          state_.closed = true;
          hard_limit_event =
              AMT::BufferExceedEvent{terminal_key_,
                                     channel_name_,
                                     AMT::BufferExceedThresholdKind::Hard,
                                     state_.cached_bytes,
                                     hard_limit_bytes,
                                     state_.cache.in_alternate_screen,
                                     state_.last_error};
        }

        if (state_.attached && state_.consumer) {
          consumer = state_.consumer;
        }
        if (buffer_exceed_callback_) {
          buffer_exceed_callback = buffer_exceed_callback_;
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

    if (buffer_exceed_callback) {
      if (soft_limit_event.has_value()) {
        try {
          buffer_exceed_callback(*soft_limit_event);
        } catch (...) {
        }
      }
      if (hard_limit_event.has_value()) {
        try {
          buffer_exceed_callback(*hard_limit_event);
        } catch (...) {
        }
      }
    }

    if (hard_limit_hit_now) {
      out.data.eof = true;
      out.data.hard_limit_hit = true;
      out.data.last_error =
          Err(ErrorCode::FilesystemNoSpace, "terminal.channel.cache.limit",
              channel_name_,
              AMStr::fmt("Terminal output cache hard limit exceeded "
                         "({}); channel closed",
                         AMStr::FormatSize(hard_limit_bytes)));
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
    return full.starts_with(prefix);
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
        if (remain.starts_with(seq)) {
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

  void EnsureVtUnlocked_(int cols, int rows) {
#ifdef AMSFTP_VT_STATIC
    state_.vt_cols = std::max(1, cols);
    state_.vt_rows = std::max(1, rows);
    if (state_.vt != nullptr) {
      return;
    }
    const uint64_t scrollback_limit = std::clamp<uint64_t>(
        terminal_manager_arg_.channel_cache_threshold_bytes.terminate /
            static_cast<size_t>(std::max(1, state_.vt_cols)),
        10000U, 500000U);
    state_.vt = AmsVtCreate(state_.vt_rows, state_.vt_cols, scrollback_limit);
#else
    (void)cols;
    (void)rows;
#endif
  }

  void ResizeVtUnlocked_(int cols, int rows) {
#ifdef AMSFTP_VT_STATIC
    EnsureVtUnlocked_(cols, rows);
    if (state_.vt != nullptr) {
      AmsVtResize(state_.vt, state_.vt_rows, state_.vt_cols);
    }
#else
    (void)cols;
    (void)rows;
#endif
  }

  void ResetVtUnlocked_() {
#ifdef AMSFTP_VT_STATIC
    if (state_.vt != nullptr) {
      AmsVtFree(state_.vt);
      state_.vt = nullptr;
    }
    vt_render_cache_ = {};
#endif
  }

  void FeedRawOutputToVtUnlocked_(std::string_view output) {
#ifdef AMSFTP_VT_STATIC
    EnsureVtUnlocked_(state_.vt_cols, state_.vt_rows);
    if (state_.vt == nullptr || output.empty()) {
      return;
    }
    AmsVtFeed(state_.vt, reinterpret_cast<const uint8_t *>(output.data()),
              output.size());
#else
    (void)output;
#endif
  }

  void RebuildVtFromCacheUnlocked_() {
#ifdef AMSFTP_VT_STATIC
    ResetVtUnlocked_();
    EnsureVtUnlocked_(state_.vt_cols, state_.vt_rows);
    if (state_.vt == nullptr) {
      return;
    }

    auto feed_toggle = [this](bool to_alternate) {
      static constexpr std::string_view kEnterAlt = "\x1b[?1049h";
      static constexpr std::string_view kExitAlt = "\x1b[?1049l";
      std::string_view const seq = to_alternate ? kEnterAlt : kExitAlt;
      AmsVtFeed(state_.vt, reinterpret_cast<const uint8_t *>(seq.data()),
                seq.size());
    };

    AMT::ScreenKind current_screen = AMT::ScreenKind::Main;
    for (const auto &block : state_.cache.blocks) {
      if (block.screen != current_screen) {
        feed_toggle(block.screen == AMT::ScreenKind::Alternate);
        current_screen = block.screen;
      }
      FeedRawOutputToVtUnlocked_(block.data);
    }

    const AMT::ScreenKind final_screen =
        state_.cache.in_alternate_screen ? AMT::ScreenKind::Alternate
                                         : AMT::ScreenKind::Main;
    if (current_screen != final_screen) {
      feed_toggle(final_screen == AMT::ScreenKind::Alternate);
    }
#endif
  }

  [[nodiscard]] std::optional<std::string> RenderVtMainReplayRawUnlocked_() const {
#ifdef AMSFTP_VT_STATIC
    if (state_.vt == nullptr) {
      return std::nullopt;
    }
    const AmsVtSnapshot snapshot = AmsVtGetSnapshot(state_.vt);
    if (snapshot.in_alternate_screen != 0U) {
      return std::string{};
    }
    char *rendered = AmsVtRenderMainReplayAnsiUtf8(state_.vt);
    if (rendered == nullptr) {
      return std::string{};
    }
    std::string out(rendered);
    AmsVtFreeString(rendered);
    return out;
#else
    return std::nullopt;
#endif
  }

  [[nodiscard]] std::optional<std::string>
  RenderVtVisibleFrameRawUnlocked_(uint64_t viewport_offset) const {
#ifdef AMSFTP_VT_STATIC
    if (state_.vt == nullptr) {
      return std::nullopt;
    }
    char *rendered =
        AmsVtRenderVisibleFrameWithOffsetAnsiUtf8(state_.vt, viewport_offset);
    if (rendered == nullptr) {
      return std::string{};
    }
    std::string out(rendered);
    AmsVtFreeString(rendered);
    return out;
#else
    return std::nullopt;
#endif
  }

  struct VtRenderBundle_ {
    std::optional<std::string> main_replay_ansi = std::nullopt;
    std::optional<std::string> visible_frame_ansi = std::nullopt;
  };

  [[nodiscard]] VtRenderBundle_
  BuildVtRenderBundleUnlocked_(const AMT::ChannelVtSnapshot &vt_snapshot,
                               uint64_t viewport_offset = 0) const {
    VtRenderBundle_ out = {};
#ifdef AMSFTP_VT_STATIC
    if (!vt_snapshot.available || state_.vt == nullptr) {
      vt_render_cache_ = {};
      return out;
    }

    if (!vt_render_cache_.valid ||
        vt_render_cache_.damage_serial != vt_snapshot.damage_serial ||
        vt_render_cache_.viewport_offset != viewport_offset ||
        vt_render_cache_.in_alternate_screen !=
            vt_snapshot.in_alternate_screen) {
      vt_render_cache_.valid = true;
      vt_render_cache_.damage_serial = vt_snapshot.damage_serial;
      vt_render_cache_.viewport_offset = viewport_offset;
      vt_render_cache_.in_alternate_screen = vt_snapshot.in_alternate_screen;
      vt_render_cache_.main_replay_ansi =
          RenderVtMainReplayRawUnlocked_().value_or("");
      vt_render_cache_.visible_frame_ansi =
          RenderVtVisibleFrameRawUnlocked_(viewport_offset).value_or("");
    }

    out.main_replay_ansi = vt_render_cache_.main_replay_ansi;
    out.visible_frame_ansi = vt_render_cache_.visible_frame_ansi;
#else
    (void)vt_snapshot;
#endif
    return out;
  }

  [[nodiscard]] AMT::ChannelVtSnapshot BuildVtSnapshotUnlocked_() const {
    AMT::ChannelVtSnapshot out = {};
#ifdef AMSFTP_VT_STATIC
    if (state_.vt == nullptr) {
      return out;
    }
    const AmsVtSnapshot snapshot = AmsVtGetSnapshot(state_.vt);
    out.available = true;
    out.rows = snapshot.rows;
    out.cols = snapshot.cols;
    out.cursor_row = snapshot.cursor_row;
    out.cursor_col = snapshot.cursor_col;
    out.history_lines = snapshot.history_lines;
    out.total_lines = snapshot.total_lines;
    out.display_offset = snapshot.display_offset;
    out.damage_serial = snapshot.damage_serial;
    out.in_alternate_screen = snapshot.in_alternate_screen != 0U;
    out.cursor_visible = snapshot.cursor_visible != 0U;
    out.rendered_main_rows = static_cast<size_t>(std::min<uint64_t>(
        snapshot.rendered_main_rows,
        static_cast<uint64_t>(std::numeric_limits<size_t>::max())));
#endif
    return out;
  }

public:
  void SetChannelName(std::string channel_name) {
    std::lock_guard<std::mutex> lock(mutex_);
    channel_name_ = std::move(channel_name);
  }

private:
  std::string terminal_key_ = {};
  std::string channel_name_ = {};
  AMT::BufferExceedCallback buffer_exceed_callback_ = {};
  AMT::TerminalManagerArg terminal_manager_arg_ = {};

  mutable std::mutex mutex_ = {};
  RuntimeState_ state_ = {};
#ifdef AMSFTP_VT_STATIC
  mutable VtRenderCache_ vt_render_cache_ = {};
#endif
};

} // namespace AMInfra::terminal
