#pragma once

#include "domain/config/ConfigSyncPort.hpp"
#include "foundation/DataClass.hpp"
#include "foundation/tools/bar.hpp"
#include "interface/style/StyleModel.hpp"
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace AMInterface::style {
/**
 * @brief Interface-layer style service backed by one config sync port.
 *
 * This manager owns a typed snapshot of `Settings.Style`, provides formatting
 * helpers for CLI rendering, and registers a dump callback so runtime mutations
 * can be serialized back to JSON on config dump.
 */
class AMStyleManager : NonCopyableNonMovable {
public:
  /**
   * @brief Construct an empty style manager.
   */
  AMStyleManager() = default;

  /**
   * @brief Unregister dump callback from the sync port on destruction.
   */
  ~AMStyleManager() override;

  /**
   * @brief Initialize from one style sync port and bind dump callback.
   */
  ECM Init(std::shared_ptr<AMDomain::config::AMConfigSyncPort> style_port);

  /**
   * @brief Reload snapshot from the currently bound sync port JSON payload.
   */
  ECM ReloadFromSyncPort();

  /**
   * @brief Apply configured style to one text segment.
   *
   * @param ori_str Raw text to style.
   * @param style_name Input-highlight style key.
   * @param path_info Optional path metadata for `Style.Path` coloring.
   * @return Styled text using bbcode tags.
   */
  [[nodiscard]] std::string Format(const std::string &ori_str,
                                   const std::string &style_name,
                                   const PathInfo *path_info = nullptr) const;

  /**
   * @brief Format a UTF-8 table using configured `Style.Table` defaults.
   */
  [[nodiscard]] std::string
  FormatUtf8Table(const std::vector<std::string> &keys,
                  const std::vector<std::vector<std::string>> &rows) const;

  /**
   * @brief Create one progress bar using configured `Style.ProgressBar`.
   */
  [[nodiscard]] AMProgressBar CreateProgressBar(int64_t total_size,
                                                const std::string &prefix);

  /**
   * @brief Return configured core prompt template text.
   */
  [[nodiscard]] std::string ResolveCorePromptTemplate() const;

  /**
   * @brief Return configured history-search prompt text.
   */
  [[nodiscard]] std::string ResolveHistorySearchPrompt() const;

  /**
   * @brief Return one dynamic shortcut style by runtime-determined key.
   */
  [[nodiscard]] std::string ResolveShortcutStyle(const std::string &key) const;

  /**
   * @brief Return a copy of current typed style snapshot.
   */
  [[nodiscard]] AMStyleSnapshot Snapshot() const;

private:
  /**
   * @brief Parse one color token into indicators color type.
   */
  static std::variant<indicators::Color, std::string>
  ParseProgressBarColor_(const std::string &value);

  /**
   * @brief Build bar rendering style from the current snapshot.
   */
  [[nodiscard]] AMProgressBarStyle BuildProgressBarStyle_() const;

  /**
   * @brief Resolve one input-highlight style tag by key.
   */
  [[nodiscard]] std::string
  ResolveInputStyleTag_(const std::string &style_name) const;

  /**
   * @brief Normalize one style token into bbcode opening tag.
   */
  [[nodiscard]] static std::string
  NormalizeStyleTag_(const std::string &raw_tag);

  /**
   * @brief Apply one bbcode tag around text.
   */
  [[nodiscard]] static std::string ApplyStyleTag_(const std::string &tag,
                                                  const std::string &text);

  /**
   * @brief Parse one `Style` JSON node into the in-memory snapshot.
   */
  void LoadStyleJson_(const Json &style_json);

  mutable std::mutex mtx_;
  std::shared_ptr<AMDomain::config::AMConfigSyncPort> style_port_;
  AMStyleSnapshot snapshot_{};
  mutable std::optional<AMProgressBarStyle> progress_bar_style_;
  bool initialized_ = false;
};
} // namespace AMInterface::style
