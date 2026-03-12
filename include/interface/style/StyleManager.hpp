#pragma once

#include "application/config/ConfigAppService.hpp"
#include "application/config/StyleSettings.hpp"
#include "foundation/DataClass.hpp"
#include "foundation/tools/bar.hpp"
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace AMInterface::style {
using AMStyleSnapshot = AMApplication::config::AMStyleSnapshot;

/**
 * @brief Interface-layer style service backed by application config service.
 *
 * The service owns a typed snapshot of `Settings.Style` and provides format
 * helpers for CLI rendering.
 */
class AMStyleService : NonCopyableNonMovable {
public:
  /**
   * @brief Construct one empty style service.
   */
  AMStyleService() = default;

  /**
   * @brief Destroy the style service.
   */
  ~AMStyleService() override = default;

  /**
   * @brief Bind config service and load style snapshot from settings.
   */
  ECM Init(AMApplication::config::AMConfigAppService *config_service);

  /**
   * @brief Reload snapshot from the currently bound config service.
   */
  ECM ReloadFromConfigService();

  /**
   * @brief Apply configured style to one text segment.
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
  [[nodiscard]] static std::string NormalizeStyleTag_(const std::string &raw_tag);

  /**
   * @brief Apply one bbcode tag around text.
   */
  [[nodiscard]] static std::string ApplyStyleTag_(const std::string &tag,
                                                  const std::string &text);

  mutable std::mutex mtx_;
  AMApplication::config::AMConfigAppService *config_service_ = nullptr;
  AMStyleSnapshot snapshot_{};
  mutable std::optional<AMProgressBarStyle> progress_bar_style_;
  bool initialized_ = false;
};
} // namespace AMInterface::style
