#pragma once

#include "infrastructure/config/ConfigDocumentHandle.hpp"
#include <filesystem>

namespace AMInfra::config {
/**
 * @brief Build default document layout rooted at one project directory.
 */
[[nodiscard]] ConfigStoreLayout
BuildDefaultConfigStoreLayout(const std::filesystem::path &root_dir);
} // namespace AMInfra::config
