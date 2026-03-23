#pragma once

#include "domain/config/ConfigModel.hpp"
#include <filesystem>

namespace AMInfra::config {
/**
 * @brief Build default config-store init arg rooted at one project directory.
 */
[[nodiscard]] AMDomain::config::ConfigStoreInitArg
BuildDefaultConfigStoreInitArg(const std::filesystem::path &root_dir);
} // namespace AMInfra::config
