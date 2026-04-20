#pragma once

#include "domain/config/ConfigModel.hpp"

#include <filesystem>

namespace AMInfra::config {

[[nodiscard]] AMDomain::config::ConfigStoreInitArg
BuildDefaultConfigStoreInitArg(const std::filesystem::path &root_dir);

} // namespace AMInfra::config
