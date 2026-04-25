#pragma once

#include "domain/config/ConfigWriteLockPort.hpp"

#include <filesystem>
#include <memory>

namespace AMInfra::config {

[[nodiscard]] std::unique_ptr<AMDomain::config::IConfigWriteLockPort>
CreateFileConfigWriteLockPort(std::filesystem::path lock_path);

} // namespace AMInfra::config
