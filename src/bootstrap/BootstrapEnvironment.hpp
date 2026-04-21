#pragma once

#include "foundation/core/DataClass.hpp"

#include <filesystem>
#include <string>

namespace AMBootstrap {
namespace fs = std::filesystem;

ECMData<fs::path> ResolveRootDir();

void PrintBootstrapWarn(const std::string &msg);

} // namespace AMBootstrap
