#pragma once

// standard library
#include <filesystem>
#include <system_error>
// project header
#include "foundation/core/Enum.hpp"

/**
 * @brief Convert std::filesystem::file_type to project PathType.
 */
PathType cast_fs_type(const std::filesystem::file_type &type);

/**
 * @brief Convert std::error_code to project ErrorCode.
 */
ErrorCode fec(const std::error_code &ec);

/**
 * @brief Convert std::error_code to project ECM pair.
 */
ECM fecm(const std::error_code &ec);
