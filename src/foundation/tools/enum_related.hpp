#pragma once

// standard library
#include <filesystem>
#include <string>
#include <system_error>
#include <utility>
// project header
#include "foundation/core/Enum.hpp"

using EC = ErrorCode;
using ECM = std::pair<ErrorCode, std::string>;
/**
 * @brief Return true when ECM indicates success.
 */
bool isok(const std::pair<ErrorCode, std::string> &ecm);

/**
 * @brief Return a success ECM.
 */
std::pair<ErrorCode, std::string> Ok();

/**
 * @brief Build an error ECM with message.
 */
std::pair<ErrorCode, std::string> Err(ErrorCode code, const std::string &msg);

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
std::pair<ErrorCode, std::string> fecm(const std::error_code &ec);
