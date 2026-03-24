#pragma once

// standard library
#include <filesystem>
#include <string>
#include <system_error>
// project header
#include "foundation/core/Enum.hpp"

/**
 * @brief Return true when ECM indicates success.
 */
inline bool isok(const ECM &ecm) { return ecm; };

/**
 * @brief Return a success ECM.
 */
inline ECM Ok() {
  const static ECM ok_instance{EC::Success, ""};
  return ok_instance;
};

/**
 * @brief Build an error ECM with message.
 */
inline ECM Err(EC code, const std::string &msg) { return {code, msg}; }

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
