#pragma once

#if !defined(AMSFTP_SUPPRESS_DEPRECATED_HEADER_NOTICE)
#if defined(_MSC_VER)
#pragma message("AMSFTP deprecated header: include/domain/filesystem/deprecated/FileSystemManagerLegacy.hpp; prefer application/filesystem/FileSystemAppService.hpp")
#elif defined(__clang__) || defined(__GNUC__)
#warning "AMSFTP deprecated header: include/domain/filesystem/deprecated/FileSystemManagerLegacy.hpp; prefer application/filesystem/FileSystemAppService.hpp"
#endif
#endif

#include "domain/filesystem/deprecated/FileSystemManager.hpp"

namespace AMDomain::filesystem::deprecated {
/**
 * @brief Compatibility alias for legacy filesystem facade.
 */
using FileSystemManagerLegacy = AMDomain::filesystem::AMFileSystem;
} // namespace AMDomain::filesystem::deprecated
