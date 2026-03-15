#pragma once

/**
 * @brief Compatibility shim for legacy filesystem manager include path.
 *
 * New code should include `domain/filesystem/deprecated/FileSystemManager.hpp`
 * only when legacy manager behavior is explicitly required.
 */
#if !defined(AMSFTP_SUPPRESS_DEPRECATED_HEADER_NOTICE)
#if defined(_MSC_VER)
#pragma message("AMSFTP deprecated header: include/domain/filesystem/FileSystemManager.hpp; prefer application/filesystem/FileSystemAppService.hpp")
#elif defined(__clang__) || defined(__GNUC__)
#warning "AMSFTP deprecated header: include/domain/filesystem/FileSystemManager.hpp; prefer application/filesystem/FileSystemAppService.hpp"
#endif
#endif

#include "domain/filesystem/deprecated/FileSystemManager.hpp"
