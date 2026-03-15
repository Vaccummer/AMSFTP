#pragma once

/**
 * @brief Deprecated compatibility shim for legacy filesystem workflow API.
 *
 * Canonical active workflow surfaces are:
 * - `application/client/ClientSessionWorkflows.hpp`
 * - `application/client/FileCommandWorkflows.hpp`
 */
#if !defined(AMSFTP_SUPPRESS_DEPRECATED_HEADER_NOTICE)
#if defined(_MSC_VER)
#pragma message("AMSFTP deprecated header: include/application/filesystem/FileSystemWorkflows.hpp; prefer application/client/{ClientSessionWorkflows,FileCommandWorkflows}.hpp")
#elif defined(__clang__) || defined(__GNUC__)
#warning "AMSFTP deprecated header: include/application/filesystem/FileSystemWorkflows.hpp; prefer application/client/{ClientSessionWorkflows,FileCommandWorkflows}.hpp"
#endif
#endif

#include "application/filesystem/dep/FileSystemWorkflows.dep.hpp"
