#pragma once

#include "domain/filesystem/FileSystemModel.hpp"

namespace AMDomain::filesystem {
/**
 * @brief Compatibility placeholder for removed redundant filesystem domain ports.
 *
 * Filesystem execution is driven by application orchestration over client ports.
 * Dedicated filesystem domain ports were removed as redundant abstractions.
 */
/* {ori_code}
class IFileSystemQueryPort { ... };
class IFileSystemMutationPort { ... };
class IFileSystemPathResolverPort { ... };
class IFileSystemSessionPort { ... };
class IFileSystemShellPort { ... };
*/
} // namespace AMDomain::filesystem
