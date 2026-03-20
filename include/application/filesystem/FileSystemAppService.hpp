#pragma once
#include "application/filesystem/FileSystemBackendPort.hpp"
#include <memory>

namespace AMApplication::filesystem {
/**
 * @brief Application facade for filesystem command orchestration.
 *
 * This facade delegates filesystem runtime execution to a backend port.
 */
class FileSystemAppService {
public:
  using Backend = runtime::IFileSystemBackendPort;

  /**
   * @brief Construct from filesystem backend port.
   */
  explicit FileSystemAppService(std::shared_ptr<Backend> backend);

  /**
   * @brief Return true when backend is available.
   */
  [[nodiscard]] bool HasBackend() const;

  /**
   * @brief Return bound filesystem backend for interface orchestration.
   */
  [[nodiscard]] std::shared_ptr<Backend> BackendPort() const;

private:
  std::shared_ptr<Backend> backend_;
};
} // namespace AMApplication::filesystem
