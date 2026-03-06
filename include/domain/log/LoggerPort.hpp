#pragma once

#include "foundation/DataClass.hpp"
#include <filesystem>
#include <functional>
#include <string>

namespace AMDomain::log {
/**
 * @brief Domain port for concrete logger writers in infrastructure.
 */
class AMLoggerWritePort : public NonCopyableNonMovable {
public:
  using ErrorReporter = std::function<void(const ECM &)>;

  /**
   * @brief Destroy writer port instance.
   */
  ~AMLoggerWritePort() override = default;

  /**
   * @brief Bind one output path used by this writer.
   */
  virtual ECM SetPath(const std::filesystem::path &path) = 0;

  /**
   * @brief Return writer output path.
   */
  [[nodiscard]] virtual std::filesystem::path Path() const = 0;

  /**
   * @brief Write one line into underlying output stream.
   */
  virtual ECM Write(const std::string &line) = 0;

  /**
   * @brief Bind callback for writer-level I/O errors.
   */
  virtual void SetErrorReporter(ErrorReporter reporter) = 0;

  /**
   * @brief Close underlying stream resources.
   */
  virtual void Close() = 0;
};
} // namespace AMDomain::log

/**
 * @brief Backward-compatible global alias for gradual migration.
 */
using AMLoggerWritePort = AMDomain::log::AMLoggerWritePort;
