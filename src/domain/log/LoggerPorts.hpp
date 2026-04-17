#pragma once
#include "foundation/core/DataClass.hpp"
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <string>

namespace AMDomain::log {
/**
 * @brief Domain port for concrete logger writers in infrastructure.
 */
class ILoggerWritePort : public NonCopyableNonMovable {
public:
  using ErrorReporter = std::function<void(const ECM &)>;

  /**
   * @brief Destroy writer port instance.
   */
  ~ILoggerWritePort() override = default;

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
   * @brief Write one raw line without logger-side formatting.
   */
  virtual ECM WriteLine(const std::string &line) { return Write(line); }

  /**
   * @brief Bind callback for writer-level I/O errors.
   */
  virtual void SetErrorReporter(ErrorReporter reporter) = 0;

  /**
   * @brief Close underlying stream resources.
   */
  virtual void Close() = 0;

  /**
   * @brief Return last writer-level ECM state.
   */
  [[nodiscard]] ECM LastError() const {
    std::lock_guard<std::mutex> lock(error_mtx_);
    return last_error_;
  }

  /**
   * @brief Clear last writer-level ECM state to success.
   */
  void ClearLastError() { SetLastError_(OK); }

protected:
  /**
   * @brief Update last writer-level ECM state.
   */
  void SetLastError_(const ECM &error) {
    std::lock_guard<std::mutex> lock(error_mtx_);
    last_error_ = error;
  }

private:
  mutable std::mutex error_mtx_;
  ECM last_error_ = OK;
};

/**
 * @brief Build the default logger writer port implementation.
 */
std::unique_ptr<ILoggerWritePort> BuildLoggerWritePort();

} // namespace AMDomain::log
