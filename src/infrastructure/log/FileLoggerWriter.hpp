#pragma once

#include "domain/log/LoggerPorts.hpp"
#include <filesystem>
#include <fstream>
#include <mutex>

/**
 * @brief Concrete infrastructure writer backed by file stream append I/O.
 */
class AMInfraFileLoggerWriter final : public AMDomain::log::ILoggerWritePort {
public:
  /**
   * @brief Construct writer with optional initial output path.
   */
  explicit AMInfraFileLoggerWriter(
      const std::filesystem::path &path = std::filesystem::path());

  /**
   * @brief Flush and close stream resources.
   */
  ~AMInfraFileLoggerWriter() override { Close(); }

  /**
   * @brief Bind one output path used by this writer.
   */
  ECM SetPath(const std::filesystem::path &path) override;

  /**
   * @brief Return writer output path.
   */
  [[nodiscard]] std::filesystem::path Path() const override;

  /**
   * @brief Write one line into underlying output stream.
   */
  ECM Write(const std::string &line) override;

  /**
   * @brief Bind callback for writer-level I/O errors.
   */
  void SetErrorReporter(ErrorReporter reporter) override;

  /**
   * @brief Close underlying stream resources.
   */
  void Close() override;

private:
  /**
   * @brief Ensure stream is open for append writing.
   */
  ECM EnsureStreamOpen_();

  /**
   * @brief Close stream while mtx_ is already held.
   */
  void CloseUnlocked_();

  /**
   * @brief Notify writer-level callback when one I/O error occurs.
   */
  void ReportError_(const ECM &rcm);

  mutable std::mutex mtx_;
  mutable std::mutex reporter_mtx_;
  std::filesystem::path path_;
  std::ofstream stream_;
  ErrorReporter error_reporter_ = {};
};
