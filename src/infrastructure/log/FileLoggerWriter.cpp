#include "infrastructure/log/FileLoggerWriter.hpp"
#include "foundation/tools/enum_related.hpp"
#include "foundation/tools/string.hpp"
#include <system_error>
#include <utility>

/**
 * @brief Construct writer with optional initial output path.
 */
AMInfraFileLoggerWriter::AMInfraFileLoggerWriter(
    const std::filesystem::path &path)
    : path_(path) {
  if (path_.empty()) {
    return;
  }
  std::lock_guard<std::mutex> lock(mtx_);
  ECM open_rcm = EnsureStreamOpen_();
  if (!isok(open_rcm)) {
    SetLastError_(open_rcm);
  }
}

/**
 * @brief Bind one output path used by this writer.
 */
ECM AMInfraFileLoggerWriter::SetPath(const std::filesystem::path &path) {
  if (path.empty()) {
    ECM invalid = Err(EC::InvalidArg, "Logger writer path cannot be empty");
    SetLastError_(invalid);
    ReportError_(invalid);
    return invalid;
  }
  std::lock_guard<std::mutex> lock(mtx_);
  if (path_ == path) {
    return Ok();
  }
  CloseUnlocked_();
  path_ = path;
  SetLastError_({EC::Success, ""});
  return Ok();
}

/**
 * @brief Return writer output path.
 */
std::filesystem::path AMInfraFileLoggerWriter::Path() const {
  std::lock_guard<std::mutex> lock(mtx_);
  return path_;
}

/**
 * @brief Write one line into underlying output stream.
 */
ECM AMInfraFileLoggerWriter::Write(const std::string &line) {
  std::lock_guard<std::mutex> lock(mtx_);
  ECM open_rcm = EnsureStreamOpen_();
  if (!isok(open_rcm)) {
    SetLastError_(open_rcm);
    ReportError_(open_rcm);
    return open_rcm;
  }
  stream_ << line << std::endl;
  stream_.flush();
  if (stream_.bad() || stream_.fail()) {
    ECM write_rcm = Err(EC::LocalFileError,
                        AMStr::fmt("Failed to write log file {}",
                                   path_.string().empty() ? "<empty>"
                                                          : path_.string()));
    stream_.clear();
    SetLastError_(write_rcm);
    ReportError_(write_rcm);
    return write_rcm;
  }
  SetLastError_({EC::Success, ""});
  return Ok();
}

/**
 * @brief Bind callback for writer-level I/O errors.
 */
void AMInfraFileLoggerWriter::SetErrorReporter(ErrorReporter reporter) {
  std::lock_guard<std::mutex> lock(reporter_mtx_);
  error_reporter_ = std::move(reporter);
}

/**
 * @brief Close underlying stream resources.
 */
void AMInfraFileLoggerWriter::Close() {
  std::lock_guard<std::mutex> lock(mtx_);
  CloseUnlocked_();
}

/**
 * @brief Ensure stream is open for append writing.
 */
ECM AMInfraFileLoggerWriter::EnsureStreamOpen_() {
  if (stream_.is_open()) {
    return Ok();
  }
  if (path_.empty()) {
    return Err(EC::InvalidArg, "Logger writer path is not configured");
  }
  std::error_code ec;
  const std::filesystem::path parent_path = path_.parent_path();
  if (!parent_path.empty()) {
    std::filesystem::create_directories(parent_path, ec);
    if (ec) {
      return Err(EC::LocalFileError,
                 AMStr::fmt("Failed to create log directory {}: {}",
                            parent_path.string(), ec.message()));
    }
  }

  stream_.clear();
  stream_.open(path_, std::ios::app);
  if (!stream_.is_open()) {
    return Err(EC::LocalFileError,
               AMStr::fmt("Failed to open log file {}", path_.string()));
  }
  return Ok();
}

/**
 * @brief Close stream while mtx_ is already held.
 */
void AMInfraFileLoggerWriter::CloseUnlocked_() {
  if (!stream_.is_open()) {
    return;
  }
  stream_.flush();
  stream_.close();
}

/**
 * @brief Notify writer-level callback when one I/O error occurs.
 */
void AMInfraFileLoggerWriter::ReportError_(const ECM &rcm) {
  ErrorReporter reporter = {};
  {
    std::lock_guard<std::mutex> lock(reporter_mtx_);
    reporter = error_reporter_;
  }
  if (reporter) {
    reporter(rcm);
  }
}

namespace AMDomain::log {

std::unique_ptr<ILoggerWritePort> BuildLoggerWritePort() {
  return std::make_unique<AMInfraFileLoggerWriter>();
}

} // namespace AMDomain::log
