#include "infrastructure/config/FileConfigWriteLock.hpp"

#include "foundation/tools/string.hpp"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <string>
#include <sys/file.h>
#include <sys/types.h>
#include <unistd.h>
#include <utility>

namespace AMInfra::config {
namespace {

std::string BuildOwnerInfo_() {
  return AMStr::fmt("pid={}", static_cast<long>(getpid()));
}

ECM EnsureLockParent_(const std::filesystem::path &lock_path) {
  const std::filesystem::path parent = lock_path.parent_path();
  if (parent.empty()) {
    return OK;
  }
  std::error_code ec = {};
  std::filesystem::create_directories(parent, ec);
  if (ec) {
    return Err(EC::ConfigDumpFailed, "config.lock", lock_path.string(),
               ec.message());
  }
  return OK;
}

class FileConfigWriteLock final : public AMDomain::config::IConfigWriteLockPort {
public:
  explicit FileConfigWriteLock(std::filesystem::path lock_path)
      : lock_path_(std::move(lock_path)) {}

  ~FileConfigWriteLock() override { Release(); }

  [[nodiscard]] ECM TryAcquire() override {
    if (IsHeld()) {
      return OK;
    }

    const ECM parent_rcm = EnsureLockParent_(lock_path_);
    if (!(parent_rcm)) {
      return parent_rcm;
    }

    const int fd = open(lock_path_.string().c_str(), O_RDWR | O_CREAT, 0666);
    if (fd < 0) {
      return Err(EC::ConfigDumpFailed, "config.lock", lock_path_.string(),
                 std::strerror(errno));
    }
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
      const int saved_errno = errno;
      close(fd);
      if (saved_errno == EWOULDBLOCK || saved_errno == EAGAIN) {
        return Err(EC::PermissionDenied, "config.lock", lock_path_.string(),
                   "config write lock is held by another session");
      }
      return Err(EC::ConfigDumpFailed, "config.lock", lock_path_.string(),
                 std::strerror(saved_errno));
    }

    owner_info_ = BuildOwnerInfo_();
    const std::string content = owner_info_ + "\n";
    (void)ftruncate(fd, 0);
    (void)lseek(fd, 0, SEEK_SET);
    (void)write(fd, content.data(), content.size());
    fd_ = fd;
    return OK;
  }

  void Release() override {
    if (fd_ >= 0) {
      (void)flock(fd_, LOCK_UN);
      (void)close(fd_);
      fd_ = -1;
    }
    owner_info_.clear();
  }

  [[nodiscard]] bool IsHeld() const override {
    return fd_ >= 0;
  }

  [[nodiscard]] std::filesystem::path LockPath() const override {
    return lock_path_;
  }

  [[nodiscard]] std::string OwnerInfo() const override { return owner_info_; }

private:
  std::filesystem::path lock_path_ = {};
  std::string owner_info_ = {};
  int fd_ = -1;
};

} // namespace

std::unique_ptr<AMDomain::config::IConfigWriteLockPort>
CreateFileConfigWriteLockPort(std::filesystem::path lock_path) {
  return std::make_unique<FileConfigWriteLock>(std::move(lock_path));
}

} // namespace AMInfra::config
