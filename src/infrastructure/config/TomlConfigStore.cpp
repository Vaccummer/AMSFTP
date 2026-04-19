#include "infrastructure/config/TomlConfigStore.hpp"

#include "infrastructure/config/TomlConfigHandle.hpp"
#include <algorithm>
#include <array>
#include <cctype>
#include <optional>
#include <vector>

namespace {
using DocumentKind = AMDomain::config::DocumentKind;

constexpr std::array<DocumentKind, 4> kRequiredKinds = {
    DocumentKind::Config, DocumentKind::Settings, DocumentKind::KnownHosts,
    DocumentKind::History};

bool IsBackupStampFolder_(const std::string &name) {
  auto match_pattern = [&](const std::array<size_t, 4> &dash_pos,
                           std::optional<size_t> underscore_pos,
                           size_t expect_size) -> bool {
    if (name.size() != expect_size) {
      return false;
    }
    for (size_t i = 0; i < name.size(); ++i) {
      if (underscore_pos.has_value() && i == underscore_pos.value()) {
        if (name[i] != '_') {
          return false;
        }
        continue;
      }
      const bool is_dash =
          std::find(dash_pos.begin(), dash_pos.end(), i) != dash_pos.end();
      if (is_dash) {
        if (name[i] != '-') {
          return false;
        }
        continue;
      }
      if (!std::isdigit(static_cast<unsigned char>(name[i]))) {
        return false;
      }
    }
    return true;
  };

  // Legacy format: YYYY-MM-DD-HH-MM
  if (match_pattern({4, 7, 10, 13}, std::nullopt, 16)) {
    return true;
  }
  // New format: YYYY-MM-DD_HH-MM-SS
  return match_pattern({4, 7, 13, 16}, 10, 19);
}

bool LessByFolderName_(const std::filesystem::path &lhs,
                       const std::filesystem::path &rhs) {
  return lhs.filename().string() < rhs.filename().string();
}

bool IsBackupStampDirectory_(const std::filesystem::directory_entry &entry,
                             std::error_code &ec) {
  if (!entry.is_directory(ec) || ec) {
    return false;
  }
  return IsBackupStampFolder_(entry.path().filename().string());
}
} // namespace

namespace AMInfra::config {
ECM AMTomlConfigStore::Configure(
    const AMDomain::config::ConfigStoreInitArg &arg) {
  Close();
  root_dir_ = arg.root_dir;
  layout_ = arg.layout;
  codec_registry_ = ArgCodecRegistry(BuildCodecMap());

  for (const auto kind : kRequiredKinds) {
    if (!layout_.contains(kind)) {
      return Err(EC::ConfigNotInitialized, "", "", "missing document layout");
    }
  }
  writer_.Start();
  initialized_ = true;
  return OK;
}

ECM AMTomlConfigStore::Load(
    std::optional<AMDomain::config::DocumentKind> kind, bool force) {
  if (!initialized_) {
    return Err(EC::ConfigNotInitialized, "", "",
               "config store is not initialized");
  }

  auto load_one = [this, force](AMDomain::config::DocumentKind target) -> ECM {
    if (!force) {
      auto existing = GetHandle_(target);
      if (existing) {
        return OK;
      }
    }
    return LoadDocument_(target);
  };

  if (kind.has_value()) {
    return load_one(kind.value());
  }
  for (const auto current : kRequiredKinds) {
    ECM rcm = load_one(current);
    if (!(rcm)) {
      return rcm;
    }
  }
  return OK;
}

ECM AMTomlConfigStore::Dump(
    AMDomain::config::DocumentKind kind, const std::filesystem::path &dst_path,
    bool async) {
  if (async) {
    const std::filesystem::path dst_copy = dst_path;
    SubmitWriteTask([this, kind, dst_copy]() -> ECM {
      return Dump(kind, dst_copy, false);
    });
    return OK;
  }

  auto handle = GetHandle_(kind);
  if (!handle) {
    ECM rcm = Err(EC::ConfigNotInitialized, "", "",
                  "document handle not initialized");
    NotifyDumpError_(rcm);
    return rcm;
  }
  if (dst_path.empty() && !handle->IsDirty()) {
    return OK;
  }

  ECM rcm = dst_path.empty() ? handle->DumpInplace() : handle->DumpTo(dst_path);
  if (!(rcm)) {
    NotifyDumpError_(rcm);
  }
  return rcm;
}

ECM AMTomlConfigStore::DumpAll(bool async) {
  if (async) {
    SubmitWriteTask([this]() -> ECM { return DumpAll(false); });
    return OK;
  }
  for (const auto kind : kRequiredKinds) {
    ECM rcm = Dump(kind, {}, false);
    if (!(rcm)) {
      return rcm;
    }
  }
  return OK;
}

void AMTomlConfigStore::Close() {
  writer_.Stop();
  std::lock_guard<std::mutex> lock(mtx_);
  for (auto &[_, handle] : handles_) {
    if (handle) {
      handle->Close();
    }
  }
  handles_.clear();
  layout_.clear();
  root_dir_.clear();
  initialized_ = false;
}

bool AMTomlConfigStore::IsDirty(
    AMDomain::config::DocumentKind kind) const {
  auto handle = GetHandle_(kind);
  return handle && handle->IsDirty();
}

bool AMTomlConfigStore::GetDataPath(
    AMDomain::config::DocumentKind kind, std::filesystem::path *out) const {
  if (!out) {
    return false;
  }
  std::lock_guard<std::mutex> lock(mtx_);
  auto it = layout_.find(kind);
  if (it == layout_.end()) {
    return false;
  }
  *out = it->second.data_path;
  return true;
}

bool AMTomlConfigStore::Read(const std::type_index &type_key, void *out) const {
  if (!out) {
    return false;
  }
  const IArgCodec *codec = codec_registry_.Find(type_key);
  if (!codec) {
    return false;
  }
  auto handle = GetHandle_(codec->Kind());
  if (!handle) {
    return false;
  }
  Json root = Json::object();
  if (!handle->GetJson(&root)) {
    return false;
  }
  return DecodeArg(codec_registry_, type_key, root, out, nullptr);
}

bool AMTomlConfigStore::Write(const std::type_index &type_key,
                              const void *in) {
  if (!in) {
    return false;
  }
  const IArgCodec *codec = codec_registry_.Find(type_key);
  if (!codec) {
    return false;
  }
  auto handle = GetHandle_(codec->Kind());
  if (!handle) {
    return false;
  }
  Json root = Json::object();
  if (!handle->GetJson(&root)) {
    return false;
  }
  if (!EncodeArg(codec_registry_, type_key, in, &root, nullptr)) {
    return false;
  }
  return handle->SetJson(root);
}

bool AMTomlConfigStore::Erase(const std::type_index &type_key,
                              const void *in) {
  if (!in) {
    return false;
  }
  const IArgCodec *codec = codec_registry_.Find(type_key);
  if (!codec) {
    return false;
  }
  auto handle = GetHandle_(codec->Kind());
  if (!handle) {
    return false;
  }
  Json root = Json::object();
  if (!handle->GetJson(&root)) {
    return false;
  }
  if (!EraseArg(codec_registry_, type_key, in, &root, nullptr)) {
    return false;
  }
  return handle->SetJson(root);
}

void AMTomlConfigStore::SetDumpErrorCallback(DumpErrorCallback cb) {
  dump_error_cb_ = std::move(cb);
}

void AMTomlConfigStore::SubmitWriteTask(std::function<ECM()> task) {
  if (!task) {
    return;
  }
  if (!writer_.IsRunning()) {
    ECM rcm = task();
    if (!(rcm)) {
      NotifyDumpError_(rcm);
    }
    return;
  }
  writer_.Submit([this, task = std::move(task)]() mutable {
    ECM rcm = task();
    if (!(rcm)) {
      NotifyDumpError_(rcm);
    }
  });
}

std::filesystem::path AMTomlConfigStore::ProjectRoot() const {
  return root_dir_;
}

ECM AMTomlConfigStore::EnsureDirectory(
    const std::filesystem::path &dir) {
  std::error_code ec;
  std::filesystem::create_directories(dir, ec);
  if (ec) {
    return Err(EC::ConfigDumpFailed, "", "", ec.message());
  }
  return OK;
}

void AMTomlConfigStore::PruneBackupFiles(
    const std::filesystem::path &bak_dir, int64_t max_count) {
  if (max_count <= 0) {
    return;
  }
  std::error_code ec;
  if (!std::filesystem::exists(bak_dir, ec) || ec) {
    return;
  }
  std::vector<std::filesystem::path> stamp_dirs = {};
  for (const auto &entry : std::filesystem::directory_iterator(bak_dir, ec)) {
    if (ec) {
      break;
    }
    if (!IsBackupStampDirectory_(entry, ec)) {
      continue;
    }
    stamp_dirs.push_back(entry.path());
  }
  if (stamp_dirs.size() <= static_cast<size_t>(max_count)) {
    return;
  }
  std::sort(stamp_dirs.begin(), stamp_dirs.end(), LessByFolderName_);
  const size_t remove_count =
      stamp_dirs.size() - static_cast<size_t>(max_count);
  for (size_t i = 0; i < remove_count; ++i) {
    std::filesystem::remove_all(stamp_dirs[i], ec);
  }
}

std::shared_ptr<IConfigFileHandle> AMTomlConfigStore::GetHandle_(
    AMDomain::config::DocumentKind kind) {
  std::lock_guard<std::mutex> lock(mtx_);
  auto it = handles_.find(kind);
  if (it == handles_.end()) {
    return nullptr;
  }
  return it->second;
}

std::shared_ptr<const IConfigFileHandle> AMTomlConfigStore::GetHandle_(
    AMDomain::config::DocumentKind kind) const {
  std::lock_guard<std::mutex> lock(mtx_);
  auto it = handles_.find(kind);
  if (it == handles_.end()) {
    return nullptr;
  }
  return it->second;
}

ECM AMTomlConfigStore::LoadDocument_(
    AMDomain::config::DocumentKind kind) {
  ConfigDocumentSpec spec = {};
  {
    std::lock_guard<std::mutex> lock(mtx_);
    auto spec_it = layout_.find(kind);
    if (spec_it == layout_.end()) {
      return Err(EC::ConfigNotInitialized, "", "", "missing document layout");
    }
    spec = spec_it->second;
  }

  auto handle = std::make_shared<TomlConfigHandle>();
  ECM rcm = handle->Init(spec);
  if (!(rcm)) {
    return rcm;
  }
  {
    std::lock_guard<std::mutex> lock(mtx_);
    handles_[kind] = std::move(handle);
  }
  return OK;
}

void AMTomlConfigStore::NotifyDumpError_(const ECM &err) const {
  if (dump_error_cb_) {
    dump_error_cb_(err);
  }
}
} // namespace AMInfra::config


