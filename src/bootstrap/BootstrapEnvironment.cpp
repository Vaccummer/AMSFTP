#include "bootstrap/BootstrapEnvironment.hpp"

#include "domain/config/ConfigStorePort.hpp"
#include "foundation/tools/string.hpp"
#include "interface/prompt/Prompt.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace AMBootstrap {
namespace {

constexpr const char *kRootEnvKey = "AMSFTP_ROOT";

struct ManagedTarget final {
  std::filesystem::path relative_path = {};
  std::string content = {};
};

std::filesystem::path NormalizeRootPath_(std::string value) {
  AMStr::VStrip(value);
  if (value.empty()) {
    return {};
  }
  std::error_code ec;
  std::filesystem::path p(value);
  p = p.lexically_normal();
  const auto abs = std::filesystem::absolute(p, ec);
  if (ec) {
    return p;
  }
  return abs.lexically_normal();
}

std::vector<ManagedTarget>
BuildManagedTargets_(const std::filesystem::path &root_dir) {
  std::vector<ManagedTarget> out = {};
  const auto init_arg =
      AMDomain::config::BuildDefaultConfigStoreInitArg(root_dir);
  std::vector<AMDomain::config::ConfigDocumentSpec> specs = {};
  specs.reserve(init_arg.layout.size());
  for (const auto &[_, spec] : init_arg.layout) {
    specs.push_back(spec);
  }
  std::ranges::sort(specs, [](const auto &lhs, const auto &rhs) {
    return static_cast<int>(lhs.kind) < static_cast<int>(rhs.kind);
  });
  out.reserve(specs.size());
  for (const auto &spec : specs) {
    out.push_back({spec.data_path.lexically_relative(root_dir), ""});
  }
  return out;
}

ECM WriteTextFile_(const std::filesystem::path &file_path,
                   const std::string &content) {
  std::error_code ec;
  const auto parent = file_path.parent_path();
  if (!parent.empty()) {
    std::filesystem::create_directories(parent, ec);
    if (ec) {
      return {EC::ConfigDumpFailed, "bootstrap init root", file_path.string(),
              ec.message()};
    }
  }

  if (std::filesystem::exists(file_path, ec) && !ec &&
      std::filesystem::is_directory(file_path, ec)) {
    return {EC::ConfigDumpFailed, "bootstrap init root", file_path.string(),
            "target path is a directory"};
  }

  std::ofstream out(file_path,
                    std::ios::out | std::ios::trunc | std::ios::binary);
  if (!out.is_open()) {
    return {EC::ConfigDumpFailed, "bootstrap init root", file_path.string(),
            "failed to open file for writing"};
  }
  out << content;
  if (!out.good()) {
    return {EC::ConfigDumpFailed, "bootstrap init root", file_path.string(),
            "failed to write file"};
  }
  return OK;
}

ECM EnsureRootLayout_(const std::filesystem::path &root_dir) {
  std::error_code ec;
  std::filesystem::create_directories(root_dir / "config", ec);
  if (ec) {
    return {EC::ConfigDumpFailed, "bootstrap init root", root_dir.string(),
            ec.message()};
  }
  std::filesystem::create_directories(root_dir / "config" / "bak", ec);
  if (ec) {
    return {EC::ConfigDumpFailed, "bootstrap init root", root_dir.string(),
            ec.message()};
  }
  return OK;
}

ECM InitProjectRoot_(const std::filesystem::path &root_dir) {
  std::error_code ec;
  if (std::filesystem::exists(root_dir, ec) && !ec &&
      !std::filesystem::is_directory(root_dir, ec)) {
    return {EC::InvalidArg, "bootstrap init root", root_dir.string(),
            "root path exists but is not a directory"};
  }

  ec.clear();
  std::filesystem::create_directories(root_dir, ec);
  if (ec) {
    return {EC::ConfigDumpFailed, "bootstrap init root", root_dir.string(),
            ec.message()};
  }

  ECM rcm = EnsureRootLayout_(root_dir);
  if (!rcm) {
    return rcm;
  }

  for (const auto &target : BuildManagedTargets_(root_dir)) {
    const auto abs_path = root_dir / target.relative_path;
    ec.clear();
    if (std::filesystem::exists(abs_path, ec) && !ec) {
      continue;
    }
    if (ec) {
      return {EC::ConfigDumpFailed, "bootstrap init root", abs_path.string(),
              ec.message()};
    }
    rcm = WriteTextFile_(abs_path, target.content);
    if (!rcm) {
      return rcm;
    }
  }

  return OK;
}

} // namespace

ECMData<fs::path> ResolveRootDir() {
  std::string env_root = {};
  if (!AMStr::GetEnv(kRootEnvKey, &env_root)) {
    return {fs::path{}, Err(EC::ConfigNotInitialized, "bootstrap resolve root",
                            "$AMSFTP_ROOT", "env variable not set")};
  }
  AMStr::VStrip(env_root);
  if (env_root.empty()) {
    return {fs::path{}, Err(EC::ConfigNotInitialized, "bootstrap resolve root",
                            "$AMSFTP_ROOT", "AMSFTP_ROOT is empty")};
  }

  fs::path root_dir = NormalizeRootPath_(env_root);
  if (root_dir.empty()) {
    return {fs::path{}, Err(EC::InvalidArg, "bootstrap resolve root", env_root,
                            "resolved root directory is empty")};
  }

  std::error_code ec;
  if (std::filesystem::exists(root_dir, ec) && !ec &&
      !std::filesystem::is_directory(root_dir, ec)) {
    return {fs::path{},
            Err(EC::InvalidArg, "bootstrap resolve root", root_dir.string(),
                "AMSFTP_ROOT exists but is not a directory")};
  }
  if (ec) {
    return {fs::path{}, Err(EC::ConfigLoadFailed, "bootstrap resolve root",
                            root_dir.string(), ec.message())};
  }

  const ECM init_rcm = InitProjectRoot_(root_dir);
  if (!init_rcm) {
    return {fs::path{}, init_rcm};
  }
  return {root_dir, OK};
}

void PrintBootstrapWarn(const std::string &msg) {
  AMInterface::prompt::PromptIOManager::StaticPrint(msg);
}

} // namespace AMBootstrap
