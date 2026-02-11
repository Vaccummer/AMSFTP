#include "AMManager/Client.hpp"
#include "AMManager/Config.hpp"
#include "AMManager/Host.hpp"

namespace AMClientManage {

Reader::Reader(AMConfigManager &config) : config_(config) {}

std::pair<ECM, AMConfigManager::ClientConfig>
Reader::GetClientConfig(const std::string &nickname) {
  return config_.Host().GetClientConfig(nickname);
}

std::pair<ECM, std::optional<AMConfigManager::KnownHostEntry>>
Reader::FindKnownHost(const std::string &hostname, int port,
                      const std::string &protocol) const {
  return config_.Host().FindKnownHost(hostname, port, protocol);
}

AMConfigManager::KnownHostCallback Reader::BuildKnownHostCallback() {
  if (known_host_cb_) {
    return known_host_cb_;
  }
  known_host_cb_ = [this](AMConfigManager::KnownHostEntry entry) -> ECM {
    if (entry.hostname.empty() || entry.protocol.empty() || entry.port <= 0) {
      return {EC::InvalidArg, "invalid known host entry"};
    }

    entry.fingerprint = AMStr::Strip(entry.fingerprint);
    entry.fingerprint_sha256 = AMStr::Strip(entry.fingerprint_sha256);
    if (entry.fingerprint.empty()) {
      return {EC::InvalidArg, "empty host fingerprint"};
    }

    auto [find_status, existing] =
        FindKnownHost(entry.hostname, entry.port, entry.protocol);
    if (find_status.first != EC::Success) {
      return find_status;
    }

    AMPromptManager &prompt = AMPromptManager::Instance();
    if (!existing.has_value() || AMStr::Strip(existing->fingerprint).empty()) {
      const std::string question = AMStr::amfmt(
          "No known host fingerprint for {}:{} {}.\n"
          "Fingerprint: {}",
          entry.hostname, entry.port, entry.protocol, entry.fingerprint);
      prompt.Print(question);
      bool canceled = false;
      const bool accepted = prompt.PromptYesNo("Add it? (y/N): ", &canceled);
      if (canceled || !accepted) {
        return {EC::ConfigCanceled, "Known host fingerprint add canceled"};
      }
      return UpsertKnownHost(entry, true);
    }

    const std::string expected_fp = AMStr::Strip(existing->fingerprint);
    const std::string expected_lower = AMStr::lowercase(expected_fp);
    if (expected_lower.rfind("sha256:", 0) == 0) {
      const std::string expected_body = AMStr::Strip(expected_fp.substr(7));
      if (entry.fingerprint_sha256.empty() ||
          expected_body != entry.fingerprint_sha256) {
        return {EC::HostFingerprintMismatch,
                AMStr::amfmt("{}:{} {} fingerprint mismatches", entry.hostname,
                             entry.port, entry.protocol)};
      }
      return {EC::Success, ""};
    }

    if (expected_fp != entry.fingerprint) {
      return {EC::HostFingerprintMismatch,
              AMStr::amfmt("{}:{} {} fingerprint mismatches", entry.hostname,
                           entry.port, entry.protocol)};
    }

    return {EC::Success, ""};
  };
  return known_host_cb_;
}

ECM Reader::UpsertKnownHost(const AMConfigManager::KnownHostEntry &entry,
                            bool dump_now) {
  return config_.Host().UpsertKnownHost(entry, dump_now);
}

} // namespace AMClientManage
