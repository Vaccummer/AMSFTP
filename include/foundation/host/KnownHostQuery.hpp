#pragma once
#include <string>
#include <string_view>
#include <vector>

/**
 * @brief Value object used to identify and validate one known-host entry.
 *
 * This model is shared by domain services and infrastructure adapters.
 */
class KnownHostQuery {
public:
  std::string nickname = "";
  std::string hostname = "";
  int port = 0;
  std::string protocol = "";
  std::string username = "";

  /**
   * @brief Construct one query from explicit host identity fields.
   */
  KnownHostQuery(std::string_view nickname, std::string_view hostname, int port,
                 std::string_view protocol, std::string_view username,
                 std::string_view fingerprint = "")
      : nickname(nickname), hostname(hostname), port(port), protocol(protocol),
        username(username), fingerprint_(fingerprint) {}

  /**
   * @brief Construct one empty query.
   */
  KnownHostQuery() = default;

  /**
   * @brief Return whether the query has minimum valid host identity fields.
   */
  [[nodiscard]] bool IsValid() const {
    return !hostname.empty() && port > 0 && port <= 65535;
  }

  /**
   * @brief Build hierarchical config path keys for known-host storage lookup.
   */
  [[nodiscard]] std::vector<std::string> GetPath() const {
    return {hostname, std::to_string(port), username, protocol};
  }

  /**
   * @brief Set fingerprint value.
   *
   * @return True when non-empty fingerprint is accepted.
   */
  bool SetFingerprint(const std::string &fingerprint) {
    if (fingerprint.empty()) {
      return false;
    }
    fingerprint_ = fingerprint;
    return true;
  }

  /**
   * @brief Get currently stored fingerprint text.
   */
  [[nodiscard]] std::string GetFingerprint() const { return fingerprint_; }

private:
  std::string fingerprint_ = "";
};
