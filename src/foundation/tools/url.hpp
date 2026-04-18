#pragma once

#include "foundation/tools/path.hpp"
#include "foundation/tools/string.hpp"

#include <algorithm>
#include <string>

namespace AMUrl {

inline std::string StripQueryAndFragment(const std::string &url) {
  const size_t query = url.find('?');
  const size_t fragment = url.find('#');
  size_t cut = std::string::npos;
  if (query != std::string::npos) {
    cut = query;
  }
  if (fragment != std::string::npos) {
    cut = (cut == std::string::npos) ? fragment : std::min(cut, fragment);
  }
  return (cut == std::string::npos) ? url : url.substr(0, cut);
}

inline bool IsHttpUrl(const std::string &url) {
  const std::string lower = AMStr::lowercase(AMStr::Strip(url));
  return lower.starts_with("http://") || lower.starts_with("https://");
}

inline bool IsHttpsUrl(const std::string &url) {
  const std::string lower = AMStr::lowercase(AMStr::Strip(url));
  return lower.starts_with("https://");
}

inline bool IsDirectoryUrl(const std::string &url) {
  const std::string clean = StripQueryAndFragment(AMStr::Strip(url));
  return !clean.empty() && clean.back() == '/';
}

inline std::string ExtractOrigin(const std::string &url) {
  const std::string trimmed = AMStr::Strip(url);
  const std::string lower = AMStr::lowercase(trimmed);
  const size_t scheme_pos = lower.find("://");
  if (scheme_pos == std::string::npos) {
    return trimmed;
  }
  const size_t host_begin = scheme_pos + 3;
  size_t host_end = trimmed.find('/', host_begin);
  if (host_end == std::string::npos) {
    host_end = trimmed.size();
  }
  return trimmed.substr(0, host_end);
}

inline std::string ResolveRedirectUrl(const std::string &base_url,
                                      const std::string &location) {
  const std::string trimmed_base = AMStr::Strip(base_url);
  const std::string trimmed_loc = AMStr::Strip(location);
  if (trimmed_loc.empty()) {
    return trimmed_base;
  }
  if (IsHttpUrl(trimmed_loc)) {
    return trimmed_loc;
  }

  const std::string origin = ExtractOrigin(trimmed_base);
  if (!trimmed_loc.empty() && trimmed_loc.front() == '/') {
    return origin + trimmed_loc;
  }

  const std::string no_qf = StripQueryAndFragment(trimmed_base);
  const size_t slash = no_qf.find_last_of('/');
  if (slash == std::string::npos) {
    return origin + "/" + trimmed_loc;
  }
  return no_qf.substr(0, slash + 1) + trimmed_loc;
}

inline std::string Basename(const std::string &url) {
  const std::string clean = StripQueryAndFragment(AMStr::Strip(url));
  return AMPath::basename(clean);
}

inline std::string ExtractUsername(const std::string &url) {
  const std::string trimmed = AMStr::Strip(url);
  const size_t scheme_pos = trimmed.find("://");
  if (scheme_pos == std::string::npos) {
    return "";
  }
  const size_t auth_begin = scheme_pos + 3;
  const size_t at = trimmed.find('@', auth_begin);
  if (at == std::string::npos) {
    return "";
  }
  const size_t slash = trimmed.find('/', auth_begin);
  if (slash != std::string::npos && at > slash) {
    return "";
  }
  const std::string auth = trimmed.substr(auth_begin, at - auth_begin);
  const size_t colon = auth.find(':');
  if (colon == std::string::npos) {
    return auth;
  }
  return auth.substr(0, colon);
}

inline std::string ExtractPassword(const std::string &url) {
  const std::string trimmed = AMStr::Strip(url);
  const size_t scheme_pos = trimmed.find("://");
  if (scheme_pos == std::string::npos) {
    return "";
  }
  const size_t auth_begin = scheme_pos + 3;
  const size_t at = trimmed.find('@', auth_begin);
  if (at == std::string::npos) {
    return "";
  }
  const size_t slash = trimmed.find('/', auth_begin);
  if (slash != std::string::npos && at > slash) {
    return "";
  }
  const std::string auth = trimmed.substr(auth_begin, at - auth_begin);
  const size_t colon = auth.find(':');
  if (colon == std::string::npos || colon + 1 >= auth.size()) {
    return "";
  }
  return auth.substr(colon + 1);
}

} // namespace AMUrl
