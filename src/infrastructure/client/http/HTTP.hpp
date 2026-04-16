#pragma once

#include "domain/client/ClientDomainService.hpp"
#include "foundation/tools/url.hpp"
#include "infrastructure/client/common/Base.hpp"
#include <curl/curl.h>
#include <optional>
#include <string>

namespace AMInfra::client::HTTP {
namespace {
using ClientStatus = AMDomain::client::ClientStatus;
using ClientControlComponent = AMDomain::client::ClientControlComponent;
using ConRequest = AMDomain::host::ConRequest;
using ClientProtocol = AMDomain::host::ClientProtocol;
namespace AMFSI = AMDomain::filesystem;
constexpr long kMaxRedirects = 10L;
constexpr const char *kHttpUserAgent = "AMSFTP/1.0 (HTTP Downloader)";

struct HttpRuntimeMetadata {
  bool transient = true;
  std::string source_url = {};
  std::string effective_url = {};
  std::string proxy = {};
  int redirect_times = 0;
};

struct HttpHeaderProbe {
  std::optional<int64_t> content_length = std::nullopt;
  std::optional<int64_t> content_range_total = std::nullopt;
  std::optional<std::string> raw_download_url = std::nullopt;
  std::optional<std::string> location_url = std::nullopt;
  bool accept_ranges_bytes = false;
};

struct CurlStopContext {
  const ClientControlComponent *control = nullptr;
};

inline static std::optional<int64_t>
ParsePositiveInt64_(const std::string &text) {
  int64_t value = 0;
  if (!AMStr::GetNumber(AMStr::Strip(text), &value) || value < 0) {
    return std::nullopt;
  }
  return value;
}

inline static size_t ProbeHeaderWk_(char *buffer, size_t size, size_t nitems,
                                    void *userdata) {
  if (!buffer || !userdata) {
    return size * nitems;
  }
  const size_t total = size * nitems;
  if (total == 0) {
    return 0;
  }
  auto *probe = static_cast<HttpHeaderProbe *>(userdata);
  std::string line(buffer, total);
  const std::string lower = AMStr::lowercase(line);
  const auto pick_value = [&](const std::string &prefix) -> std::string {
    if (!lower.starts_with(prefix)) {
      return "";
    }
    return AMStr::Strip(line.substr(prefix.size()));
  };

  if (const std::string v = pick_value("content-length:"); !v.empty()) {
    auto parsed = ParsePositiveInt64_(v);
    if (parsed.has_value()) {
      probe->content_length = *parsed;
    }
  } else if (const std::string v = pick_value("accept-ranges:"); !v.empty()) {
    const std::string lower_v = AMStr::lowercase(v);
    if (lower_v.find("bytes") != std::string::npos) {
      probe->accept_ranges_bytes = true;
    }
  } else if (const std::string v = pick_value("content-range:"); !v.empty()) {
    const size_t slash = v.find('/');
    if (slash != std::string::npos && slash + 1 < v.size()) {
      auto parsed = ParsePositiveInt64_(v.substr(slash + 1));
      if (parsed.has_value()) {
        probe->content_range_total = *parsed;
      }
    }
  } else if (const std::string v = pick_value("x-raw-download:"); !v.empty()) {
    const std::string url = AMStr::Strip(v);
    if (AMUrl::IsHttpUrl(url)) {
      probe->raw_download_url = url;
    }
  } else if (const std::string v = pick_value("location:"); !v.empty()) {
    const std::string url = AMStr::Strip(v);
    if (AMUrl::IsHttpUrl(url)) {
      probe->location_url = url;
    }
  }
  return total;
}

inline static size_t DiscardWriteWk_(char *ptr, size_t size, size_t nmemb,
                                     void *userdata) {
  (void)ptr;
  (void)userdata;
  return size * nmemb;
}

inline static int CurlStopWk_(void *clientp, curl_off_t dltotal,
                              curl_off_t dlnow, curl_off_t ultotal,
                              curl_off_t ulnow) {
  (void)dltotal;
  (void)dlnow;
  (void)ultotal;
  (void)ulnow;
  auto *ctx = static_cast<CurlStopContext *>(clientp);
  if (!ctx || !ctx->control) {
    return 0;
  }
  if (ctx->control->IsInterrupted() || ctx->control->IsTimeout()) {
    return 1;
  }
  return 0;
}

inline static ECM MapHttpResponse_(long http_code, const std::string &action,
                                   const std::string &target) {
  if (http_code >= 200 && http_code < 300) {
    return OK;
  }
  if (http_code == 404) {
    return Err(EC::PathNotExist, action, target, "Remote file not found");
  }
  if (http_code == 401 || http_code == 403) {
    return Err(EC::PermissionDenied, action, target, "Permission denied");
  }
  if (http_code == 416) {
    return Err(EC::InvalidOffset, action, target, "Invalid range");
  }
  if (http_code >= 400 && http_code < 500) {
    return Err(EC::InvalidArg, action, target,
               AMStr::fmt("HTTP status {}", http_code));
  }
  if (http_code >= 500 && http_code < 600) {
    return Err(EC::CommonFailure, action, target,
               AMStr::fmt("HTTP status {}", http_code));
  }
  return Err(EC::UnknownError, action, target,
             AMStr::fmt("Unexpected HTTP status {}", http_code));
}

inline static ECM BuildCurlError_(CURLcode code, const std::string &action,
                                  const std::string &target) {
  if (code == CURLE_ABORTED_BY_CALLBACK) {
    return Err(EC::Terminate, action, target, "Operation interrupted",
               RawError{RawErrorSource::Curl, static_cast<int>(code)});
  }
  return Err(EC::NetworkError, action, target, curl_easy_strerror(code),
             RawError{RawErrorSource::Curl, static_cast<int>(code)});
}
} // namespace

class AMHTTPIOCore final : public ClientIOBase {
public:
  struct HeadProbeResult {
    long response_code = 0;
    std::string location_url = {};
    std::optional<int64_t> content_length = std::nullopt;
  };

  struct RedirectResolveResult {
    std::string final_url = {};
    int redirect_count = 0;
    long final_response_code = 0;
    std::optional<int64_t> content_length = std::nullopt;
  };

  struct RangeProbeResult {
    long response_code = 0;
    bool is_allowed = false;
    bool supports_resume = false;
    std::optional<int64_t> total_size = std::nullopt;
    std::string raw_download_url = {};
  };

  AMHTTPIOCore(AMDomain::client::IClientConfigPort *config,
               AMDomain::client::IClientControlToken *control,
               AMDomain::client::IClientMetaDataPort *metadata = nullptr)
      : ClientIOBase(config, control), metadata_part_(metadata) {}

  [[nodiscard]] bool SupportsRange() const {
    return supports_range_.load(std::memory_order_acquire);
  }
  [[nodiscard]] bool HasKnownSize() const {
    return has_known_size_.load(std::memory_order_acquire);
  }

  [[nodiscard]] std::string Proxy() const { return ResolveProxy_(); }
  [[nodiscard]] std::string BearerToken() const {
    return ResolveBearerToken_();
  }

  [[nodiscard]] ECMData<HeadProbeResult>
  ProbeHead(const std::string &url,
            const ClientControlComponent &control) const {
    if (!AMUrl::IsHttpUrl(url) || AMUrl::IsDirectoryUrl(url)) {
      return {HeadProbeResult{},
              Err(EC::InvalidArg, "http.head", url, "Invalid HTTP URL")};
    }
    const std::string proxy = ResolveProxy_();
    const std::string bear_token = ResolveBearerToken_();

    CURL *curl = curl_easy_init();
    if (!curl) {
      return {HeadProbeResult{}, Err(EC::InvalidHandle, "http.head", url,
                                     "curl_easy_init failed")};
    }

    CurlStopContext stop_ctx = {&control};
    HttpHeaderProbe probe = {};
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, ProbeHeaderWk_);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &probe);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, DiscardWriteWk_);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, nullptr);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, CurlStopWk_);
    curl_easy_setopt(curl, CURLOPT_XFERINFODATA, &stop_ctx);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, kHttpUserAgent);
    if (!proxy.empty()) {
      curl_easy_setopt(curl, CURLOPT_PROXY, proxy.c_str());
    }

    struct curl_slist *headers = nullptr;
    if (!bear_token.empty()) {
      headers = curl_slist_append(
          headers, AMStr::fmt("Authorization: Bearer {}", bear_token).c_str());
      curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }

    CURLcode curl_rcm = curl_easy_perform(curl);
    long response = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);
    const bool need_get_fallback =
        (curl_rcm != CURLE_OK || response == 405 || response == 501);
    if (need_get_fallback) {
      probe = {};
      curl_easy_reset(curl);
      curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
      curl_easy_setopt(curl, CURLOPT_NOBODY, 0L);
      curl_easy_setopt(curl, CURLOPT_RANGE, "bytes=0-0");
      curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, ProbeHeaderWk_);
      curl_easy_setopt(curl, CURLOPT_HEADERDATA, &probe);
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, DiscardWriteWk_);
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, nullptr);
      curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
      curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, CurlStopWk_);
      curl_easy_setopt(curl, CURLOPT_XFERINFODATA, &stop_ctx);
      curl_easy_setopt(curl, CURLOPT_USERAGENT, kHttpUserAgent);
      if (!proxy.empty()) {
        curl_easy_setopt(curl, CURLOPT_PROXY, proxy.c_str());
      }
      if (headers) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
      }
      curl_rcm = curl_easy_perform(curl);
      response = 0;
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);
    }

    if (headers) {
      curl_slist_free_all(headers);
    }
    curl_easy_cleanup(curl);

    if (control.IsInterrupted()) {
      return {HeadProbeResult{}, Err(EC::Terminate, "http.head", url,
                                     "Operation interrupted by user")};
    }
    if (control.IsTimeout()) {
      return {HeadProbeResult{},
              Err(EC::OperationTimeout, "http.head", url, "Operation timeout")};
    }
    if (curl_rcm != CURLE_OK) {
      return {HeadProbeResult{}, BuildCurlError_(curl_rcm, "http.head", url)};
    }

    HeadProbeResult result = {};
    result.response_code = response;
    if (probe.location_url.has_value()) {
      result.location_url = *probe.location_url;
    }
    if (probe.content_length.has_value() && *probe.content_length >= 0) {
      result.content_length = probe.content_length;
    } else if (probe.content_range_total.has_value() &&
               *probe.content_range_total >= 0) {
      result.content_length = probe.content_range_total;
    }
    if (probe.raw_download_url.has_value() && result.location_url.empty()) {
      result.location_url = *probe.raw_download_url;
    }
    return {result, OK};
  }

  [[nodiscard]] ECMData<RedirectResolveResult>
  ResolveRedirectChain(const std::string &url, int max_redirects,
                       const ClientControlComponent &control) const {
    const std::string normalized = AMStr::Strip(url);
    if (!AMUrl::IsHttpUrl(normalized) || AMUrl::IsDirectoryUrl(normalized)) {
      return {RedirectResolveResult{}, Err(EC::InvalidArg, "http.redirect",
                                           normalized, "Invalid HTTP URL")};
    }
    int redirect_limit = max_redirects;
    if (redirect_limit < 0) {
      redirect_limit = 0;
    }

    RedirectResolveResult out = {};
    out.final_url = normalized;
    for (int hops = 0; hops <= redirect_limit; ++hops) {
      auto probe = ProbeHead(out.final_url, control);
      if (!probe.rcm) {
        return {out, probe.rcm};
      }
      out.final_response_code = probe.data.response_code;
      out.content_length = probe.data.content_length;
      const std::string location = AMStr::Strip(probe.data.location_url);
      if (location.empty()) {
        return {out, OK};
      }
      if (hops >= redirect_limit) {
        return {out,
                Err(EC::OperationUnsupported, "http.redirect", normalized,
                    AMStr::fmt("Redirect exceeds limit {}", redirect_limit))};
      }
      const std::string next =
          AMUrl::ResolveRedirectUrl(out.final_url, location);
      if (!AMUrl::IsHttpUrl(next)) {
        return {out,
                Err(EC::InvalidArg, "http.redirect", normalized,
                    AMStr::fmt("Unsupported redirect target: {}", location))};
      }
      if (next == out.final_url) {
        return {out, OK};
      }
      out.final_url = next;
      out.redirect_count = hops + 1;
    }
    return {out, OK};
  }

  [[nodiscard]] ECMData<RangeProbeResult>
  ProbeOneByteRange(const std::string &url,
                    const ClientControlComponent &control) const {
    if (!AMUrl::IsHttpUrl(url) || AMUrl::IsDirectoryUrl(url)) {
      return {RangeProbeResult{},
              Err(EC::InvalidArg, "http.probe", url, "Invalid HTTP URL")};
    }
    const std::string proxy = ResolveProxy_();
    const std::string bear_token = ResolveBearerToken_();

    CURL *curl = curl_easy_init();
    if (!curl) {
      return {RangeProbeResult{}, Err(EC::InvalidHandle, "http.probe", url,
                                      "curl_easy_init failed")};
    }

    CurlStopContext stop_ctx = {&control};
    HttpHeaderProbe probe = {};
    struct curl_slist *headers = nullptr;
    if (!bear_token.empty()) {
      headers = curl_slist_append(
          headers, AMStr::fmt("Authorization: Bearer {}", bear_token).c_str());
    }

    long response = 0;
    const auto run_probe = [&](bool no_body) -> CURLcode {
      probe = {};
      curl_easy_reset(curl);
      curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
      curl_easy_setopt(curl, CURLOPT_MAXREDIRS, kMaxRedirects);
      curl_easy_setopt(curl, CURLOPT_USERAGENT, kHttpUserAgent);
      curl_easy_setopt(curl, CURLOPT_NOBODY, no_body ? 1L : 0L);
      curl_easy_setopt(curl, CURLOPT_RANGE, "bytes=0-0");
      curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, ProbeHeaderWk_);
      curl_easy_setopt(curl, CURLOPT_HEADERDATA, &probe);
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, DiscardWriteWk_);
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, nullptr);
      curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
      curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, CurlStopWk_);
      curl_easy_setopt(curl, CURLOPT_XFERINFODATA, &stop_ctx);
      if (!proxy.empty()) {
        curl_easy_setopt(curl, CURLOPT_PROXY, proxy.c_str());
      }
      if (headers) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
      }
      const CURLcode code = curl_easy_perform(curl);
      response = 0;
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);
      return code;
    };

    CURLcode curl_rcm = run_probe(true);
    const auto has_total_size = [&]() -> bool {
      return (probe.content_range_total.has_value() &&
              *probe.content_range_total > 0) ||
             (probe.content_length.has_value() && *probe.content_length > 0);
    };
    const bool need_get_fallback =
        (curl_rcm != CURLE_OK || response == 405 || response == 501 ||
         ((response == 200 || response == 206) && !has_total_size()));
    if (need_get_fallback) {
      curl_rcm = run_probe(false);
    }

    if (headers) {
      curl_slist_free_all(headers);
    }
    curl_easy_cleanup(curl);

    if (control.IsInterrupted()) {
      return {RangeProbeResult{}, Err(EC::Terminate, "http.probe", url,
                                      "Operation interrupted by user")};
    }
    if (control.IsTimeout()) {
      return {RangeProbeResult{}, Err(EC::OperationTimeout, "http.probe", url,
                                      "Operation timeout")};
    }
    if (curl_rcm != CURLE_OK) {
      return {RangeProbeResult{}, BuildCurlError_(curl_rcm, "http.probe", url)};
    }

    RangeProbeResult result = {};
    result.response_code = response;
    result.is_allowed = (response == 200 || response == 206);
    result.supports_resume = (response == 206);
    if (probe.content_range_total.has_value() &&
        *probe.content_range_total > 0) {
      result.total_size = probe.content_range_total;
    } else if (probe.content_length.has_value() && *probe.content_length > 0) {
      result.total_size = probe.content_length;
    }
    if (probe.raw_download_url.has_value()) {
      result.raw_download_url = *probe.raw_download_url;
    }

    supports_range_.store(result.supports_resume || probe.accept_ranges_bytes,
                          std::memory_order_release);
    has_known_size_.store(result.total_size.has_value(),
                          std::memory_order_release);
    return {result, OK};
  }

  [[nodiscard]] ECMData<bool>
  ProbeResumeSupport(const std::string &url, size_t offset,
                     const ClientControlComponent &control) const {
    if (!AMUrl::IsHttpUrl(url) || AMUrl::IsDirectoryUrl(url)) {
      return {false,
              Err(EC::InvalidArg, "http.probe", url, "Invalid HTTP URL")};
    }
    const std::string proxy = ResolveProxy_();
    const std::string bear_token = ResolveBearerToken_();
    if (offset == 0) {
      auto probe = ProbeOneByteRange(url, control);
      if (!(probe.rcm)) {
        return {false, probe.rcm};
      }
      return {probe.data.is_allowed, OK};
    }

    CURL *curl = curl_easy_init();
    if (!curl) {
      return {false, Err(EC::InvalidHandle, "http.probe", url,
                         "curl_easy_init failed")};
    }

    CurlStopContext stop_ctx = {&control};
    HttpHeaderProbe probe = {};
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, kMaxRedirects);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, kHttpUserAgent);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, ProbeHeaderWk_);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &probe);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, DiscardWriteWk_);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, nullptr);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, CurlStopWk_);
    curl_easy_setopt(curl, CURLOPT_XFERINFODATA, &stop_ctx);
    const std::string range_header = AMStr::fmt("bytes={}-", offset);
    curl_easy_setopt(curl, CURLOPT_RANGE, range_header.c_str());
    if (!proxy.empty()) {
      curl_easy_setopt(curl, CURLOPT_PROXY, proxy.c_str());
    }

    struct curl_slist *headers = nullptr;
    if (!bear_token.empty()) {
      headers = curl_slist_append(
          headers, AMStr::fmt("Authorization: Bearer {}", bear_token).c_str());
      curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }

    const CURLcode curl_rcm = curl_easy_perform(curl);
    long response = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);
    if (headers) {
      curl_slist_free_all(headers);
    }
    curl_easy_cleanup(curl);

    if (control.IsInterrupted()) {
      return {false, Err(EC::Terminate, "http.probe", url,
                         "Operation interrupted by user")};
    }
    if (control.IsTimeout()) {
      return {false, Err(EC::OperationTimeout, "http.probe", url,
                         "Operation timeout")};
    }
    if (curl_rcm != CURLE_OK) {
      return {false, BuildCurlError_(curl_rcm, "http.probe", url)};
    }
    return {response == 206, OK};
  }

  ECMData<AMFSI::UpdateOSTypeResult>
  UpdateOSType(const AMFSI::UpdateOSTypeArgs &args = {},
               const ClientControlComponent &control = {}) override {
    (void)args;
    (void)control;
    return {AMFSI::UpdateOSTypeResult{OS_TYPE::Unknown}, OK};
  }

  ECMData<AMFSI::UpdateHomeDirResult>
  UpdateHomeDir(const AMFSI::UpdateHomeDirArgs &args = {},
                const ClientControlComponent &control = {}) override {
    (void)args;
    (void)control;
    return {AMFSI::UpdateHomeDirResult{""},
            Err(EC::OperationUnsupported, "http.update_home", ClientTarget_(),
                "HTTP source has no home directory")};
  }

  ECMData<AMFSI::CheckResult>
  Check(const AMFSI::CheckArgs &args = {},
        const ClientControlComponent &control = {}) override {
    (void)args;
    if (control.IsInterrupted()) {
      return {AMFSI::CheckResult{ClientStatus::ConnectionBroken},
              Err(EC::Terminate, "http.check", ClientTarget_(),
                  "Operation interrupted")};
    }
    if (control.IsTimeout()) {
      return {AMFSI::CheckResult{ClientStatus::ConnectionBroken},
              Err(EC::OperationTimeout, "http.check", ClientTarget_(),
                  "Operation timeout")};
    }
    return {AMFSI::CheckResult{ClientStatus::OK}, OK};
  }

  ECMData<AMFSI::ConnectResult>
  Connect(const AMFSI::ConnectArgs &args = {},
          const ClientControlComponent &control = {}) override {
    (void)args;
    if (control.IsInterrupted()) {
      return {AMFSI::ConnectResult{ClientStatus::ConnectionBroken},
              Err(EC::Terminate, "http.connect", ClientTarget_(),
                  "Operation interrupted")};
    }
    if (control.IsTimeout()) {
      return {AMFSI::ConnectResult{ClientStatus::ConnectionBroken},
              Err(EC::OperationTimeout, "http.connect", ClientTarget_(),
                  "Operation timeout")};
    }
    connect_state("initialize HTTP source", ClientTarget_());
    return {AMFSI::ConnectResult{ClientStatus::OK}, OK};
  }

  ECMData<AMFSI::RTTResult>
  GetRTT(const AMFSI::GetRTTArgs &args = {},
         const ClientControlComponent &control = {}) override {
    (void)args;
    (void)control;
    return {AMFSI::RTTResult{-1.0},
            Err(EC::OperationUnsupported, "http.rtt", ClientTarget_(),
                "HTTP source does not support RTT test")};
  }

  ECMData<AMFSI::RunResult>
  ConductCmd(const AMFSI::ConductCmdArgs &args,
             const ClientControlComponent &control = {}) override {
    (void)args;
    (void)control;
    return {AMFSI::RunResult{"", -1},
            Err(EC::OperationUnsupported, "http.cmd", ClientTarget_(),
                "HTTP source does not support shell command")};
  }

  ECMData<AMFSI::StatResult>
  stat(const AMFSI::StatArgs &args,
       const ClientControlComponent &control = {}) override {
    const std::string url = AMStr::Strip(args.path);
    if (!AMUrl::IsHttpUrl(url)) {
      return {AMFSI::StatResult{},
              Err(EC::InvalidArg, "http.stat", args.path,
                  "Only http:// and https:// are supported")};
    }
    if (AMUrl::IsDirectoryUrl(url)) {
      return {AMFSI::StatResult{}, Err(EC::NotAFile, "http.stat", url,
                                       "HTTP directory URL is unsupported")};
    }
    const std::string proxy = ResolveProxy_();
    const std::string bear_token = ResolveBearerToken_();

    CURL *curl = curl_easy_init();
    if (!curl) {
      return {AMFSI::StatResult{}, Err(EC::InvalidHandle, "http.stat", url,
                                       "curl_easy_init failed")};
    }

    CurlStopContext stop_ctx = {&control};
    HttpHeaderProbe probe = {};
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, kMaxRedirects);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, kHttpUserAgent);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, ProbeHeaderWk_);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &probe);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, DiscardWriteWk_);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, nullptr);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, CurlStopWk_);
    curl_easy_setopt(curl, CURLOPT_XFERINFODATA, &stop_ctx);
    if (!proxy.empty()) {
      curl_easy_setopt(curl, CURLOPT_PROXY, proxy.c_str());
    }

    struct curl_slist *headers = nullptr;
    if (!bear_token.empty()) {
      headers = curl_slist_append(
          headers, AMStr::fmt("Authorization: Bearer {}", bear_token).c_str());
      curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }

    CURLcode curl_rcm = curl_easy_perform(curl);
    long response = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);
    bool need_get_fallback =
        (curl_rcm != CURLE_OK || response == 405 || response == 501);

    if (need_get_fallback) {
      probe = {};
      curl_easy_reset(curl);
      curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
      curl_easy_setopt(curl, CURLOPT_MAXREDIRS, kMaxRedirects);
      curl_easy_setopt(curl, CURLOPT_USERAGENT, kHttpUserAgent);
      curl_easy_setopt(curl, CURLOPT_RANGE, "bytes=0-0");
      curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, ProbeHeaderWk_);
      curl_easy_setopt(curl, CURLOPT_HEADERDATA, &probe);
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, DiscardWriteWk_);
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, nullptr);
      curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
      curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, CurlStopWk_);
      curl_easy_setopt(curl, CURLOPT_XFERINFODATA, &stop_ctx);
      if (!proxy.empty()) {
        curl_easy_setopt(curl, CURLOPT_PROXY, proxy.c_str());
      }
      if (headers) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
      }
      curl_rcm = curl_easy_perform(curl);
      response = 0;
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);
    }

    if (headers) {
      curl_slist_free_all(headers);
    }
    curl_easy_cleanup(curl);

    if (control.IsInterrupted()) {
      return {AMFSI::StatResult{},
              Err(EC::Terminate, "http.stat", url, "Operation interrupted")};
    }
    if (control.IsTimeout()) {
      return {AMFSI::StatResult{},
              Err(EC::OperationTimeout, "http.stat", url, "Operation timeout")};
    }
    if (curl_rcm != CURLE_OK) {
      return {AMFSI::StatResult{}, BuildCurlError_(curl_rcm, "http.stat", url)};
    }

    const ECM http_rcm = MapHttpResponse_(response, "http.stat", url);
    if (!(http_rcm)) {
      return {AMFSI::StatResult{}, http_rcm};
    }

    supports_range_.store(probe.accept_ranges_bytes, std::memory_order_release);
    has_known_size_.store(probe.content_range_total.has_value() ||
                              probe.content_length.has_value(),
                          std::memory_order_release);
    size_t size = 0;
    if (probe.content_range_total.has_value() &&
        *probe.content_range_total > 0) {
      size = static_cast<size_t>(*probe.content_range_total);
    } else if (probe.content_length.has_value() && *probe.content_length > 0) {
      size = static_cast<size_t>(*probe.content_length);
    }

    PathInfo info = {};
    info.path = url;
    info.name = AMUrl::Basename(url);
    if (info.name.empty()) {
      info.name = "download.bin";
    }
    info.dir = AMUrl::StripQueryAndFragment(url);
    const size_t slash = info.dir.find_last_of('/');
    if (slash != std::string::npos) {
      info.dir = info.dir.substr(0, slash);
    }
    info.size = size;
    info.type = PathType::FILE;
    info.mode_int = 0644;
    info.mode_str = "rw-r--r--";
    info.modify_time = AMTime::seconds();

    return {AMFSI::StatResult{info}, OK};
  }

  ECMData<AMFSI::ListResult>
  listdir(const AMFSI::ListdirArgs &args,
          const ClientControlComponent &control = {}) override {
    (void)args;
    (void)control;
    return {AMFSI::ListResult{},
            Err(EC::OperationUnsupported, "http.listdir", ClientTarget_(),
                "HTTP source does not support directory listing")};
  }

  ECMData<AMFSI::ListNamesResult>
  listnames(const AMFSI::ListNamesArgs &args,
            const ClientControlComponent &control = {}) override {
    (void)args;
    (void)control;
    return {AMFSI::ListNamesResult{},
            Err(EC::OperationUnsupported, "http.listnames", ClientTarget_(),
                "HTTP source does not support directory listing")};
  }

  ECMData<AMFSI::MkdirResult>
  mkdir(const AMFSI::MkdirArgs &args,
        const ClientControlComponent &control = {}) override {
    (void)args;
    (void)control;
    return {AMFSI::MkdirResult{},
            Err(EC::OperationUnsupported, "http.mkdir", ClientTarget_(),
                "HTTP source is read-only")};
  }

  ECMData<AMFSI::MkdirsResult>
  mkdirs(const AMFSI::MkdirsArgs &args,
         const ClientControlComponent &control = {}) override {
    (void)args;
    (void)control;
    return {AMFSI::MkdirsResult{},
            Err(EC::OperationUnsupported, "http.mkdirs", ClientTarget_(),
                "HTTP source is read-only")};
  }

  ECMData<AMFSI::RMResult>
  rmdir(const AMFSI::RmdirArgs &args,
        const ClientControlComponent &control = {}) override {
    (void)args;
    (void)control;
    return {AMFSI::RMResult{},
            Err(EC::OperationUnsupported, "http.rmdir", ClientTarget_(),
                "HTTP source is read-only")};
  }

  ECMData<AMFSI::RMResult>
  rmfile(const AMFSI::RmfileArgs &args,
         const ClientControlComponent &control = {}) override {
    (void)args;
    (void)control;
    return {AMFSI::RMResult{},
            Err(EC::OperationUnsupported, "http.rmfile", ClientTarget_(),
                "HTTP source is read-only")};
  }

  ECMData<AMFSI::MoveResult>
  rename(const AMFSI::RenameArgs &args,
         const ClientControlComponent &control = {}) override {
    (void)control;
    return {AMFSI::MoveResult{},
            Err(EC::OperationUnsupported, "http.rename", "",
                "HTTP client does not support rename")};
  }

private:
  [[nodiscard]] std::string ClientTarget_() const {
    if (!config_part_) {
      return "<http-client>";
    }
    const ConRequest req = config_part_->GetRequest();
    if (!AMStr::Strip(req.nickname).empty()) {
      return req.nickname;
    }
    if (!AMStr::Strip(req.hostname).empty()) {
      return req.hostname;
    }
    return "<http-client>";
  }

  [[nodiscard]] std::string ResolveProxy_() const {
    if (!metadata_part_) {
      return {};
    }
    auto runtime_meta = metadata_part_->QueryTypedValue<HttpRuntimeMetadata>();
    if (!runtime_meta.has_value()) {
      return {};
    }
    return runtime_meta->proxy;
  }

  [[nodiscard]] std::string ResolveBearerToken_() const {
    if (!config_part_) {
      return {};
    }
    return config_part_->GetRequest().password;
  }

  AMDomain::client::IClientMetaDataPort *metadata_part_ = nullptr;
  mutable std::atomic<bool> supports_range_{false};
  mutable std::atomic<bool> has_known_size_{false};
};

inline std::pair<ECM, AMDomain::client::ClientHandle>
CreateTransientHttpSourceClient(const std::string &url,
                                const std::string &proxy = "",
                                const std::string &bear_token = "",
                                const std::string &username = "",
                                int redirect_times = 0) {
  const std::string normalized_url = AMStr::Strip(url);
  if (!AMUrl::IsHttpUrl(normalized_url)) {
    return {Err(EC::InvalidArg, "http.create_client", url,
                "Only http:// and https:// are supported"),
            nullptr};
  }

  ConRequest request = {};
  request.protocol = ClientProtocol::HTTP;
  request.nickname = "__http__";
  request.hostname = AMUrl::ExtractOrigin(normalized_url);
  request.username = username;
  request.password = bear_token;
  request.port = AMUrl::IsHttpsUrl(normalized_url) ? 443 : 80;

  auto metadata_port = std::make_unique<AMInfra::client::ClientMetaDataStore>();
  auto config_port =
      std::make_unique<AMInfra::client::ClientConfigStore>(request);
  auto control_port = std::make_unique<AMInfra::client::ClientControlToken>();
  auto io_port = std::make_unique<AMHTTPIOCore>(
      config_port.get(), control_port.get(), metadata_port.get());
  auto client = std::make_shared<AMInfra::client::BaseClient>(
      std::move(metadata_port), std::move(config_port), std::move(control_port),
      std::move(io_port),
      AMDomain::client::ClientService::GenerateID(ClientProtocol::HTTP));
  if (!client) {
    return {Err(EC::InvalidHandle, "http.create_client", url,
                "Failed to create transient HTTP client"),
            nullptr};
  }

  (void)client->MetaDataPort().StoreTypedValue(HttpRuntimeMetadata{
      true, normalized_url, normalized_url, proxy, redirect_times});
  client->ConfigPort().SetState({AMFSI::CheckResult{ClientStatus::OK}, OK});
  return {OK, client};
}
} // namespace AMInfra::client::HTTP

