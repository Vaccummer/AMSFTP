#pragma once

#include "domain/client/ClientDomainService.hpp"
#include "foundation/tools/string.hpp"
#include "foundation/tools/url.hpp"
#include "infrastructure/client/common/Base.hpp"
#include <atomic>
#include <cstdint>
#include <curl/curl.h>
#include <optional>
#include <string>

namespace AMInfra::client::HTTP {
inline constexpr const char *kTransientHttpNickname = "__wget_http__";
inline constexpr const char *kHttpProxyMetaKey = "http.proxy";
inline constexpr const char *kHttpMaxRedirectTimesMetaKey =
    "http.max_redirect_times";
inline constexpr const char *kHttpBearTokenMetaKey = "http.bear_token";
namespace {
using ClientStatus = AMDomain::client::ClientStatus;
using ConRequest = AMDomain::host::ConRequest;
using ClientProtocol = AMDomain::host::ClientProtocol;
using OS_TYPE = AMDomain::client::OS_TYPE;
namespace AMFSI = AMDomain::filesystem;
constexpr long kMaxRedirects = 20L;
constexpr const char *kHttpUserAgent = "AMSFTP/1.0 (HTTP Downloader)";

struct HttpHeaderProbe {
  std::optional<int64_t> content_length = std::nullopt;
  std::optional<int64_t> content_range_total = std::nullopt;
  std::optional<std::string> raw_download_url = std::nullopt;
  std::optional<std::string> location_url = std::nullopt;
  bool accept_ranges_bytes = false;
};

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
    int64_t value = 0;
    if (AMStr::GetNumber<int64_t>(v, &value)) {
      probe->content_length = value;
    }
  } else if (const std::string v = pick_value("accept-ranges:"); !v.empty()) {
    const std::string lower_v = AMStr::lowercase(v);
    if (lower_v.find("bytes") != std::string::npos) {
      probe->accept_ranges_bytes = true;
    }
  } else if (const std::string v = pick_value("content-range:"); !v.empty()) {
    const size_t slash = v.find('/');
    if (slash != std::string::npos && slash + 1 < v.size()) {
      int64_t value = 0;
      if (AMStr::GetNumber<int64_t>(v.substr(slash + 1), &value) &&
          value >= 0) {
        probe->content_range_total = value;
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

[[nodiscard]] inline static std::optional<ECM>
BuildStopRCM_(const ControlComponent &control, const std::string &action,
              const std::string &target) {
  if (auto stop_rcm = control.BuildECM(action, target); stop_rcm.has_value()) {
    return stop_rcm;
  }
  return control.BuildRequestECM(action, target);
}

struct CurlInterruptContext {
  const ControlComponent *control = nullptr;
  std::string action = {};
  std::string target = {};
};

inline static int CurlXferInfoWk_(void *clientp,
                                  [[maybe_unused]] curl_off_t dltotal,
                                  [[maybe_unused]] curl_off_t dlnow,
                                  [[maybe_unused]] curl_off_t ultotal,
                                  [[maybe_unused]] curl_off_t ulnow) {
  auto *ctx = static_cast<CurlInterruptContext *>(clientp);
  if (ctx == nullptr || ctx->control == nullptr) {
    return 0;
  }
  return BuildStopRCM_(*ctx->control, ctx->action, ctx->target).has_value() ? 1
                                                                            : 0;
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

inline static ECM BuildCurlMultiError_(CURLMcode code,
                                       const std::string &action,
                                       const std::string &target) {
  return Err(EC::NetworkError, action, target, curl_multi_strerror(code),
             RawError{RawErrorSource::Curl, static_cast<int>(code)});
}
} // namespace

class AMHTTPReadOnlyIOBase : public ClientIOBase {
protected:
  AMHTTPReadOnlyIOBase(AMDomain::client::IClientConfigPort *config,
                       InterruptControl *control)
      : ClientIOBase(config, control) {}

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

  template <typename T>
  [[nodiscard]] ECMData<T>
  UnsupportedResult_(T data, const ControlComponent &control,
                     const std::string &action,
                     const std::string &message) const {
    const std::string target = ClientTarget_();
    if (auto stop_rcm = BuildStopRCM_(control, action, target);
        stop_rcm.has_value()) {
      return {std::move(data), std::move(*stop_rcm)};
    }
    return {std::move(data),
            Err(EC::OperationUnsupported, action, target, message)};
  }

public:
  ECMData<AMFSI::UpdateOSTypeResult>
  UpdateOSType(const AMFSI::UpdateOSTypeArgs &args = {},
               const ControlComponent &control = {}) override {
    (void)args;
    return UnsupportedResult_(AMFSI::UpdateOSTypeResult{OS_TYPE::Unknown},
                              control, "http.update_ostype",
                              "HTTP source does not support OS detection");
  }

  ECMData<AMFSI::ConnectResult>
  Connect(const AMFSI::ConnectArgs &args = {},
          const ControlComponent &control = {}) override {
    (void)args;
    return UnsupportedResult_(AMFSI::ConnectResult{ClientStatus::OK}, control,
                              "http.connect",
                              "HTTP source is temporary and does not connect");
  }

  ECMData<AMFSI::UpdateHomeDirResult>
  UpdateHomeDir(const AMFSI::UpdateHomeDirArgs &args = {},
                const ControlComponent &control = {}) override {
    (void)args;
    return UnsupportedResult_(AMFSI::UpdateHomeDirResult{""}, control,
                              "http.update_home",
                              "HTTP source has no home directory");
  }

  ECMData<AMFSI::RTTResult>
  GetRTT(const AMFSI::GetRTTArgs &args = {},
         const ControlComponent &control = {}) override {
    (void)args;
    return UnsupportedResult_(AMFSI::RTTResult{-1.0}, control, "http.rtt",
                              "HTTP source does not support RTT test");
  }

  ECMData<AMFSI::RunResult>
  ConductCmd(const AMFSI::ConductCmdArgs &args,
             const ControlComponent &control = {}) override {
    (void)args;
    return UnsupportedResult_(AMFSI::RunResult("", -1), control, "http.cmd",
                              "HTTP source does not support shell command");
  }

  ECMData<AMFSI::ListResult>
  listdir(const AMFSI::ListdirArgs &args,
          const ControlComponent &control = {}) override {
    (void)args;
    return UnsupportedResult_(AMFSI::ListResult{}, control, "http.listdir",
                              "HTTP source does not support directory listing");
  }

  ECMData<AMFSI::ListNamesResult>
  listnames(const AMFSI::ListNamesArgs &args,
            const ControlComponent &control = {}) override {
    (void)args;
    return UnsupportedResult_(AMFSI::ListNamesResult{}, control,
                              "http.listnames",
                              "HTTP source does not support directory listing");
  }

  ECMData<AMFSI::MkdirResult>
  mkdir(const AMFSI::MkdirArgs &args,
        const ControlComponent &control = {}) override {
    (void)args;
    return UnsupportedResult_(AMFSI::MkdirResult{}, control, "http.mkdir",
                              "HTTP source is read-only");
  }

  ECMData<AMFSI::MkdirsResult>
  mkdirs(const AMFSI::MkdirsArgs &args,
         const ControlComponent &control = {}) override {
    (void)args;
    return UnsupportedResult_(AMFSI::MkdirsResult{}, control, "http.mkdirs",
                              "HTTP source is read-only");
  }

  ECMData<AMFSI::RMResult>
  rmdir(const AMFSI::RmdirArgs &args,
        const ControlComponent &control = {}) override {
    (void)args;
    return UnsupportedResult_(AMFSI::RMResult{}, control, "http.rmdir",
                              "HTTP source is read-only");
  }

  ECMData<AMFSI::RMResult>
  rmfile(const AMFSI::RmfileArgs &args,
         const ControlComponent &control = {}) override {
    (void)args;
    return UnsupportedResult_(AMFSI::RMResult{}, control, "http.rmfile",
                              "HTTP source is read-only");
  }

  ECMData<AMFSI::MoveResult>
  rename(const AMFSI::RenameArgs &args,
         const ControlComponent &control = {}) override {
    (void)args;
    return UnsupportedResult_(AMFSI::MoveResult{}, control, "http.rename",
                              "HTTP source does not support rename");
  }
};

class AMHTTPIOCore final : public AMHTTPReadOnlyIOBase {
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

  AMHTTPIOCore(AMDomain::client::IClientMetaDataPort *metadata,
               AMDomain::client::IClientConfigPort *config,
               InterruptControl *control)
      : AMHTTPReadOnlyIOBase(config, control), metadata_part_(metadata) {}

  void SetProxy(const std::string &proxy) {
    SetNamedMetadata_(kHttpProxyMetaKey, AMStr::Strip(proxy));
  }

  void SetMaxRedirectTimes(int max_redirect_times) {
    const int normalized = max_redirect_times < 0 ? 0 : max_redirect_times;
    SetNamedMetadata_(kHttpMaxRedirectTimesMetaKey, normalized);
  }

  void SetBearerToken(const std::string &bear_token) {
    SetNamedMetadata_(kHttpBearTokenMetaKey, AMStr::Strip(bear_token));
  }

  [[nodiscard]] bool SupportsRange() const {
    return supports_range_.load(std::memory_order_acquire);
  }

  [[nodiscard]] bool HasKnownSize() const {
    return has_known_size_.load(std::memory_order_acquire);
  }

  [[nodiscard]] std::string Proxy() const {
    if (const auto value = QueryNamedMetadata_<std::string>(kHttpProxyMetaKey);
        value.has_value()) {
      return *value;
    }
    return {};
  }

  [[nodiscard]] std::string BearerToken() const {
    return ResolveBearerToken_();
  }

  [[nodiscard]] std::string BasicUsername() const {
    if (!config_part_) {
      return {};
    }
    return AMStr::Strip(config_part_->GetRequest().username);
  }

  [[nodiscard]] std::string BasicPassword() const {
    if (!config_part_) {
      return {};
    }
    return config_part_->GetRequest().password;
  }

  [[nodiscard]] int MaxRedirectTimes() const {
    if (const auto value =
            QueryNamedMetadata_<int>(kHttpMaxRedirectTimesMetaKey);
        value.has_value()) {
      return *value;
    }
    return static_cast<int>(kMaxRedirects);
  }

  [[nodiscard]] long CurlMaxRedirects() const {
    const int max_redirects = MaxRedirectTimes();
    if (max_redirects < 0) {
      return 0L;
    }
    const long as_long = static_cast<long>(max_redirects);
    return as_long > kMaxRedirects ? kMaxRedirects : as_long;
  }

  template <typename ConfigureFn>
  [[nodiscard]] ECMData<CURLcode>
  NBPerform(const std::string &action, const std::string &target,
            const ControlComponent &control, long *response_code,
            ConfigureFn &&configure) const {
    if (auto stop_rcm = BuildStopRCM_(control, action, target);
        stop_rcm.has_value()) {
      return {CURLE_ABORTED_BY_CALLBACK, std::move(*stop_rcm)};
    }

    CURL *curl = curl_easy_init();
    if (!curl) {
      return {CURLE_FAILED_INIT,
              Err(EC::InvalidHandle, action, target, "curl_easy_init failed")};
    }

    struct CurlHandleGuard {
      CURL *curl = nullptr;
      struct curl_slist *headers = nullptr;
      CURLM *multi = nullptr;
      bool attached = false;
      ~CurlHandleGuard() {
        if (attached && multi && curl) {
          curl_multi_remove_handle(multi, curl);
        }
        if (multi) {
          curl_multi_cleanup(multi);
        }
        if (headers) {
          curl_slist_free_all(headers);
        }
        if (curl) {
          curl_easy_cleanup(curl);
        }
      }
    } guard{curl, nullptr, nullptr, false};

    CurlInterruptContext interrupt_ctx{
        .control = &control,
        .action = action,
        .target = target,
    };
    configure(curl, &guard.headers);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, CurlXferInfoWk_);
    curl_easy_setopt(curl, CURLOPT_XFERINFODATA, &interrupt_ctx);
    guard.multi = curl_multi_init();
    if (!guard.multi) {
      return {CURLE_FAILED_INIT,
              Err(EC::InvalidHandle, action, target, "curl_multi_init failed")};
    }
    if (CURLMcode add_rcm = curl_multi_add_handle(guard.multi, curl);
        add_rcm != CURLM_OK) {
      return {CURLE_FAILED_INIT, BuildCurlMultiError_(add_rcm, action, target)};
    }
    guard.attached = true;

#if LIBCURL_VERSION_NUM >= 0x074400
    const AMDomain::client::InterruptWakeupSafeGuard wakeup_guard(
        control.InterruptRaw(), [multi = guard.multi]() {
          if (multi != nullptr) {
            (void)curl_multi_wakeup(multi);
          }
        });
#endif

    int running = 0;
    CURLMcode multi_rcm = curl_multi_perform(guard.multi, &running);
    while (multi_rcm == CURLM_OK && running > 0) {
      if (auto stop_rcm = BuildStopRCM_(control, action, target);
          stop_rcm.has_value()) {
        return {CURLE_ABORTED_BY_CALLBACK, std::move(*stop_rcm)};
      }
      int numfds = 0;
      multi_rcm = curl_multi_poll(guard.multi, nullptr, 0, 100, &numfds);
      if (multi_rcm != CURLM_OK) {
        break;
      }
      multi_rcm = curl_multi_perform(guard.multi, &running);
    }

    long response = 0;
    if (response_code != nullptr) {
      (void)curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);
      *response_code = response;
    }

    if (auto stop_rcm = BuildStopRCM_(control, action, target);
        stop_rcm.has_value()) {
      return {CURLE_ABORTED_BY_CALLBACK, std::move(*stop_rcm)};
    }
    if (multi_rcm != CURLM_OK) {
      return {CURLE_FAILED_INIT,
              BuildCurlMultiError_(multi_rcm, action, target)};
    }

    int msgs_left = 0;
    CURLcode curl_rcm = CURLE_OK;
    while (CURLMsg *msg = curl_multi_info_read(guard.multi, &msgs_left)) {
      if (msg->msg == CURLMSG_DONE) {
        curl_rcm = msg->data.result;
        break;
      }
    }
    if (curl_rcm == CURLE_ABORTED_BY_CALLBACK) {
      if (auto stop_rcm = BuildStopRCM_(control, action, target);
          stop_rcm.has_value()) {
        return {curl_rcm, std::move(*stop_rcm)};
      }
    }
    if (curl_rcm == CURLE_OK) {
      (void)curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);
      if (response_code != nullptr) {
        *response_code = response;
      }
    }
    return {curl_rcm, OK};
  }

  [[nodiscard]] ECMData<HeadProbeResult>
  ProbeHead(const std::string &url, const ControlComponent &control) const {
    const std::string normalized = ResolveHttpUrl_(url);
    if (!AMUrl::IsHttpUrl(normalized) || AMUrl::IsDirectoryUrl(normalized)) {
      return {HeadProbeResult{},
              Err(EC::InvalidArg, "http.head", normalized, "Invalid HTTP URL")};
    }
    const std::string proxy = Proxy();
    const std::string bear_token = BearerToken();
    const std::string basic_username = BasicUsername();
    const std::string basic_password = BasicPassword();
    HttpHeaderProbe probe = {};
    long response = 0;
    const auto configure = [&](CURL *curl, struct curl_slist **headers) {
      curl_easy_setopt(curl, CURLOPT_URL, normalized.c_str());
      curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
      curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
      curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, ProbeHeaderWk_);
      curl_easy_setopt(curl, CURLOPT_HEADERDATA, &probe);
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, DiscardWriteWk_);
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, nullptr);
      curl_easy_setopt(curl, CURLOPT_USERAGENT, kHttpUserAgent);
      if (!proxy.empty()) {
        curl_easy_setopt(curl, CURLOPT_PROXY, proxy.c_str());
      }
      if (!bear_token.empty()) {
        *headers = curl_slist_append(
            *headers,
            AMStr::fmt("Authorization: Bearer {}", bear_token).c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, *headers);
      } else if (!basic_username.empty() || !basic_password.empty()) {
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
        curl_easy_setopt(curl, CURLOPT_USERNAME, basic_username.c_str());
        curl_easy_setopt(curl, CURLOPT_PASSWORD, basic_password.c_str());
      }
    };

    auto curl_res =
        NBPerform("http.head", normalized, control, &response, configure);
    if (!curl_res) {
      return {HeadProbeResult{}, std::move(curl_res.rcm)};
    }
    const CURLcode curl_rcm = curl_res.data;
    const bool need_get_fallback =
        (curl_rcm != CURLE_OK || response == 405 || response == 501);
    if (need_get_fallback) {
      probe = {};
      response = 0;
      const auto configure_get = [&](CURL *curl, struct curl_slist **headers) {
        curl_easy_setopt(curl, CURLOPT_URL, normalized.c_str());
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
        curl_easy_setopt(curl, CURLOPT_NOBODY, 0L);
        curl_easy_setopt(curl, CURLOPT_RANGE, "bytes=0-0");
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, ProbeHeaderWk_);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, &probe);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, DiscardWriteWk_);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, nullptr);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, kHttpUserAgent);
        if (!proxy.empty()) {
          curl_easy_setopt(curl, CURLOPT_PROXY, proxy.c_str());
        }
        if (!bear_token.empty()) {
          *headers = curl_slist_append(
              *headers,
              AMStr::fmt("Authorization: Bearer {}", bear_token).c_str());
          curl_easy_setopt(curl, CURLOPT_HTTPHEADER, *headers);
        } else if (!basic_username.empty() || !basic_password.empty()) {
          curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
          curl_easy_setopt(curl, CURLOPT_USERNAME, basic_username.c_str());
          curl_easy_setopt(curl, CURLOPT_PASSWORD, basic_password.c_str());
        }
      };
      curl_res =
          NBPerform("http.head", normalized, control, &response, configure_get);
      if (!curl_res) {
        return {HeadProbeResult{}, std::move(curl_res.rcm)};
      }
      if (curl_res.data != CURLE_OK) {
        return {HeadProbeResult{},
                BuildCurlError_(curl_res.data, "http.head", normalized)};
      }
    }
    if (curl_res.data != CURLE_OK) {
      return {HeadProbeResult{},
              BuildCurlError_(curl_res.data, "http.head", normalized)};
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
                       const ControlComponent &control) const {
    const std::string normalized = ResolveHttpUrl_(url);
    if (!AMUrl::IsHttpUrl(normalized) || AMUrl::IsDirectoryUrl(normalized)) {
      return {RedirectResolveResult{}, Err(EC::InvalidArg, "http.redirect",
                                           normalized, "Invalid HTTP URL")};
    }
    int redirect_limit = max_redirects;
    if (redirect_limit < 0) {
      redirect_limit = MaxRedirectTimes();
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

  [[nodiscard]] ECMData<std::string>
  FollowRedirects(const std::string &url,
                  const ControlComponent &control) const {
    auto res = ResolveRedirectChain(url, -1, control);
    if (!res.rcm) {
      return {{}, std::move(res.rcm)};
    }
    const std::string final_url = AMStr::Strip(res.data.final_url).empty()
                                      ? AMStr::Strip(url)
                                      : res.data.final_url;
    return {final_url, OK};
  }

  [[nodiscard]] ECMData<RangeProbeResult>
  ProbeOneByteRange(const std::string &url,
                    const ControlComponent &control) const {
    const std::string normalized = ResolveHttpUrl_(url);
    if (!AMUrl::IsHttpUrl(normalized) || AMUrl::IsDirectoryUrl(normalized)) {
      return {RangeProbeResult{}, Err(EC::InvalidArg, "http.probe", normalized,
                                      "Invalid HTTP URL")};
    }
    const std::string proxy = Proxy();
    const std::string bear_token = BearerToken();
    const std::string basic_username = BasicUsername();
    const std::string basic_password = BasicPassword();
    HttpHeaderProbe probe = {};
    long response = 0;
    const auto run_probe = [&](bool no_body) -> ECMData<CURLcode> {
      probe = {};
      const auto configure = [&](CURL *curl, struct curl_slist **headers) {
        curl_easy_setopt(curl, CURLOPT_URL, normalized.c_str());
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_MAXREDIRS, CurlMaxRedirects());
        curl_easy_setopt(curl, CURLOPT_USERAGENT, kHttpUserAgent);
        curl_easy_setopt(curl, CURLOPT_NOBODY, no_body ? 1L : 0L);
        curl_easy_setopt(curl, CURLOPT_RANGE, "bytes=0-0");
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, ProbeHeaderWk_);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, &probe);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, DiscardWriteWk_);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, nullptr);
        if (!proxy.empty()) {
          curl_easy_setopt(curl, CURLOPT_PROXY, proxy.c_str());
        }
        if (!bear_token.empty()) {
          *headers = curl_slist_append(
              *headers,
              AMStr::fmt("Authorization: Bearer {}", bear_token).c_str());
          curl_easy_setopt(curl, CURLOPT_HTTPHEADER, *headers);
        } else if (!basic_username.empty() || !basic_password.empty()) {
          curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
          curl_easy_setopt(curl, CURLOPT_USERNAME, basic_username.c_str());
          curl_easy_setopt(curl, CURLOPT_PASSWORD, basic_password.c_str());
        }
      };
      return NBPerform("http.probe", normalized, control, &response, configure);
    };

    auto curl_res = run_probe(true);
    if (!curl_res) {
      return {RangeProbeResult{}, std::move(curl_res.rcm)};
    }
    CURLcode curl_rcm = curl_res.data;
    const auto has_total_size = [&]() -> bool {
      return (probe.content_range_total.has_value() &&
              *probe.content_range_total > 0) ||
             (probe.content_length.has_value() && *probe.content_length > 0);
    };
    const bool need_get_fallback =
        (curl_rcm != CURLE_OK || response == 405 || response == 501 ||
         ((response == 200 || response == 206) && !has_total_size()));
    if (need_get_fallback) {
      curl_res = run_probe(false);
      if (!curl_res) {
        return {RangeProbeResult{}, std::move(curl_res.rcm)};
      }
      curl_rcm = curl_res.data;
    }
    if (curl_rcm != CURLE_OK) {
      return {RangeProbeResult{},
              BuildCurlError_(curl_rcm, "http.probe", normalized)};
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
                     const ControlComponent &control) const {
    const std::string normalized = ResolveHttpUrl_(url);
    if (!AMUrl::IsHttpUrl(normalized) || AMUrl::IsDirectoryUrl(normalized)) {
      return {false, Err(EC::InvalidArg, "http.probe", normalized,
                         "Invalid HTTP URL")};
    }
    const std::string proxy = Proxy();
    const std::string bear_token = BearerToken();
    const std::string basic_username = BasicUsername();
    const std::string basic_password = BasicPassword();
    if (offset == 0) {
      auto probe = ProbeOneByteRange(normalized, control);
      if (!(probe.rcm)) {
        return {false, probe.rcm};
      }
      return {probe.data.is_allowed, OK};
    }
    HttpHeaderProbe probe = {};
    const std::string range_header = AMStr::fmt("bytes={}-", offset);
    long response = 0;
    const auto configure = [&](CURL *curl, struct curl_slist **headers) {
      curl_easy_setopt(curl, CURLOPT_URL, normalized.c_str());
      curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
      curl_easy_setopt(curl, CURLOPT_MAXREDIRS, CurlMaxRedirects());
      curl_easy_setopt(curl, CURLOPT_USERAGENT, kHttpUserAgent);
      curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
      curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, ProbeHeaderWk_);
      curl_easy_setopt(curl, CURLOPT_HEADERDATA, &probe);
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, DiscardWriteWk_);
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, nullptr);
      curl_easy_setopt(curl, CURLOPT_RANGE, range_header.c_str());
      if (!proxy.empty()) {
        curl_easy_setopt(curl, CURLOPT_PROXY, proxy.c_str());
      }
      if (!bear_token.empty()) {
        *headers = curl_slist_append(
            *headers,
            AMStr::fmt("Authorization: Bearer {}", bear_token).c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, *headers);
      } else if (!basic_username.empty() || !basic_password.empty()) {
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
        curl_easy_setopt(curl, CURLOPT_USERNAME, basic_username.c_str());
        curl_easy_setopt(curl, CURLOPT_PASSWORD, basic_password.c_str());
      }
    };
    const auto curl_res =
        NBPerform("http.probe", normalized, control, &response, configure);
    if (!curl_res) {
      return {false, std::move(curl_res.rcm)};
    }
    if (curl_res.data != CURLE_OK) {
      return {false, BuildCurlError_(curl_res.data, "http.probe", normalized)};
    }
    return {response == 206, OK};
  }

  ECMData<AMFSI::UpdateOSTypeResult>
  UpdateOSType(const AMFSI::UpdateOSTypeArgs &args = {},
               const ControlComponent &control = {}) override {
    (void)args;
    return UnsupportedResult_(AMFSI::UpdateOSTypeResult{OS_TYPE::Unknown},
                              control, "http.update_ostype",
                              "HTTP source does not support OS detection");
  }

  ECMData<AMFSI::CheckResult>
  Check(const AMFSI::CheckArgs &args = {},
        const ControlComponent &control = {}) override {
    (void)args;
    (void)control;
    return {AMFSI::CheckResult{ClientStatus::OK}, OK};
  }

  ECMData<AMFSI::ConnectResult>
  Connect(const AMFSI::ConnectArgs &args = {},
          const ControlComponent &control = {}) override {
    (void)args;
    return UnsupportedResult_(AMFSI::ConnectResult{ClientStatus::OK}, control,
                              "http.connect",
                              "HTTP source is temporary and does not connect");
  }

  ECMData<AMFSI::StatResult>
  stat(const AMFSI::StatArgs &args,
       const ControlComponent &control = {}) override {
    const std::string url = ResolveHttpUrl_(args.path);
    if (!AMUrl::IsHttpUrl(url)) {
      return {AMFSI::StatResult{},
              Err(EC::InvalidArg, "http.stat", args.path,
                  "Only http:// and https:// are supported")};
    }
    if (AMUrl::IsDirectoryUrl(url)) {
      return {AMFSI::StatResult{}, Err(EC::NotAFile, "http.stat", url,
                                       "HTTP directory URL is unsupported")};
    }
    if (auto stop_rcm = BuildStopRCM_(control, "http.stat", url);
        stop_rcm.has_value()) {
      return {AMFSI::StatResult{}, std::move(*stop_rcm)};
    }
    const std::string proxy = Proxy();
    const std::string bear_token = BearerToken();
    const std::string basic_username = BasicUsername();
    const std::string basic_password = BasicPassword();
    HttpHeaderProbe probe = {};
    long response = 0;
    const auto run_probe = [&](bool no_body) -> ECMData<CURLcode> {
      probe = {};
      const auto configure = [&](CURL *curl, struct curl_slist **headers) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_MAXREDIRS, CurlMaxRedirects());
        curl_easy_setopt(curl, CURLOPT_USERAGENT, kHttpUserAgent);
        curl_easy_setopt(curl, CURLOPT_NOBODY, no_body ? 1L : 0L);
        if (!no_body) {
          curl_easy_setopt(curl, CURLOPT_RANGE, "bytes=0-0");
        }
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, ProbeHeaderWk_);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, &probe);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, DiscardWriteWk_);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, nullptr);
        if (!proxy.empty()) {
          curl_easy_setopt(curl, CURLOPT_PROXY, proxy.c_str());
        }
        if (!bear_token.empty()) {
          *headers = curl_slist_append(
              *headers,
              AMStr::fmt("Authorization: Bearer {}", bear_token).c_str());
          curl_easy_setopt(curl, CURLOPT_HTTPHEADER, *headers);
        } else if (!basic_username.empty() || !basic_password.empty()) {
          curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
          curl_easy_setopt(curl, CURLOPT_USERNAME, basic_username.c_str());
          curl_easy_setopt(curl, CURLOPT_PASSWORD, basic_password.c_str());
        }
      };
      return NBPerform("http.stat", url, control, &response, configure);
    };

    auto curl_res = run_probe(true);
    if (!curl_res) {
      return {AMFSI::StatResult{}, std::move(curl_res.rcm)};
    }
    CURLcode curl_rcm = curl_res.data;
    bool need_get_fallback =
        (curl_rcm != CURLE_OK || response == 405 || response == 501);

    if (need_get_fallback) {
      curl_res = run_probe(false);
      if (!curl_res) {
        return {AMFSI::StatResult{}, std::move(curl_res.rcm)};
      }
      curl_rcm = curl_res.data;
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

private:
  template <typename T>
  [[nodiscard]] std::optional<T>
  QueryNamedMetadata_(const std::string &name) const {
    if (metadata_part_ == nullptr) {
      return std::nullopt;
    }
    auto query = metadata_part_->QueryNamedValue<T>(name);
    if (!query.name_found || !query.type_match || !query.value.has_value()) {
      return std::nullopt;
    }
    return query.value;
  }

  template <typename T>
  void SetNamedMetadata_(const std::string &name, T value) {
    if (metadata_part_ == nullptr || name.empty()) {
      return;
    }
    (void)metadata_part_->StoreNamedValue<T>(name, std::move(value), true);
  }

  [[nodiscard]] std::string ResolveHttpUrl_(const std::string &url) const {
    const std::string normalized = AMStr::Strip(url);
    if (AMUrl::IsHttpUrl(normalized)) {
      return normalized;
    }
    if (!config_part_) {
      return normalized;
    }
    const std::string host = AMStr::Strip(config_part_->GetRequest().hostname);
    if (host.empty()) {
      return normalized;
    }
    if (normalized.empty()) {
      return host;
    }
    return AMUrl::ResolveRedirectUrl(host, normalized);
  }

  [[nodiscard]] std::string ResolveBearerToken_() const {
    if (const auto meta =
            QueryNamedMetadata_<std::string>(kHttpBearTokenMetaKey);
        meta.has_value()) {
      return *meta;
    }
    if (!config_part_) {
      return {};
    }
    const ConRequest request = config_part_->GetRequest();
    if (!AMStr::Strip(request.username).empty()) {
      return {};
    }
    return request.password;
  }

  AMDomain::client::IClientMetaDataPort *metadata_part_ = nullptr;
  mutable std::atomic<bool> supports_range_{false};
  mutable std::atomic<bool> has_known_size_{false};
};

inline std::pair<ECM, AMDomain::client::ClientHandle>
BuildTransientHttpSourceClient(const std::string &url,
                               const std::string &nickname = "",
                               const std::string &username = "",
                               const std::string &password = "") {
  const std::string normalized_url = AMStr::Strip(url);
  if (!AMUrl::IsHttpUrl(normalized_url)) {
    return {Err(EC::InvalidArg, "http.build_client", url,
                "Only http:// and https:// are supported"),
            nullptr};
  }

  ConRequest request = {};
  request.protocol = ClientProtocol::HTTP;
  request.nickname = AMStr::Strip(nickname).empty()
                         ? std::string(kTransientHttpNickname)
                         : AMStr::Strip(nickname);
  request.hostname = AMUrl::ExtractOrigin(normalized_url);
  request.username = username;
  request.password = password;
  request.port = AMUrl::IsHttpsUrl(normalized_url) ? 443 : 80;

  auto metadata_port = std::make_unique<AMInfra::client::ClientMetaDataStore>();
  auto config_port =
      std::make_unique<AMInfra::client::ClientConfigStore>(request);
  auto control_port = std::make_unique<InterruptControl>();
  auto io_port = std::make_unique<AMHTTPIOCore>(
      metadata_port.get(), config_port.get(), control_port.get());

  auto client = std::make_shared<AMInfra::client::BaseClient>(
      std::move(metadata_port), std::move(config_port), std::move(control_port),
      std::move(io_port),
      AMDomain::client::ClientService::GenerateID(ClientProtocol::HTTP));
  if (!client) {
    return {Err(EC::InvalidHandle, "http.build_client", url,
                "Failed to create transient HTTP client"),
            nullptr};
  }

  client->ConfigPort().SetState(
      {AMDomain::filesystem::CheckResult{ClientStatus::OK}, OK});
  return {OK, client};
}

} // namespace AMInfra::client::HTTP
