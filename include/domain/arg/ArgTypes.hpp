#pragma once
#include "foundation/tools/json.hpp"

namespace AMDomain::config {
struct HandleInitSpec;
enum class DocumentKind;

} // namespace AMDomain::config

namespace AMDomain::host {
struct HostConfigArg;
struct KnownHostEntryArg;
} // namespace AMDomain::host

namespace AMDomain::arg {
/**
 * @brief Generic config-document arg wrapper backed by full JSON object.
 */
struct ConfigArg {
  Json value = Json::object();
};

/**
 * @brief Generic settings-document arg wrapper backed by full JSON object.
 */
struct SettingsArg {
  Json value = Json::object();
};

/**
 * @brief Generic known-hosts arg wrapper backed by full JSON object.
 */
struct KnownHostsArg {
  Json value = Json::object();
};

/**
 * @brief Generic history arg wrapper backed by full JSON object.
 */
struct HistoryArg {
  Json value = Json::object();
};

/**
 * @brief Runtime type discriminator for config arg payloads.
 */
enum class TypeTag {
  Config,
  Settings,
  KnownHosts,
  History,
  HostConfig,
  KnownHostEntry,
};

template <typename T> struct TypeTagOf;

template <> struct TypeTagOf<ConfigArg> {
  static constexpr TypeTag value = TypeTag::Config;
};

template <> struct TypeTagOf<SettingsArg> {
  static constexpr TypeTag value = TypeTag::Settings;
};

template <> struct TypeTagOf<KnownHostsArg> {
  static constexpr TypeTag value = TypeTag::KnownHosts;
};

template <> struct TypeTagOf<HistoryArg> {
  static constexpr TypeTag value = TypeTag::History;
};

template <> struct TypeTagOf<AMDomain::host::HostConfigArg> {
  static constexpr TypeTag value = TypeTag::HostConfig;
};

template <> struct TypeTagOf<AMDomain::host::KnownHostEntryArg> {
  static constexpr TypeTag value = TypeTag::KnownHostEntry;
};

template <typename T> inline constexpr bool kSupportedArgType = false;

template <> inline constexpr bool kSupportedArgType<ConfigArg> = true;
template <> inline constexpr bool kSupportedArgType<SettingsArg> = true;
template <> inline constexpr bool kSupportedArgType<KnownHostsArg> = true;
template <> inline constexpr bool kSupportedArgType<HistoryArg> = true;
template <>
inline constexpr bool kSupportedArgType<AMDomain::host::HostConfigArg> = true;
template <>
inline constexpr bool kSupportedArgType<AMDomain::host::KnownHostEntryArg> =
    true;

bool FindDocumentKind(TypeTag type, AMDomain::config::DocumentKind *out);

} // namespace AMDomain::arg
