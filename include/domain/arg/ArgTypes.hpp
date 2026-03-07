#pragma once

namespace AMDomain::config {
struct HandleInitSpec;
enum class DocumentKind : int;
}

namespace AMDomain::arg {
struct ConfigArg;
struct SettingsArg;
struct KnownHostsArg;
struct HistoryArg;

/**
 * @brief Runtime type discriminator for config arg payloads.
 */
enum class TypeTag {
  Config,
  Settings,
  KnownHosts,
  History,
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

template <typename T> inline constexpr bool kSupportedArgType = false;

template <> inline constexpr bool kSupportedArgType<ConfigArg> = true;
template <> inline constexpr bool kSupportedArgType<SettingsArg> = true;
template <> inline constexpr bool kSupportedArgType<KnownHostsArg> = true;
template <> inline constexpr bool kSupportedArgType<HistoryArg> = true;

bool FindDocumentKind(TypeTag type, AMDomain::config::DocumentKind *out);
} // namespace AMDomain::arg
