#pragma once

#include "domain/config/ConfigModel.hpp"

namespace AMDomain::config::schema {
inline constexpr const char *kConfigTomlSchemaJson = R"json(
{
  "type": "object",
  "properties": {
    "HOSTS": {
      "type": "object",
      "additionalProperties": {
        "type": "object",
        "additionalProperties": true
      }
    },
    "private_keys": {
      "type": "array",
      "items": {
        "type": "string"
      }
    },
    "Options": {
      "type": "object",
      "additionalProperties": true
    }
  },
  "additionalProperties": true
}
)json";

inline constexpr const char *kSettingsTomlSchemaJson = R"json(
{
  "type": "object",
  "properties": {
    "Options": {
      "type": "object",
      "additionalProperties": true
    },
    "Style": {
      "type": "object",
      "additionalProperties": true
    },
    "PromptProfile": {
      "type": "object",
      "additionalProperties": true
    },
    "Complete": {
      "type": "object",
      "additionalProperties": true
    },
    "VarSet": {
      "type": "object",
      "additionalProperties": true
    }
  },
  "additionalProperties": true
}
)json";

inline constexpr const char *kKnownHostsTomlSchemaJson = R"json(
{
  "type": "object",
  "additionalProperties": {
    "type": "object",
    "additionalProperties": {
      "type": "object",
      "additionalProperties": {
        "type": "object",
        "additionalProperties": {
          "type": "string"
        }
      }
    }
  }
}
)json";

inline constexpr const char *kHistoryTomlSchemaJson = R"json(
{
  "type": "object",
  "additionalProperties": {
    "type": "object",
    "properties": {
      "commands": {
        "type": "array",
        "items": {
          "type": "string"
        }
      }
    },
    "additionalProperties": false
  }
}
)json";

[[nodiscard]] inline const char *GetSchemaJson(DocumentKind kind) {
  switch (kind) {
  case DocumentKind::Config:
    return kConfigTomlSchemaJson;
  case DocumentKind::Settings:
    return kSettingsTomlSchemaJson;
  case DocumentKind::KnownHosts:
    return kKnownHostsTomlSchemaJson;
  case DocumentKind::History:
    return kHistoryTomlSchemaJson;
  default:
    return "{}";
  }
}
} // namespace AMDomain::config::schema
