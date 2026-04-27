#pragma once

#include "domain/config/ConfigModel.hpp"

namespace AMDomain::config::schema {
inline constexpr const char *kConfigTomlSchemaJson = R"json(
{
  "type": "object",
  "properties": {
    "HOSTS": {
      "type": "object",
      "propertyNames": {
        "pattern": "^[A-Za-z0-9_-]+$"
      },
      "additionalProperties": {
        "type": "object",
        "properties": {
          "hostname": {
            "type": "string"
          },
          "username": {
            "type": "string"
          },
          "port": {
            "type": "integer",
            "minimum": 1,
            "maximum": 65535
          },
          "password": {
            "type": "string"
          },
          "protocol": {
            "type": "string",
            "enum": [
              "sftp",
              "ftp",
              "local",
              "http"
            ]
          },
          "trash_dir": {
            "type": "string"
          },
          "login_dir": {
            "type": "string"
          },
          "cwd": {
            "type": "string"
          },
          "keyfile": {
            "type": "string"
          },
          "compression": {
            "type": "boolean"
          },
          "cmd_template": {
            "type": "string"
          }
        },
        "additionalProperties": false
      }
    },
    "private_keys": {
      "type": "array",
      "items": {
        "type": "string"
      },
      "uniqueItems": true
    }
  },
  "additionalProperties": false
}
)json";

inline constexpr const char *kSettingsTomlSchemaJson = R"json(
{
  "type": "object",
  "properties": {
    "Options": {
      "type": "object",
      "properties": {
        "AutoConfigBackup": {
          "type": "object",
          "properties": {
            "enabled": {
              "type": "boolean"
            },
            "interval_s": {
              "type": "integer",
              "minimum": 15
            },
            "max_backup_count": {
              "type": "integer",
              "minimum": 1
            },
            "last_backup_time_s": {
              "type": "integer",
              "minimum": 0
            }
          },
          "additionalProperties": false
        },
        "TransferManager": {
          "type": "object",
          "properties": {
            "max_threads": {
              "type": "integer",
              "minimum": 1,
              "maximum": 1024
            },
            "refresh_interval_ms": {
              "type": "integer",
              "minimum": 1
            },
            "speed_windows_size_s": {
              "type": "integer",
              "minimum": 1
            },
            "ring_buffersize": {
              "type": "integer",
              "minimum": 1
            }
          },
          "additionalProperties": false
        },
        "LogManager": {
          "type": "object",
          "properties": {
            "client_trace_level": {
              "type": "integer",
              "minimum": -1,
              "maximum": 4
            },
            "program_trace_level": {
              "type": "integer",
              "minimum": -1,
              "maximum": 4
            },
            "ClientLogPath": {
              "type": "string"
            },
            "ProgramLogPath": {
              "type": "string"
            },
            "client_log_path": {
              "type": "string"
            },
            "program_log_path": {
              "type": "string"
            }
          },
          "additionalProperties": false
        },
        "TerminalManager": {
          "type": "object",
          "properties": {
            "read_timeout_ms": {
              "type": "integer",
              "anyOf": [
                {
                  "const": -1
                },
                {
                  "minimum": 1
                }
              ]
            },
            "send_timeout_ms": {
              "type": "integer",
              "anyOf": [
                {
                  "const": -1
                },
                {
                  "minimum": 0
                }
              ]
            },
            "channel_cache_threshold_bytes": {
              "type": "object",
              "properties": {
                "warning": {
                  "type": "integer",
                  "minimum": 1
                },
                "terminate": {
                  "type": "integer",
                  "minimum": 1
                }
              },
              "additionalProperties": false
            }
          },
          "additionalProperties": false
        },
        "Completer": {
          "type": "object",
          "properties": {
            "maxnum": {
              "type": "integer",
              "minimum": 1
            },
            "maxrows_perpage": {
              "type": "integer",
              "minimum": 1
            },
            "number_pick": {
              "type": "boolean"
            },
            "auto_fillin": {
              "type": "boolean"
            },
            "complete_delay_ms": {
              "type": "integer",
              "minimum": 0
            }
          },
          "additionalProperties": false
        },
        "ClientManager": {
          "type": "object",
          "properties": {
            "heartbeat_interval_s": {
              "type": "integer",
              "minimum": 1
            },
            "heartbeat_timeout_ms": {
              "type": "integer",
              "minimum": 1
            },
            "check_timeout_ms": {
              "type": "integer",
              "minimum": 1
            }
          },
          "additionalProperties": false
        },
        "FileSystem": {
          "type": "object",
          "properties": {
            "max_cd_history": {
              "type": "integer",
              "minimum": 1
            },
            "wget_max_redirect": {
              "type": "integer",
              "minimum": 0
            }
          },
          "additionalProperties": false
        },
        "PromptHistoryManager": {
          "type": "object",
          "properties": {
            "history_dir": {
              "type": "string"
            },
            "allow_continuous_duplicates": {
              "type": "boolean"
            },
            "max_count": {
              "type": "integer",
              "minimum": 1,
              "maximum": 200
            }
          },
          "additionalProperties": false
        }
      },
      "additionalProperties": false
    },
    "Style": {
      "type": "object",
      "properties": {
        "Shortcut": {
          "type": "object",
          "additionalProperties": {
            "type": "string"
          }
        },
        "CompleteMenu": {
          "type": "object",
          "properties": {
            "item_select_sign": {
              "type": "string"
            },
            "order_num_style": {
              "type": "string"
            },
            "help_style": {
              "type": "string"
            }
          },
          "additionalProperties": false
        },
        "ProgressBar": {
          "type": "object",
          "properties": {
            "prefix_template": {
              "type": "string"
            },
            "bar_template": {
              "type": "string"
            },
            "refresh_interval_ms": {
              "type": "integer",
              "minimum": 1
            },
            "prefix_fixed_width": {
              "type": "integer",
              "minimum": 0
            },
            "Bar": {
              "type": "object",
              "properties": {
                "fill": {
                  "type": "string"
                },
                "lead": {
                  "type": "string"
                },
                "remaining": {
                  "type": "string"
                },
                "bar_width": {
                  "type": "integer",
                  "minimum": 1
                }
              },
              "additionalProperties": false
            },
            "Speed": {
              "type": "object",
              "properties": {
                "speed_num_fixed_width": {
                  "type": "integer",
                  "minimum": 0
                },
                "speed_num_max_float_digits": {
                  "type": "integer",
                  "minimum": 0
                },
                "speed_window_ms": {
                  "type": "integer",
                  "minimum": 1
                }
              },
              "additionalProperties": false
            },
            "Size": {
              "type": "object",
              "properties": {
                "totol_size_fixed_width": {
                  "type": "integer",
                  "minimum": 0
                },
                "totol_size_max_float_digits": {
                  "type": "integer",
                  "minimum": 0
                },
                "transferred_size_fixed_width": {
                  "type": "integer",
                  "minimum": 0
                },
                "transferred_size_max_float_digits": {
                  "type": "integer",
                  "minimum": 0
                }
              },
              "additionalProperties": false
            }
          },
          "additionalProperties": false
        },
        "CLIPrompt": {
          "type": "object",
          "properties": {
            "icons": {
              "type": "object",
              "properties": {
                "default": {
                  "type": "string"
                },
                "windows": {
                  "type": "string"
                },
                "linux": {
                  "type": "string"
                },
                "macos": {
                  "type": "string"
                },
                "freebsd": {
                  "type": "string"
                },
                "unix": {
                  "type": "string"
                }
              },
              "additionalProperties": false
            },
            "Icons": {
              "type": "object",
              "properties": {
                "default": {
                  "type": "string"
                },
                "windows": {
                  "type": "string"
                },
                "linux": {
                  "type": "string"
                },
                "macos": {
                  "type": "string"
                },
                "freebsd": {
                  "type": "string"
                },
                "unix": {
                  "type": "string"
                }
              },
              "additionalProperties": false
            },
            "template": {
              "type": "object",
              "properties": {
                "core_prompt": {
                  "type": "string"
                },
                "history_search_prompt": {
                  "type": "string"
                }
              },
              "additionalProperties": false
            }
          },
          "additionalProperties": false
        },
        "Common": {
          "type": "object",
          "properties": {
            "default": {
              "type": "string"
            },
            "type": {
              "type": "object",
              "properties": {
                "string": {
                  "type": "string"
                },
                "error": {
                  "type": "string"
                },
                "number": {
                  "type": "string"
                },
                "protocol": {
                  "type": "string"
                },
                "username": {
                  "type": "string"
                },
                "abort": {
                  "type": "string"
                },
                "hostname": {
                  "type": "string"
                },
                "shell_cmd": {
                  "type": "string"
                },
                "table_skeleton": {
                  "type": "string"
                }
              },
              "additionalProperties": false
            },
            "sign": {
              "type": "object",
              "properties": {
                "escaped": {
                  "type": "string"
                },
                "bang": {
                  "type": "string"
                }
              },
              "additionalProperties": false
            },
            "cli": {
              "type": "object",
              "properties": {
                "command": {
                  "type": "string"
                },
                "unexpected": {
                  "type": "string"
                },
                "illegal_command": {
                  "type": "string"
                },
                "module": {
                  "type": "string"
                },
                "option": {
                  "type": "string"
                }
              },
              "additionalProperties": false
            },
            "varname": {
              "type": "object",
              "properties": {
                "public": {
                  "type": "string"
                },
                "private": {
                  "type": "string"
                },
                "zone": {
                  "type": "string"
                },
                "nonexistent": {
                  "type": "string"
                },
                "dollar": {
                  "type": "string"
                },
                "left_brace": {
                  "type": "string"
                },
                "right_brace": {
                  "type": "string"
                },
                "colon": {
                  "type": "string"
                },
                "equal": {
                  "type": "string"
                }
              },
              "additionalProperties": false
            },
            "varvalue": {
              "type": "string"
            },
            "nickname": {
              "type": "object",
              "properties": {
                "ok": {
                  "type": "string"
                },
                "at": {
                  "type": "string"
                },
                "disconnected": {
                  "type": "string"
                },
                "unestablished": {
                  "type": "string"
                },
                "nonexistent": {
                  "type": "string"
                },
                "new": {
                  "type": "object",
                  "properties": {
                    "valid": {
                      "type": "string"
                    },
                    "invalid": {
                      "type": "string"
                    }
                  },
                  "additionalProperties": false
                }
              },
              "additionalProperties": false
            },
            "termname": {
              "type": "object",
              "properties": {
                "ok": {
                  "type": "string"
                },
                "at": {
                  "type": "string"
                },
                "disconnected": {
                  "type": "string"
                },
                "nonexistent": {
                  "type": "string"
                },
                "new": {
                  "type": "object",
                  "properties": {
                    "valid": {
                      "type": "string"
                    },
                    "invalid": {
                      "type": "string"
                    }
                  },
                  "additionalProperties": false
                }
              },
              "additionalProperties": false
            },
            "attr": {
              "type": "object",
              "properties": {
                "valid": {
                  "type": "string"
                },
                "invalid": {
                  "type": "string"
                }
              },
              "additionalProperties": false
            }
          },
          "additionalProperties": false
        },
        "ValueQueryHighlight": {
          "type": "object",
          "properties": {
            "valid_value": {
              "type": "string"
            },
            "invalid_value": {
              "type": "string"
            }
          },
          "additionalProperties": false
        },
        "InternalStyle": {
          "type": "object",
          "properties": {
            "inline_hint": {
              "type": "string"
            },
            "default_prompt_style": {
              "type": "string"
            }
          },
          "additionalProperties": false
        },
        "Path": {
          "type": "object",
          "properties": {
            "default": {
              "type": "string"
            },
            "tree": {
              "type": "object",
              "properties": {
                "root": {
                  "type": "string"
                },
                "node": {
                  "type": "string"
                },
                "leaf": {
                  "type": "string"
                }
              },
              "additionalProperties": false
            },
            "type": {
              "type": "object",
              "properties": {
                "dir": {
                  "type": "string"
                },
                "regular": {
                  "type": "string"
                },
                "symlink": {
                  "type": "string"
                },
                "otherspecial": {
                  "type": "string"
                },
                "nonexistent": {
                  "type": "string"
                }
              },
              "additionalProperties": false
            },
            "find": {
              "type": "object",
              "properties": {
                "pattern": {
                  "type": "string"
                }
              },
              "additionalProperties": false
            }
          },
          "additionalProperties": false
        },
        "Terminal": {
          "type": "object",
          "properties": {
            "banner": {
              "type": "object",
              "properties": {
                "template": {
                  "type": "string"
                },
                "background": {
                  "type": "string"
                },
                "align": {
                  "type": "string"
                }
              },
              "additionalProperties": false
            },
            "banner_template": {
              "type": "string"
            }
          },
          "additionalProperties": false
        }
      },
      "additionalProperties": false
    },
    "PromptProfile": {
      "type": "object",
      "propertyNames": {
        "pattern": "^(\\*|[A-Za-z0-9_-]+)$"
      },
      "additionalProperties": {
        "type": "object",
        "properties": {
          "Prompt": {
            "type": "object",
            "properties": {
              "marker": {
                "type": "string"
              },
              "continuation_marker": {
                "type": "string"
              },
              "enable_multiline": {
                "type": "boolean"
              }
            },
            "additionalProperties": false
          },
          "History": {
            "type": "object",
            "properties": {
              "enable": {
                "type": "boolean"
              },
              "enable_duplicates": {
                "type": "boolean"
              },
              "max_count": {
                "type": "integer",
                "minimum": 1,
                "maximum": 200
              }
            },
            "additionalProperties": false
          },
          "InlineHint": {
            "type": "object",
            "properties": {
              "enable": {
                "type": "boolean"
              },
              "render_delay_ms": {
                "type": "integer",
                "minimum": 0
              },
              "delay_ms": {
                "type": "integer",
                "minimum": 0
              },
              "search_delay_ms": {
                "type": "integer",
                "minimum": 0
              },
              "Path": {
                "type": "object",
                "properties": {
                  "enable": {
                    "type": "boolean"
                  },
                  "use_async": {
                    "type": "boolean"
                  },
                  "timeout_ms": {
                    "type": "integer",
                    "minimum": 1
                  }
                },
                "additionalProperties": false
              }
            },
            "additionalProperties": false
          },
          "Complete": {
            "type": "object",
            "properties": {
              "Searcher": {
                "type": "object",
                "properties": {
                  "Path": {
                    "type": "object",
                    "properties": {
                      "use_async": {
                        "type": "boolean"
                      },
                      "timeout_ms": {
                        "type": "integer",
                        "minimum": 1
                      }
                    },
                    "additionalProperties": false
                  }
                },
                "additionalProperties": false
              }
            },
            "additionalProperties": false
          },
          "Highlight": {
            "type": "object",
            "properties": {
              "delay_ms": {
                "type": "integer",
                "minimum": 0
              },
              "Path": {
                "type": "object",
                "properties": {
                  "enable": {
                    "type": "boolean"
                  },
                  "timeout_ms": {
                    "type": "integer",
                    "minimum": 1
                  }
                },
                "additionalProperties": false
              }
            },
            "additionalProperties": false
          }
        },
        "additionalProperties": false
      }
    },
    "UserVars": {
      "type": "object",
      "propertyNames": {
        "pattern": "^(\\*|[A-Za-z0-9_-]+)$"
      },
      "additionalProperties": {
        "oneOf": [
          {
            "type": "string"
          },
          {
            "type": "boolean"
          },
          {
            "type": "integer"
          },
          {
            "type": "number"
          },
          {
            "type": "object",
            "propertyNames": {
              "pattern": "^[A-Za-z0-9_]+$"
            },
            "additionalProperties": {
              "type": [
                "string",
                "boolean",
                "integer",
                "number"
              ]
            }
          }
        ]
      }
    }
  },
  "additionalProperties": false
}
)json";

inline constexpr const char *kKnownHostsTomlSchemaJson = R"json(
{
  "type": "object",
  "propertyNames": {
    "minLength": 1
  },
  "additionalProperties": {
    "type": "object",
    "propertyNames": {
      "pattern": "^(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3})$"
    },
    "additionalProperties": {
      "type": "object",
      "additionalProperties": {
        "type": "object",
        "propertyNames": {
          "minLength": 1
        },
        "additionalProperties": {
          "type": "string",
          "minLength": 1
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
        },
        "uniqueItems": false
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
