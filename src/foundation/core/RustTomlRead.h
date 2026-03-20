#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// -------- Export macros: Windows / GCC/Clang --------
#if defined(_WIN32) || defined(_WIN64)
#if defined(CFGFFI_BUILD_DLL)
#define CFGFFI_API __declspec(dllexport)
#else
#define CFGFFI_API __declspec(dllimport)
#endif
#else
#define CFGFFI_API __attribute__((visibility("default")))
#endif

using ConfigHandle = struct ConfigHandle;
// Read TOML and filter unknown fields by JSON Schema; return a handle
// Returns NULL on failure; out_err returns UTF-8 error text and must be freed with cfgffi_free_string
// Release
CFGFFI_API ConfigHandle *cfgffi_read(const char *path, const char *schema_json,
                                     char **out_err);

// Get filtered JSON (UTF-8). Memory is allocated by Rust and must be freed with cfgffi_free_string
CFGFFI_API char *cfgffi_get_json(const ConfigHandle *h);

// Get filtered TOML (UTF-8). Memory is allocated by Rust and must be freed with cfgffi_free_string
CFGFFI_API char *cfgffi_get_toml(const ConfigHandle *h);

// Write back TOML:
// - new_json is a UTF-8 JSON string (filtered again by schema)
// - Existing key order is preserved; new keys are appended to the end
// Returns 0 on success; non-zero on failure. out_err returns error text (must be freed with cfgffi_free_string)
CFGFFI_API int cfgffi_write(ConfigHandle *h, const char *out_path,
                            const char *new_json, char **out_err);

// Optional: write directly back to the original path read
CFGFFI_API int cfgffi_write_inplace(ConfigHandle *h, const char *new_json,
                                    char **out_err);

// Debug: compare TOML key order after Rust-side filtering with generated JSON key order
// Returns JSON string: {"same":bool,"before":[...],"after":[...]}
// Returned memory is allocated by Rust and must be freed with cfgffi_free_string
CFGFFI_API char *cfgffi_debug_order(const char *path, const char *schema_json,
                                    char **out_err);

// Release
CFGFFI_API void cfgffi_free_string(char *p);
CFGFFI_API void cfgffi_free_handle(ConfigHandle *h);

#ifdef __cplusplus
} // extern "C"
#endif
