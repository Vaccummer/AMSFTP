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

// Opaque handle
typedef struct ConfigHandle ConfigHandle;

// Read TOML and filter unknown fields by JSON Schema, then return a handle
// Returns NULL on failure; out_err returns UTF-8 error text and must be freed
// by RustTomlFreeString
CFGFFI_API ConfigHandle *RustTomlRead(const char *path,
                                      const char *schema_json,
                                      char **out_err);

// Get filtered JSON (UTF-8). Memory is allocated by Rust and must be freed by
// RustTomlFreeString
CFGFFI_API char *RustTomlGetJson(const ConfigHandle *h);

// Get filtered TOML (UTF-8). Memory is allocated by Rust and must be freed by
// RustTomlFreeString
CFGFFI_API char *RustTomlGetToml(const ConfigHandle *h);

// Write TOML back:
// - new_json is a UTF-8 JSON string (filtered by schema again)
// - Existing key order remains unchanged; new keys are appended at the end
// Returns 0 on success; non-zero on failure, out_err returns error text (free
// with RustTomlFreeString)
CFGFFI_API int RustTomlWrite(ConfigHandle *h, const char *out_path,
                             const char *new_json, char **out_err);

// Optional: write directly back to the original path from read
CFGFFI_API int RustTomlWriteInplace(ConfigHandle *h, const char *new_json,
                                    char **out_err);

// Debug: compare TOML key order after Rust-side filtering with generated JSON
// key order Returns JSON string: {"same":bool,"before":[...],"after":[...]}
// Returned memory is allocated by Rust and must be freed by RustTomlFreeString
CFGFFI_API char *RustTomlDebugOrder(const char *path,
                                    const char *schema_json, char **out_err);

// Release
CFGFFI_API void RustTomlFreeString(char *p);
CFGFFI_API void RustTomlFreeHandle(ConfigHandle *h);

#ifdef __cplusplus
} // extern "C"
#endif
