#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handle
typedef struct ConfigHandle ConfigHandle;

// Read TOML and filter unknown fields by JSON Schema, then return a handle
// Returns NULL on failure; out_err returns UTF-8 error text and must be freed
// by RustTomlFreeString
ConfigHandle *RustTomlRead(const char *path, const char *schema_json,
                           char **out_err);

// Get filtered JSON (UTF-8). Memory is allocated by Rust and must be freed by
// RustTomlFreeString
char *RustTomlGetJson(const ConfigHandle *h);

// Get filtered TOML (UTF-8). Memory is allocated by Rust and must be freed by
// RustTomlFreeString
char *RustTomlGetToml(const ConfigHandle *h);

// Write TOML back:
// - new_json is a UTF-8 JSON string (filtered by schema again)
// - Existing key order remains unchanged; new keys are appended at the end
// Returns 0 on success; non-zero on failure, out_err returns error text (free
// with RustTomlFreeString)
int RustTomlWrite(ConfigHandle *h, const char *out_path,
                  const char *new_json, char **out_err);

// Optional: write directly back to the original path from read
int RustTomlWriteInplace(ConfigHandle *h, const char *new_json,
                         char **out_err);

// Debug: compare TOML key order after Rust-side filtering with generated JSON
// key order Returns JSON string: {"same":bool,"before":[...],"after":[...]}
// Returned memory is allocated by Rust and must be freed by RustTomlFreeString
char *RustTomlDebugOrder(const char *path, const char *schema_json,
                         char **out_err);

// Release
void RustTomlFreeString(char *p);
void RustTomlFreeHandle(ConfigHandle *h);

#ifdef __cplusplus
} // extern "C"
#endif
