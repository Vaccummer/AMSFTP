#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// -------- 导出宏：Windows / GCC/Clang --------
#if defined(_WIN32) || defined(_WIN64)
#if defined(CFGFFI_BUILD_DLL)
#define CFGFFI_API __declspec(dllexport)
#else
#define CFGFFI_API __declspec(dllimport)
#endif
#else
#define CFGFFI_API __attribute__((visibility("default")))
#endif

// 不透明句柄
typedef struct ConfigHandle ConfigHandle;

// 读取 TOML 并按 JSON Schema 过滤未知字段，返回句柄
// 失败返回 NULL，out_err 返回错误信息（UTF-8），需要 cfgffi_free_string 释放
CFGFFI_API ConfigHandle *cfgffi_read(const char *path, const char *schema_json,
                                     char **out_err);

// 获取过滤后的 JSON（UTF-8）。返回内存由 Rust 分配，需 cfgffi_free_string 释放
CFGFFI_API char *cfgffi_get_json(const ConfigHandle *h);

// 获取过滤后的 TOML（UTF-8）。返回内存由 Rust 分配，需 cfgffi_free_string 释放
CFGFFI_API char *cfgffi_get_toml(const ConfigHandle *h);

// 写回 TOML：
// - new_json 是 UTF-8 JSON 字符串（会按 schema 再过滤一次）
// - 原有 key 顺序不变；新增 key 追加到末尾
// 返回 0 成功；非 0 失败，out_err 返回错误信息（需 cfgffi_free_string 释放）
CFGFFI_API int cfgffi_write(ConfigHandle *h, const char *out_path,
                            const char *new_json, char **out_err);

// 可选：直接写回到 read 的原路径
CFGFFI_API int cfgffi_write_inplace(ConfigHandle *h, const char *new_json,
                                    char **out_err);

// 调试：比较 Rust 侧过滤后的 TOML key 顺序与生成 JSON 的 key 顺序
// 返回 JSON 字符串：{"same":bool,"before":[...],"after":[...]}
// 返回内存由 Rust 分配，需 cfgffi_free_string 释放
CFGFFI_API char *cfgffi_debug_order(const char *path, const char *schema_json,
                                    char **out_err);

// 释放
CFGFFI_API void cfgffi_free_string(char *p);
CFGFFI_API void cfgffi_free_handle(ConfigHandle *h);

#ifdef __cplusplus
} // extern "C"
#endif
