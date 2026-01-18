#pragma once
#include <magic_enum/magic_enum.hpp>
#include <pybind11/pybind11.h>
#include <tuple>
#include <type_traits>
#include <utility>

namespace py = pybind11;

// ==============================================================================
// New Auto-binding helper - Two naming conventions
// ==============================================================================
//
// auto_def_xx  : Fluent API, requires .bind() call
//   auto_def(cls, "method", &Class::method)
//       .arg("param1")
//       .arg("param2", default_value)
//       .doc("documentation")
//       .bind();
//
// auto_macro_xx : Uses ARG()/DOC() macros directly, no .bind() needed
//   auto_macro_def(cls, "method", &Class::method,
//       ARG("param1"),
//       ARG_V("param2", default_value),
//       DOC("documentation"));
//

namespace am_binding {

// ==============================================================================
// Helper wrappers for arguments
// ==============================================================================

struct ArgRequired {
  const char *name;
  constexpr ArgRequired(const char *n) : name(n) {}
  auto to_py_arg() const { return py::arg(name); }
};

template <typename T> struct ArgOptional {
  const char *name;
  T default_value;

  constexpr ArgOptional(const char *n, T &&val)
      : name(n), default_value(std::forward<T>(val)) {}
  constexpr ArgOptional(const char *n, const T &val)
      : name(n), default_value(val) {}

  auto to_py_arg() const { return py::arg(name) = default_value; }
};

struct DocString {
  const char *value;
  constexpr DocString(const char *v) : value(v) {}
};

// ==============================================================================
// Type traits
// ==============================================================================

template <typename T> struct is_arg_wrapper : std::false_type {};
template <> struct is_arg_wrapper<ArgRequired> : std::true_type {};
template <typename T> struct is_arg_wrapper<ArgOptional<T>> : std::true_type {};

template <typename T> struct is_doc_wrapper : std::false_type {};
template <> struct is_doc_wrapper<DocString> : std::true_type {};

// ==============================================================================
// Function traits to extract argument count
// ==============================================================================

template <typename T> struct function_arity;

// Member function pointers
template <typename R, typename C, typename... Args>
struct function_arity<R (C::*)(Args...)> {
  static constexpr size_t value = sizeof...(Args);
  using class_type = C;
};
template <typename R, typename C, typename... Args>
struct function_arity<R (C::*)(Args...) const> {
  static constexpr size_t value = sizeof...(Args);
  using class_type = C;
};
template <typename R, typename C, typename... Args>
struct function_arity<R (C::*)(Args...) noexcept> {
  static constexpr size_t value = sizeof...(Args);
  using class_type = C;
};
template <typename R, typename C, typename... Args>
struct function_arity<R (C::*)(Args...) const noexcept> {
  static constexpr size_t value = sizeof...(Args);
  using class_type = C;
};

// Free function pointers
template <typename R, typename... Args> struct function_arity<R (*)(Args...)> {
  static constexpr size_t value = sizeof...(Args);
};
template <typename R, typename... Args>
struct function_arity<R (*)(Args...) noexcept> {
  static constexpr size_t value = sizeof...(Args);
};

// Count ARG/ARG_V in extras
template <typename... Ts> struct count_args;
template <> struct count_args<> {
  static constexpr size_t value = 0;
};
template <typename T, typename... Rest> struct count_args<T, Rest...> {
  static constexpr size_t value =
      (is_arg_wrapper<std::decay_t<T>>::value ? 1 : 0) +
      count_args<Rest...>::value;
};

namespace detail {

// Helper to convert our wrappers to py::arg equivalents
template <typename T> auto convert_to_py_extra(T &&val) {
  if constexpr (std::is_same_v<std::decay_t<T>, ArgRequired>) {
    return py::arg(val.name);
  } else if constexpr (is_arg_wrapper<std::decay_t<T>>::value) {
    return val.to_py_arg();
  } else if constexpr (std::is_same_v<std::decay_t<T>, DocString>) {
    return val.value;
  } else {
    return std::forward<T>(val);
  }
}

} // namespace detail

// ==============================================================================
// Convenience macros
// ==============================================================================

#define ARG(name) ::am_binding::ArgRequired(name)
#define ARG_V(name, default_val) ::am_binding::ArgOptional(name, default_val)
#define DOC(text) ::am_binding::DocString(text)

// ==============================================================================
// Fluent API: auto_def - class method binding (requires .bind())
// ==============================================================================

template <typename ClassType, typename FuncType, typename... Extras>
class DefBuilder {
private:
  ClassType *cls_ptr;
  const char *func_name;
  FuncType func_ptr;
  std::tuple<Extras...> extras;
  const char *doc_str = "";

public:
  DefBuilder(ClassType &cls, const char *name, FuncType func)
      : cls_ptr(&cls), func_name(name), func_ptr(func), extras() {}

  DefBuilder(ClassType &cls, const char *name, FuncType func,
             std::tuple<Extras...> ex, const char *doc = "")
      : cls_ptr(&cls), func_name(name), func_ptr(func), extras(std::move(ex)),
        doc_str(doc) {}

  DefBuilder(const DefBuilder &) = delete;
  DefBuilder &operator=(const DefBuilder &) = delete;
  DefBuilder(DefBuilder &&) = default;
  DefBuilder &operator=(DefBuilder &&) = default;

  [[nodiscard]] auto arg(const char *name) && {
    auto new_extras =
        std::tuple_cat(std::move(extras), std::make_tuple(ArgRequired(name)));
    return DefBuilder<ClassType, FuncType, Extras..., ArgRequired>(
        *cls_ptr, func_name, func_ptr, std::move(new_extras), doc_str);
  }

  template <typename T>
  [[nodiscard]] auto arg(const char *name, T &&default_val) && {
    using DecayT = std::decay_t<T>;
    auto new_extras = std::tuple_cat(std::move(extras),
                                     std::make_tuple(ArgOptional<DecayT>(
                                         name, std::forward<T>(default_val))));
    return DefBuilder<ClassType, FuncType, Extras..., ArgOptional<DecayT>>(
        *cls_ptr, func_name, func_ptr, std::move(new_extras), doc_str);
  }

  [[nodiscard]] auto doc(const char *documentation) && {
    return DefBuilder<ClassType, FuncType, Extras...>(
        *cls_ptr, func_name, func_ptr, std::move(extras), documentation);
  }

  void bind() {
    constexpr size_t func_arity = function_arity<FuncType>::value;
    constexpr size_t arg_count = sizeof...(Extras);

    static_assert(func_arity == arg_count,
                  "\n\n"
                  "========== AUTO_DEF ERROR ==========\n"
                  "ARG count does not match function!\n"
                  "Check FuncType in error message.\n"
                  "====================================\n");

    bind_impl(std::index_sequence_for<Extras...>{});
  }

private:
  template <size_t... Is> void bind_impl(std::index_sequence<Is...>) {
    if constexpr (sizeof...(Extras) == 0) {
      cls_ptr->def(func_name, func_ptr, doc_str);
    } else {
      cls_ptr->def(func_name, func_ptr, std::get<Is>(extras).to_py_arg()...,
                   doc_str);
    }
  }
};

template <typename ClassType, typename FuncType>
[[nodiscard]] auto auto_def(ClassType &cls, const char *name, FuncType func) {
  return DefBuilder<ClassType, FuncType>(cls, name, func);
}

// ==============================================================================
// Macro API: auto_macro_def - class method binding (no .bind() needed)
// ==============================================================================

template <typename ClassType, typename FuncType, typename... Extras>
void auto_macro_def(ClassType &cls, const char *name, FuncType func,
                    Extras &&...extras) {
  constexpr size_t func_arity = function_arity<FuncType>::value;
  constexpr size_t arg_count = count_args<Extras...>::value;

  static_assert(func_arity == arg_count,
                "\n\n"
                "========== AUTO_MACRO_DEF ERROR ==========\n"
                "ARG count does not match function!\n"
                "==========================================\n");

  cls.def(name, func,
          detail::convert_to_py_extra(std::forward<Extras>(extras))...);
}

// ==============================================================================
// Fluent API: auto_def_func - free function binding (requires .bind())
// ==============================================================================

template <typename FuncType, typename... Extras> class DefFuncBuilder {
private:
  py::module_ *mod_ptr;
  const char *func_name;
  FuncType func_ptr;
  std::tuple<Extras...> extras;
  const char *doc_str = "";

public:
  DefFuncBuilder(py::module_ &mod, const char *name, FuncType func)
      : mod_ptr(&mod), func_name(name), func_ptr(func), extras() {}

  DefFuncBuilder(py::module_ &mod, const char *name, FuncType func,
                 std::tuple<Extras...> ex, const char *doc = "")
      : mod_ptr(&mod), func_name(name), func_ptr(func), extras(std::move(ex)),
        doc_str(doc) {}

  DefFuncBuilder(const DefFuncBuilder &) = delete;
  DefFuncBuilder &operator=(const DefFuncBuilder &) = delete;
  DefFuncBuilder(DefFuncBuilder &&) = default;
  DefFuncBuilder &operator=(DefFuncBuilder &&) = default;

  [[nodiscard]] auto arg(const char *name) && {
    auto new_extras =
        std::tuple_cat(std::move(extras), std::make_tuple(ArgRequired(name)));
    return DefFuncBuilder<FuncType, Extras..., ArgRequired>(
        *mod_ptr, func_name, func_ptr, std::move(new_extras), doc_str);
  }

  template <typename T>
  [[nodiscard]] auto arg(const char *name, T &&default_val) && {
    using DecayT = std::decay_t<T>;
    auto new_extras = std::tuple_cat(std::move(extras),
                                     std::make_tuple(ArgOptional<DecayT>(
                                         name, std::forward<T>(default_val))));
    return DefFuncBuilder<FuncType, Extras..., ArgOptional<DecayT>>(
        *mod_ptr, func_name, func_ptr, std::move(new_extras), doc_str);
  }

  [[nodiscard]] auto doc(const char *documentation) && {
    return DefFuncBuilder<FuncType, Extras...>(
        *mod_ptr, func_name, func_ptr, std::move(extras), documentation);
  }

  void bind() {
    constexpr size_t func_arity = function_arity<FuncType>::value;
    constexpr size_t arg_count = sizeof...(Extras);

    static_assert(func_arity == arg_count,
                  "\n\n"
                  "========== AUTO_DEF_FUNC ERROR ==========\n"
                  "ARG count does not match function!\n"
                  "=========================================\n");

    bind_impl(std::index_sequence_for<Extras...>{});
  }

private:
  template <size_t... Is> void bind_impl(std::index_sequence<Is...>) {
    if constexpr (sizeof...(Extras) == 0) {
      mod_ptr->def(func_name, func_ptr, doc_str);
    } else {
      mod_ptr->def(func_name, func_ptr, std::get<Is>(extras).to_py_arg()...,
                   doc_str);
    }
  }
};

template <typename FuncType>
[[nodiscard]] auto auto_def_func(py::module_ &mod, const char *name,
                                 FuncType func) {
  return DefFuncBuilder<FuncType>(mod, name, func);
}

// ==============================================================================
// Macro API: auto_macro_func - free function binding (no .bind() needed)
// ==============================================================================

template <typename FuncType, typename... Extras>
void auto_macro_func(py::module_ &mod, const char *name, FuncType func,
                     Extras &&...extras) {
  constexpr size_t func_arity = function_arity<FuncType>::value;
  constexpr size_t arg_count = count_args<Extras...>::value;

  static_assert(func_arity == arg_count,
                "\n\n"
                "========== AUTO_MACRO_FUNC ERROR ==========\n"
                "ARG count does not match function!\n"
                "===========================================\n");

  mod.def(name, func,
          detail::convert_to_py_extra(std::forward<Extras>(extras))...);
}

// ==============================================================================
// Enum binding using magic_enum
// ==============================================================================

template <typename EnumType>
py::enum_<EnumType> bind_enum(py::module_ &m, const char *name,
                              const char *doc = "",
                              bool export_values = false) {
  py::enum_<EnumType> enum_obj(m, name, doc);

  constexpr auto &entries = magic_enum::enum_entries<EnumType>();
  for (const auto &[value, name_sv] : entries) {
    enum_obj.value(std::string(name_sv).c_str(), value);
  }

  if (export_values) {
    enum_obj.export_values();
  }
  return enum_obj;
}

// ==============================================================================
// Macro API: auto_macro_init - constructor binding (no .bind() needed)
// ==============================================================================
// Usage:
//   auto_macro_init<MyClass, int, std::string>(cls,
//       ARG("x"), ARG_V("name", "default"), DOC("doc"));

template <typename ClassType, typename... CtorArgs, typename... Extras>
void auto_macro_init(py::class_<ClassType> &cls, Extras &&...extras) {
  constexpr size_t ctor_arity = sizeof...(CtorArgs);
  constexpr size_t arg_count = count_args<Extras...>::value;

  static_assert(ctor_arity == arg_count,
                "\n\n"
                "========== AUTO_MACRO_INIT ERROR ==========\n"
                "ARG count does not match constructor!\n"
                "===========================================\n");

  cls.def(py::init<CtorArgs...>(),
          detail::convert_to_py_extra(std::forward<Extras>(extras))...);
}

// ==============================================================================
// Macro API: auto_macro_static - static method binding (no .bind() needed)
// ==============================================================================

template <typename ClassType, typename FuncType, typename... Extras>
void auto_macro_static(ClassType &cls, const char *name, FuncType func,
                       Extras &&...extras) {
  constexpr size_t func_arity = function_arity<FuncType>::value;
  constexpr size_t arg_count = count_args<Extras...>::value;

  static_assert(func_arity == arg_count,
                "\n\n"
                "========== AUTO_MACRO_STATIC ERROR ==========\n"
                "ARG count does not match function!\n"
                "=============================================\n");

  cls.def_static(name, func,
                 detail::convert_to_py_extra(std::forward<Extras>(extras))...);
}

} // namespace am_binding

// ==============================================================================
// Global aliases
// ==============================================================================

// Fluent API (requires .bind())
using am_binding::auto_def;
using am_binding::auto_def_func;

// Macro API (uses ARG/DOC, no .bind())
using am_binding::auto_macro_def;
using am_binding::auto_macro_func;
using am_binding::auto_macro_init;
using am_binding::auto_macro_static;

using am_binding::bind_enum;
