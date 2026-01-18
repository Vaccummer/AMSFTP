#pragma once
#include <cstdlib>
#include <fmt/format.h>
#include <iostream>
#include <magic_enum/magic_enum.hpp>
#include <pybind11/pybind11.h>
#include <string>
#include <type_traits>
#include <vector>

namespace py = pybind11;

// ==============================================================================
// Function traits to extract argument count at compile time
// ==============================================================================

// Primary template - for generic callable types (lambdas, functors)
template <typename T>
struct function_traits : function_traits<decltype(&T::operator())> {};

// Specialization for member function pointers
template <typename R, typename C, typename... Args>
struct function_traits<R (C::*)(Args...)> {
  static constexpr size_t arity = sizeof...(Args);
};

// Specialization for const member function pointers
template <typename R, typename C, typename... Args>
struct function_traits<R (C::*)(Args...) const> {
  static constexpr size_t arity = sizeof...(Args);
};

// Specialization for regular function pointers
template <typename R, typename... Args> struct function_traits<R (*)(Args...)> {
  static constexpr size_t arity = sizeof...(Args);
};

// Specialization for function references
template <typename R, typename... Args> struct function_traits<R (&)(Args...)> {
  static constexpr size_t arity = sizeof...(Args);
};

// ==============================================================================
// Auto-binding helper using fluent API (Compile-time Argument Count Version)
// Usage: auto_def(cls, "method", &Class::method)
//           .arg("param1", default1)
//           .arg("param2", default2)
//           .doc("function doc");
// ==============================================================================

// Non-template base class to store argument info
class AutoDefHelperBase {
protected:
  struct ArgInfo {
    std::string name;
    py::object default_value;
    bool has_default;
  };
  std::vector<ArgInfo> args_info;
  std::string func_doc;
};

template <typename ClassType, typename FuncType>
class AutoDefHelper : public AutoDefHelperBase {
private:
  static constexpr size_t FuncArity = function_traits<FuncType>::arity;
  ClassType *cls_ptr;
  const char *func_name;
  FuncType func_ptr;
  bool bound = false;

public:
  AutoDefHelper(ClassType &cls, const char *name, FuncType func)
      : cls_ptr(&cls), func_name(name), func_ptr(func) {}

  // Prevent copy to avoid double binding
  AutoDefHelper(const AutoDefHelper &) = delete;
  AutoDefHelper &operator=(const AutoDefHelper &) = delete;
  AutoDefHelper(AutoDefHelper &&other) noexcept
      : AutoDefHelperBase(std::move(other)), cls_ptr(other.cls_ptr),
        func_name(other.func_name), func_ptr(other.func_ptr),
        bound(other.bound) {
    other.bound = true; // Prevent other from binding
  }

  // Add argument without default value (required parameter)
  AutoDefHelper &arg(const char *name) {
    args_info.push_back({name, py::none(), false});
    return *this;
  }

  // Add argument with default value only (including const char*)
  template <typename T, typename = typename std::enable_if<
                            !std::is_convertible<T, std::string>::value ||
                            std::is_same<typename std::decay<T>::type,
                                         const char *>::value>::type>
  AutoDefHelper &arg(const char *name, T &&default_val) {
    args_info.push_back({name, py::cast(std::forward<T>(default_val)), true});
    return *this;
  }

  // Set function documentation
  AutoDefHelper &doc(const char *documentation) {
    func_doc = documentation;
    return *this;
  }

  // Finalize binding (called by destructor)
  ~AutoDefHelper() {
    if (!bound) {
      bind();
    }
  }

  void bind() {
    if (bound)
      return;
    bound = true;

    // Runtime check: verify argument count matches function arity
    if (args_info.size() != FuncArity) {
      std::cerr << fmt::format(
          "\n[FATAL] auto_def error for '{}': expected {} arguments but got "
          "{}.\n        Add .arg() calls for all parameters.\n",
          func_name, FuncArity, args_info.size());
      std::abort();
    }

    // Use compile-time arity to select the correct binding
    bind_with_args<FuncArity>();
  }

private:
  template <size_t N> void bind_with_args() {
    if constexpr (N == 0) {
      cls_ptr->def(func_name, func_ptr, func_doc.c_str());
    } else if constexpr (N == 1) {
      if (args_info[0].has_default)
        cls_ptr->def(func_name, func_ptr,
                     py::arg(args_info[0].name.c_str()) =
                         args_info[0].default_value,
                     func_doc.c_str());
      else
        cls_ptr->def(func_name, func_ptr, py::arg(args_info[0].name.c_str()),
                     func_doc.c_str());
    } else if constexpr (N == 2) {
      bind_2_args();
    } else if constexpr (N == 3) {
      bind_3_args();
    } else if constexpr (N == 4) {
      bind_4_args();
    } else if constexpr (N == 5) {
      bind_5_args();
    } else if constexpr (N == 6) {
      bind_6_args();
    } else if constexpr (N == 7) {
      bind_7_args();
    } else if constexpr (N == 8) {
      bind_8_args();
    } else if constexpr (N == 9) {
      bind_9_args();
    } else if constexpr (N == 10) {
      bind_10_args();
    } else if constexpr (N == 11) {
      bind_11_args();
    } else if constexpr (N == 12) {
      bind_12_args();
    } else {
      // Fallback: all required (no defaults)
      cls_ptr->def(func_name, func_ptr, func_doc.c_str());
    }
  }

// Helper macros for generating arg expressions
#define ARG_OR_ARG_V(i)                                                        \
  (args_info[i].has_default                                                    \
       ? py::arg(args_info[i].name.c_str()) = args_info[i].default_value       \
       : py::arg(args_info[i].name.c_str()))

  void bind_2_args() {
    auto a0 =
        args_info[0].has_default
            ? py::arg_v(args_info[0].name.c_str(), args_info[0].default_value)
            : py::arg_v(args_info[0].name.c_str(), py::none());
    auto a1 =
        args_info[1].has_default
            ? py::arg_v(args_info[1].name.c_str(), args_info[1].default_value)
            : py::arg_v(args_info[1].name.c_str(), py::none());

    // Now we need to call def with the right combination...
    // This is getting complicated. Let's try a different approach.

    // Actually, let's just enumerate all 4 combinations for 2 args
    if (args_info[0].has_default && args_info[1].has_default) {
      cls_ptr->def(
          func_name, func_ptr,
          py::arg(args_info[0].name.c_str()) = args_info[0].default_value,
          py::arg(args_info[1].name.c_str()) = args_info[1].default_value,
          func_doc.c_str());
    } else if (args_info[0].has_default && !args_info[1].has_default) {
      cls_ptr->def(func_name, func_ptr,
                   py::arg(args_info[0].name.c_str()) =
                       args_info[0].default_value,
                   py::arg(args_info[1].name.c_str()), func_doc.c_str());
    } else if (!args_info[0].has_default && args_info[1].has_default) {
      cls_ptr->def(func_name, func_ptr, py::arg(args_info[0].name.c_str()),
                   py::arg(args_info[1].name.c_str()) =
                       args_info[1].default_value,
                   func_doc.c_str());
    } else {
      cls_ptr->def(func_name, func_ptr, py::arg(args_info[0].name.c_str()),
                   py::arg(args_info[1].name.c_str()), func_doc.c_str());
    }
  }

  void bind_3_args() {
    // 8 combinations - use bitmask
    int mask = (args_info[0].has_default ? 1 : 0) |
               (args_info[1].has_default ? 2 : 0) |
               (args_info[2].has_default ? 4 : 0);
    switch (mask) {
    case 0: // none
      cls_ptr->def(func_name, func_ptr, py::arg(args_info[0].name.c_str()),
                   py::arg(args_info[1].name.c_str()),
                   py::arg(args_info[2].name.c_str()), func_doc.c_str());
      break;
    case 1: // 0 only
      cls_ptr->def(func_name, func_ptr,
                   py::arg(args_info[0].name.c_str()) =
                       args_info[0].default_value,
                   py::arg(args_info[1].name.c_str()),
                   py::arg(args_info[2].name.c_str()), func_doc.c_str());
      break;
    case 2: // 1 only
      cls_ptr->def(func_name, func_ptr, py::arg(args_info[0].name.c_str()),
                   py::arg(args_info[1].name.c_str()) =
                       args_info[1].default_value,
                   py::arg(args_info[2].name.c_str()), func_doc.c_str());
      break;
    case 3: // 0,1
      cls_ptr->def(
          func_name, func_ptr,
          py::arg(args_info[0].name.c_str()) = args_info[0].default_value,
          py::arg(args_info[1].name.c_str()) = args_info[1].default_value,
          py::arg(args_info[2].name.c_str()), func_doc.c_str());
      break;
    case 4: // 2 only
      cls_ptr->def(func_name, func_ptr, py::arg(args_info[0].name.c_str()),
                   py::arg(args_info[1].name.c_str()),
                   py::arg(args_info[2].name.c_str()) =
                       args_info[2].default_value,
                   func_doc.c_str());
      break;
    case 5: // 0,2
      cls_ptr->def(
          func_name, func_ptr,
          py::arg(args_info[0].name.c_str()) = args_info[0].default_value,
          py::arg(args_info[1].name.c_str()),
          py::arg(args_info[2].name.c_str()) = args_info[2].default_value,
          func_doc.c_str());
      break;
    case 6: // 1,2
      cls_ptr->def(
          func_name, func_ptr, py::arg(args_info[0].name.c_str()),
          py::arg(args_info[1].name.c_str()) = args_info[1].default_value,
          py::arg(args_info[2].name.c_str()) = args_info[2].default_value,
          func_doc.c_str());
      break;
    case 7: // all
      cls_ptr->def(
          func_name, func_ptr,
          py::arg(args_info[0].name.c_str()) = args_info[0].default_value,
          py::arg(args_info[1].name.c_str()) = args_info[1].default_value,
          py::arg(args_info[2].name.c_str()) = args_info[2].default_value,
          func_doc.c_str());
      break;
    }
  }

  void bind_4_args() {
    // 16 combinations - simplified: assume common patterns
    // Most common: all have defaults or none have defaults
    bool all_default = true, none_default = true;
    for (int i = 0; i < 4; i++) {
      if (args_info[i].has_default)
        none_default = false;
      else
        all_default = false;
    }

    if (all_default) {
      cls_ptr->def(
          func_name, func_ptr,
          py::arg(args_info[0].name.c_str()) = args_info[0].default_value,
          py::arg(args_info[1].name.c_str()) = args_info[1].default_value,
          py::arg(args_info[2].name.c_str()) = args_info[2].default_value,
          py::arg(args_info[3].name.c_str()) = args_info[3].default_value,
          func_doc.c_str());
    } else if (none_default) {
      cls_ptr->def(func_name, func_ptr, py::arg(args_info[0].name.c_str()),
                   py::arg(args_info[1].name.c_str()),
                   py::arg(args_info[2].name.c_str()),
                   py::arg(args_info[3].name.c_str()), func_doc.c_str());
    } else {
      // Mixed - use a generic fallback with all defaults set to none for
      // required This won't give proper signatures but at least won't crash
      cls_ptr->def(
          func_name, func_ptr,
          args_info[0].has_default
              ? py::arg(args_info[0].name.c_str()) = args_info[0].default_value
              : py::arg(args_info[0].name.c_str()),
          args_info[1].has_default
              ? py::arg(args_info[1].name.c_str()) = args_info[1].default_value
              : py::arg(args_info[1].name.c_str()),
          args_info[2].has_default
              ? py::arg(args_info[2].name.c_str()) = args_info[2].default_value
              : py::arg(args_info[2].name.c_str()),
          args_info[3].has_default
              ? py::arg(args_info[3].name.c_str()) = args_info[3].default_value
              : py::arg(args_info[3].name.c_str()),
          func_doc.c_str());
    }
  }

  void bind_5_args() {
    bool all_default = true, none_default = true;
    for (int i = 0; i < 5; i++) {
      if (args_info[i].has_default)
        none_default = false;
      else
        all_default = false;
    }

    if (all_default) {
      cls_ptr->def(
          func_name, func_ptr,
          py::arg(args_info[0].name.c_str()) = args_info[0].default_value,
          py::arg(args_info[1].name.c_str()) = args_info[1].default_value,
          py::arg(args_info[2].name.c_str()) = args_info[2].default_value,
          py::arg(args_info[3].name.c_str()) = args_info[3].default_value,
          py::arg(args_info[4].name.c_str()) = args_info[4].default_value,
          func_doc.c_str());
    } else if (none_default) {
      cls_ptr->def(func_name, func_ptr, py::arg(args_info[0].name.c_str()),
                   py::arg(args_info[1].name.c_str()),
                   py::arg(args_info[2].name.c_str()),
                   py::arg(args_info[3].name.c_str()),
                   py::arg(args_info[4].name.c_str()), func_doc.c_str());
    } else {
      // Fallback
      cls_ptr->def(func_name, func_ptr, func_doc.c_str());
    }
  }

  void bind_6_args() {
    bool all_default = true, none_default = true;
    for (int i = 0; i < 6; i++) {
      if (args_info[i].has_default)
        none_default = false;
      else
        all_default = false;
    }

    if (all_default) {
      cls_ptr->def(
          func_name, func_ptr,
          py::arg(args_info[0].name.c_str()) = args_info[0].default_value,
          py::arg(args_info[1].name.c_str()) = args_info[1].default_value,
          py::arg(args_info[2].name.c_str()) = args_info[2].default_value,
          py::arg(args_info[3].name.c_str()) = args_info[3].default_value,
          py::arg(args_info[4].name.c_str()) = args_info[4].default_value,
          py::arg(args_info[5].name.c_str()) = args_info[5].default_value,
          func_doc.c_str());
    } else if (none_default) {
      cls_ptr->def(func_name, func_ptr, py::arg(args_info[0].name.c_str()),
                   py::arg(args_info[1].name.c_str()),
                   py::arg(args_info[2].name.c_str()),
                   py::arg(args_info[3].name.c_str()),
                   py::arg(args_info[4].name.c_str()),
                   py::arg(args_info[5].name.c_str()), func_doc.c_str());
    } else {
      cls_ptr->def(func_name, func_ptr, func_doc.c_str());
    }
  }

  // Helper: find first index with default (returns N if none have defaults)
  int first_default_index(int N) {
    for (int i = 0; i < N; i++) {
      if (args_info[i].has_default)
        return i;
    }
    return N;
  }

  // Helper: check if pattern is "first K required, rest have defaults"
  bool is_trailing_defaults_pattern(int N) {
    int first_def = first_default_index(N);
    for (int i = first_def; i < N; i++) {
      if (!args_info[i].has_default)
        return false;
    }
    return true;
  }

// Macros for generating arg expressions
#define A(i) py::arg(args_info[i].name.c_str())
#define AD(i) py::arg(args_info[i].name.c_str()) = args_info[i].default_value

  void bind_7_args() {
    if (!is_trailing_defaults_pattern(7)) {
      cls_ptr->def(func_name, func_ptr, func_doc.c_str());
      return;
    }
    int k = first_default_index(7);
    switch (k) {
    case 0:
      cls_ptr->def(func_name, func_ptr, AD(0), AD(1), AD(2), AD(3), AD(4),
                   AD(5), AD(6), func_doc.c_str());
      break;
    case 1:
      cls_ptr->def(func_name, func_ptr, A(0), AD(1), AD(2), AD(3), AD(4), AD(5),
                   AD(6), func_doc.c_str());
      break;
    case 2:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), AD(2), AD(3), AD(4), AD(5),
                   AD(6), func_doc.c_str());
      break;
    case 3:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), AD(3), AD(4), AD(5),
                   AD(6), func_doc.c_str());
      break;
    case 4:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), AD(4), AD(5),
                   AD(6), func_doc.c_str());
      break;
    case 5:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), AD(5),
                   AD(6), func_doc.c_str());
      break;
    case 6:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   AD(6), func_doc.c_str());
      break;
    case 7:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   A(6), func_doc.c_str());
      break;
    }
  }

  void bind_8_args() {
    if (!is_trailing_defaults_pattern(8)) {
      cls_ptr->def(func_name, func_ptr, func_doc.c_str());
      return;
    }
    int k = first_default_index(8);
    switch (k) {
    case 0:
      cls_ptr->def(func_name, func_ptr, AD(0), AD(1), AD(2), AD(3), AD(4),
                   AD(5), AD(6), AD(7), func_doc.c_str());
      break;
    case 1:
      cls_ptr->def(func_name, func_ptr, A(0), AD(1), AD(2), AD(3), AD(4), AD(5),
                   AD(6), AD(7), func_doc.c_str());
      break;
    case 2:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), AD(2), AD(3), AD(4), AD(5),
                   AD(6), AD(7), func_doc.c_str());
      break;
    case 3:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), AD(3), AD(4), AD(5),
                   AD(6), AD(7), func_doc.c_str());
      break;
    case 4:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), AD(4), AD(5),
                   AD(6), AD(7), func_doc.c_str());
      break;
    case 5:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), AD(5),
                   AD(6), AD(7), func_doc.c_str());
      break;
    case 6:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   AD(6), AD(7), func_doc.c_str());
      break;
    case 7:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   A(6), AD(7), func_doc.c_str());
      break;
    case 8:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   A(6), A(7), func_doc.c_str());
      break;
    }
  }

  void bind_9_args() {
    if (!is_trailing_defaults_pattern(9)) {
      cls_ptr->def(func_name, func_ptr, func_doc.c_str());
      return;
    }
    int k = first_default_index(9);
    switch (k) {
    case 0:
      cls_ptr->def(func_name, func_ptr, AD(0), AD(1), AD(2), AD(3), AD(4),
                   AD(5), AD(6), AD(7), AD(8), func_doc.c_str());
      break;
    case 1:
      cls_ptr->def(func_name, func_ptr, A(0), AD(1), AD(2), AD(3), AD(4), AD(5),
                   AD(6), AD(7), AD(8), func_doc.c_str());
      break;
    case 2:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), AD(2), AD(3), AD(4), AD(5),
                   AD(6), AD(7), AD(8), func_doc.c_str());
      break;
    case 3:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), AD(3), AD(4), AD(5),
                   AD(6), AD(7), AD(8), func_doc.c_str());
      break;
    case 4:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), AD(4), AD(5),
                   AD(6), AD(7), AD(8), func_doc.c_str());
      break;
    case 5:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), AD(5),
                   AD(6), AD(7), AD(8), func_doc.c_str());
      break;
    case 6:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   AD(6), AD(7), AD(8), func_doc.c_str());
      break;
    case 7:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   A(6), AD(7), AD(8), func_doc.c_str());
      break;
    case 8:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   A(6), A(7), AD(8), func_doc.c_str());
      break;
    case 9:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   A(6), A(7), A(8), func_doc.c_str());
      break;
    }
  }

  void bind_10_args() {
    if (!is_trailing_defaults_pattern(10)) {
      cls_ptr->def(func_name, func_ptr, func_doc.c_str());
      return;
    }
    int k = first_default_index(10);
    switch (k) {
    case 0:
      cls_ptr->def(func_name, func_ptr, AD(0), AD(1), AD(2), AD(3), AD(4),
                   AD(5), AD(6), AD(7), AD(8), AD(9), func_doc.c_str());
      break;
    case 1:
      cls_ptr->def(func_name, func_ptr, A(0), AD(1), AD(2), AD(3), AD(4), AD(5),
                   AD(6), AD(7), AD(8), AD(9), func_doc.c_str());
      break;
    case 2:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), AD(2), AD(3), AD(4), AD(5),
                   AD(6), AD(7), AD(8), AD(9), func_doc.c_str());
      break;
    case 3:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), AD(3), AD(4), AD(5),
                   AD(6), AD(7), AD(8), AD(9), func_doc.c_str());
      break;
    case 4:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), AD(4), AD(5),
                   AD(6), AD(7), AD(8), AD(9), func_doc.c_str());
      break;
    case 5:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), AD(5),
                   AD(6), AD(7), AD(8), AD(9), func_doc.c_str());
      break;
    case 6:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   AD(6), AD(7), AD(8), AD(9), func_doc.c_str());
      break;
    case 7:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   A(6), AD(7), AD(8), AD(9), func_doc.c_str());
      break;
    case 8:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   A(6), A(7), AD(8), AD(9), func_doc.c_str());
      break;
    case 9:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   A(6), A(7), A(8), AD(9), func_doc.c_str());
      break;
    case 10:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   A(6), A(7), A(8), A(9), func_doc.c_str());
      break;
    }
  }

  void bind_11_args() {
    if (!is_trailing_defaults_pattern(11)) {
      cls_ptr->def(func_name, func_ptr, func_doc.c_str());
      return;
    }
    int k = first_default_index(11);
    switch (k) {
    case 0:
      cls_ptr->def(func_name, func_ptr, AD(0), AD(1), AD(2), AD(3), AD(4),
                   AD(5), AD(6), AD(7), AD(8), AD(9), AD(10), func_doc.c_str());
      break;
    case 1:
      cls_ptr->def(func_name, func_ptr, A(0), AD(1), AD(2), AD(3), AD(4), AD(5),
                   AD(6), AD(7), AD(8), AD(9), AD(10), func_doc.c_str());
      break;
    case 2:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), AD(2), AD(3), AD(4), AD(5),
                   AD(6), AD(7), AD(8), AD(9), AD(10), func_doc.c_str());
      break;
    case 3:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), AD(3), AD(4), AD(5),
                   AD(6), AD(7), AD(8), AD(9), AD(10), func_doc.c_str());
      break;
    case 4:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), AD(4), AD(5),
                   AD(6), AD(7), AD(8), AD(9), AD(10), func_doc.c_str());
      break;
    case 5:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), AD(5),
                   AD(6), AD(7), AD(8), AD(9), AD(10), func_doc.c_str());
      break;
    case 6:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   AD(6), AD(7), AD(8), AD(9), AD(10), func_doc.c_str());
      break;
    case 7:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   A(6), AD(7), AD(8), AD(9), AD(10), func_doc.c_str());
      break;
    case 8:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   A(6), A(7), AD(8), AD(9), AD(10), func_doc.c_str());
      break;
    case 9:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   A(6), A(7), A(8), AD(9), AD(10), func_doc.c_str());
      break;
    case 10:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   A(6), A(7), A(8), A(9), AD(10), func_doc.c_str());
      break;
    case 11:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   A(6), A(7), A(8), A(9), A(10), func_doc.c_str());
      break;
    }
  }

  void bind_12_args() {
    if (!is_trailing_defaults_pattern(12)) {
      cls_ptr->def(func_name, func_ptr, func_doc.c_str());
      return;
    }
    int k = first_default_index(12);
    switch (k) {
    case 0:
      cls_ptr->def(func_name, func_ptr, AD(0), AD(1), AD(2), AD(3), AD(4),
                   AD(5), AD(6), AD(7), AD(8), AD(9), AD(10), AD(11),
                   func_doc.c_str());
      break;
    case 1:
      cls_ptr->def(func_name, func_ptr, A(0), AD(1), AD(2), AD(3), AD(4), AD(5),
                   AD(6), AD(7), AD(8), AD(9), AD(10), AD(11),
                   func_doc.c_str());
      break;
    case 2:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), AD(2), AD(3), AD(4), AD(5),
                   AD(6), AD(7), AD(8), AD(9), AD(10), AD(11),
                   func_doc.c_str());
      break;
    case 3:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), AD(3), AD(4), AD(5),
                   AD(6), AD(7), AD(8), AD(9), AD(10), AD(11),
                   func_doc.c_str());
      break;
    case 4:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), AD(4), AD(5),
                   AD(6), AD(7), AD(8), AD(9), AD(10), AD(11),
                   func_doc.c_str());
      break;
    case 5:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), AD(5),
                   AD(6), AD(7), AD(8), AD(9), AD(10), AD(11),
                   func_doc.c_str());
      break;
    case 6:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   AD(6), AD(7), AD(8), AD(9), AD(10), AD(11),
                   func_doc.c_str());
      break;
    case 7:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   A(6), AD(7), AD(8), AD(9), AD(10), AD(11), func_doc.c_str());
      break;
    case 8:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   A(6), A(7), AD(8), AD(9), AD(10), AD(11), func_doc.c_str());
      break;
    case 9:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   A(6), A(7), A(8), AD(9), AD(10), AD(11), func_doc.c_str());
      break;
    case 10:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   A(6), A(7), A(8), A(9), AD(10), AD(11), func_doc.c_str());
      break;
    case 11:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   A(6), A(7), A(8), A(9), A(10), AD(11), func_doc.c_str());
      break;
    case 12:
      cls_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   A(6), A(7), A(8), A(9), A(10), A(11), func_doc.c_str());
      break;
    }
  }

#undef A
#undef AD
#undef ARG_OR_ARG_V
};

// Factory function for method binding
template <typename ClassType, typename FuncType>
AutoDefHelper<ClassType, FuncType>
auto_def(ClassType &cls, const char *func_name, FuncType func_ptr) {
  return AutoDefHelper<ClassType, FuncType>(cls, func_name, func_ptr);
}

// ==============================================================================
// Auto-binding helper for module-level (free) functions
// Usage: auto_def_func(m, "func_name", &some_function)
//           .arg("param1", default1)
//           .arg("param2", default2)
//           .doc("function doc");
// ==============================================================================

template <typename FuncType>
class AutoDefFuncHelper : public AutoDefHelperBase {
private:
  static constexpr size_t FuncArity = function_traits<FuncType>::arity;
  py::module *mod_ptr;
  const char *func_name;
  FuncType func_ptr;
  bool bound = false;

public:
  AutoDefFuncHelper(py::module &mod, const char *name, FuncType func)
      : mod_ptr(&mod), func_name(name), func_ptr(func) {}

  // Prevent copy to avoid double binding
  AutoDefFuncHelper(const AutoDefFuncHelper &) = delete;
  AutoDefFuncHelper &operator=(const AutoDefFuncHelper &) = delete;
  AutoDefFuncHelper(AutoDefFuncHelper &&other) noexcept
      : AutoDefHelperBase(std::move(other)), mod_ptr(other.mod_ptr),
        func_name(other.func_name), func_ptr(other.func_ptr),
        bound(other.bound) {
    other.bound = true; // Prevent other from binding
  }

  // Add argument without default value (required parameter)
  AutoDefFuncHelper &arg(const char *name) {
    args_info.push_back({name, py::none(), false});
    return *this;
  }

  // Add argument with default value only (including const char*)
  template <typename T, typename = typename std::enable_if<
                            !std::is_convertible<T, std::string>::value ||
                            std::is_same<typename std::decay<T>::type,
                                         const char *>::value>::type>
  AutoDefFuncHelper &arg(const char *name, T &&default_val) {
    args_info.push_back({name, py::cast(std::forward<T>(default_val)), true});
    return *this;
  }

  // Set function documentation
  AutoDefFuncHelper &doc(const char *documentation) {
    func_doc = documentation;
    return *this;
  }

  // Finalize binding (called by destructor)
  ~AutoDefFuncHelper() {
    if (!bound) {
      bind();
    }
  }

  void bind() {
    if (bound)
      return;
    bound = true;

    // Runtime check: verify argument count matches function arity
    if (args_info.size() != FuncArity) {
      std::cerr << fmt::format(
          "\n[FATAL] auto_def_func error for '{}': expected {} arguments but "
          "got {}.\n        Add .arg() calls for all parameters.\n",
          func_name, FuncArity, args_info.size());
      std::abort();
    }

    // Use compile-time arity to select the correct binding
    bind_with_args<FuncArity>();
  }

private:
  template <size_t N> void bind_with_args() {
    if constexpr (N == 0) {
      mod_ptr->def(func_name, func_ptr, func_doc.c_str());
    } else if constexpr (N == 1) {
      if (args_info[0].has_default)
        mod_ptr->def(func_name, func_ptr,
                     py::arg(args_info[0].name.c_str()) =
                         args_info[0].default_value,
                     func_doc.c_str());
      else
        mod_ptr->def(func_name, func_ptr, py::arg(args_info[0].name.c_str()),
                     func_doc.c_str());
    } else if constexpr (N == 2) {
      bind_2_args();
    } else if constexpr (N == 3) {
      bind_3_args();
    } else if constexpr (N == 4) {
      bind_4_args();
    } else if constexpr (N == 5) {
      bind_5_args();
    } else if constexpr (N == 6) {
      bind_6_args();
    } else if constexpr (N == 7) {
      bind_7_args();
    } else if constexpr (N == 8) {
      bind_8_args();
    } else if constexpr (N == 9) {
      bind_9_args();
    } else if constexpr (N == 10) {
      bind_10_args();
    } else if constexpr (N == 11) {
      bind_11_args();
    } else if constexpr (N == 12) {
      bind_12_args();
    } else {
      mod_ptr->def(func_name, func_ptr, func_doc.c_str());
    }
  }

  void bind_2_args() {
    if (args_info[0].has_default && args_info[1].has_default) {
      mod_ptr->def(
          func_name, func_ptr,
          py::arg(args_info[0].name.c_str()) = args_info[0].default_value,
          py::arg(args_info[1].name.c_str()) = args_info[1].default_value,
          func_doc.c_str());
    } else if (args_info[0].has_default && !args_info[1].has_default) {
      mod_ptr->def(func_name, func_ptr,
                   py::arg(args_info[0].name.c_str()) =
                       args_info[0].default_value,
                   py::arg(args_info[1].name.c_str()), func_doc.c_str());
    } else if (!args_info[0].has_default && args_info[1].has_default) {
      mod_ptr->def(func_name, func_ptr, py::arg(args_info[0].name.c_str()),
                   py::arg(args_info[1].name.c_str()) =
                       args_info[1].default_value,
                   func_doc.c_str());
    } else {
      mod_ptr->def(func_name, func_ptr, py::arg(args_info[0].name.c_str()),
                   py::arg(args_info[1].name.c_str()), func_doc.c_str());
    }
  }

  void bind_3_args() {
    int mask = (args_info[0].has_default ? 1 : 0) |
               (args_info[1].has_default ? 2 : 0) |
               (args_info[2].has_default ? 4 : 0);
    switch (mask) {
    case 0:
      mod_ptr->def(func_name, func_ptr, py::arg(args_info[0].name.c_str()),
                   py::arg(args_info[1].name.c_str()),
                   py::arg(args_info[2].name.c_str()), func_doc.c_str());
      break;
    case 1:
      mod_ptr->def(func_name, func_ptr,
                   py::arg(args_info[0].name.c_str()) =
                       args_info[0].default_value,
                   py::arg(args_info[1].name.c_str()),
                   py::arg(args_info[2].name.c_str()), func_doc.c_str());
      break;
    case 2:
      mod_ptr->def(func_name, func_ptr, py::arg(args_info[0].name.c_str()),
                   py::arg(args_info[1].name.c_str()) =
                       args_info[1].default_value,
                   py::arg(args_info[2].name.c_str()), func_doc.c_str());
      break;
    case 3:
      mod_ptr->def(
          func_name, func_ptr,
          py::arg(args_info[0].name.c_str()) = args_info[0].default_value,
          py::arg(args_info[1].name.c_str()) = args_info[1].default_value,
          py::arg(args_info[2].name.c_str()), func_doc.c_str());
      break;
    case 4:
      mod_ptr->def(func_name, func_ptr, py::arg(args_info[0].name.c_str()),
                   py::arg(args_info[1].name.c_str()),
                   py::arg(args_info[2].name.c_str()) =
                       args_info[2].default_value,
                   func_doc.c_str());
      break;
    case 5:
      mod_ptr->def(
          func_name, func_ptr,
          py::arg(args_info[0].name.c_str()) = args_info[0].default_value,
          py::arg(args_info[1].name.c_str()),
          py::arg(args_info[2].name.c_str()) = args_info[2].default_value,
          func_doc.c_str());
      break;
    case 6:
      mod_ptr->def(
          func_name, func_ptr, py::arg(args_info[0].name.c_str()),
          py::arg(args_info[1].name.c_str()) = args_info[1].default_value,
          py::arg(args_info[2].name.c_str()) = args_info[2].default_value,
          func_doc.c_str());
      break;
    case 7:
      mod_ptr->def(
          func_name, func_ptr,
          py::arg(args_info[0].name.c_str()) = args_info[0].default_value,
          py::arg(args_info[1].name.c_str()) = args_info[1].default_value,
          py::arg(args_info[2].name.c_str()) = args_info[2].default_value,
          func_doc.c_str());
      break;
    }
  }

  void bind_4_args() {
    bool all_default = true, none_default = true;
    for (int i = 0; i < 4; i++) {
      if (args_info[i].has_default)
        none_default = false;
      else
        all_default = false;
    }

    if (all_default) {
      mod_ptr->def(
          func_name, func_ptr,
          py::arg(args_info[0].name.c_str()) = args_info[0].default_value,
          py::arg(args_info[1].name.c_str()) = args_info[1].default_value,
          py::arg(args_info[2].name.c_str()) = args_info[2].default_value,
          py::arg(args_info[3].name.c_str()) = args_info[3].default_value,
          func_doc.c_str());
    } else if (none_default) {
      mod_ptr->def(func_name, func_ptr, py::arg(args_info[0].name.c_str()),
                   py::arg(args_info[1].name.c_str()),
                   py::arg(args_info[2].name.c_str()),
                   py::arg(args_info[3].name.c_str()), func_doc.c_str());
    } else {
      // Fallback - no arg names
      mod_ptr->def(func_name, func_ptr, func_doc.c_str());
    }
  }

  void bind_5_args() {
    bool all_default = true, none_default = true;
    for (int i = 0; i < 5; i++) {
      if (args_info[i].has_default)
        none_default = false;
      else
        all_default = false;
    }

    if (all_default) {
      mod_ptr->def(
          func_name, func_ptr,
          py::arg(args_info[0].name.c_str()) = args_info[0].default_value,
          py::arg(args_info[1].name.c_str()) = args_info[1].default_value,
          py::arg(args_info[2].name.c_str()) = args_info[2].default_value,
          py::arg(args_info[3].name.c_str()) = args_info[3].default_value,
          py::arg(args_info[4].name.c_str()) = args_info[4].default_value,
          func_doc.c_str());
    } else if (none_default) {
      mod_ptr->def(func_name, func_ptr, py::arg(args_info[0].name.c_str()),
                   py::arg(args_info[1].name.c_str()),
                   py::arg(args_info[2].name.c_str()),
                   py::arg(args_info[3].name.c_str()),
                   py::arg(args_info[4].name.c_str()), func_doc.c_str());
    } else {
      mod_ptr->def(func_name, func_ptr, func_doc.c_str());
    }
  }

  void bind_6_args() {
    bool all_default = true, none_default = true;
    for (int i = 0; i < 6; i++) {
      if (args_info[i].has_default)
        none_default = false;
      else
        all_default = false;
    }

    if (all_default) {
      mod_ptr->def(
          func_name, func_ptr,
          py::arg(args_info[0].name.c_str()) = args_info[0].default_value,
          py::arg(args_info[1].name.c_str()) = args_info[1].default_value,
          py::arg(args_info[2].name.c_str()) = args_info[2].default_value,
          py::arg(args_info[3].name.c_str()) = args_info[3].default_value,
          py::arg(args_info[4].name.c_str()) = args_info[4].default_value,
          py::arg(args_info[5].name.c_str()) = args_info[5].default_value,
          func_doc.c_str());
    } else if (none_default) {
      mod_ptr->def(func_name, func_ptr, py::arg(args_info[0].name.c_str()),
                   py::arg(args_info[1].name.c_str()),
                   py::arg(args_info[2].name.c_str()),
                   py::arg(args_info[3].name.c_str()),
                   py::arg(args_info[4].name.c_str()),
                   py::arg(args_info[5].name.c_str()), func_doc.c_str());
    } else {
      mod_ptr->def(func_name, func_ptr, func_doc.c_str());
    }
  }

  // Helper: find first index with default (returns N if none have defaults)
  int first_default_index(int N) {
    for (int i = 0; i < N; i++) {
      if (args_info[i].has_default)
        return i;
    }
    return N;
  }

  // Helper: check if pattern is "first K required, rest have defaults"
  bool is_trailing_defaults_pattern(int N) {
    int first_def = first_default_index(N);
    for (int i = first_def; i < N; i++) {
      if (!args_info[i].has_default)
        return false;
    }
    return true;
  }

// Macros for generating arg expressions
#define A(i) py::arg(args_info[i].name.c_str())
#define AD(i) py::arg(args_info[i].name.c_str()) = args_info[i].default_value

  void bind_7_args() {
    if (!is_trailing_defaults_pattern(7)) {
      mod_ptr->def(func_name, func_ptr, func_doc.c_str());
      return;
    }
    int k = first_default_index(7);
    switch (k) {
    case 0:
      mod_ptr->def(func_name, func_ptr, AD(0), AD(1), AD(2), AD(3), AD(4),
                   AD(5), AD(6), func_doc.c_str());
      break;
    case 1:
      mod_ptr->def(func_name, func_ptr, A(0), AD(1), AD(2), AD(3), AD(4), AD(5),
                   AD(6), func_doc.c_str());
      break;
    case 2:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), AD(2), AD(3), AD(4), AD(5),
                   AD(6), func_doc.c_str());
      break;
    case 3:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), AD(3), AD(4), AD(5),
                   AD(6), func_doc.c_str());
      break;
    case 4:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), AD(4), AD(5),
                   AD(6), func_doc.c_str());
      break;
    case 5:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), AD(5),
                   AD(6), func_doc.c_str());
      break;
    case 6:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   AD(6), func_doc.c_str());
      break;
    case 7:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   A(6), func_doc.c_str());
      break;
    }
  }

  void bind_8_args() {
    if (!is_trailing_defaults_pattern(8)) {
      mod_ptr->def(func_name, func_ptr, func_doc.c_str());
      return;
    }
    int k = first_default_index(8);
    switch (k) {
    case 0:
      mod_ptr->def(func_name, func_ptr, AD(0), AD(1), AD(2), AD(3), AD(4),
                   AD(5), AD(6), AD(7), func_doc.c_str());
      break;
    case 1:
      mod_ptr->def(func_name, func_ptr, A(0), AD(1), AD(2), AD(3), AD(4), AD(5),
                   AD(6), AD(7), func_doc.c_str());
      break;
    case 2:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), AD(2), AD(3), AD(4), AD(5),
                   AD(6), AD(7), func_doc.c_str());
      break;
    case 3:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), AD(3), AD(4), AD(5),
                   AD(6), AD(7), func_doc.c_str());
      break;
    case 4:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), AD(4), AD(5),
                   AD(6), AD(7), func_doc.c_str());
      break;
    case 5:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), AD(5),
                   AD(6), AD(7), func_doc.c_str());
      break;
    case 6:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   AD(6), AD(7), func_doc.c_str());
      break;
    case 7:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   A(6), AD(7), func_doc.c_str());
      break;
    case 8:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   A(6), A(7), func_doc.c_str());
      break;
    }
  }

  void bind_9_args() {
    if (!is_trailing_defaults_pattern(9)) {
      mod_ptr->def(func_name, func_ptr, func_doc.c_str());
      return;
    }
    int k = first_default_index(9);
    switch (k) {
    case 0:
      mod_ptr->def(func_name, func_ptr, AD(0), AD(1), AD(2), AD(3), AD(4),
                   AD(5), AD(6), AD(7), AD(8), func_doc.c_str());
      break;
    case 1:
      mod_ptr->def(func_name, func_ptr, A(0), AD(1), AD(2), AD(3), AD(4), AD(5),
                   AD(6), AD(7), AD(8), func_doc.c_str());
      break;
    case 2:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), AD(2), AD(3), AD(4), AD(5),
                   AD(6), AD(7), AD(8), func_doc.c_str());
      break;
    case 3:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), AD(3), AD(4), AD(5),
                   AD(6), AD(7), AD(8), func_doc.c_str());
      break;
    case 4:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), AD(4), AD(5),
                   AD(6), AD(7), AD(8), func_doc.c_str());
      break;
    case 5:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), AD(5),
                   AD(6), AD(7), AD(8), func_doc.c_str());
      break;
    case 6:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   AD(6), AD(7), AD(8), func_doc.c_str());
      break;
    case 7:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   A(6), AD(7), AD(8), func_doc.c_str());
      break;
    case 8:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   A(6), A(7), AD(8), func_doc.c_str());
      break;
    case 9:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   A(6), A(7), A(8), func_doc.c_str());
      break;
    }
  }

  void bind_10_args() {
    if (!is_trailing_defaults_pattern(10)) {
      mod_ptr->def(func_name, func_ptr, func_doc.c_str());
      return;
    }
    int k = first_default_index(10);
    switch (k) {
    case 0:
      mod_ptr->def(func_name, func_ptr, AD(0), AD(1), AD(2), AD(3), AD(4),
                   AD(5), AD(6), AD(7), AD(8), AD(9), func_doc.c_str());
      break;
    case 1:
      mod_ptr->def(func_name, func_ptr, A(0), AD(1), AD(2), AD(3), AD(4), AD(5),
                   AD(6), AD(7), AD(8), AD(9), func_doc.c_str());
      break;
    case 2:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), AD(2), AD(3), AD(4), AD(5),
                   AD(6), AD(7), AD(8), AD(9), func_doc.c_str());
      break;
    case 3:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), AD(3), AD(4), AD(5),
                   AD(6), AD(7), AD(8), AD(9), func_doc.c_str());
      break;
    case 4:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), AD(4), AD(5),
                   AD(6), AD(7), AD(8), AD(9), func_doc.c_str());
      break;
    case 5:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), AD(5),
                   AD(6), AD(7), AD(8), AD(9), func_doc.c_str());
      break;
    case 6:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   AD(6), AD(7), AD(8), AD(9), func_doc.c_str());
      break;
    case 7:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   A(6), AD(7), AD(8), AD(9), func_doc.c_str());
      break;
    case 8:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   A(6), A(7), AD(8), AD(9), func_doc.c_str());
      break;
    case 9:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   A(6), A(7), A(8), AD(9), func_doc.c_str());
      break;
    case 10:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   A(6), A(7), A(8), A(9), func_doc.c_str());
      break;
    }
  }

  void bind_11_args() {
    if (!is_trailing_defaults_pattern(11)) {
      mod_ptr->def(func_name, func_ptr, func_doc.c_str());
      return;
    }
    int k = first_default_index(11);
    switch (k) {
    case 0:
      mod_ptr->def(func_name, func_ptr, AD(0), AD(1), AD(2), AD(3), AD(4),
                   AD(5), AD(6), AD(7), AD(8), AD(9), AD(10), func_doc.c_str());
      break;
    case 1:
      mod_ptr->def(func_name, func_ptr, A(0), AD(1), AD(2), AD(3), AD(4), AD(5),
                   AD(6), AD(7), AD(8), AD(9), AD(10), func_doc.c_str());
      break;
    case 2:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), AD(2), AD(3), AD(4), AD(5),
                   AD(6), AD(7), AD(8), AD(9), AD(10), func_doc.c_str());
      break;
    case 3:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), AD(3), AD(4), AD(5),
                   AD(6), AD(7), AD(8), AD(9), AD(10), func_doc.c_str());
      break;
    case 4:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), AD(4), AD(5),
                   AD(6), AD(7), AD(8), AD(9), AD(10), func_doc.c_str());
      break;
    case 5:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), AD(5),
                   AD(6), AD(7), AD(8), AD(9), AD(10), func_doc.c_str());
      break;
    case 6:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   AD(6), AD(7), AD(8), AD(9), AD(10), func_doc.c_str());
      break;
    case 7:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   A(6), AD(7), AD(8), AD(9), AD(10), func_doc.c_str());
      break;
    case 8:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   A(6), A(7), AD(8), AD(9), AD(10), func_doc.c_str());
      break;
    case 9:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   A(6), A(7), A(8), AD(9), AD(10), func_doc.c_str());
      break;
    case 10:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   A(6), A(7), A(8), A(9), AD(10), func_doc.c_str());
      break;
    case 11:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   A(6), A(7), A(8), A(9), A(10), func_doc.c_str());
      break;
    }
  }

  void bind_12_args() {
    if (!is_trailing_defaults_pattern(12)) {
      mod_ptr->def(func_name, func_ptr, func_doc.c_str());
      return;
    }
    int k = first_default_index(12);
    switch (k) {
    case 0:
      mod_ptr->def(func_name, func_ptr, AD(0), AD(1), AD(2), AD(3), AD(4),
                   AD(5), AD(6), AD(7), AD(8), AD(9), AD(10), AD(11),
                   func_doc.c_str());
      break;
    case 1:
      mod_ptr->def(func_name, func_ptr, A(0), AD(1), AD(2), AD(3), AD(4), AD(5),
                   AD(6), AD(7), AD(8), AD(9), AD(10), AD(11),
                   func_doc.c_str());
      break;
    case 2:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), AD(2), AD(3), AD(4), AD(5),
                   AD(6), AD(7), AD(8), AD(9), AD(10), AD(11),
                   func_doc.c_str());
      break;
    case 3:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), AD(3), AD(4), AD(5),
                   AD(6), AD(7), AD(8), AD(9), AD(10), AD(11),
                   func_doc.c_str());
      break;
    case 4:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), AD(4), AD(5),
                   AD(6), AD(7), AD(8), AD(9), AD(10), AD(11),
                   func_doc.c_str());
      break;
    case 5:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), AD(5),
                   AD(6), AD(7), AD(8), AD(9), AD(10), AD(11),
                   func_doc.c_str());
      break;
    case 6:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   AD(6), AD(7), AD(8), AD(9), AD(10), AD(11),
                   func_doc.c_str());
      break;
    case 7:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   A(6), AD(7), AD(8), AD(9), AD(10), AD(11), func_doc.c_str());
      break;
    case 8:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   A(6), A(7), AD(8), AD(9), AD(10), AD(11), func_doc.c_str());
      break;
    case 9:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   A(6), A(7), A(8), AD(9), AD(10), AD(11), func_doc.c_str());
      break;
    case 10:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   A(6), A(7), A(8), A(9), AD(10), AD(11), func_doc.c_str());
      break;
    case 11:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   A(6), A(7), A(8), A(9), A(10), AD(11), func_doc.c_str());
      break;
    case 12:
      mod_ptr->def(func_name, func_ptr, A(0), A(1), A(2), A(3), A(4), A(5),
                   A(6), A(7), A(8), A(9), A(10), A(11), func_doc.c_str());
      break;
    }
  }

#undef A
#undef AD
};

// Factory function for module-level function binding
template <typename FuncType>
AutoDefFuncHelper<FuncType>
auto_def_func(py::module &mod, const char *func_name, FuncType func_ptr) {
  return AutoDefFuncHelper<FuncType>(mod, func_name, func_ptr);
}

// ==============================================================================
// Auto-binding helper for properties
// Usage: auto_property(cls, "prop_name", &Class::member).doc("Property doc");
//        auto_property_readonly(cls, "prop_name",
//        &Class::member).doc("Property doc");
// ==============================================================================

template <typename ActualClassType, typename ClassType, typename MemberType>
class AutoPropertyHelper {
private:
  ActualClassType *cls_ptr;
  const char *prop_name;
  MemberType member_ptr;
  std::string prop_doc;
  bool is_readonly;

public:
  AutoPropertyHelper(ActualClassType &cls, const char *name, MemberType member,
                     bool readonly = false)
      : cls_ptr(&cls), prop_name(name), member_ptr(member),
        is_readonly(readonly) {}

  // Set property documentation
  AutoPropertyHelper &doc(const char *documentation) {
    prop_doc = documentation;
    return *this;
  }

  // Finalize binding
  ~AutoPropertyHelper() {
    if (is_readonly) {
      cls_ptr->def_readonly(prop_name, member_ptr, prop_doc.c_str());
    } else {
      cls_ptr->def_readwrite(prop_name, member_ptr, prop_doc.c_str());
    }
  }
};

// Factory functions for property binding
template <typename ActualClassType, typename ClassType, typename MemberType>
AutoPropertyHelper<ActualClassType, ClassType, MemberType>
auto_property(ActualClassType &cls, const char *prop_name,
              MemberType member_ptr) {
  return AutoPropertyHelper<ActualClassType, ClassType, MemberType>(
      cls, prop_name, member_ptr, false);
}

template <typename ActualClassType, typename ClassType, typename MemberType>
AutoPropertyHelper<ActualClassType, ClassType, MemberType>
auto_property_readonly(ActualClassType &cls, const char *prop_name,
                       MemberType member_ptr) {
  return AutoPropertyHelper<ActualClassType, ClassType, MemberType>(
      cls, prop_name, member_ptr, true);
};
// ==============================================================================
// Auto-binding helper for enums
// Usage: auto_enum(m, "EnumName", "Enum documentation")
//           .value("VALUE1", EnumType::VALUE1, "Value1 doc")
//           .value("VALUE2", EnumType::VALUE2, "Value2 doc")
//           .export_values();
// ==============================================================================

template <typename EnumType> class AutoEnumHelper {
private:
  py::enum_<EnumType> *enum_ptr;
  bool should_export_values = false;

public:
  AutoEnumHelper(py::module &m, const char *name, const char *doc = "")
      : enum_ptr(new py::enum_<EnumType>(m, name, doc)) {}

  // Add enum value with documentation
  AutoEnumHelper &value(const char *name, EnumType value,
                        const char *doc = "") {
    enum_ptr->value(name, value, doc);
    return *this;
  }

  // Export values to parent scope (like Python enum behavior)
  AutoEnumHelper &export_values() {
    should_export_values = true;
    return *this;
  }

  // Finalize binding
  ~AutoEnumHelper() {
    if (should_export_values) {
      enum_ptr->export_values();
    }
    delete enum_ptr;
  }
};

// Factory function for enum binding
template <typename EnumType>
AutoEnumHelper<EnumType> auto_enum(py::module &m, const char *name,
                                   const char *doc = "") {
  return AutoEnumHelper<EnumType>(m, name, doc);
}

// ==============================================================================
// Fully automatic enum binding using magic_enum
// Automatically binds ALL enum values without manual specification
// ==============================================================================

template <typename EnumType>
py::enum_<EnumType> bind_enum_auto(py::module &m, const char *name,
                                   const char *doc = "",
                                   bool export_values = false) {
  py::enum_<EnumType> enum_obj(m, name, doc);

  // Use magic_enum to iterate over all enum values
  constexpr auto &entries = magic_enum::enum_entries<EnumType>();
  for (const auto &[value, name_sv] : entries) {
    enum_obj.value(std::string(name_sv).c_str(), value);
  }

  if (export_values) {
    enum_obj.export_values();
  }

  return enum_obj;
};
