#pragma once
#include <magic_enum/magic_enum.hpp>
#include <pybind11/pybind11.h>
#include <string>
#include <type_traits>
#include <vector>

namespace py = pybind11;

// ==============================================================================
// Function traits to extract argument count at compile time
// ==============================================================================

// Primary template - for generic callable types
template <typename T> struct function_traits;

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
template <typename R, typename... Args>
struct function_traits<R (*)(Args...)> {
  static constexpr size_t arity = sizeof...(Args);
};

// Specialization for function references
template <typename R, typename... Args>
struct function_traits<R (&)(Args...)> {
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
    py::object value;
    bool has_default;
    std::string doc;
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
    args_info.push_back({name, py::none(), false, ""});
    return *this;
  }

  // Add argument with documentation only (required parameter + doc)
  AutoDefHelper &arg(const char *name, const std::string &doc) {
    args_info.push_back({name, py::none(), false, doc});
    return *this;
  }

  // Add argument with default value only (including const char*)
  template <typename T, typename = typename std::enable_if<
                            !std::is_convertible<T, std::string>::value ||
                            std::is_same<typename std::decay<T>::type,
                                         const char *>::value>::type>
  AutoDefHelper &arg(const char *name, T &&default_val) {
    args_info.push_back({name, py::cast(std::forward<T>(default_val)), true, ""});
    return *this;
  }

  // Add argument with default value and documentation
  template <typename T>
  AutoDefHelper &arg(const char *name, T &&default_val, const std::string &doc) {
    args_info.push_back({name, py::cast(std::forward<T>(default_val)), true, doc});
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
    
    // Use compile-time arity to select the correct binding
    bind_with_args<FuncArity>();
  }

private:
// Macro to get arg_v from args_info
#define MAKE_ARG(i)                                                            \
  (args_info[i].has_default                                                    \
       ? py::arg(args_info[i].name.c_str()) = args_info[i].value               \
       : py::arg(args_info[i].name.c_str()))

  template <size_t N> void bind_with_args() {
    if constexpr (N == 0) {
      cls_ptr->def(func_name, func_ptr, func_doc.c_str());
    } else if constexpr (N == 1) {
      cls_ptr->def(func_name, func_ptr, MAKE_ARG(0), func_doc.c_str());
    } else if constexpr (N == 2) {
      cls_ptr->def(func_name, func_ptr, MAKE_ARG(0), MAKE_ARG(1),
                   func_doc.c_str());
    } else if constexpr (N == 3) {
      cls_ptr->def(func_name, func_ptr, MAKE_ARG(0), MAKE_ARG(1), MAKE_ARG(2),
                   func_doc.c_str());
    } else if constexpr (N == 4) {
      cls_ptr->def(func_name, func_ptr, MAKE_ARG(0), MAKE_ARG(1), MAKE_ARG(2),
                   MAKE_ARG(3), func_doc.c_str());
    } else if constexpr (N == 5) {
      cls_ptr->def(func_name, func_ptr, MAKE_ARG(0), MAKE_ARG(1), MAKE_ARG(2),
                   MAKE_ARG(3), MAKE_ARG(4), func_doc.c_str());
    } else if constexpr (N == 6) {
      cls_ptr->def(func_name, func_ptr, MAKE_ARG(0), MAKE_ARG(1), MAKE_ARG(2),
                   MAKE_ARG(3), MAKE_ARG(4), MAKE_ARG(5), func_doc.c_str());
    } else if constexpr (N == 7) {
      cls_ptr->def(func_name, func_ptr, MAKE_ARG(0), MAKE_ARG(1), MAKE_ARG(2),
                   MAKE_ARG(3), MAKE_ARG(4), MAKE_ARG(5), MAKE_ARG(6),
                   func_doc.c_str());
    } else if constexpr (N == 8) {
      cls_ptr->def(func_name, func_ptr, MAKE_ARG(0), MAKE_ARG(1), MAKE_ARG(2),
                   MAKE_ARG(3), MAKE_ARG(4), MAKE_ARG(5), MAKE_ARG(6),
                   MAKE_ARG(7), func_doc.c_str());
    } else {
      // Fallback for functions with more than 8 arguments - bind without arg names
      cls_ptr->def(func_name, func_ptr, func_doc.c_str());
    }
  }
#undef MAKE_ARG
};

// Factory function for method binding
template <typename ClassType, typename FuncType>
AutoDefHelper<ClassType, FuncType>
auto_def(ClassType &cls, const char *func_name, FuncType func_ptr) {
  return AutoDefHelper<ClassType, FuncType>(cls, func_name, func_ptr);
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
