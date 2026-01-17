#pragma once
#include <magic_enum/magic_enum.hpp>
#include <pybind11/pybind11.h>
#include <string>
#include <type_traits>
#include <vector>

namespace py = pybind11;

// ==============================================================================
// Auto-binding helper using fluent API
// Usage: auto_def(cls, "method", &Class::method)
//           .arg("param1", default1)
//           .arg("param2", default2)
//           .doc("function doc");
//
// For overloaded functions, use py::overload_cast to disambiguate:
//   auto_def(cls, "process", py::overload_cast<int>(&Class::process))
//   auto_def(cls, "process", py::overload_cast<const
//   std::string&>(&Class::process))
//
// For virtual functions that need Python override, use pybind11 trampoline
// class:
//   See:
//   https://pybind11.readthedocs.io/en/stable/advanced/classes.html#overriding-virtual-functions-in-python
// ==============================================================================
template <typename ClassType, typename FuncType> class AutoDefHelper {
private:
  ClassType *cls_ptr;
  const char *func_name;
  FuncType func_ptr;
  std::string func_doc;

  struct ArgInfo {
    std::string name;
    py::handle value;
    bool has_default;
    std::string doc;
  };

  std::vector<ArgInfo> args_info;

public:
  AutoDefHelper(ClassType &cls, const char *name, FuncType func)
      : cls_ptr(&cls), func_name(name), func_ptr(func) {}

  // Add argument without default value (required parameter)
  AutoDefHelper &arg(const char *name) {
    args_info.push_back({name, py::none(), false, ""});
    return *this;
  }

  // Add argument with documentation only (required parameter + doc)
  // Second parameter is std::string - treated as documentation
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
    args_info.push_back(
        {name, py::cast(std::forward<T>(default_val)), true, ""});
    return *this;
  }

  // Add argument with default value and documentation
  template <typename T>
  AutoDefHelper &arg(const char *name, T &&default_val,
                     const std::string &doc) {
    args_info.push_back(
        {name, py::cast(std::forward<T>(default_val)), true, doc});
  }

  // Set function documentation
  AutoDefHelper &doc(const char *documentation) {
    func_doc = documentation;
    return *this;
  }

  // Finalize binding (called by destructor)
  ~AutoDefHelper() { bind(); }

  void bind() {
    size_t n = args_info.size();
    if (n == 0) {
      cls_ptr->def(func_name, func_ptr, func_doc.c_str());
    } else if (n == 1) {
      bind_1arg();
    } else if (n == 2) {
      bind_2arg();
    } else if (n == 3) {
      bind_3arg();
    } else if (n == 4) {
      bind_4arg();
    } else if (n == 5) {
      bind_5arg();
    } else if (n == 6) {
      bind_6arg();
    } else if (n == 7) {
      bind_7arg();
    } else if (n == 8) {
      bind_8arg();
    }
  }

private:
  void bind_1arg() {
    auto &a0 = args_info[0];
#define ARG(n)                                                                 \
  (a##n.has_default ? py::arg(a##n.name.c_str()) = a##n.value                  \
                    : py::arg(a##n.name.c_str()))
    cls_ptr->def(func_name, func_ptr, ARG(0), func_doc.c_str());
#undef ARG
  }

  void bind_2arg() {
    auto &a0 = args_info[0];
    auto &a1 = args_info[1];
#define ARG(n)                                                                 \
  (a##n.has_default ? py::arg(a##n.name.c_str()) = a##n.value                  \
                    : py::arg(a##n.name.c_str()))
    cls_ptr->def(func_name, func_ptr, ARG(0), ARG(1), func_doc.c_str());
#undef ARG
  }

  void bind_3arg() {
    auto &a0 = args_info[0];
    auto &a1 = args_info[1];
    auto &a2 = args_info[2];
#define ARG(n)                                                                 \
  (a##n.has_default ? py::arg(a##n.name.c_str()) = a##n.value                  \
                    : py::arg(a##n.name.c_str()))
    cls_ptr->def(func_name, func_ptr, ARG(0), ARG(1), ARG(2), func_doc.c_str());
#undef ARG
  }

  void bind_4arg() {
    auto &a0 = args_info[0];
    auto &a1 = args_info[1];
    auto &a2 = args_info[2];
    auto &a3 = args_info[3];
#define ARG(n)                                                                 \
  (a##n.has_default ? py::arg(a##n.name.c_str()) = a##n.value                  \
                    : py::arg(a##n.name.c_str()))
    cls_ptr->def(func_name, func_ptr, ARG(0), ARG(1), ARG(2), ARG(3),
                 func_doc.c_str());
#undef ARG
  }

  void bind_5arg() {
    auto &a0 = args_info[0];
    auto &a1 = args_info[1];
    auto &a2 = args_info[2];
    auto &a3 = args_info[3];
    auto &a4 = args_info[4];
#define ARG(n)                                                                 \
  (a##n.has_default ? py::arg(a##n.name.c_str()) = a##n.value                  \
                    : py::arg(a##n.name.c_str()))
    cls_ptr->def(func_name, func_ptr, ARG(0), ARG(1), ARG(2), ARG(3), ARG(4),
                 func_doc.c_str());
#undef ARG
  }

  void bind_6arg() {
    auto &a0 = args_info[0];
    auto &a1 = args_info[1];
    auto &a2 = args_info[2];
    auto &a3 = args_info[3];
    auto &a4 = args_info[4];
    auto &a5 = args_info[5];
#define ARG(n)                                                                 \
  (a##n.has_default ? py::arg(a##n.name.c_str()) = a##n.value                  \
                    : py::arg(a##n.name.c_str()))
    cls_ptr->def(func_name, func_ptr, ARG(0), ARG(1), ARG(2), ARG(3), ARG(4),
                 ARG(5), func_doc.c_str());
#undef ARG
  }

  void bind_7arg() {
    auto &a0 = args_info[0];
    auto &a1 = args_info[1];
    auto &a2 = args_info[2];
    auto &a3 = args_info[3];
    auto &a4 = args_info[4];
    auto &a5 = args_info[5];
    auto &a6 = args_info[6];
#define ARG(n)                                                                 \
  (a##n.has_default ? py::arg(a##n.name.c_str()) = a##n.value                  \
                    : py::arg(a##n.name.c_str()))
    cls_ptr->def(func_name, func_ptr, ARG(0), ARG(1), ARG(2), ARG(3), ARG(4),
                 ARG(5), ARG(6), func_doc.c_str());
#undef ARG
  }

  void bind_8arg() {
    auto &a0 = args_info[0];
    auto &a1 = args_info[1];
    auto &a2 = args_info[2];
    auto &a3 = args_info[3];
    auto &a4 = args_info[4];
    auto &a5 = args_info[5];
    auto &a6 = args_info[6];
    auto &a7 = args_info[7];

    // Build argument list dynamically based on which have defaults
    // This is complex because py::arg and py::arg_v are different types
    // Simplified approach: use helper macro or template

    if (!a0.has_default && !a1.has_default && !a2.has_default &&
        !a3.has_default && !a4.has_default && !a5.has_default &&
        !a6.has_default && !a7.has_default) {
      cls_ptr->def(func_name, func_ptr, py::arg(a0.name.c_str()),
                   py::arg(a1.name.c_str()), py::arg(a2.name.c_str()),
                   py::arg(a3.name.c_str()), py::arg(a4.name.c_str()),
                   py::arg(a5.name.c_str()), py::arg(a6.name.c_str()),
                   py::arg(a7.name.c_str()), func_doc.c_str());
    } else {
// If any has default, use py::arg() = value syntax which returns arg_v
#define ARG(n)                                                                 \
  (a##n.has_default ? py::arg(a##n.name.c_str()) = a##n.value                  \
                    : py::arg(a##n.name.c_str()))
      cls_ptr->def(func_name, func_ptr, ARG(0), ARG(1), ARG(2), ARG(3), ARG(4),
                   ARG(5), ARG(6), ARG(7), func_doc.c_str());
#undef ARG
    }
  }
};

// Factory function for method binding
template <typename ClassType, typename FuncType>
AutoDefHelper<ClassType, FuncType>
auto_def(ClassType &cls, const char *func_name, FuncType func_ptr) {
  return AutoDefHelper<ClassType, FuncType>(cls, func_name, func_ptr);
}

// ==============================================================================
// Auto-binding helper for __init__ (constructor)
// Usage: auto_init<MyClass>(cls).arg("param1").arg("param2",
// default2).doc("Constructor doc");
// ==============================================================================

template <typename ActualClassType, typename ClassType> class AutoInitHelper {
private:
  ActualClassType *cls_ptr;
  std::string init_doc;

  struct ArgInfo {
    std::string name;
    py::handle value;
    bool has_default;
    std::string doc;
  };

  std::vector<ArgInfo> args_info;

public:
  AutoInitHelper(ActualClassType &cls) : cls_ptr(&cls) {}

  // Add argument without default value (required parameter)
  AutoInitHelper &arg(const char *name) {
    args_info.push_back({name, py::none(), false, ""});
    return *this;
  }

  // Add argument with documentation only (required parameter + doc)
  AutoInitHelper &arg(const char *name, const std::string &doc) {
    args_info.push_back({name, py::none(), false, doc});
    return *this;
  }

  // Add argument with default value only (including const char*)
  template <typename T, typename = typename std::enable_if<
                            !std::is_convertible<T, std::string>::value ||
                            std::is_same<typename std::decay<T>::type,
                                         const char *>::value>::type>
  AutoInitHelper &arg(const char *name, T &&default_val) {
    args_info.push_back(
        {name, py::cast(std::forward<T>(default_val)), true, ""});
    return *this;
  }

  // Add argument with default value and documentation
  template <typename T>
  AutoInitHelper &arg(const char *name, T &&default_val,
                      const std::string &doc) {
    args_info.push_back(
        {name, py::cast(std::forward<T>(default_val)), true, doc});
    return *this;
  }

  // Set constructor documentation
  AutoInitHelper &doc(const char *documentation) {
    init_doc = documentation;
    return *this;
  }

  // Finalize binding (called by destructor)
  ~AutoInitHelper() { bind(); }

  void bind() {
    size_t n = args_info.size();
    if (n == 0) {
      bind_0arg();
    } else if (n == 1) {
      bind_1arg();
    } else if (n == 2) {
      bind_2arg();
    } else if (n == 3) {
      bind_3arg();
    } else if (n == 4) {
      bind_4arg();
    } else if (n == 5) {
      bind_5arg();
    } else if (n == 6) {
      bind_6arg();
    } else if (n == 7) {
      bind_7arg();
    } else if (n == 8) {
      bind_8arg();
    }
  }

private:
  void bind_0arg() { cls_ptr->def(py::init<>(), init_doc.c_str()); }

  void bind_1arg() {
    auto &a0 = args_info[0];
#define ARG(n)                                                                 \
  (a##n.has_default ? py::arg(a##n.name.c_str()) = a##n.value                  \
                    : py::arg(a##n.name.c_str()))
    cls_ptr->def(py::init([](py::object val) {
                   return std::make_shared<ClassType>(val);
                 }),
                 ARG(0), init_doc.c_str());
#undef ARG
  }

  void bind_2arg() {
    auto &a0 = args_info[0];
    auto &a1 = args_info[1];
#define ARG(n)                                                                 \
  (a##n.has_default ? py::arg(a##n.name.c_str()) = a##n.value                  \
                    : py::arg(a##n.name.c_str()))
    cls_ptr->def(py::init([](py::object v0, py::object v1) {
                   return std::make_shared<ClassType>(v0, v1);
                 }),
                 ARG(0), ARG(1), init_doc.c_str());
#undef ARG
  }

  void bind_3arg() {
    auto &a0 = args_info[0];
    auto &a1 = args_info[1];
    auto &a2 = args_info[2];
#define ARG(n)                                                                 \
  (a##n.has_default ? py::arg(a##n.name.c_str()) = a##n.value                  \
                    : py::arg(a##n.name.c_str()))
    cls_ptr->def(py::init([](py::object v0, py::object v1, py::object v2) {
                   return std::make_shared<ClassType>(v0, v1, v2);
                 }),
                 ARG(0), ARG(1), ARG(2), init_doc.c_str());
#undef ARG
  }

  void bind_4arg() {
    auto &a0 = args_info[0];
    auto &a1 = args_info[1];
    auto &a2 = args_info[2];
    auto &a3 = args_info[3];
#define ARG(n)                                                                 \
  (a##n.has_default ? py::arg(a##n.name.c_str()) = a##n.value                  \
                    : py::arg(a##n.name.c_str()))
    cls_ptr->def(py::init([](py::object v0, py::object v1, py::object v2,
                             py::object v3) {
                   return std::make_shared<ClassType>(v0, v1, v2, v3);
                 }),
                 ARG(0), ARG(1), ARG(2), ARG(3), init_doc.c_str());
#undef ARG
  }

  void bind_5arg() {
    auto &a0 = args_info[0];
    auto &a1 = args_info[1];
    auto &a2 = args_info[2];
    auto &a3 = args_info[3];
    auto &a4 = args_info[4];
#define ARG(n)                                                                 \
  (a##n.has_default ? py::arg(a##n.name.c_str()) = a##n.value                  \
                    : py::arg(a##n.name.c_str()))
    cls_ptr->def(py::init([](py::object v0, py::object v1, py::object v2,
                             py::object v3, py::object v4) {
                   return std::make_shared<ClassType>(v0, v1, v2, v3, v4);
                 }),
                 ARG(0), ARG(1), ARG(2), ARG(3), ARG(4), init_doc.c_str());
#undef ARG
  }

  void bind_6arg() {
    auto &a0 = args_info[0];
    auto &a1 = args_info[1];
    auto &a2 = args_info[2];
    auto &a3 = args_info[3];
    auto &a4 = args_info[4];
    auto &a5 = args_info[5];
#define ARG(n)                                                                 \
  (a##n.has_default ? py::arg(a##n.name.c_str()) = a##n.value                  \
                    : py::arg(a##n.name.c_str()))
    cls_ptr->def(py::init([](py::object v0, py::object v1, py::object v2,
                             py::object v3, py::object v4, py::object v5) {
                   return std::make_shared<ClassType>(v0, v1, v2, v3, v4, v5);
                 }),
                 ARG(0), ARG(1), ARG(2), ARG(3), ARG(4), ARG(5),
                 init_doc.c_str());
#undef ARG
  }

  void bind_7arg() {
    auto &a0 = args_info[0];
    auto &a1 = args_info[1];
    auto &a2 = args_info[2];
    auto &a3 = args_info[3];
    auto &a4 = args_info[4];
    auto &a5 = args_info[5];
    auto &a6 = args_info[6];
#define ARG(n)                                                                 \
  (a##n.has_default ? py::arg(a##n.name.c_str()) = a##n.value                  \
                    : py::arg(a##n.name.c_str()))
    cls_ptr->def(
        py::init([](py::object v0, py::object v1, py::object v2, py::object v3,
                    py::object v4, py::object v5, py::object v6) {
          return std::make_shared<ClassType>(v0, v1, v2, v3, v4, v5, v6);
        }),
        ARG(0), ARG(1), ARG(2), ARG(3), ARG(4), ARG(5), ARG(6),
        init_doc.c_str());
#undef ARG
  }

  void bind_8arg() {
    auto &a0 = args_info[0];
    auto &a1 = args_info[1];
    auto &a2 = args_info[2];
    auto &a3 = args_info[3];
    auto &a4 = args_info[4];
    auto &a5 = args_info[5];
    auto &a6 = args_info[6];
    auto &a7 = args_info[7];
#define ARG(n)                                                                 \
  (a##n.has_default ? py::arg(a##n.name.c_str()) = a##n.value                  \
                    : py::arg(a##n.name.c_str()))
    cls_ptr->def(py::init([](py::object v0, py::object v1, py::object v2,
                             py::object v3, py::object v4, py::object v5,
                             py::object v6, py::object v7) {
                   return std::make_shared<ClassType>(v0, v1, v2, v3, v4, v5,
                                                      v6, v7);
                 }),
                 ARG(0), ARG(1), ARG(2), ARG(3), ARG(4), ARG(5), ARG(6), ARG(7),
                 init_doc.c_str());
#undef ARG
  }
};

// Factory function for __init__ binding
template <typename ClassType, typename ActualClassType>
AutoInitHelper<ActualClassType, ClassType> auto_init(ActualClassType &cls) {
  return AutoInitHelper<ActualClassType, ClassType>(cls);
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
