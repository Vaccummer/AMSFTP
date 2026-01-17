#pragma once
#include <magic_enum/magic_enum.hpp>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <string>
#include <vector>

namespace py = pybind11;

// Simple auto-binding helpers - no parameter annotations, only names and
// defaults

template <typename ClassType, typename FuncType> class AutoDefHelper {
private:
  struct ArgInfo {
    std::string name;
    py::handle value;
    bool has_default;
  };
  ClassType *cls_ptr;
  const char *func_name;
  FuncType func_ptr;
  std::string func_doc;
  std::vector<ArgInfo> args_info;

public:
  AutoDefHelper(ClassType &cls, const char *name, FuncType func)
      : cls_ptr(&cls), func_name(name), func_ptr(func) {}

  AutoDefHelper &arg(const char *name) {
    args_info.push_back({name, py::none(), false});
    return *this;
  }

  template <typename T> AutoDefHelper &arg(const char *name, T &&value) {
    args_info.push_back({name, py::cast(std::forward<T>(value)), true});
    return *this;
  }

  AutoDefHelper &doc(const char *documentation) {
    func_doc = documentation;
    return *this;
  }

  ~AutoDefHelper() {
    size_t n = args_info.size();
#define ARG(i)                                                                 \
  (args_info[i].has_default                                                    \
       ? py::arg(args_info[i].name.c_str()) = args_info[i].value               \
       : py::arg(args_info[i].name.c_str()))
    switch (n) {
    case 0:
      cls_ptr->def(func_name, func_ptr, func_doc.c_str());
      break;
    case 1:
      cls_ptr->def(func_name, func_ptr, ARG(0), func_doc.c_str());
      break;
    case 2:
      cls_ptr->def(func_name, func_ptr, ARG(0), ARG(1), func_doc.c_str());
      break;
    case 3:
      cls_ptr->def(func_name, func_ptr, ARG(0), ARG(1), ARG(2),
                   func_doc.c_str());
      break;
    case 4:
      cls_ptr->def(func_name, func_ptr, ARG(0), ARG(1), ARG(2), ARG(3),
                   func_doc.c_str());
      break;
    case 5:
      cls_ptr->def(func_name, func_ptr, ARG(0), ARG(1), ARG(2), ARG(3), ARG(4),
                   func_doc.c_str());
      break;
    case 6:
      cls_ptr->def(func_name, func_ptr, ARG(0), ARG(1), ARG(2), ARG(3), ARG(4),
                   ARG(5), func_doc.c_str());
      break;
    case 7:
      cls_ptr->def(func_name, func_ptr, ARG(0), ARG(1), ARG(2), ARG(3), ARG(4),
                   ARG(5), ARG(6), func_doc.c_str());
      break;
    case 8:
      cls_ptr->def(func_name, func_ptr, ARG(0), ARG(1), ARG(2), ARG(3), ARG(4),
                   ARG(5), ARG(6), ARG(7), func_doc.c_str());
      break;
    }
#undef ARG
  }
};

template <typename ClassType, typename FuncType>
AutoDefHelper<ClassType, FuncType>
auto_def(ClassType &cls, const char *func_name, FuncType func_ptr) {
  return AutoDefHelper<ClassType, FuncType>(cls, func_name, func_ptr);
}

template <typename ActualClassType, typename ClassType> class AutoInitHelper {
private:
  struct ArgInfo {
    std::string name;
    py::handle value;
    bool has_default;
  };
  ActualClassType *cls_ptr;
  std::string init_doc;
  std::vector<ArgInfo> args_info;

public:
  AutoInitHelper(ActualClassType &cls) : cls_ptr(&cls) {}

  AutoInitHelper &arg(const char *name) {
    args_info.push_back({name, py::none(), false});
    return *this;
  }

  template <typename T> AutoInitHelper &arg(const char *name, T &&value) {
    args_info.push_back({name, py::cast(std::forward<T>(value)), true});
    return *this;
  }

  AutoInitHelper &doc(const char *documentation) {
    init_doc = documentation;
    return *this;
  }

  ~AutoInitHelper() {
    size_t n = args_info.size();
#define ARG(i)                                                                 \
  (args_info[i].has_default                                                    \
       ? py::arg(args_info[i].name.c_str()) = args_info[i].value               \
       : py::arg(args_info[i].name.c_str()))
    switch (n) {
    case 0:
      cls_ptr->def(py::init([]() { return std::make_shared<ClassType>(); }),
                   init_doc.c_str());
      break;
    case 1:
      cls_ptr->def(
          py::init([](auto a0) { return std::make_shared<ClassType>(a0); }),
          ARG(0), init_doc.c_str());
      break;
    case 2:
      cls_ptr->def(py::init([](auto a0, auto a1) {
                     return std::make_shared<ClassType>(a0, a1);
                   }),
                   ARG(0), ARG(1), init_doc.c_str());
      break;
    case 3:
      cls_ptr->def(py::init([](auto a0, auto a1, auto a2) {
                     return std::make_shared<ClassType>(a0, a1, a2);
                   }),
                   ARG(0), ARG(1), ARG(2), init_doc.c_str());
      break;
    case 4:
      cls_ptr->def(py::init([](auto a0, auto a1, auto a2, auto a3) {
                     return std::make_shared<ClassType>(a0, a1, a2, a3);
                   }),
                   ARG(0), ARG(1), ARG(2), ARG(3), init_doc.c_str());
      break;
    case 5:
      cls_ptr->def(py::init([](auto a0, auto a1, auto a2, auto a3, auto a4) {
                     return std::make_shared<ClassType>(a0, a1, a2, a3, a4);
                   }),
                   ARG(0), ARG(1), ARG(2), ARG(3), ARG(4), init_doc.c_str());
      break;
    case 6:
      cls_ptr->def(
          py::init([](auto a0, auto a1, auto a2, auto a3, auto a4, auto a5) {
            return std::make_shared<ClassType>(a0, a1, a2, a3, a4, a5);
          }),
          ARG(0), ARG(1), ARG(2), ARG(3), ARG(4), ARG(5), init_doc.c_str());
      break;
    case 7:
      cls_ptr->def(py::init([](auto a0, auto a1, auto a2, auto a3, auto a4,
                               auto a5, auto a6) {
                     return std::make_shared<ClassType>(a0, a1, a2, a3, a4, a5,
                                                        a6);
                   }),
                   ARG(0), ARG(1), ARG(2), ARG(3), ARG(4), ARG(5), ARG(6),
                   init_doc.c_str());
      break;
    case 8:
      cls_ptr->def(py::init([](auto a0, auto a1, auto a2, auto a3, auto a4,
                               auto a5, auto a6, auto a7) {
                     return std::make_shared<ClassType>(a0, a1, a2, a3, a4, a5,
                                                        a6, a7);
                   }),
                   ARG(0), ARG(1), ARG(2), ARG(3), ARG(4), ARG(5), ARG(6),
                   ARG(7), init_doc.c_str());
      break;
    }
#undef ARG
  }
};

template <typename ActualClassType, typename ClassType>
AutoInitHelper<ActualClassType, ClassType> auto_init(ActualClassType &cls) {
  return AutoInitHelper<ActualClassType, ClassType>(cls);
}

template <typename EnumType>
void bind_enum_auto(py::module &m, const char *enum_name) {
  auto enum_obj = py::enum_<EnumType>(m, enum_name);
  for (auto [value, name] : magic_enum::enum_entries<EnumType>()) {
    enum_obj.value(name.data(), value);
  }
  enum_obj.export_values();
}
