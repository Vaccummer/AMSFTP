#pragma once

#include "AMBase/tools/string.hpp"

#include <algorithm>
#include <limits>
#include <nlohmann/json.hpp>
#include <string>
#include <type_traits>
#include <vector>

namespace AMJson {
using Json = nlohmann::ordered_json;

template <class T>
inline constexpr bool kValueTypeSupported =
    std::is_arithmetic_v<std::decay_t<T>> ||
    std::is_same_v<std::decay_t<T>, std::string> ||
    std::is_same_v<std::decay_t<T>, std::vector<std::string>> ||
    std::is_same_v<std::decay_t<T>, Json>;

template <typename T>
inline bool QueryKey(const Json &root, const std::vector<std::string> &path,
                     T *value) {
  static_assert(kValueTypeSupported<T>, "T is not supported");
  if (!value) {
    return false;
  }
  const Json *node = &root;
  for (const auto &seg : path) {
    if (!node->is_object()) {
      return false;
    }
    auto it = node->find(seg);
    if (it == node->end()) {
      return false;
    }
    node = &(*it);
  }
  if constexpr (std::is_same_v<T, bool>) {
    if (!node->is_boolean()) {
      if (node->is_number_integer()) {
        *value = node->get<int64_t>() != 0;
        return true;
      }
      if (node->is_number_unsigned()) {
        *value = node->get<size_t>() != 0;
        return true;
      }
      if (node->is_string()) {
        const std::string token = AMStr::lowercase(node->get<std::string>());
        if (token == "true" || token == "1" || token == "yes" ||
            token == "on") {
          *value = true;
          return true;
        }
        if (token == "false" || token == "0" || token == "no" ||
            token == "off") {
          *value = false;
          return true;
        }
      }
      return false;
    }
    *value = node->get<bool>();
    return true;
  } else if constexpr (std::is_same_v<T, std::string>) {
    if (node->is_string()) {
      *value = node->get<std::string>();
      return true;
    }
    if (node->is_boolean()) {
      *value = node->get<bool>() ? "true" : "false";
      return true;
    }
    if (node->is_number_integer()) {
      *value = std::to_string(node->get<int64_t>());
      return true;
    }
    if (node->is_number_unsigned()) {
      *value = std::to_string(node->get<size_t>());
      return true;
    }
    if (node->is_number_float()) {
      *value = std::to_string(node->get<double>());
      return true;
    }
    return false;
  } else if constexpr (std::is_same_v<T, std::vector<std::string>>) {
    if (!node->is_array()) {
      return false;
    }
    std::vector<std::string> out;
    out.reserve(node->size());
    for (const auto &item : *node) {
      if (item.is_string()) {
        out.push_back(item.get<std::string>());
        continue;
      }
      if (item.is_boolean()) {
        out.push_back(item.get<bool>() ? "true" : "false");
        continue;
      }
      if (item.is_number_integer()) {
        out.push_back(std::to_string(item.get<int64_t>()));
        continue;
      }
      if (item.is_number_unsigned()) {
        out.push_back(std::to_string(item.get<size_t>()));
        continue;
      }
      if (item.is_number_float()) {
        out.push_back(std::to_string(item.get<double>()));
        continue;
      }
      return false;
    }
    *value = std::move(out);
    return true;
  } else if constexpr (std::is_same_v<T, Json>) {
    *value = *node;
    return true;
  } else if constexpr (std::is_floating_point_v<T>) {
    if (node->is_number()) {
      *value = static_cast<T>(node->get<double>());
      return true;
    }
    if (node->is_string()) {
      try {
        *value = static_cast<T>(std::stod(node->get<std::string>()));
        return true;
      } catch (...) {
        return false;
      }
    }
    return false;
  } else if constexpr (std::is_integral_v<T>) {
    if (node->is_number_integer()) {
      const int64_t raw = node->get<int64_t>();
      if (raw < static_cast<int64_t>(std::numeric_limits<T>::min()) ||
          raw > static_cast<int64_t>(std::numeric_limits<T>::max())) {
        return false;
      }
      *value = static_cast<T>(raw);
      return true;
    }
    if (node->is_number_unsigned()) {
      const uint64_t raw = node->get<uint64_t>();
      if (raw > static_cast<uint64_t>(std::numeric_limits<T>::max())) {
        return false;
      }
      *value = static_cast<T>(raw);
      return true;
    }
    if (node->is_string()) {
      try {
        const int64_t raw = std::stoll(node->get<std::string>());
        if (raw < static_cast<int64_t>(std::numeric_limits<T>::min()) ||
            raw > static_cast<int64_t>(std::numeric_limits<T>::max())) {
          return false;
        }
        *value = static_cast<T>(raw);
        return true;
      } catch (...) {
        return false;
      }
    }
    return false;
  } else {
    return false;
  }
}

template <typename T>
inline bool SetKey(Json &root, const std::vector<std::string> &path, T value) {
  static_assert(kValueTypeSupported<T>, "T is not supported");
  if (path.empty()) {
    root = value;
    return true;
  }
  Json *node = &root;
  for (size_t i = 0; i < path.size(); ++i) {
    const std::string &seg = path[i];
    if (i + 1 == path.size()) {
      (*node)[seg] = value;
      return true;
    }
    if (!node->is_object()) {
      *node = Json::object();
    }
    if (!node->contains(seg) || !(*node)[seg].is_object()) {
      (*node)[seg] = Json::object();
    }
    node = &(*node)[seg];
  }
  return false;
}

bool DelKey(Json &root, const std::vector<std::string> &path);

template <typename T> bool StrValueParse(const std::string &input, T *out) {
  static_assert(std::is_arithmetic_v<std::decay_t<T>> ||
                    std::is_same_v<std::decay_t<T>, std::string> ||
                    std::is_same_v<T, bool>,
                "T is not supported");
  if constexpr (std::is_same_v<T, bool>) {
    const std::string token = AMStr::lowercase(input);
    if (token == "true") {
      *out = true;
      return true;
    }
    if (token == "false") {
      *out = false;
      return true;
    }
  }
  if constexpr (std::is_same_v<T, std::string>) {
    *out = input;
    return true;
  }
  if constexpr (std::is_arithmetic_v<std::decay_t<T>>) {
    try {
      auto tmp_d = std::stod(input);
      if (tmp_d < 0 && std::is_unsigned_v<std::decay_t<T>>) {
        return false;
      }
      if (tmp_d > static_cast<double>(std::numeric_limits<T>::max()) ||
          tmp_d < static_cast<double>(std::numeric_limits<T>::min())) {
        return false;
      }
      *out = static_cast<T>(tmp_d);
      return true;
    } catch (...) {
      return false;
    }
  }

  return false;
}

template <typename T> std::vector<T> VectorDedup(const std::vector<T> &input) {
  std::vector<T> output;
  output.reserve(input.size());
  for (const auto &item : input) {
    if (std::find(output.begin(), output.end(), item) == output.end()) {
      output.push_back(item);
    }
  }
  return output;
}
} // namespace AMJson

// Compatibility alias for JSON value type.
using Json = nlohmann::ordered_json;
