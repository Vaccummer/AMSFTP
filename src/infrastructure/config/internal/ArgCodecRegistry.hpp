#pragma once

#include "foundation/tools/json.hpp"
#include "IArgCodec.hpp"

#include <memory>
#include <string>
#include <typeindex>
#include <unordered_map>
#include <vector>

namespace AMInfra::config {
/**
 * @brief Immutable registry that maps runtime payload types to codec strategies.
 */
class ArgCodecRegistry {
public:
  /**
   * @brief Return shared singleton registry instance.
   */
  [[nodiscard]] static const ArgCodecRegistry &Instance();

  /**
   * @brief Lookup codec by runtime payload type.
   */
  [[nodiscard]] const IArgCodec *Find(const std::type_index &type) const;

private:
  /**
   * @brief Construct registry with all built-in codecs.
   */
  ArgCodecRegistry();

  std::vector<std::unique_ptr<IArgCodec>> codecs_ = {};
  std::unordered_map<std::type_index, const IArgCodec *> map_ = {};
};

/**
 * @brief Decode JSON root into one typed payload by runtime type.
 */
[[nodiscard]] bool DecodeArg(const std::type_index &type, const Json &root,
                             void *out, std::string *error = nullptr);

/**
 * @brief Encode one typed payload into JSON root by runtime type.
 */
[[nodiscard]] bool EncodeArg(const std::type_index &type, const void *in,
                             Json *root, std::string *error = nullptr);

/**
 * @brief Erase one typed payload subtree from JSON root by runtime type.
 */
[[nodiscard]] bool EraseArg(const std::type_index &type, const void *in,
                            Json *root, std::string *error = nullptr);
} // namespace AMInfra::config
