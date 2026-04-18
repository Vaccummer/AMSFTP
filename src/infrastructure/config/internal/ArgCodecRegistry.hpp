#pragma once

#include "domain/config/ConfigModel.hpp"
#include "foundation/tools/json.hpp"

#include <string>
#include <typeindex>
#include <unordered_map>

namespace AMInfra::config {
/**
 * @brief Strategy interface for one typed payload <-> document-json conversion.
 */
class IArgCodec {
public:
  virtual ~IArgCodec() = default;

  /**
   * @brief Return RTTI key for the payload this codec handles.
   */
  [[nodiscard]] virtual std::type_index TypeKey() const = 0;

  /**
   * @brief Return document kind this codec belongs to.
   */
  [[nodiscard]] virtual AMDomain::config::DocumentKind Kind() const = 0;

  /**
   * @brief Decode one JSON root into output payload.
   */
  [[nodiscard]] virtual bool Decode(const AMJson::Json &root, void *out,
                                    std::string *error) const = 0;

  /**
   * @brief Encode one payload into JSON root.
   */
  [[nodiscard]] virtual bool Encode(const void *in, AMJson::Json *root,
                                    std::string *error) const = 0;

  /**
   * @brief Erase one payload subtree from JSON root.
   */
  [[nodiscard]] virtual bool Erase(const void *in, AMJson::Json *root,
                                   std::string *error) const = 0;
};

/**
 * @brief Registry mapping RTTI keys to codec implementations.
 */
class ArgCodecRegistry {
public:
  ArgCodecRegistry() = default;
  explicit ArgCodecRegistry(
      std::unordered_map<std::type_index, const IArgCodec *> map);

  /**
   * @brief Lookup codec by RTTI key.
   */
  [[nodiscard]] const IArgCodec *Find(const std::type_index &type_key) const;

private:
  std::unordered_map<std::type_index, const IArgCodec *> map_ = {};
};

/**
 * @brief Build the full codec lookup map.
 */
[[nodiscard]] std::unordered_map<std::type_index, const IArgCodec *>
BuildCodecMap();

/**
 * @brief Decode JSON root into one typed payload by RTTI key.
 */
[[nodiscard]] bool DecodeArg(const ArgCodecRegistry &registry,
                             const std::type_index &type_key,
                             const AMJson::Json &root, void *out,
                             std::string *error = nullptr);

/**
 * @brief Encode one typed payload into JSON root by RTTI key.
 */
[[nodiscard]] bool EncodeArg(const ArgCodecRegistry &registry,
                             const std::type_index &type_key, const void *in,
                             AMJson::Json *root, std::string *error = nullptr);

/**
 * @brief Erase one typed payload subtree from JSON root by RTTI key.
 */
[[nodiscard]] bool EraseArg(const ArgCodecRegistry &registry,
                            const std::type_index &type_key, const void *in,
                            AMJson::Json *root, std::string *error = nullptr);
} // namespace AMInfra::config
