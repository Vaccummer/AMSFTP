#pragma once

#include "domain/arg/ArgStructTag.hpp"
#include "domain/config/ConfigModel.hpp"
#include "foundation/tools/json.hpp"

#include <string>
#include <unordered_map>

namespace AMInfra::config {
/**
 * @brief Strategy interface for one typed payload <-> document-json conversion.
 */
class IArgCodec {
public:
  virtual ~IArgCodec() = default;

  /**
   * @brief Return payload tag this codec handles.
   */
  [[nodiscard]] virtual AMDomain::config::ConfigPayloadTag Tag() const = 0;

  /**
   * @brief Return document kind this codec belongs to.
   */
  [[nodiscard]] virtual AMDomain::config::DocumentKind Kind() const = 0;

  /**
   * @brief Decode one JSON root into output payload.
   */
  [[nodiscard]] virtual bool Decode(const Json &root, void *out,
                                    std::string *error) const = 0;

  /**
   * @brief Encode one payload into JSON root.
   */
  [[nodiscard]] virtual bool Encode(const void *in, Json *root,
                                    std::string *error) const = 0;

  /**
   * @brief Erase one payload subtree from JSON root.
   */
  [[nodiscard]] virtual bool Erase(const void *in, Json *root,
                                   std::string *error) const = 0;
};

/**
 * @brief Registry mapping payload tags to codec implementations.
 */
class ArgCodecRegistry {
public:
  ArgCodecRegistry() = default;
  explicit ArgCodecRegistry(
      std::unordered_map<AMDomain::config::ConfigPayloadTag,
                         const IArgCodec *> map);

  /**
   * @brief Lookup codec by payload tag.
   */
  [[nodiscard]] const IArgCodec *
  Find(AMDomain::config::ConfigPayloadTag tag) const;

private:
  std::unordered_map<AMDomain::config::ConfigPayloadTag, const IArgCodec *> map_ =
      {};
};

/**
 * @brief Build the full codec lookup map.
 */
[[nodiscard]] std::unordered_map<AMDomain::config::ConfigPayloadTag,
                                 const IArgCodec *>
BuildCodecMap();

/**
 * @brief Decode JSON root into one typed payload by payload tag.
 */
[[nodiscard]] bool DecodeArg(const ArgCodecRegistry &registry,
                             AMDomain::config::ConfigPayloadTag tag,
                             const Json &root, void *out,
                             std::string *error = nullptr);

/**
 * @brief Encode one typed payload into JSON root by payload tag.
 */
[[nodiscard]] bool EncodeArg(const ArgCodecRegistry &registry,
                             AMDomain::config::ConfigPayloadTag tag,
                             const void *in, Json *root,
                             std::string *error = nullptr);

/**
 * @brief Erase one typed payload subtree from JSON root by payload tag.
 */
[[nodiscard]] bool EraseArg(const ArgCodecRegistry &registry,
                            AMDomain::config::ConfigPayloadTag tag,
                            const void *in, Json *root,
                            std::string *error = nullptr);
} // namespace AMInfra::config
