#pragma once

#include "domain/config/ConfigModel.hpp"
#include "foundation/tools/json.hpp"

#include <string>
#include <typeindex>

namespace AMInfra::config {
/**
 * @brief Strategy interface for one typed payload <-> document-json conversion pair.
 */
class IArgCodec {
public:
  virtual ~IArgCodec() = default;

  /**
   * @brief Return runtime payload type this codec handles.
   */
  [[nodiscard]] virtual std::type_index Type() const = 0;

  /**
   * @brief Return document kind this codec belongs to.
   */
  [[nodiscard]] virtual AMDomain::config::DocumentKind Kind() const = 0;

  /**
   * @brief Decode one JSON root into output arg instance.
   */
  [[nodiscard]] virtual bool Decode(const Json &root, void *out,
                                    std::string *error) const = 0;

  /**
   * @brief Encode one payload instance into JSON root.
   */
  [[nodiscard]] virtual bool Encode(const void *in, Json *root,
                                    std::string *error) const = 0;

  /**
   * @brief Erase one payload subtree from JSON root.
   */
  [[nodiscard]] virtual bool Erase(const void *in, Json *root,
                                   std::string *error) const = 0;
};
} // namespace AMInfra::config
