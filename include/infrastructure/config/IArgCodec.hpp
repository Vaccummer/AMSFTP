#pragma once
#include "domain/arg/ArgTypes.hpp"
#include "foundation/tools/json.hpp"

#include <string>

namespace AMInfra::config {
/**
 * @brief Strategy interface for one arg<->json conversion pair.
 */
class IArgCodec {
public:
  virtual ~IArgCodec() = default;

  /**
   * @brief Return runtime arg type tag this codec handles.
   */
  [[nodiscard]] virtual AMDomain::arg::TypeTag Tag() const = 0;

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
   * @brief Encode one arg instance into JSON root.
   */
  [[nodiscard]] virtual bool Encode(const void *in, Json *root,
                                    std::string *error) const = 0;
};
} // namespace AMInfra::config
