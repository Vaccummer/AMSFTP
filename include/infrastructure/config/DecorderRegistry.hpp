#pragma once
#include "domain/arg/ArgTypes.hpp"
#include "foundation/tools/json.hpp"
#include "infrastructure/config/IArgCodec.hpp"

#include <map>
#include <memory>
#include <string>
#include <vector>

namespace AMInfra::config {
/**
 * @brief Immutable registry that maps arg type tags to codec strategies.
 */
class DecoderRegistry {
public:
  /**
   * @brief Return shared singleton registry instance.
   */
  [[nodiscard]] static const DecoderRegistry &Instance();

  /**
   * @brief Lookup codec by arg runtime type tag.
   */
  [[nodiscard]] const IArgCodec *Find(AMDomain::arg::TypeTag type) const;

private:
  /**
   * @brief Construct registry with all built-in codecs.
   */
  DecoderRegistry();

  std::vector<std::unique_ptr<IArgCodec>> codecs_ = {};
  std::map<AMDomain::arg::TypeTag, const IArgCodec *> map_ = {};
};

/**
 * @brief Decode JSON root into typed arg payload by runtime type tag.
 */
[[nodiscard]] bool DecodeArg(AMDomain::arg::TypeTag type, const Json &root,
                             void *out, std::string *error = nullptr);

/**
 * @brief Encode typed arg payload into JSON root by runtime type tag.
 */
[[nodiscard]] bool EncodeArg(AMDomain::arg::TypeTag type, const void *in,
                             Json *root, std::string *error = nullptr);

} // namespace AMInfra::config
