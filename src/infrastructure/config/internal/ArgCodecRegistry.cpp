#include "infrastructure/config/internal/ArgCodecRegistry.hpp"
#include <utility>

namespace {
bool Fail_(std::string *error, const std::string &msg) {
  if (error) {
    *error = msg;
  }
  return false;
}
} // namespace

namespace AMInfra::config {
ArgCodecRegistry::ArgCodecRegistry(
    std::unordered_map<std::type_index, const IArgCodec *> map)
    : map_(std::move(map)) {}

const IArgCodec *ArgCodecRegistry::Find(const std::type_index &type_key) const {
  auto it = map_.find(type_key);
  if (it == map_.end()) {
    return nullptr;
  }
  return it->second;
}

bool DecodeArg(const ArgCodecRegistry &registry,
               const std::type_index &type_key, const AMJson::Json &root,
               void *out, std::string *error) {
  const IArgCodec *codec = registry.Find(type_key);
  if (!codec) {
    return Fail_(error, "codec not found for type key");
  }
  return codec->Decode(root, out, error);
}

bool EncodeArg(const ArgCodecRegistry &registry,
               const std::type_index &type_key, const void *in,
               AMJson::Json *root, std::string *error) {
  const IArgCodec *codec = registry.Find(type_key);
  if (!codec) {
    return Fail_(error, "codec not found for type key");
  }
  return codec->Encode(in, root, error);
}

bool EraseArg(const ArgCodecRegistry &registry, const std::type_index &type_key,
              const void *in, AMJson::Json *root, std::string *error) {
  const IArgCodec *codec = registry.Find(type_key);
  if (!codec) {
    return Fail_(error, "codec not found for type key");
  }
  return codec->Erase(in, root, error);
}
} // namespace AMInfra::config
