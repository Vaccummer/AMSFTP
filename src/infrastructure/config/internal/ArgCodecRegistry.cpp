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
    std::unordered_map<AMDomain::config::ConfigPayloadTag, const IArgCodec *> map)
    : map_(std::move(map)) {}

const IArgCodec *
ArgCodecRegistry::Find(AMDomain::config::ConfigPayloadTag tag) const {
  auto it = map_.find(tag);
  if (it == map_.end()) {
    return nullptr;
  }
  return it->second;
}

bool DecodeArg(const ArgCodecRegistry &registry,
               AMDomain::config::ConfigPayloadTag tag, const Json &root,
               void *out, std::string *error) {
  const IArgCodec *codec = registry.Find(tag);
  if (!codec) {
    return Fail_(error, "codec not found for payload tag");
  }
  return codec->Decode(root, out, error);
}

bool EncodeArg(const ArgCodecRegistry &registry,
               AMDomain::config::ConfigPayloadTag tag, const void *in,
               Json *root, std::string *error) {
  const IArgCodec *codec = registry.Find(tag);
  if (!codec) {
    return Fail_(error, "codec not found for payload tag");
  }
  return codec->Encode(in, root, error);
}

bool EraseArg(const ArgCodecRegistry &registry,
              AMDomain::config::ConfigPayloadTag tag, const void *in, Json *root,
              std::string *error) {
  const IArgCodec *codec = registry.Find(tag);
  if (!codec) {
    return Fail_(error, "codec not found for payload tag");
  }
  return codec->Erase(in, root, error);
}
} // namespace AMInfra::config
