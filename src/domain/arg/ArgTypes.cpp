#include "domain/arg/ArgTypes.hpp"

#include "domain/config/ConfigModel.hpp"

namespace AMDomain::arg {
bool FindDocumentKind(TypeTag type, AMDomain::config::DocumentKind *out) {
  if (!out) {
    return false;
  }

  using DocumentKind = AMDomain::config::DocumentKind;
  switch (type) {
  case TypeTag::Config:
    *out = DocumentKind::Config;
    return true;
  case TypeTag::Settings:
    *out = DocumentKind::Settings;
    return true;
  case TypeTag::KnownHosts:
    *out = DocumentKind::KnownHosts;
    return true;
  case TypeTag::History:
    *out = DocumentKind::History;
    return true;
  case TypeTag::HostConfig:
    *out = DocumentKind::Config;
    return true;
  case TypeTag::KnownHostEntry:
    *out = DocumentKind::KnownHosts;
    return true;
  default:
    return false;
  }
}
} // namespace AMDomain::arg
