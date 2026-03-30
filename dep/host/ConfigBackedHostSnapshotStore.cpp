#include "infrastructure/host/ConfigBackedHostSnapshotStore.hpp"

#include "domain/config/ConfigModel.hpp"
#include "foundation/tools/enum_related.hpp"

namespace {
using DocumentKind = AMDomain::config::DocumentKind;

ECM RequireConfigService_(
    const AMApplication::config::AMConfigAppService *config_service,
    const char *context) {
  if (config_service) {
    return Ok();
  }
  return Err(EC::ConfigNotInitialized,
             AMStr::fmt("config service is not bound for {}", context));
}

ECM NormalizeDumpError_(const ECM &dump_rcm, const char *context) {
  if (isok(dump_rcm)) {
    return Ok();
  }
  return Err(EC::CommonFailure,
             dump_rcm.second.empty()
                 ? AMStr::fmt("failed to dump {} snapshot", context)
                 : dump_rcm.second);
}
} // namespace

namespace AMInfra::host {
ConfigBackedHostConfigSnapshotStore::ConfigBackedHostConfigSnapshotStore(
    AMApplication::config::AMConfigAppService *config_service)
    : config_service_(config_service) {}

void ConfigBackedHostConfigSnapshotStore::Bind(
    AMApplication::config::AMConfigAppService *config_service) {
  config_service_ = config_service;
}

std::pair<ECM, AMDomain::host::HostConfigArg>
ConfigBackedHostConfigSnapshotStore::LoadSnapshot() const {
  ECM bound_rcm =
      RequireConfigService_(config_service_, "host config snapshot load");
  if (!isok(bound_rcm)) {
    return {bound_rcm, {}};
  }

  AMDomain::host::HostConfigArg snapshot = {};
  if (config_service_->Read(&snapshot)) {
    return {Ok(), snapshot};
  }

  ECM load_rcm = config_service_->Load(DocumentKind::Config, false);
  if (!isok(load_rcm)) {
    return {load_rcm, {}};
  }
  if (!config_service_->Read(&snapshot)) {
    return {Ok(), {}};
  }
  return {Ok(), snapshot};
}

ECM ConfigBackedHostConfigSnapshotStore::SaveSnapshot(
    const AMDomain::host::HostConfigArg &snapshot, bool dump_async) {
  ECM bound_rcm =
      RequireConfigService_(config_service_, "host config snapshot save");
  if (!isok(bound_rcm)) {
    return bound_rcm;
  }
  if (!config_service_->Write(snapshot)) {
    return Err(EC::CommonFailure, "failed to write host config snapshot");
  }
  return NormalizeDumpError_(
      config_service_->Dump(DocumentKind::Config, "", dump_async),
      "host config");
}

ConfigBackedKnownHostSnapshotStore::ConfigBackedKnownHostSnapshotStore(
    AMApplication::config::AMConfigAppService *config_service)
    : config_service_(config_service) {}

void ConfigBackedKnownHostSnapshotStore::Bind(
    AMApplication::config::AMConfigAppService *config_service) {
  config_service_ = config_service;
}

std::pair<ECM, AMDomain::host::KnownHostEntryArg>
ConfigBackedKnownHostSnapshotStore::LoadSnapshot() const {
  ECM bound_rcm =
      RequireConfigService_(config_service_, "known-host snapshot load");
  if (!isok(bound_rcm)) {
    return {bound_rcm, {}};
  }

  AMDomain::host::KnownHostEntryArg snapshot = {};
  if (config_service_->Read(&snapshot)) {
    return {Ok(), snapshot};
  }

  ECM load_rcm = config_service_->Load(DocumentKind::KnownHosts, false);
  if (!isok(load_rcm)) {
    return {load_rcm, {}};
  }
  if (!config_service_->Read(&snapshot)) {
    return {Ok(), {}};
  }
  return {Ok(), snapshot};
}

ECM ConfigBackedKnownHostSnapshotStore::SaveSnapshot(
    const AMDomain::host::KnownHostEntryArg &snapshot, bool dump_async) {
  ECM bound_rcm =
      RequireConfigService_(config_service_, "known-host snapshot save");
  if (!isok(bound_rcm)) {
    return bound_rcm;
  }
  if (!config_service_->Write(snapshot)) {
    return Err(EC::CommonFailure, "failed to write known-host snapshot");
  }
  return NormalizeDumpError_(
      config_service_->Dump(DocumentKind::KnownHosts, "", dump_async),
      "known-host");
}
} // namespace AMInfra::host
