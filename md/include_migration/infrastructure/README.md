# infrastructure

Adapters for external systems and platform integration (config IO, logging,
signals, protocol wrappers).

## Client Adapter Canonical Paths

Client adapter headers are now canonical under:

- `include/infrastructure/client/common/Base.hpp`
- `include/infrastructure/client/ftp/FTP.hpp`
- `include/infrastructure/client/sftp/SFTP.hpp`
- `include/infrastructure/client/local/Local.hpp`
- `include/infrastructure/client/runtime/IOCore.hpp`

`BaseClient` in `common/Base.hpp` implements
`domain/client/ClientPort.hpp` as the current domain-facing client
port contract.

Legacy `include/AMClient/*.hpp` headers are compatibility shims for migration
only and should not be used for new includes.

## Manager Contract Canonical Paths

Manager contracts used by CLI/bootstrap wiring are canonical under `include/domain`:

- `include/domain/client/ClientManager.hpp`
- `include/domain/host/HostManager.hpp`
- `include/application/transfer/TransferAppService.hpp`
- `include/domain/var/VarManager.hpp`
- `include/application/filesystem/FileSystemAppService.hpp`

Legacy `include/AMManager/*.hpp` include prefixes are removed from first-party
sources and should not be reintroduced.
