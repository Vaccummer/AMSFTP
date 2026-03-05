# domain

Business models, invariants, and domain services without CLI or adapter
coupling.

Current WF-3 modules:

- `host/HostModel.hpp`: host config models + validation contracts.
- `host/HostDomainService.hpp`: host in-memory business rules.
- `host/HostPorts.hpp`: host config/known-host repository ports.
- `var/VarModel.hpp`: variable token parsing + `VarInfo`.
- `var/VarDomainService.hpp`: in-memory variable domain service.
- `var/VarPorts.hpp`: variable persistence/current-domain ports.
- `client/ClientPorts.hpp`: client registry/operator ports.
- `filesystem/FileSystemPorts.hpp`: filesystem query/mutation ports.
- `transfer/TransferPorts.hpp`: transfer task execution/query ports.
- `transfer/TransferCacheDomainService.hpp`: transfer cache bookkeeping rules.
