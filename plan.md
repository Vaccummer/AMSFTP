ClientAppService Improve

1. ClientServiceArg

only holds 

    int heartbeat_interval_s = 60;

    int heartbeat_timeout_ms = 100;
move its definition to domain ClientModel

2. write a base class of ClientAppService layer

this class holds all kinds of callbacks and private_keys and amf

this class construct with ClientServiceArg

this class supplies interfaces:

1. to register callbacks(callbacks has two kind, one for client in maintainer, one for public pool)
2. get/set private keys
3. get/set heartbeat args
4. get init args
5. register amf
