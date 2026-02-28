## Client Init config

Conrequest change to has attrs: nickname,hostname,trash_dir,buffer_size,protocol,port,username,password,keyfile,compression

when Client need diretly read and write attr in Conrequest instead of maintaing a copy

Client only supply public interface to get const ref of Conrequest

HostConfig in HostManager contains {Conrequest, ClientMetaData}

ClientMetaData contains cmd_prefix wrap_cmd login_dir

# AMTracer Var cache system refactor

use two store container :

std::**unordered_map**<std::**type_index**, std::**any**>

std::**unordered_map**<std::**string**, std::**any**>

the former can directly pass value to store, and use type to get

the latter use name and type to query, use name and value to store

operation protocol

store rules:

bool(is written) store(... bool overwrite)

query rules:

need to return pointer type

when using name to query, need to distinguish name not exists and type mismatch
