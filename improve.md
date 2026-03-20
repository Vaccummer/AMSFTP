
@include\domain\client_tmp

@include\infrastructure\client\runtime\IOCore.hpp

refactor ressult mixed with legacy functions confuse me , so i add a new folder to store the refactor result

Ports:

## port for client

remove cwd, or login_dir related function. that's upper layer responsibility, this layer only exposes functions to operate metadata



Manager:

+ hold Attr

1. <nicname, client> dict
2. private keys
3. heartbeat set
4. heartbeat thread

refer to IOCore.hpp ClientMaintainer, you can view it as a base templete for ClientManager, but you can't use it. IOCore.hpp will be deprecated in the future cause it has too many functions that shall not belong to Infra layer

Query-Like Function:

1. use nickname to get client port
2. check nickname exists
3. get local client
4. get clients dict
5. get heartbeat set
6. get private keys in use

Set-Like Function:

1. add/remove private keys
2. set heartbeat args
3. set client disconnect callback
4. set client pass query callback
5. Create Client
6. Add Client
7. Remove Client
