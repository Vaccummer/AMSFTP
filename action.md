# Refactor the whole HostConfig and realted codes

## Client Init config

Client 的构造函数额外需要 Conrequest, UserArgs

Conrequest 包含: nickname,hostname,trash_dir,buffer_size,protocol,port,username,password,keyfile,compression

UserArgs 实际上为模板类型, 是用于传入用户自己的参数class

Conrequest 在client只向外提供常引用

UserArgs 提供
