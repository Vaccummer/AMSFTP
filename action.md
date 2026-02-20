@include\AMManager\Var.hpp

当前AMVarManager存在大量的legacy函数, 现在需要进行清理

when SetManager inits, it should reads data from ConfigManager and stores them in dict<nickname, AMHostSetPathConfig>. Set read or write functions should operate on AMHostSetPathConfig, when call save, turn AMHostSetPathConfig in json(you can set a function in struct GetJson like HostConfig does)  and write back to ConfigManager's Json then save to toml file
