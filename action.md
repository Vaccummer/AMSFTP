# AMConfigManager Improve

ConfigManager具有太多的函数, 负担过重, 维护困难, 所以需要对其进行拆分. 总体来讲拆分三个类

1. 负责维护底层config的数据, 实现dump和接收vector `<str>`型路径进行key的查询和写入, 自动备份, 以及文件写入线程
2.
