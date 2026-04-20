Infrastruture Client Part Refactor

# 通用规则

1. 基础排版格式
   1.1 两个文件, 例如FTP.hpp, FTP.cpp
   1.2 FTP.hpp: 存放完整的核心类FTPBase, AMFTPIOCore, 在匿名空间中声明辅助函数
   1.3 FTP.cpp: 实现辅助函数
   1.4 尽量维持核心类不太臃肿, 抽离类的静态函数, 或者与类绑定不深的函数为辅助函数
2.
