I have a new improve plan, do you have any suggestion?
@src\cli\CLIBind.cpp

@include\AMCLI\CommandTree.hpp

将各种arg struct和app的CliCommands 到新的CLIArg.hpp中

将具体的绑定函数移动到include\AMCLI\InteractiveLoop.hpp中

# CommandTree

弃用CommandTree, 使用CommandNode自身作为顶层, 成为和CLI11::App一样的完全链式结构

# CommandNode

设置一个Instance()静态函数以获取一个静态对象(用于兼容当前代码), 但是不能去继承NoCopy的那个class, 公有初始化函数

将CommandNode移出CommandTree, 转换成class

移除CommandNode中AddFunction/Flag/Option 对target是否已经存在的检查, 

新建一个find(Path)函数, 用于寻找下级节点

AddFunction 新加两个参数: CliArgsPool&args, T CliArgsPool::*member, 用于设置原本的CLI11回调

AddFlag 需要新加一个参数: bool & 用于CLI11绑定参数存储位置

AddOption需要设置为模版函数, 设置一个T&value用于CLI11绑定参数存储位置
