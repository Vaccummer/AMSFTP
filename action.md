@include\AMManager\Var.hpp

当前AMVarManager存在大量的legacy函数, 现在需要进行清理

AMVarManager在Init函数中读取ConfigManager中的数据, 保存为 dict<nickname, dict `<varname, varvalue>>` varvalue 必须为字符串

新的AMVarManager的Var只有两种类型, 公有Var([UserVars."*"]), 各个Host的私有Var([UserVars.Nickname])

Var需要以VarInfo为最小单元进行处理, VarInfo包括domain, varname, varvalue的attrs

还包括bool IsPublic() 函数, ECM IsValid()函数, 后者需要检查domain或varname是否为空: 为空则为未初始化的VarInfo, 用于查询失败时的结果返回

AMVarManager 还需要提供一个save函数, 将数据写回json并保存到toml文件


还需要一个子类VarCLISet, 主要包含一些用于CLI绑定的函数

+ Var Query函数

CLI调用方式为 var get $varname

检索所有名为varname的变量, 输出

[zonename] $varname = value

[zonename2] $varname = value

(可以不对齐, 但需要字符串style化)

+ Var Add函数

CLI调用方式为 var def -g $varname varvalue

-g: --global, 如果为true, 则定义到pulic区中, 如果为false, 定义到当前host的private区中

注意: 当定义到private区中时, 如果改private区已经存在, 需要打印已经存在的键值对, 并向用户进行确认是否覆盖

+ Var Delete函数

CLI调用方式为 var del -a (nickname) $varname

-a: --all 删除所有私有区和公有区的$varname (需要打印匹配到的键值对, 并进行确认)

nickname: 目标区的名称, 可为*, nickname. 当-a提供时, 不允许提供nickname

指定区删除不进行确认, 若删除失败, 需要报错

+ var List函数

CLI调用方式为 var ls 区名1 区名2 区名3

可接收多个区名, 也可以空区名(打印所有区的变量)

多个区名需要先去重, 然后滤除不合法的区名并报错, 然后打印变量

打印格式为

[name]

$var1 = value1

$var2 = value2

$var3 = value3

[name2]

$var1 = value1

$var2 = value2

$var3 = value3

+ 注意$varname的对齐
+ 值为空字符串时, 需要打印为"", 而不是空白
