# Interactive Loop

交互模式本质是一个询问指令->执行指令->询问指令的循环

但我需要对这个循环进行一定的设置

## Input Custom

+ Prompt

  + 格式为
  + sysicon在setting.toml中
  + EC从函数返回值取

  {sysicon} {username}@{hostname}  {last_eplased}  ✅/❌ {EC_name if not success}

    ({nickname}){work_dir} $

## 参数解析

+ 参数使用CLI11进行解析, 解析不通过报错
+ 在参数解析之前, 需要分离自定义的符号
  + ! 在开头代表将指令作为作为终端命令指令(调用ConductCmd)
    + 只有SFTPClient支持ConductCmd
    + 其他client类型报错
  + & 在结尾, 且函数为transfer以及task submit时, 用于异步执行
    + 不符合要求时, 不进行剥离
+ 参数解析前, 还需要进行UserPaths变量替换
  + 输入格式包括两种

    + $dsk/test1  \$dsk\test1
      + 这是有分隔符做界限, $不需要包裹目标
    + $(dsk)1
      + 没有分隔符做界限, 需要包裹目标
    + 原始路径中存在$, 用户需要用`转义
      + 如果解析到非法的$, 报错并提醒用户转义\$或者包裹目标
