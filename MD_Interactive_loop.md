## DispatchCliCommands优化:

返回类型改为ECM

在函数最前方检测有没有subcommand匹配到, 打印错误, 返回错误

在函数下方验证是否为Interactive模式, 非交互模式退出, 返回EC::OperationUnsupported, {cmd_name} not supported in Non-Interactive mode

然后继续写分派执行交互模式函数的逻辑

# Interactive Loop

交互模式本质是一个询问指令->执行指令->询问指令的循环

但我需要对这个循环进行一定的设置

## 整体流程

1. 使用replxx库获取用户输入
2. 如果命令在去除两段空格并且转小写后为exit, 则清理资源退出程序
3. 使用CommandPreprocessor预解析参数
   1. 部分函数会在预处理阶段执行
   2. 部分操作可能在预处理阶段完成
4. 使用CLI11 解析命令(部分情况会跳过)
5. 解析失败则打印CLI11的报错信息
6. DispatchCliCommands执行命令
7. 获取执行结果更新input中的状态信息

## Input Custom

+ Prompt

  + 格式为
  + sysicon在setting.toml中, 需要结合GetOSType选择适当的图标
  + EC从函数返回值取
  + 复制生成Input可以缓存一个当前nickname的变量, 可以检测这个变量是否改变, 决定是否更新{sysicon} {username}{hostname}{nickname}

  {sysicon} {username}@{hostname}  {last_eplased}  ✅/❌ {EC_name if not success}

  ({nickname}){work_dir} $
+ input函数的注意点

  1. 需要额外的prompt的函数, 并为将来的补全留下接口(刚才提到的Completer)
  2. input
  3. 该input前需要激活信号处理器中的PROMPT, 重置amgif(不重置iskill)
  4. 获取input内容后需要检查amgif
     3.1 如果amgif的iskill触发, 则清理资源退出
     3.2 如果amgif的is_interrupted触发, 则打印信息告诉用户如何退出(输入exit), 然后continue
  5. 获取input后需要沉默PROMPT
  6. 如果用户输入内容为空或者全是空字符, continue
