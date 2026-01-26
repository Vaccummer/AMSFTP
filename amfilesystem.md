# AMFileSystem

可以持有client manager

AMFileSystem(amfsm) 是整个项目的核心模块之一, 主要负责将client的操作进行进一步包装, 与用于进行交互

所以这些函数中, 需要很多检查与信息打印的操作

input format

1. 路径格式: {client_name}@{path}
   1. 部分路径本身存在@, 可以通过检测分隔出的nickname是否存在来区分
   2. local路径可写为@{path}, 算作语法糖
   3. local@{path}也是本地路径
   4. 直接使用{path}代表当前client的路径
   5. nickname在检测时不区分大小写

output Format

1. client打印格式

✅  {client_name}@{work_dir} (正常情况)

❌  {client_name}@{work_dir}  {EC_name} : {EC_msg}

2. size信息: 必须转化为人类可读的MB/GB/KB单位
3. pathinfo打印模板(stat)

[path]

type : {pathtype_name}

owner :  am

mode :  rwxrwx---

size:  12KB

(ps: 左对齐上述几行的关键字, 与下面几行分开对齐)

create_time:  2025/01/26  15:46:32

modify_time:  "同上"

access_time:  "同上"

4. ls -l型打印(每项都需要对其)

drwxrwx---  am   0B  2025/01/26  15:46:32   item_name

Function(返回ECM)

1. check: 接收昵称即可
2. connect 对应add client
3. change_client 改变当前client, 不存在时创建
4. remove_client: 用于删除client, 注意, 只是从clientmanager里删除, 不能动config, 删除时二次确认
5. cd 函数
   1. cd 支持 cd {path}
   2. 也支持解析 cd {hostname}@{path}
   3. cd的目标client不存在时, 可询问用户是否创建
   4. cd 保留最近一次历史位置, 以字符串保存{nickname}@{path}, 用于cd -
   5. cd - 使用后清空历史位置,  直到下次cd 到其他位置
   6. cd 到空目标时不做操作, 但cd {nickname}@时等效于chang client
6. print_clients: 打印当前所有client信息(使用update=true方法检测状态) 依照上方定义的格式
7. stat :可接收{nickname}@{path}格式, path信息参考上方
8. getsize 可接收{nickname}@{path}格式   简单打印"12KB"类似即可
9. find 可接收{nickname}@{path}格式  每行打印一个路径即可, 注意style化
10. mkdir 可接收{nickname}@{path}格式  可递归创建
11. rm 可接收{nickname}@{path}格式  不提供permanent用saferm方法, 提供用remove方法

## AMTransfer

AMTransfer

需要实现的功能类似于@core_func.py 的CliTransfer.copy
