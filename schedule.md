# 非交互模式

✅❌

### 1、config函数

1. ✅list 打印所有config信息()
2. ✅src 获取config文件路径
3. ✅query 获取指定昵称的host信息
4. ✅delete 删除指定host
5. ✅add 增加一个host
6. ✅modify 修改指定host的信息

### 2、transfer函数

1. ✅接受src路径和-o 输出路径， 解析{hostname}@{path}格式的路径
2. ✅支持*匹配

# 交互模式

### 0、继承非交互状态的所有函数

### 1、Host管理

1. ✅check （-ensure）
2. ✅ch (change host， host不存在时询问是否创建)
3. ✅查看所有已经创建的client，
4. ✅remove_host
5. ✅connect

### 2、补全函数

1. 上下键历史指令
2. 路径补全
3. 函数补全
4. host 昵称补全
5. 快捷键绑定 -> IO函数异步执行
   1. 暂停
   2. 终止

### 3、FileSystem函数

1. ✅cd (支持 host@path格式)
2. ✅ls (-l )
3. ✅cp
4. ✅rm (permanant and saferm)
5. ✅mkdir
6. ✅tree (-l )
7. ✅size
8. ✅stat
9. ✅find
