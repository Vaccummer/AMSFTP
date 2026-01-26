### Client Manager

管理的对象为SFTPClient, FTPClient和LocalClient

manager主要是为了集中管理client, 并提供统一的接口供其他函数使用

client自身提供一些操作函数

### 1、Host管理

1. ✅check （-ensure）
2. ✅ch (change host， host不存在时询问是否创建)
3. ✅查看所有已经创建的client，
4. ✅remove_host
5. ✅connect
