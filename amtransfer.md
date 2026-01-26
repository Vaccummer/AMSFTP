## AMWorkManager Improve

AMWorkManager中涉及TaskInfo的均采用智能指针, 减少内存占用

AMWorkManager的transfer改为submit, 接收taskinfo进行提交, 然后新增一个和原transfer签名相同, 但返回shared `<taskinfo>` 的函数

taskinfo新加一个属性, 结果回调函数, 签名为void `(<std::shared_ptr<taskinfo>>>)` , 在执行完毕后直接返回taskinfo, 不再存入result

progressdata在executetask前创建, 在退出ExecuteTask时销毁

AMWorkManager需要额外一个新的结果处理机制: 在完成任务后, 检查是否存在结果回调函数, 有则直接回调, 没有才加入result中(这个操作可以封装成函数, 因为terminate函数中也需要用到)

## AMTransferManager

AMWorkManager的回调需要经过AMTransferManager包装, 实现线程安全

TransferManager 负责文件的传输, 是面向用户的对AMWorkManager进一步封装

TransferManager 持有两种client存储(都不进行heartbeat检验)

一个是AMClient的Transfer pool, 一种是闲置pool

AMClientManager的AddClient新加一种重载, poolkind参数换为hostmanager

### 基础transfer函数

1. 阻塞型函数, 虽然AMWorkManager会立即返回, 但是需要在函数中循环查询任务状态并获取执行结果
2. 启用进度条打印(也可设置选项关闭), 进度条信息格式, 不需要额外字符表示进度, size相关的都需要是人类阅读格式
   {file_name}            {Persentage}   {ALL_Transferred}/{Total}   {Speed} [elapse - remain time]

### 非阻塞transfer

流程

1. 分析所需要的client, 先从TransferManager的公有池取, 再从
