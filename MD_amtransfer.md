New DataStruct------UserTransferSet

## UserTransferSet(用于存储用户的原始传输设置)

- vector `<pair<src, dst>>`
- mkdir
- overwrite
- ignore_special_file

## TaskInfo Improve

对TaskInfo实现线程安全, 数值以及枚举属性变成atomic, 内置锁供非数值修改

Taskinfo中新增一个属性, vector `<UserTransferSet>`

新增一个bool, quiet, 不需要加锁, 因为创建了就不会修改

taskinfo新加一个属性, 结果回调函数, 签名为void `(<std::shared_ptr<taskinfo>>>)` 

taksinfo新加一个属性, thread_id, 指定到某个thread上执行

ps

+ StreamRingBuffer中的char[]换做std::array, 用C++风格的类型

## PromptManager Improve

设置一个接收TASKINFO, 标准且线程安全地打印结果信息的函数, 注意, quiet模式不打印

## AMWorkManager(wm) Improve

AMWorkManager中涉及TaskInfo的均采用智能指针, 减少内存占用

AMWorkManager的transfer改为submit, 接收taskinfo进行提交, 然后新增一个和原transfer签名相同, 但返回shared `<taskinfo>` 的函数

progressdata在executetask前创建, 在退出ExecuteTask时销毁

AMWorkManager需要额外一个新的结果处理机制: 在完成任务后, 检查是否存在结果回调函数, 有则直接回调, 没有才加入worker的result缓存中

1. 使用多线程的模式, 每个线程配备独立的数据队列, 使用std::list, 每个线程具有自己的逻辑id, 从0开始编号, 0号为基础固有ID
2. 维护一个taskRegistry, `unordered_map<TaskId, TaskRecord>`
3. `TaskRecord` 包含 Taskinfo, AssignType, AffinityID, std::list `<TaskId>`::iterator it

   1. AssignType分affinity or public, 前者是指定了线程id, 后者是未指定或者指定非法id
   2. std::list `<TaskId>`::iterator it指向 该任务在queue中的位置
   3. 线程的queue只存放任务id
4. 任务提交时, 需要检查设置的线程ID是否存在, 设置好, 然后加入taskRegistry以及对应的队列中
5. 线程执行时, 优先从自身的队列里面选择id, 然后再从公共队列里面选id

   1. 选择id后, 加锁修改taskRegistry中的状态等相关信息, 并从自身pending队列中移除该id
   2. 任务执行完成需要从taskRegistry中移除
6. 对应的terminate等任务操作函数也需要进行修改, conducting_task改成当前正在执行的任务ID的vector
7. 新设获取当前所有线程ID的函数
8. 新设改变当前线程数的函数(1-64): 增加立刻生效, 减少需要等待线程完全空闲(没亲和任务等待, 也无正在执行的任务)
