@include\AMBase\DataClass.hpp

@include\AMManager\Logger.hpp

@log

优化TraceInfo: 新增一个 std::optional `<ConRequest>`

优化LogManager

logger支持两种类型的log

+ client log: 使用回调绑定到Client上, 写入@log\Client.log
+ program log: 无ConRequest 的trace, 写入@log\Programm.log

logger需要提供两种类型Trace的公开函数, 都是任务提交的异步模式

logger持续打开两个log文件, 不再循环打开关闭
