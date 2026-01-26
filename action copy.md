根据对新的AMConfigProcessor调整 AMConfigManager 中的函数调用

AMConfigManager不再使用FlatMap作为config数据的存储对象, FlatMap只用在初始加载时的  

非法key过滤中, 过滤完后需要转换成标准的TOML数据格式  

相应的, 涉及到config数据读取的操作也需要进行更改
