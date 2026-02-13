AMCompleteEngine Improve

# 低耦合性和可扩展性是该类设计的主要目标

该类依旧存在很强的耦合性, 你需要进行如下改善:

1. AMCompleteEngine不包含任何补全搜索的逻辑, 而是提供一个接口RegisterSearchEngine(vector CompletionTarget, SearchEngine_ptr) 并将指针放入字典中
2. SearchEngine是一个搜索引擎的基类, 有CollectCandidate, SortCandate 的纯虚函数

   1. CollectCandidate是同步的, 如果需要异步补全, 需要在CollectCandidate返回一个AsynRequest供AMCompleteEngine识别, 然后进入异步处理流程

      1. AsynRequest 至少包含以下内容
         1. ID
         2. Timeout_ms
         3. Interuput flag(用于AMCompleteEngine终止函数执行)
         4. 具体搜索函数Attr(本质上为SearchEngine)
         5. 成员函数Search(使用AsynRequest中的参数执行4中的函数)
   2. 同步或者异步处理流程完全由AMCompleteEngine实现, 同时异步的工作线程也由AMCompleteEngine管理

      1. Cache 之类的由SearchEngine自行管理
   3. AMCompleteEngine不必再持有config_manager_, client_manager_, filesystem_, transfer_manager_, 因为它不需要实现具体的补全搜索逻辑
