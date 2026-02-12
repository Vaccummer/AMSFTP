@src\manager\host\cli.cpp

对于所有函数, 去除:

  ECMstatus = EnsureReady_("HostQuery");

  if (status.first!=EC::Success) {

    returnstatus;

  }

  CollectHosts_();


cls::Delete(conststd::vector[std::string](std::string) &targets)

+ 先进行去重
+ 检查nickname是否有效, 无效报错
+ prompt确认是否删除(prompt中需要包含所有将被删除的名称)
  + 取消时提示操作终止
+ 逐个删除, 删除失败报错

cls::Query

+ 去重
+ 先报错
+ 再打印内容
