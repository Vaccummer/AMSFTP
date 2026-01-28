用于打印任务信息, 可以单设一个类TaskInfoPrint

## TaskSubmitPrint

用于在transfer_async提交时报告

格式:

+ Sumbmit  ID: [{taskid}]  FileNum: {num}  TotalSize: {size}  Clients: {nicknames}
+ 用client_mantainer的get_nicknames()获取nicknames

## TaskResultPrint

用于在任务执行完成后打印

taskinfo.queit 设置时不打印

格式

+ ✅/❌  [{taskid}]  {transferred_size}/{total_size}  TheadID: {}   {rcm}
+ ✅/❌看rcm,   ✅时后面也不需要打印rcm

## Show

用于简单查询任务情况的函数, 但遇到不同状态的任务, 进行不同格式打印

### 1. show pending_task

[{taskid}]  Status: {}  TotalSize: {}  AffinityThread: {}   SubmitTime: {}

+ 时刻为 16:02格式

### 2. show finished_task

[{taskid}]  Status: {}  {transferred_size}/{total_size}  ThreadID: {}   ElapsedTime: {}

+ ElapsedTime用1m30s格式

### 3. show conducting_task

使用进度条

prefix设置为{src_hostname}@{src_filename}  -> {dst_hostname}@{dst_filename}

循环读取taskinfo进行刷新

show函数设置一个interrupt_flag用于终止进度条

## List

用于批量打印任务信息

### History/Pending

对每个任务使用show即可

### Conducting

创建多个进度条输出进度信息

## Inspect

用于打印任务的详细信息

包括id, status, submit_time, start_time,finished_time,rcm,total_transferred_size,total_size, files_num, quiet, affinity_thread, OnWhichThread, 

buffer_size, client_names

每行打印一个属性, 属性名称可以略作修改, 方便人类理解

属性名称需要对齐

### task子命令

用于打印taskinfo中所有task信息

格式为

[order]

src: {nickname}@{path}

dst: {nickname}@{path}

size: {}

transferred: {}

rcm: (IsFinished为true才打印该属性)

### set子命令

用于打印任务的原始指令设置(UserTransferSet)

[order]

+ 只有一个UserTransferSet的话不用index

{src1} -> {dst1}

{src2} -> {dst2}

...

mkdir = 

overwrite = 

ignore_special_file = 

(不用对齐)
