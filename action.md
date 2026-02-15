@config\settings.toml

以下为原先版本的备份, 你可以用来参考

@bak.toml
我对settings.toml的数据排布进行了修改, 这种修改有的只是单纯的key变换, 但有些改变需要更改原先的config管理代码

[Options] 内的设置为单纯的key位置变换, 更新读取函数的key即可

[Style] 大部分是单出的位置修改, 但有些例外

+ [Style.CompleteMenu] 是新加的属性
+ [Style.Path] 需要两种匹配
  + 路径类型匹配: dir/regular/link/special/nonexistent
  + 权限匹配: nowrite, fullaccess(rwxrwxrwx)
    + fullaccess只在


windows server

先libssh2 stat

再尝试exec获取如下信息

+ owner
+ permission
