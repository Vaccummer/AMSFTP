from worker.managers import (
    ConfigManager,
    ClientManager,
    APPEC,
    ErrorProcessor,
    SFTPWorker,
    PromptManager,
    unflatten_dict,
)
from worker.transfer_thread import TransferThreadManager
from AMSFTP import AMSFTPClient
from AMSFTP import AMEnum, AMData, AMFS
from typing import Literal
import os
import asyncio


class CliTransfer:
    def __init__(
        self,
        prompt_manager: PromptManager,
        client_manager: ClientManager,
        worker_manager: SFTPWorker,
    ):
        self.pm = prompt_manager
        self.cm = client_manager
        self.ep: ErrorProcessor = self.cm.ep
        self.mg: ConfigManager = self.cm.mg
        self.wm: SFTPWorker = worker_manager

    def copy(
        self,
        srcs: list[str],
        dst: str,
        quiet: bool = False,
        onlydir: bool = False,
        onlyfile: bool = False,
        no_mkdir: bool = False,
        force_overwrite: bool = False,
    ) -> None:
        # 当在同一个host内复制时，使用自身作为桥接，带宽减半，但可控性增强
        if onlydir and onlyfile:
            # TODO: 连接到error处理函数，报错 俩option只能选择一个
            return
        elif onlydir:
            src_type = AMEnum.SearchType.Directory
        elif onlyfile:
            src_type = AMEnum.SearchType.File
        else:
            src_type = AMEnum.SearchType.All
        src_host_path = list[tuple[str, str, AMSFTPClient | APPEC | None]]()
        for src in srcs:
            src_host_path.append(self.cm.PathParse(src))

        dst_host, dst_path, dst_client = self.cm.PathParse(dst)

        if isinstance(dst_client, APPEC):
            # TODO: 连接到error处理函数，报错dst客户端不存在
            return
        dst_path = self.cm.RealPath(dst_client, dst_path)

        # 创建src客户端
        src_paths = dict[str, list[AMData.PathInfo]]()
        use_regex = False
        already_report = set[str]()
        ok_clients = set[str]()
        for src_host, src_path, src_client in src_host_path:
            if src_host:
                if src_host in already_report:
                    continue
                elif src_host not in ok_clients:
                    if src_client.Check(False)[0] != AMEnum.ErrorCode.Success:
                        # TODO: 连接到error处理函数，报错客户端连接异常
                        already_report.add(src_host)
                        continue
                    ok_clients.add(src_host)

                paths_t = src_client.find(
                    self.cm.RealPath(src_client, src_path), src_type
                )
                if len(paths_t) == 0:
                    # TODO: 连接到error处理函数，报错路径不存在
                    continue

                if not use_regex and len(paths_t) > 1:
                    use_regex = True

                src_paths.setdefault(src_host, []).extend(paths_t)

        path_n = sum(len(paths) for paths in src_paths.values())
        if path_n == 0:
            self.pm.print("No Paths Matched")
            return

        # 📁📑
        if not quiet and use_regex:
            # 只有在使用*和<>匹配时才进行二次确认
            self.pm.print(f"Found {path_n} paths to transfer")
            for src_host, paths in src_paths.items():
                if len(paths) == 0:
                    continue
                # 排序， 先打印文件，再打印目录
                paths.sort(key=lambda x: x.type != AMEnum.PathType.DIR)
                for path in paths:
                    if path.type == AMEnum.PathType.DIR:
                        self.pm.print(f"📁   {src_host}@{path.path}")
                    else:
                        self.pm.print(f"📑   {src_host}@{path.path}")
            check = self.pm.promt(
                f"Are you sure to transfer these paths to {dst_host}? (y/n): "
            )
            if check != "y":
                self.pm.promt("Transfer cancelled")
                return

        tasks = list[AMData.TransferTask]()
        for src_host, paths in src_paths.items():
            for path in paths:
                ecm, tasks_t = self.wm.worker.load_tasks(
                    path.path,
                    dst_path,
                    self.cm.hostm,
                    "" if src_host.lower() == "local" else src_host,
                    "" if dst_host.lower() == "local" else dst_host,
                    force_overwrite,
                    False if no_mkdir else True,
                    True,
                )
                if ecm[0] != AMEnum.ErrorCode.Success:
                    # TODO: 连接到error处理函数，报错加载任务失败
                    continue
                tasks.extend(tasks_t)

        self.wm.transfer(tasks, self.cm.hostm)


class TerminalOperator:
    def __init__(
        self,
        client_manager: ClientManager,
        prompt_manager: PromptManager,
    ):
        self.cm = client_manager
        self.ep: ErrorProcessor = self.cm.ep
        self.pm = prompt_manager
        self.caches = dict[Literal["former_wd"], str]()

    def command_parse(self, command: str) -> None:
        pass

    def check(self, nickname: str | list) -> bool:
        if isinstance(nickname, list):
            return all(self.check(n) for n in nickname)

        if nickname not in self.cm.mg.hostd:
            # TODO: 连接到error处理函数，报错host名称不存在
            return
        client = self.cm.GetClient(nickname)
        if isinstance(client, tuple):
            # TODO: 连接到error处理函数，报错客户端不存在
            return
        self.cm.CLIENT = client
        res = client.Check(True)
        if res[0] != APPEC.Success:
            # TODO: 连接到error处理函数，报错客户端连接异常
            return
        else:
            self.pm.print(f"✅  {nickname} is checked")

    def connect(self, nickname: str | list) -> bool:
        if isinstance(nickname, list):
            return all(self.connect(n) for n in nickname)
        if nickname not in self.cm.mg.hostd:
            # TODO: 连接到error处理函数，报错host名称不存在
            return False
        client = self.cm.GetClient(nickname)
        if client is None:
            # TODO: 连接到error处理函数，报错客户端不存在
            return False
        ec, msg = client.Check(True)
        if ec == AMEnum.ErrorCode.Success:
            self.pm.print(f"✅  {nickname} is already connected")
            return True
        ec, msg = client.BaseConnect(True)
        if ec != AMEnum.ErrorCode.Success:
            # TODO: 连接到error处理函数，报错客户端连接异常
            return False
        self.pm.print(f"✅  {nickname} is reconnected")
        return True

    def change_client(self, nickname: str) -> bool:
        if nickname == "local":
            self.cm = self.cm.LocalClient
        if nickname not in self.mg.hostd:
            # TODO: 连接到error处理函数，报错host名称不存在
            return False
        client = self.cm.GetClient(nickname)
        if client is None:
            check = self.pm.promt(
                f"Client {nickname} not found, press y to create (y/n): "
            )
            if check != "y":
                return True
            client = self.cm.AddHost(nickname)
            if isinstance(client, tuple):
                # TODO: 连接到error处理函数，报错客户端创建失败
                return False
            self.cm.ChangeHost(client)
            return True
        else:
            if client.Check()[0] != AMEnum.ErrorCode.Success:
                # TODO: 连接到error处理函数，报错客户端连接异常
                if (self.pm.promt("press y to reconnect (y/n): ")) != "y":
                    return False
                ec, msg = client.BaseConnect(True)
                if ec != AMEnum.ErrorCode.Success:
                    # TODO: 连接到error处理函数，报错客户端连接异常
                    return False
                else:
                    self.pm.print(f"✅  {nickname} is reconnected")
            self.pm.print(f"✅  Change to : {nickname}")
            wd_new = client.GetPublicVar("cwd", None)
            if wd_new is None or not client.exists(wd_new)[1]:
                client.SetPublicVar("cwd", client.GetHomeDir())
            self.cm.ChangeHost(client)
            return True

    def remove_client(self, nickname: str | list) -> bool:
        if isinstance(nickname, list):
            return all(self.remove_client(n) for n in nickname)
        ecm, msg = self.cm.RemoveHost(nickname)
        if ecm[0] != AMEnum.ErrorCode.Success:
            # TODO: 连接到error处理函数，报错客户端删除失败
            return False
        return True

    def cd(self, path: str = "") -> bool:
        if self.cm.CLIENT is None:
            # TODO: 连接到error处理函数，报错客户端不存在
            return

        if path == "-":
            if "former_wd" not in self.caches:
                return False
            tmp_path = self.caches.get("former_wd", "")
            self.caches["former_wd"] = ""
            return self.cd(tmp_path)
        elif len(path) == 0 or path == ".":
            return True
        elif path == "..":
            return self.cd(
                os.path.dirname(
                    self.cm.CLIENT.GetPublicVar("cwd", self.cm.CLIENT.GetHomeDir())
                )
            )

        host, path_t, client = self.cm.PathParse(path)
        if host and host != self.cm.CLIENT.GetNickname():
            ori_host = self.cm.CLIENT.GetNickname()
            cur_wd = self.cm.CLIENT.GetPublicVar("cwd", self.cm.CLIENT.GetHomeDir())
            if isinstance(client, tuple):
                # TODO: 连接到error处理函数，报错客户端不存在
                return False
            if client.Check(True)[0] != AMEnum.ErrorCode.Success:
                # TODO: 连接到error处理函数，报错客户端连接异常
                return False
            pathf = self.cm.RealPath(client, path_t)
            if not client.exists(pathf)[1]:
                # TODO: 连接到error处理函数，报错路径不存在
                return False
            self.cm.ChangeHost(client)
            client.SetPublicVar("cwd", pathf)
            self.caches["former_wd"] = f"{ori_host}@{cur_wd}"
            return True
        else:
            cur_wd = self.cm.CLIENT.GetPublicVar("cwd", self.cm.CLIENT.GetHomeDir())
            pathf = self.cm.RealPath(host, path_t)
            if cur_wd == pathf:
                return True
            ecm, sign = self.cm.CLIENT.exists(pathf)
            if ecm[0] != AMEnum.ErrorCode.Success:
                # TODO: 连接到error处理函数，报错CLIENT连接异常
                return True
            elif not sign:
                # TODO: 连接到error处理函数，报错路径不存在
                return True
            self.cm.CLIENT.SetPublicVar("cwd", pathf)
            self.caches["former_wd"] = cur_wd
            return True

    def print_clients(self) -> None:
        self.pm.print(
            f"✅ {self.cm.CLIENT.GetNickname()}@{self.cm.CLIENT.GetPublicVar('cwd', self.cm.CLIENT.GetHomeDir())} (builtin local client)"
        )
        for client in self.cm.GetAllClients():
            nickname = client.GetNickname()
            wkdr = client.GetPublicVar("cwd", client.GetHomeDir())
            ec, msg = client.Check(True)
            if ec != AMEnum.ErrorCode.Success:
                str_t = f"❌  {nickname}@{wkdr} (Connection Error: {msg})"
            else:
                str_t = f"✅  {nickname}@{wkdr}"
            self.pm.print(str_t)


class FSOperator:
    def __init__(
        self,
        client_manager: ClientManager,
        prompt_manager: PromptManager,
    ):
        self.cm = client_manager
        self.ep = self.cm.mg
        self.pm = prompt_manager

    def tree_print(self, tree_dict: dict, prefix: str = "") -> None:
        """Recursively print a nested dictionary as a tree.
        Supported shapes:
        - {name: { ... }} -> directory with children
        - {name: [leaf1, leaf2]} -> directory with list of leaf names
        - {name: None} or {name: "file"} -> leaf

        Prints using box-drawing characters similar to Linux `tree`.
        """
        if not isinstance(tree_dict, dict) or len(tree_dict) == 0:
            return
        items = list(tree_dict.items())
        total = len(items)
        for idx, (name, child) in enumerate(items):
            is_last = idx == total - 1
            connector = "└── " if is_last else "├── "
            print(f"{prefix}{connector}{name}")

            # Prepare prefix for children
            child_prefix = prefix + ("    " if is_last else "│   ")

            # If child is a dict, recurse
            if isinstance(child, dict):
                self.tree_print(child, child_prefix)
            # If child is a list/tuple, print each leaf in it
            elif isinstance(child, (list, tuple)):
                for jdx, leaf in enumerate(child):
                    leaf_is_last = jdx == len(child) - 1
                    leaf_connector = "└── " if leaf_is_last else "├── "
                    # If leaf is a mapping, recurse into it, otherwise print
                    if isinstance(leaf, dict):
                        # For anonymous dicts in lists, print its single entry
                        self.tree_print(leaf, child_prefix)
                    else:
                        print(f"{child_prefix}{leaf_connector}{leaf}")
            else:
                # Primitive value: print it as a child node under the current key
                pass

    def format_path_info(self, path_info: AMData.PathInfo) -> str:
        name_f = ""
        permission_f = ""
        match path_info.type:
            case AMEnum.PathType.FILE:
                name_f = self.pm.f(path_info.name, "commonfile")
                permission_f = f"f{path_info.mode_str}"
            case AMEnum.PathType.DIR:
                name_f = self.pm.f(path_info.name, "directory")
                permission_f = f"d{path_info.mode_str}"
            case AMEnum.PathType.SYMLINK:
                name_f = self.pm.f(path_info.name, "syslink")
                permission_f = f"l{path_info.mode_str}"
            case AMEnum.PathType.SOCKET:
                name_f = self.pm.f(path_info.name, "otherspecial")
                permission_f = f"s{path_info.mode_str}"
            case AMEnum.PathType.FIFO:
                name_f = self.pm.f(path_info.name, "otherspecial")
                permission_f = f"p{path_info.mode_str}"
            case AMEnum.PathType.BLOCK_DEVICE:
                name_f = self.pm.f(path_info.name, "otherspecial")
                permission_f = f"b{path_info.mode_str}"
            case AMEnum.PathType.CHARACTER_DEVICE:
                name_f = self.pm.f(path_info.name, "otherspecial")
                permission_f = f"c{path_info.mode_str}"
            case AMEnum.PathType.UNKNOWN:
                name_f = self.pm.f(path_info.name, "otherspecial")
                permission_f = f"u{path_info.mode_str}"
        return f"{permission_f}\t{path_info.owner}\t{self.pm.FormatSize(path_info.size)}\t{self.pm.FormatTime(path_info.modify_time)}\t{name_f}"

    def stat(self, path: str) -> bool:
        host, path_t, client = self.cm.PathParse(path)
        if isinstance(client, tuple):
            # TODO: 连接到error处理函数，报错客户端不存在或者host不存在
            return False
        ecm, path_info = client.stat(self.cm.RealPath(client, path_t))
        if ecm[0] != AMEnum.ErrorCode.Success:
            # TODO: 连接到error处理函数，报错路径不存在
            return False
        self.pm.print(f"{'Host:':<16} {host}")
        # self.pm.print(f"{'Ori Path:':<16} {path}")
        self.pm.print(f"{'Real Path:':<16} {path_info.path}")
        self.pm.print(f"{'Owner:':<16} {path_info.owner}")
        self.pm.print(f"{'Type:':<16} {path_info.type}")
        self.pm.print(f"{'Size:':<16} {path_info.size}")
        self.pm.print(f"{'Permissions:':<16} {path_info.mode_str}")
        self.pm.print(
            f"{'Created At:':<16} {self.pm.FormatTime(path_info.create_time)}"
        )
        self.pm.print(
            f"{'Last Modified:':<16} {self.pm.FormatTime(path_info.modify_time)}"
        )
        self.pm.print(
            f"{'Last Accessed:':<16} {self.pm.FormatTime(path_info.access_time)}"
        )
        return True

    def ls(self, path: str, listall: bool) -> bool:
        host, path_t, client = self.cm.PathParse(path)
        if isinstance(client, tuple):
            # TODO: 连接到error处理函数，报错客户端不存在或者host不存在
            return False

        ecm, paths = client.listdir(self.cm.RealPath(client, path_t))
        if ecm[0] != AMEnum.ErrorCode.Success:
            # TODO: 连接到error处理函数，报错路径不存在
            return False
        if not listall:
            all_str = ""
            for path_info in paths:
                match path_info.type:
                    case AMEnum.PathType.FILE:
                        all_str += self.pm.f(path_info.name, "commonfile") + "\t"
                    case AMEnum.PathType.DIR:
                        all_str += self.pm.f(path_info.name, "directory") + "\t"
                    case AMEnum.PathType.SYMLINK:
                        all_str += self.pm.f(path_info.name, "syslink") + "\t"
                    case _:
                        all_str += self.pm.f(path_info.name, "otherspecial") + "\t"
            self.pm.print(all_str[:-1], need_escape=False)
            return True
        for path_info in paths:
            self.pm.print(self.format_path_info(path_info), need_escape=False)
        return True

    def getsize(self, path: str | list) -> bool:
        if isinstance(path, list):
            return all(self.getsize(p) for p in path)

        host, path_t, client = self.cm.PathParse(path)
        if isinstance(client, tuple):
            # TODO: 连接到error处理函数，报错客户端不存在
            return False

        pathf = self.cm.RealPath(client, path_t)
        self.pm.print(self.pm.FormatSize(client.getsize(pathf)))
        return True

    def find(self, path: str, dir: bool = False, file: bool = False):
        host, path_t, client = self.cm.PathParse(path)
        if isinstance(client, tuple):
            # TODO: 连接到error处理函数，报错客户端不存在
            return False

        if file == dir:
            stype = AMEnum.PathType.ALL
        if dir:
            stype = AMEnum.PathType.DIR
        elif file:
            stype = AMEnum.PathType.FILE
        paths = client.find(path_t, stype)
        for path_info in paths:
            match path_info.type:
                case AMEnum.PathType.DIR:
                    self.pm.print(
                        self.pm.f(path_info.path, "directory"), need_escape=False
                    )
                case AMEnum.PathType.FILE:
                    self.pm.print(
                        self.pm.f(path_info.path, "commonfile"), need_escape=False
                    )
                case _:
                    self.pm.print(
                        self.pm.f(path_info.path, "otherspecial"), need_escape=False
                    )

    def tree(self, path: str, level: int = -1):
        host, path_t, client = self.cm.PathParse(path)
        if isinstance(client, tuple):
            # TODO: 连接到error处理函数，报错客户端不存在
            return False

        path_t = self.cm.RealPath(client, path_t)
        ecm, paths = client.walk(path_t, level)
        if ecm[0] != AMEnum.ErrorCode.Success:
            # TODO: 连接到error处理函数，报错路径不存在
            return False
        ori_dcit = {}
        for path, path_info in paths:
            ori_dcit[tuple(path)] = path_info
        uf_dict = unflatten_dict(ori_dcit)
        if len(uf_dict) == 0:
            self.pm.print(f"No files or directories in {host}@{path_t}")
            return
        elif len(uf_dict) != 1:
            self.pm.print("Unexpected return value: Multiple roots found")
            return False
        key0 = list(uf_dict.keys())[0]
        self.pm.print(key0)
        self.tree_print(uf_dict[key0])
        return True

    def mkdir(self, path: str) -> bool:
        host, path_t, client = self.cm.PathParse(path)
        if isinstance(client, tuple):
            # TODO: 连接到error处理函数，报错客户端不存在
            return False
        path_t = self.cm.RealPath(client, path_t)
        ecm, path_info = client.mkdir(self.cm.RealPath(client, path_t))
        if ecm[0] != AMEnum.ErrorCode.Success:
            # TODO: 连接到error处理函数，报错路径不存在
            return False
        else:
            self.pm.print(f"✅  {path} is created")

    def rm(self, path: str | list, permanent: bool = False) -> bool:
        if isinstance(path, list):
            return all(self.rm(p, permanent) for p in path)

        host, path_t, client = self.cm.PathParse(path)
        if isinstance(client, tuple):
            # TODO: 连接到error处理函数，报错客户端不存在
            return False
        path_t = self.cm.RealPath(client, path_t)
        path_l = client.find(path_t, AMEnum.SearchType.All)
        if len(path_l) == 0:
            # TODO: 连接到error处理函数，报错路径不存在
            return False
        elif len(path_l) > 1:
            self.pm.print("Found multiple paths:")
            for path_i in path_l:
                match path_i.type:
                    case AMEnum.PathType.DIR:
                        self.pm.print(
                            self.pm.f(path_i.path, "directory"), need_escape=False
                        )
                    case AMEnum.PathType.FILE:
                        self.pm.print(
                            self.pm.f(path_i.path, "commonfile"), need_escape=False
                        )
                    case AMEnum.PathType.SYMLINK:
                        self.pm.print(
                            self.pm.f(path_i.path, "syslink"), need_escape=False
                        )
                    case _:
                        self.pm.print(
                            self.pm.f(path_i.path, "otherspecial"), need_escape=False
                        )
            ans = self.pm.promt("Are you sure you want to remove all of them? (y/n): ")
            if ans != "y":
                return True

        if permanent:
            for path_ti in path_l:
                out = client.remove(self.cm.RealPath(client, path_ti))
                if isinstance(out, tuple):
                    # TODO: 连接到error处理函数，报错路径不存在
                    return False
                all_yes = True
                for path_i, ecm in out:
                    if ecm[0] != AMEnum.ErrorCode.Success:
                        self.pm.print(f"⚠️  {path_i} removed fail: {ecm[1]}")
                        all_yes = False
                if all_yes:
                    self.pm.print(f"✅  {path_t} permanently removed")
                    return True
                else:
                    return False

        ecm = client.EnsureTrashDir()
        if ecm[0] != AMEnum.ErrorCode.Success:
            # TODO: 连接到error处理函数，报错路径不存在
            return False
        self.pm.print(f"Trash directory: {client.GetTrashDir()}")
        for path_ti in path_l:
            out = client.saferm(path_ti.path)
            if out[0] != AMEnum.ErrorCode.Success:
                # TODO: 连接到error处理函数，报错路径不存在
                pass
            else:
                self.pm.print(f"✅  {path_ti.path} moved to trash")
