from ruamel.yaml import YAML
from dataclasses import dataclass
from worker.transfer_thread import TransferThreadManager
from AMSFTP import AMData, AMEnum, AMFS, AMSFTPClient, AMSFTPWorker, HostMaintainer
import copy
from typing import Any, Literal
import os
from tqdm import tqdm
from prompt_toolkit import PromptSession
from rich.console import Console
from prompt_toolkit import print_formatted_text
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.styles import Style
import time
import re
import shutil
from functools import partial


def unflatten_dict(dict_f: dict):
    # unflatten dict, keys of multi layers stored in Atuple
    out_dict = {}
    for key, value in dict_f.items():
        if not isinstance(key, tuple):
            out_dict[key] = value
            continue
        tar_dict = out_dict
        for key_i in key[:-1]:
            tar_dict.setdefault(key_i, {})
            tar_dict = tar_dict[key_i]
        tar_dict[key[-1]] = value
    return out_dict


@dataclass
class SError:
    title: str
    message: str


@dataclass
class ClientCache:
    nickname: str
    work_dir: str


class HostNicknameState:
    NotFoundInConig = -2
    NotCreated = -1
    Created = 0
    TestOK = 1


class APPEC(AMEnum.ErrorCode):
    NoHostConfig = 100


class ConfigManager:
    def __init__(self, config_path: str = "data/config.yaml"):
        self.config_path = config_path
        self.config: dict = {}  # ori config data
        self.hostd: dict = {}  # {nickname:config}
        self.private_keys = []
        self.styles: dict[str:str] = {}
        self.yaml = YAML()
        self.nickname_pattern = re.compile(r"^[a-zA-Z0-9\u4e00-\u9fa5]+$")
        self.load()

    def load(self) -> None | Exception:
        if os.path.exists(self.config_path) and (
            self.config_path.endswith(".yaml") or self.config_path.endswith(".yml")
        ):
            try:
                with open(self.config_path, "r", encoding="utf-8") as data_f:
                    self.config = self.yaml.load(data_f)
            except Exception as e:
                return e
        else:
            return FileNotFoundError(
                f"path {self.config_path} is not a valid yaml file"
            )
        self.hostd = self.config.get("hosts", {})
        self.private_keys = self.config.get("private_keys", [])
        self.Vars: dict[Literal["local_trash_dir", "local_default_work_dir"], str] = (
            self.config.setdefault("Vars", {})
        )
        self.load_styles()

    def load_styles(self) -> None:
        self.styles = self.config.setdefault("styles", {})
        self.styles.setdefault("default", "")
        self.styles.setdefault("error", "red")
        self.styles.setdefault("warning", "yellow")
        self.styles.setdefault("success", "green")
        self.styles.setdefault("info", "blue")
        self.styles.setdefault("debug", "gray")
        self.styles.setdefault("trace", "gray")
        self.styles.setdefault("fatal", "red")
        self.styles.setdefault("critical", "red")

    def GetConrRequest(
        self, nickname: str, use_compression: bool = False
    ) -> AMData.ConRequst | None:
        host = self.hostd.get(nickname, None)
        if host is None:
            return None
        return AMData.ConRequst(
            nickname=nickname,
            username=host.get("username", ""),
            hostname=host.get("hostname", ""),
            port=host.get("port", 22),
            password=host.get("password", ""),
            keyfile=host.get("keyfile", ""),
            compression=use_compression,
            trash_dir=host.get("trash_dir", ""),
        )

    def GetOriConfig(self, nickname: str) -> dict | None:
        self.hostd.get(nickname, None)

    def GetHosts(self) -> dict:
        all_dict: dict = copy.deepcopy(self.hostd)
        # 如果有example, 删除example
        all_dict.pop("example", None)
        return all_dict

    def AddHost(
        self,
        nickname: str,
        hostname: str,
        username: str,
        trash_dir: str,
        port: int = 22,
        key_file: str = "",
        password: str = "",
    ) -> bool:
        if not self.IsNicknameAvailable(nickname)[0]:
            return False
        self.hostd[nickname] = {
            "hostname": hostname,
            "username": username,
            "port": port,
            "trash_dir": trash_dir,
            "keyfile": key_file,
            "password": password,
        }
        self.dump()

    def RemoveHost(self, nickname: str) -> None:
        res = self.hostd.pop(nickname, None)
        if res is None:
            return False
        self.dump()
        return True

    def ModifyHost(
        self,
        nickname: str,
        hostname: str,
        username: str,
        port: int,
        password: str,
        key_file: str,
        trash_dir: str,
    ) -> bool:
        if nickname in self.hostd:
            self.hostd[nickname] = {
                "hostname": hostname,
                "username": username,
                "port": port,
                "trash_dir": trash_dir,
                "keyfile": key_file,
                "password": password,
            }
            self.dump()
            return True
        return False

    def RenameHost(self, nickname: str, new_nickname: str) -> bool:
        if (
            nickname in self.hostd
            and self.IsNicknameAvailable(new_nickname)[0]
            and new_nickname not in self.hostd
        ):
            self.hostd[new_nickname] = self.hostd.pop(nickname)
            self.dump()
            return True
        return False

    def PrivateKeys(self) -> list[str]:
        return self.private_keys

    def dump(self, hosts: dict = None) -> None:
        if hosts is None:
            hosts = self.hostd
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        hosts["example(host的昵称只允许中英文字符, 不允许使用example或local)"] = {
            "username": "David",
            "hostname": "127.0.0.1(ip或者域名均可)",
            "port": "22(端口, 默认22, 需要数字)",
            "keyfile": "C:\\Example\\id_rsa(可选，如果使用密码登录，则不需要)",
            "password": "1234(可选，如果使用密钥登录，则不需要, 建议用密钥登入)",
            "banner": "David(可选，显示在登录前的欢迎信息)",
            "trash_dir": "/home/David/trash(垃圾桶地址, saferm函数需要)",
        }
        self.config["hosts"] = hosts
        with open(self.config_path, "w", encoding="utf-8") as data_f:
            self.yaml.dump(self.config, data_f)

    def IsValidNickname(self, nickname: str) -> tuple[bool, str]:
        if self.nickname_pattern.match(nickname) is None:
            return (
                False,
                "nickname is invalid, only allow English, Chinese, Numbers, no blank spaces and special characters!",
            )
        return (True, "")

    def IsNicknameAvailable(self, nickname: str) -> tuple[bool, str]:
        if nickname.lower() == "example":
            return (False, 'nickname "example" is reserved!')
        elif nickname.lower() == "local":
            return (False, 'nickname "local" is reserved!')
        elif nickname in self.hostd:
            return (False, f'nickname "{nickname}" already exists!')
        return self.IsValidNickname(nickname)


class LocalIOClient:
    def __init__(self, config_manager: ConfigManager):
        self.mg = config_manager
        self.PublicVar = {}
        self.mode_pattern = re.compile(r"^[-r][-w][-x][-r][-w][-x][-r][-w][-x]$")
        self.mode_pattern2 = re.compile(r"^[0-7][0-7][0-7]$")
        self.finder = AMFS.PathMatch()
        self.init()

    def GetAvailableTrashDir(self) -> str:
        ori_path = os.path.expanduser("~/.AMSFTP_trash")
        count = 1
        while True:
            try:
                os.makedirs(ori_path, exist_ok=True)
                return ori_path
            except Exception:
                ori_path = os.path.expanduser(f"~/.AMSFTP_trash({count})")
                count += 1

    def init(self) -> None:
        self.TrashDir = self.mg.Vars.get("local_trash_dir", None)
        if self.TrashDir is None:
            self.TrashDir = self.GetAvailableTrashDir()
            self.mg.Vars["local_trash_dir"] = self.TrashDir
            self.mg.dump()
        else:
            try:
                os.makedirs(self.TrashDir, exist_ok=True)
            except Exception:
                self.TrashDir = self.GetAvailableTrashDir()
                self.mg.Vars["local_trash_dir"] = self.TrashDir
                self.mg.dump()

        self.DefaultWorkDir = self.mg.Vars.get("local_default_work_dir", None)
        if self.DefaultWorkDir is None or not os.path.isdir(self.DefaultWorkDir):
            self.DefaultWorkDir = os.path.expanduser("~")
            self.mg.Vars["local_default_work_dir"] = self.DefaultWorkDir
            self.mg.dump()
        self.SetPublicVar("cwd", self.DefaultWorkDir)

    def ClearPublicVar(self) -> None:
        self.PublicVar.clear()

    def DelPublicVar(self, key: str) -> bool:
        return self.PublicVar.pop(key, False)

    def GetPublicVar(self, key: str, default: Any = None) -> Any:
        return self.PublicVar.get(key, default)

    def SetPublicVar(
        self, key: str, value: Any, overwrite: bool = False
    ) -> tuple[AMEnum.ErrorCode, str]:
        if key in self.PublicVar and not overwrite:
            return (AMEnum.ErrorCode.KeyExists, f"Key {key} already exists")
        self.PublicVar[key] = value

    def GetAllPublicVar(self) -> dict:
        return self.PublicVar

    def GetHomeDir(self) -> str:
        return os.path.expanduser("~")

    def GetTrashDir(self) -> str:
        return self.TrashDir

    def GetNickname(self) -> str:
        return "local"

    def HasPublicVar(self, key: str) -> bool:
        return key in self.PublicVar

    def TransMode(self, mode: str | int) -> int | str:
        if isinstance(mode, str):
            if self.mode_pattern.match(mode):
                int_str = ""
                for i in range(3):
                    tmp_v = 0
                    tmp_v += 4 if mode[i * 3] == "r" else 0
                    tmp_v += 2 if mode[i * 3 + 1] == "w" else 0
                    tmp_v += 1 if mode[i * 3 + 2] == "x" else 0
                    int_str += str(tmp_v)
                mode = int(int_str, 8)
            elif self.mode_pattern2.match(mode):
                mode = int(mode, 8)
            else:
                return "Invalid mode string: " + mode
        elif isinstance(mode, int):
            if mode < 0 or mode > 0o777:
                return f"Invalid mode integer value: {mode}"
            mode = int(mode, 8)
        return mode

    def _chmod(
        self,
        path: str,
        mode: int,
        recursive: bool = False,
        errors: list[tuple[AMEnum.ErrorCode, str]] = None,
    ) -> None:
        paths = AMFS.iwalk(path, ignore_sepcial_file=True)
        for path_i in paths:
            try:
                os.chmod(path_i.path, mode)
            except PermissionError:
                errors[path_i.path] = (
                    AMEnum.ErrorCode.PermissionDenied,
                    f"Permission denied: {path_i.path}",
                )
            except Exception as e:
                errors[path_i.path] = (
                    AMEnum.ErrorCode.LocalFileError,
                    f"Chmod error: {str(e)}",
                )

    def chmod(
        self, path: str, mode: str | int, recursive: bool = False
    ) -> tuple[AMEnum.ErrorCode, str] | dict[str, tuple[AMEnum.ErrorCode, str]]:
        mode = self.TransMode(mode)
        if isinstance(mode, str):
            return (AMEnum.ErrorCode.InvalidArg, mode)
        if not os.path.exists(path):
            return (AMEnum.ErrorCode.FileNotFoundError, f"Path not exists: {path}")
        errors = {}
        self._chmod(path, mode, recursive, errors)
        if len(errors) == 0:
            return (AMEnum.ErrorCode.Success, "")
        elif len(errors) == 1 and path in errors:
            return errors[path]
        else:
            return errors

    def Check(self, need_trace: bool) -> tuple[APPEC, str]:
        return (APPEC.Success, "")

    def find(self, path: str, path_type: AMEnum.SearchType) -> list[str]:
        return self.finder.find(path, path_type)

    def exists(self, path: str) -> tuple[APPEC, bool]:
        return (APPEC.Success, os.path.exists(path))

    def listdir(self, path: str, time_out_s=-1) -> list[AMData.PathInfo]:
        return AMFS.listdir(path, time_out_s)

    def stat(self, path: str) -> tuple[tuple[APPEC, str], AMData.PathInfo]:
        if not os.path.exists(path):
            return ((APPEC.PathNotExistError, f"Path not exists: {path}"), None)
        msg, path_info = AMFS.stat(path)
        if len(msg) > 0:
            return ((APPEC.LocalStatError, msg), AMData.PathInfo())
        return ((APPEC.Success, ""), path_info)

    def getsize(self, path: str) -> int:
        return AMFS.getsize(path)

    def walk(
        self, path: str, level: int = -1
    ) -> list[tuple[list[str], list[AMData.PathInfo]]]:
        if not os.path.exists(path):
            return ((APPEC.PathNotExistError, f"Path not exists: {path}"), [])
        return ((APPEC.Success, ""), AMFS.walk(path, level))

    def mkdir(self, path: str) -> tuple[APPEC, str]:
        res = os.makedirs(path, exist_ok=True)
        if res:
            return (APPEC.Success, "")
        else:
            return (APPEC.LocalFileError, res)

    def delete_cb(
        self, func, path_f, exc_info, errors: list[tuple[str, tuple[APPEC, str]]]
    ):
        try:
            os.chmod(path_f, os.stat.S_IWRITE)
            func(path_f)
        except FileNotFoundError:
            errors.append(
                (path_f, (APPEC.PathNotExistError, f"Path not exists: {path_f}"))
            )
        except PermissionError:
            errors.append(
                (path_f, (APPEC.PermissionDenied, f"Permission denied: {path_f}"))
            )
        except Exception as e:
            errors.append((path_f, (APPEC.LocalFileError, f"Error: {str(e)}")))

    def _rm(self, path_f: str, errors: list[tuple[str, tuple[APPEC, str]]]) -> None:
        if os.path.isdir(path_f):
            shutil.rmtree(path_f, onerror=partial(self.delete_cb, errors=errors))
        else:
            try:
                os.remove(path_f)
            except PermissionError:
                os.chmod(path_f, os.stat.S_IWRITE)
                try:
                    os.remove(path_f)
                except PermissionError:
                    errors.append(
                        path_f,
                        (APPEC.PermissionDenied, f"Permission denied: {path_f}"),
                    )
                except Exception as e:
                    errors.append((path_f, (APPEC.LocalFileError, f"Error: {str(e)}")))

    def rm(self, path: str) -> list[tuple[str, tuple[APPEC, str]]] | tuple[APPEC, str]:
        errors = []
        if not os.path.exists(path):
            return (APPEC.PathNotExistError, f"Path not exists: {path}")
        self._rm(path, errors)
        return errors

    def EnsureTrashDir(self) -> tuple[APPEC, str]:
        if len(self.TrashDir) == 0:
            self.TrashDir = self.GetAvailableTrashDir()
            return (APPEC.Success, "")
        try:
            os.makedirs(self.TrashDir, exist_ok=True)
            return (APPEC.Success, "")
        except Exception:
            self.TrashDir = self.GetAvailableTrashDir()
            self.mg.Vars["local_trash_dir"] = self.TrashDir
            self.mg.dump()
            return (APPEC.Success, "")

    def saferm(self, path: str) -> tuple[APPEC, str]:
        dst_path = os.path.join(self.TrashDir, time.strftime("%Y-%m-%d-%H-%M-%S"))
        count = 1
        while True:
            if os.path.exists(os.path.join(dst_path, os.path.basename(path))):
                dst_path = os.path.join(
                    self.TrashDir, time.strftime("%Y-%m-%d-%H-%M-%S") + f"({count})"
                )
                count += 1
            else:
                break
        try:
            os.makedirs(dst_path, exist_ok=True)
            shutil.move(path, dst_path)
            return (APPEC.Success, "")
        except PermissionError:
            return (APPEC.PermissionDenied, f"Permission denied: {path}")
        except Exception as e:
            return (APPEC.LocalFileError, f"Failed to move to trash: {str(e)}")

    def copy(
        self, src: str, dst: str, need_mkdir: bool = False
    ) -> tuple[AMEnum.ErrorCode, str]:
        pass


class ErrorProcessor:
    def __init__(self, level: AMEnum.TraceLevel = AMEnum.TraceLevel.Debug):
        self.trace_level = level
        self.console = Console()
        self.printf = Console.print
        self.prompt_session = PromptSession()

    def SessionTrace(self, traceinfo: AMData.TraceInfo) -> None:
        pass

    def ErrorFormat(self, ECM: tuple[APPEC, str]) -> None:
        pass

    def printf(self, message: str) -> None:
        Console.print(message)

    def input(self, prompt: str) -> str:
        return self.prompt_session.prompt(prompt)

    def transfer_error_cb(self, error_info: AMData.ErrorCBInfo) -> None:
        pass


class ClientManager:
    def __init__(self, config_manager: ConfigManager, error_processor: ErrorProcessor):
        self.mg = config_manager
        self.hostm: HostMaintainer = HostMaintainer(60, self.ClientDisconnectCallback)
        self.ep: ErrorProcessor = error_processor
        self.local_finder = AMFS.PathMatch()
        self.LOCAL_CLIENT: LocalIOClient = LocalIOClient(config_manager)
        self.CLIENT: AMSFTPClient | LocalIOClient = self.LOCAL_CLIENT

    def AddHost(
        self, nickname: str, overwrite: bool = False
    ) -> tuple[APPEC, str] | AMSFTPClient:
        client_ori = self.hostm.get_host(nickname)
        if client_ori is not None and not overwrite:
            return client_ori
        config = self.mg.GetConrRequest(nickname)
        if config is None:
            return (APPEC.NoHostConfig, f"host {nickname} not found")

        client = AMSFTPClient(
            request=config,
            keys=self.mg.PrivateKeys(),
            error_num=30,
            trace_cb=self.ep.SessionTrace,
            auth_cb=self.PasswordCallback,
        )
        ecm = client.Connect()
        if ecm[0] != AMEnum.ErrorCode.Success:
            return ecm

        self.hostm.add_host(nickname, client, overwrite)

        if self.CLIENT is None:
            self.CLIENT = client

        return client

    def GetClient(
        self, nickname: str
    ) -> AMSFTPClient | LocalIOClient | tuple[APPEC, str]:
        if nickname.lower() == self.LOCAL_CLIENT.GetNickname():
            return self.LOCAL_CLIENT
        if nickname not in self.mg.hostd:
            return (APPEC.NoHostConfig, f"Host {nickname} not found in config file")
        return self.hostm.get_host(nickname)

    def CheckHost(
        self, nickname: str | None = None, update: bool = False
    ) -> tuple[APPEC, str]:
        if nickname is None:
            nickname = self.CurrentCache.nickname
        if nickname not in self.mg.hostd:
            return (APPEC.NoHostConfig, f"Host {nickname} not found in config file")
        return self.hostm.test_host(nickname, update)

    def RemoveHost(self, nickname: str) -> tuple[APPEC, str]:
        if self.hostm.get_host(nickname) is None:
            return (APPEC.ClientNotFound, f"Client {nickname} not created")
        if nickname == self.CLIENT.GetNickname():
            return (APPEC.ClientIsCurrent, f"Client {nickname} is current")
        self.hostm.remove_host(nickname)
        return (AMEnum.ErrorCode.Success, "")

    def GetAllHosts(self) -> list[str]:
        return self.hostm.GetHosts()

    # (nickname, work_dir, (APPEC, msg))
    def GetAllClients(self) -> list[AMSFTPClient]:
        return self.hostm.get_clients()

    def PasswordCallback(self, info: AMData.AuthCBInfo) -> str | None:
        # TODO: 格式化获取密码
        pass

    def ClientDisconnectCallback(
        self, client: AMSFTPClient, errorm: tuple[AMEnum.ErrorCode, str]
    ) -> None:
        pass

    def ChangeHost(self, nickname: str | AMSFTPClient) -> AMSFTPClient | None:
        if isinstance(nickname, AMSFTPClient):
            self.CLIENT = nickname
            return nickname
        elif isinstance(nickname, str):
            client = self.hostm.get_host(nickname)
            if client is not None:
                self.CLIENT = client
                return client
            else:
                return None


class SFTPWorker:
    def __init__(
        self,
        error_manager: ErrorProcessor,
        callback_interval_s: float = 0.1,
    ):
        self.transfer_thread = TransferThreadManager()
        self.progress_bar: tqdm = None
        self.transfer_state = None
        self.error_cb = error_manager.transfer_error_cb
        self.worker = AMSFTPWorker(
            AMData.TransferCallback(
                total_size=self._total_size_cb,
                error=self.error_cb,
                progress=self.progress_trace,
            )
        )

    def init(self) -> None | SError:
        return None

    def reset(self) -> None:
        # TODO: 重置状态参数
        pass

    def pause(self) -> None:
        self.worker.pause()

    def resume(self) -> None:
        self.worker.resume()

    def terminate(self) -> None:
        self.worker.terminate()

    def progress_trace(
        self, progressinfo: AMData.ProgressCBInfo
    ) -> AMEnum.TransferControl | None:
        if self.progress_bar is None:
            return self.transfer_state

        src_hostn = f"{progressinfo.src_host}@" if progressinfo.src_host else ""
        text = f"{src_hostn}{os.path.basename(progressinfo.src)} ➡️  {progressinfo.dst_host if progressinfo.dst_host else 'Local'}"

        if self.progress_bar.desc != text:
            self.progress_bar.set_description(text)
        self.progress_bar.n = progressinfo.accumulated_size
        self.progress_bar.refresh()

        return self.transfer_state

    def _total_size_cb(self, total_size: int) -> None:
        self.progress_bar.total = total_size
        self.progress_bar.refresh()

    def show_progress_bar(self, sign: bool = True) -> None:
        if sign:
            self.progress_bar.disable = False
        else:
            self.progress_bar.disable = True

    def transfer(self, tasks: list[AMData.TransferTask], hostd: HostMaintainer) -> None:
        self.reset()
        self.progress_bar = tqdm(
            desc="", unit="B", unit_scale=True, total=sum(task.size for task in tasks)
        )
        try:
            result = self.transfer_thread.execute_transfer(
                self.worker.transfer,
                tasks,
                hostd,
                16 * 1024 * 1024,
                2 * 1024 * 1024,
                2 * 1024 * 1024,
            )
            print(result)
        except KeyboardInterrupt:
            print("Transfer cancelled by user (Ctrl+C)")
            self.worker.terminate()
        except Exception as e:
            raise
        self.progress_bar.close()
        self.progress_bar = None
        self.transfer_state = None


class PromptManager:
    def __init__(self, config_manager: ConfigManager):
        self.mg = config_manager
        self.session = PromptSession()
        self.style: Style = Style.from_dict(self.mg.styles)

    def print(self, message: str, need_escape: bool = True) -> None:
        try:
            if need_escape:
                message = message.replace("<", "&lt;").replace(">", "&gt;")
            print_formatted_text(HTML(message), style=self.style)
        except Exception:
            print(message)

    def promt(self, prompt: str, default: str = "") -> str:
        return self.session.prompt(prompt, style=self.style, default=default)

    def FormatTime(self, timef: float) -> str:
        if timef == 0:
            return ""
        # time为unix时间戳
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timef))

    def FormatSize(self, size: int) -> str:
        if size < 1024:
            return f"{size}B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.2f}KB"
        elif size < 1024 * 1024 * 1024:
            return f"{size / 1024 / 1024:.2f}MB"
        else:
            return f"{size / 1024 / 1024 / 1024:.2f}GB"

    def f(self, string: str, style: str = "default") -> str:
        str_f = string.replace("<", "&lt;").replace(">", "&gt;")
        return f"""<div class="{style}">{str_f}</div>"""
