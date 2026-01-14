"""
A SFTP Client Module Based on libssh2
"""
from __future__ import annotations
import typing
from . import AMData
from . import AMEnum
from . import AMFS
__all__ = ['AMData', 'AMEnum', 'AMFS', 'AMSFTPClient', 'AMSFTPWorker', 'AMSession', 'BaseSFTPClient', 'HostMaintainer']
class AMSFTPClient(BaseSFTPClient, AMFS.BasePathMatch):
    """
    Core SFTP Client Class
    """
    @typing.overload
    def ClearPublicVar(self) -> None:
        """
        Clear all stored Python objects
        """
    @typing.overload
    def ClearPublicVar(self) -> None:
        """
        Clear all stored Python objects
        """
    def Connect(self, force: bool = False) -> tuple[AMEnum.ErrorCode, str]:
        """
        Wrapper of BaseConnect, will get OS type and home directory if conducted the first time
        """
    @typing.overload
    def DelPublicVar(self, key: str) -> bool:
        """
        Delete a stored Python object, returns True if deleted
        """
    @typing.overload
    def DelPublicVar(self, key: str) -> bool:
        """
        Delete a stored Python object, returns True if deleted
        """
    def EnsureTrashDir(self) -> tuple[AMEnum.ErrorCode, str]:
        ...
    @typing.overload
    def GetAllPublicVars(self) -> dict:
        """
        Get all stored Python objects as a dictionary with deep copies
        """
    @typing.overload
    def GetAllPublicVars(self) -> dict:
        """
        Get all stored Python objects as a dictionary with deep copies
        """
    def GetHomeDir(self) -> str:
        """
        Get the home directory
        """
    @typing.overload
    def GetPublicVar(self, key: str, default: typing.Any = None) -> typing.Any:
        """
        Get a stored Python object, returns a deep copy
        """
    @typing.overload
    def GetPublicVar(self, key: str, default_value: typing.Any = None) -> typing.Any:
        """
        Get a stored Python object, returns a deep copy
        """
    def GetTrashDir(self) -> str:
        """
        Get the trash directory
        """
    @typing.overload
    def HasPublicVar(self, key: str) -> bool:
        """
        Check if a key exists in the public variable dictionary
        """
    @typing.overload
    def HasPublicVar(self, key: str) -> bool:
        """
        Check if a key exists in the public variable dictionary
        """
    @typing.overload
    def SetPublicVar(self, key: str, value: typing.Any, overwrite: bool = False) -> tuple[AMEnum.ErrorCode, str]:
        """
        Store a Python object in C++ side with deep copy, C++ owns the copy
        """
    @typing.overload
    def SetPublicVar(self, key: str, value: typing.Any, overwrite: bool = False) -> tuple[AMEnum.ErrorCode, str]:
        """
        Store a Python object in C++ side with deep copy, C++ owns the copy
        """
    def SetTrashDir(self, trash_dir: str = '') -> tuple[AMEnum.ErrorCode, str]:
        """
        Set the trash directory and create it if it doesn't exist
        """
    def StrUid(self, uid: int) -> str:
        """
        Convert a uid to a string
        """
    def __init__(self, request: AMData.ConRequst, keys: list[str], error_num: int = 10, trace_cb: typing.Any = None, auth_cb: typing.Any = None) -> None:
        ...
    def chmod(self, path: str, mode: str | int, recursive: bool = False) -> dict[str, tuple[AMEnum.ErrorCode, str]] | tuple[AMEnum.ErrorCode, str]:
        ...
    def copy(self, src: str, dst: str, need_mkdir: bool = False) -> tuple[AMEnum.ErrorCode, str]:
        """
        Unstable, using shell command to copy
        """
    def exists(self, path: str) -> tuple[tuple[AMEnum.ErrorCode, str], bool]:
        ...
    def get_path_type(self, path: str) -> tuple[tuple[AMEnum.ErrorCode, str], AMEnum.PathType]:
        ...
    def getsize(self, path: str, ignore_sepcial_file: bool = True) -> int:
        ...
    def is_dir(self, path: str) -> tuple[tuple[AMEnum.ErrorCode, str], bool]:
        ...
    def is_regular(self, path: str) -> tuple[tuple[AMEnum.ErrorCode, str], bool]:
        ...
    def is_symlink(self, path: str) -> tuple[tuple[AMEnum.ErrorCode, str], bool]:
        ...
    def iwalk(self, path: str, ignore_sepcial_file: bool = True) -> list[AMData.PathInfo]:
        """
        Recursive walk the path, ignore path structure, just return list[PathInfo]
        """
    def listdir(self, path: str, max_time_ms: int = -1) -> tuple[tuple[AMEnum.ErrorCode, str], list[AMData.PathInfo]]:
        ...
    def mkdir(self, path: str) -> tuple[AMEnum.ErrorCode, str]:
        ...
    def mkdirs(self, path: str) -> tuple[AMEnum.ErrorCode, str]:
        ...
    def move(self, src: str, dst: str, need_mkdir: bool = False, force_write: bool = False) -> tuple[AMEnum.ErrorCode, str]:
        """
        Move source path src to Destination Directory dst
        """
    def realpath(self, path: str) -> tuple[tuple[AMEnum.ErrorCode, str], str]:
        """
        Parse and return the absolute path, ~ in client will be parsed, .. and . will be parsed by server, if there are these symbols, the path must exist
        """
    def remove(self, path: str) -> list[tuple[str, tuple[AMEnum.ErrorCode, str]]] | tuple[AMEnum.ErrorCode, str]:
        """
        Permanently remove a file or directory, if return (ErrorCode, str), the whole operation failed, otherwise return list[tuple[str, tuple[ErrorCode, str]]], means some paths failed to remove
        """
    def rename(self, src: str, dst: str, overwrite: bool = False) -> tuple[AMEnum.ErrorCode, str]:
        """
        Turn src_path into dst_path, if overwrite is true, the dst_path will be overwritten
        """
    def rmdir(self, path: str) -> tuple[AMEnum.ErrorCode, str]:
        ...
    def rmfile(self, path: str) -> tuple[AMEnum.ErrorCode, str]:
        ...
    def saferm(self, path: str) -> tuple[AMEnum.ErrorCode, str]:
        """
        Not real remove, just move it to {trash_dir}/{year-month-day-hour-minute-second}/{pathname}
        """
    def stat(self, path: str) -> tuple[tuple[AMEnum.ErrorCode, str], AMData.PathInfo]:
        ...
    def walk(self, path: str, max_depth: int = -1, ignore_sepcial_file: bool = True) -> tuple[tuple[AMEnum.ErrorCode, str], list[tuple[list[str], list[AMData.PathInfo]]]]:
        """
        Recursive walk the path, record parent dir, return list[tuple[list[str],PathInfo]]
        """
class AMSFTPWorker:
    """
    A worker for transferring files
    """
    def IsPause(self) -> bool:
        ...
    def IsRunning(self) -> bool:
        ...
    def IsTerminate(self) -> bool:
        ...
    def __init__(self, callback: AMData.TransferCallback = ..., cb_interval_s: float = 0.1) -> None:
        ...
    def load_tasks(self, src: str, dst: str, hostd: HostMaintainer, src_hostname: str = '', dst_hostname: str = '', overwrite: bool = False, mkdir: bool = True, ignore_sepcial_file: bool = True) -> tuple[tuple[AMEnum.ErrorCode, str], list[AMData.TransferTask]]:
        ...
    def pause(self) -> None:
        ...
    def reset(self) -> None:
        """
        Rset Internal Status like is_terminate, is_pause, current_size, total_size
        """
    def resume(self) -> None:
        ...
    def set_cb_interval(self, interval_s: float) -> None:
        """
        Set the interval of the callback in seconds, default is 0.1s
        """
    def terminate(self) -> None:
        ...
    def transfer(self, tasks: list[AMData.TransferTask], hostd: HostMaintainer, chunk_large: int = 16777216, chunk_middle: int = 2097152, chunk_small: int = 262144) -> list[AMData.TransferTask]:
        ...
class AMSession(AMData.AMTracer):
    """
    Session Class
    """
    def BaseConnect(self, force: bool = False) -> tuple[AMEnum.ErrorCode, str]:
        """
        Connect to the session, force will force to reconnect even if the session is already connected
        """
    def Check(self, arg0: bool) -> tuple[AMEnum.ErrorCode, str]:
        """
        Realtime check the session status and update the state
        """
    def Disconnect(self) -> None:
        """
        Disconnect the session
        """
    def GetKeys(self) -> list[str]:
        """
        Get all shared private keys of the session
        """
    def GetLastEC(self) -> AMEnum.ErrorCode:
        """
        Get the last error code of the session
        """
    def GetLastErrorMsg(self) -> str:
        """
        Get the last error message of the session
        """
    def GetNickname(self) -> str:
        """
        Get the nickname of the session
        """
    def GetRequest(self) -> AMData.ConRequst:
        """
        Get the request data
        """
    def GetState(self) -> tuple[AMEnum.ErrorCode, str]:
        """
        Get the current state of the session
        """
    def IsValidKey(self, key: str) -> bool:
        """
        Check whether a file is a valid private key file
        """
    def SetAuthCallback(self, auth_cb: typing.Any = None) -> None:
        """
        When password authentication is needed, this callback will be called, callable[[AuthCBInfo], bool]
        """
    def SetKeys(self, keys: list[str]) -> None:
        """
        Set shared private keys
        """
    def __init__(self, request: AMData.ConRequst, keys: list[str], error_num: int = 10, trace_cb: typing.Any = None, auth_cb: typing.Any = None) -> None:
        ...
class BaseSFTPClient(AMSession):
    def ConductCmd(self, cmd: str) -> tuple[tuple[AMEnum.ErrorCode, str], tuple[str, int]]:
        """
        Conduct a command and return the result
        """
    def GetOSType(self, update: bool = False) -> AMEnum.OS_TYPE:
        """
        Update will force to re-detect the OS type
        """
    def GetRTT(self, times: int = 5) -> float:
        """
        Get the round-trip time of the session
        """
    def __init__(self, request: AMData.ConRequst, keys: list[str], error_num: int = 10, trace_cb: typing.Any = None, auth_cb: typing.Any = None) -> None:
        ...
class HostMaintainer:
    """
    The Client Maintainer Class, Check clients status all the time
    """
    def __init__(self, heartbeat_interval_s: int) -> None:
        ...
    def add_host(self, nickname: str, client: AMSFTPClient, overwrite: bool = False) -> None:
        ...
    def get_host(self, nickname: str) -> AMSFTPClient:
        ...
    def get_hosts(self) -> list[str]:
        """
        Just return all hostnames
        """
    def remove_host(self, nickname: str) -> None:
        ...
    def test_host(self, nickname: str, update: bool = False) -> tuple[AMEnum.ErrorCode, str]:
        """
        Test the host connection, return (ErrorCode, str)
        """
_cleanup: typing.Any  # value = <capsule object>
