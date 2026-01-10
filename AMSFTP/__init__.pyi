"""
A SFTP Client Module Based on libssh2
"""
from __future__ import annotations
import typing
from . import AMData
from . import AMEnum
from . import AMFS
__all__ = ['AMData', 'AMEnum', 'AMFS', 'AMSFTPClient', 'AMSFTPWorker', 'BaseSFTPClient']
class AMSFTPClient(BaseSFTPClient):
    """
    Core SFTP Client Class
    """
    def EnsureTrashDir(self) -> tuple[AMEnum.ErrorCode, str]:
        ...
    def GetHomeDir(self) -> str:
        ...
    def SetTrashDir(self, trash_dir: str = '') -> tuple[AMEnum.ErrorCode, str]:
        """
        Set the trash directory and create it if it doesn't exist
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
    def walk(self, path: str, max_depth: int = -1, ignore_sepcial_file: bool = True) -> tuple[tuple[AMEnum.ErrorCode, str], list[tuple[list[str], AMData.PathInfo]]]:
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
    def load_tasks(self, src: str, dst: str, hostd: AMData.Hostd, src_hostname: str = '', dst_hostname: str = '', overwrite: bool = False, mkdir: bool = True, ignore_sepcial_file: bool = True) -> tuple[tuple[AMEnum.ErrorCode, str], list[AMData.TransferTask]]:
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
    def transfer(self, tasks: list[AMData.TransferTask], hostd: AMData.Hostd, chunk_large: int = 16777216, chunk_middle: int = 2097152, chunk_small: int = 262144) -> list[AMData.TransferTask]:
        ...
class BaseSFTPClient:
    def Check(self) -> tuple[AMEnum.ErrorCode, str]:
        ...
    def Connect(self) -> tuple[AMEnum.ErrorCode, str]:
        ...
    def Disconnect(self) -> None:
        ...
    def EnsureConnect(self) -> tuple[AMEnum.ErrorCode, str]:
        ...
    def GetAllTraceErrors(self) -> list[AMData.TraceInfo]:
        """
        Get all trace errors, return list[TraceInfo]
        """
    def GetOSType(self, update: bool = False) -> AMEnum.OS_TYPE:
        """
        Update will force to re-detect the OS type
        """
    def GetTraceCapacity(self) -> int:
        """
        Get the capacity of the trace buffer
        """
    def GetTraceNum(self) -> int:
        ...
    def GetTrashDir(self) -> str:
        ...
    def IsValidKey(self, key: str) -> bool:
        """
        Check whether a file is a valid private key file
        """
    def LastTraceError(self) -> typing.Any | AMData.TraceInfo:
        """
        Get the last trace error, return Optional[TraceInfo]
        """
    def Nickname(self) -> str:
        """
        Get the nickname of the client
        """
    def SetAuthCallback(self, auth_cb: typing.Any = None) -> None:
        """
        When password authentication is needed, this callback will be called, callable[[AuthCBInfo], bool]
        """
    def SetPyTrace(self, trace_cb: typing.Any = None) -> None:
        """
        Set the python trace callback, callable[TraceInfo, None]
        """
    def __init__(self, request: AMData.ConRequst, keys: list[str], error_num: int = 10, trace_cb: typing.Any = None, auth_cb: typing.Any = None) -> None:
        ...
_cleanup: typing.Any  # value = <capsule object>
