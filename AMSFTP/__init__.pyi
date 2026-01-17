"""
A SFTP Client Module Based on libssh2
"""
from __future__ import annotations
import typing
from . import AMData
from . import AMEnum
from . import AMFS
__all__ = ['AMData', 'AMEnum', 'AMFS', 'AMFTPClient', 'AMSFTPClient', 'AMSFTPWorker', 'AMSession', 'BaseClient', 'HostMaintainer']
class AMFTPClient(AMFS.BasePathMatch):
    """
    FTP Client Class Based on libcurl
    """
    def Check(self, arg0: bool) -> tuple[AMEnum.ErrorCode, str]:
        """
        Check if the connection is still valid using PWD command
        """
    def Connect(self, force: bool = False) -> tuple[AMEnum.ErrorCode, str]:
        """
        Connect to FTP server, if force=True, will disconnect and reconnect
        """
    def GetHomeDir(self) -> str:
        """
        Get the home directory path
        """
    def __init__(self, request: AMData.ConRequst, buffer_capacity: int = 10, trace_cb: typing.Any = None) -> None:
        """
        Create an FTP client instance
        """
    def download(self, remote_path: str, local_path: str, progress_callback: typing.Any = None) -> tuple[AMEnum.ErrorCode, str]:
        """
        Download a file from remote FTP server to local
        """
    def exists(self, path: str) -> tuple[tuple[AMEnum.ErrorCode, str], bool]:
        """
        Check if a path exists
        """
    def is_dir(self, path: str) -> tuple[tuple[AMEnum.ErrorCode, str], bool]:
        """
        Check if a path is a directory
        """
    def iwalk(self, path: str, ignore_special_file: bool = True) -> list[AMData.PathInfo]:
        """
        Recursively walk the path, return list of leaf nodes (files and empty directories)
        """
    def mkdir(self, path: str) -> tuple[AMEnum.ErrorCode, str]:
        """
        Create a single directory
        """
    def mkdirs(self, path: str) -> tuple[AMEnum.ErrorCode, str]:
        """
        Create multiple nested directories (like mkdir -p)
        """
    def move(self, src: str, dst: str, need_mkdir: bool = False, force_write: bool = False) -> tuple[AMEnum.ErrorCode, str]:
        """
        Move source path to destination directory
        """
    def remove(self, path: str) -> list[tuple[str, tuple[AMEnum.ErrorCode, str]]] | tuple[AMEnum.ErrorCode, str]:
        """
        Recursively delete a file or directory. Returns list of errors if any occurred
        """
    def rename(self, src: str, dst: str, overwrite: bool = False) -> tuple[AMEnum.ErrorCode, str]:
        """
        Rename or move a file/directory from src to dst
        """
    def rmdir(self, path: str) -> tuple[AMEnum.ErrorCode, str]:
        """
        Delete an empty directory
        """
    def rmfile(self, path: str) -> tuple[AMEnum.ErrorCode, str]:
        """
        Delete a single file
        """
    def stat(self, path: str) -> tuple[tuple[AMEnum.ErrorCode, str], AMData.PathInfo]:
        """
        Get detailed information about a path (file or directory)
        """
    def upload(self, local_path: str, remote_path: str, progress_callback: typing.Any = None) -> tuple[AMEnum.ErrorCode, str]:
        """
        Upload a file from local to remote FTP server
        """
    def walk(self, path: str, max_depth: int = -1, ignore_special_file: bool = True) -> tuple[tuple[AMEnum.ErrorCode, str], list[tuple[list[str], list[AMData.PathInfo]]]]:
        """
        Recursively walk the path with structure, return list[tuple[list[str], list[PathInfo]]]
        """
class AMSFTPClient(BaseClient, AMFS.BasePathMatch):
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
    def iterator_listdir(self, path: str) -> typing.Any:
        """
        Return an iterator that yields PathInfo one by one, useful for large directories
        """
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
    def UnionTransfer(self, task: AMData.TransferTask, src_client: BaseClient = None, dst_client: BaseClient = None) -> tuple[AMEnum.ErrorCode, str]:
        ...
    def __init__(self, callback: AMData.TransferCallback = ..., cb_interval_s: float = 0.1) -> None:
        ...
    def load_tasks(self, src: str, dst: str, hostd: HostMaintainer, src_hostname: str = '', dst_hostname: str = '', overwrite: bool = False, mkdir: bool = True, ignore_sepcial_file: bool = True) -> tuple[tuple[AMEnum.ErrorCode, str], list[AMData.TransferTask]]:
        ...
    def transfer(self, tasks: list[AMData.TransferTask], hostd: HostMaintainer, chunk_large: int = 16777216, chunk_middle: int = 2097152, chunk_small: int = 262144) -> list[AMData.TransferTask]:
        ...
class AMSession(BaseClient):
    """
    Session Class
    """
    def BaseConnect(self, force: bool = False) -> tuple[AMEnum.ErrorCode, str]:
        """
        Connect to the session, force will force to reconnect even if the session is already connected
        """
    def Check(self, need_trace: bool = False) -> tuple[AMEnum.ErrorCode, str]:
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
class BaseClient(AMData.AMTracer):
    def __init__(self, request: AMData.ConRequst, buffer_capacity: int = 10, trace_cb: typing.Any = None) -> None:
        ...
class HostMaintainer:
    """
    The Client Maintainer Class, Check clients status all the time
    """
    def __init__(self, heartbeat_interval_s: int, disconnect_cb: typing.Any = None) -> None:
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
