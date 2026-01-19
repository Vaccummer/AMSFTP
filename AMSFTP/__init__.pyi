"""
A SFTP Client Module Based on libssh2
"""
from __future__ import annotations
import typing
from . import AMData
from . import AMEnum
from . import AMFS
__all__ = ['AMData', 'AMEnum', 'AMFS', 'AMFTPClient', 'AMSFTPClient', 'AMSFTPWorker', 'AMSession', 'AMTracer', 'BaseClient', 'BasePathMatch', 'ClientMaintainer', 'PathMatch']
class AMFTPClient(BaseClient):
    """
    An FTP Client Class Based on libcurl
    """
    def Check(self, need_trace: bool = False) -> tuple[AMEnum.ErrorCode, str]:
        """
        Check FTP connection status
        """
    def Connect(self, force: bool = False) -> tuple[AMEnum.ErrorCode, str]:
        """
        Connect to FTP server
        """
    def GetHomeDir(self) -> str:
        ...
    def GetState(self) -> tuple[AMEnum.ErrorCode, str]:
        ...
    def __init__(self, request: AMData.ConRequst, buffer_capacity: int = 10, trace_cb: typing.Any = None) -> None:
        ...
    def exists(self, path: str) -> tuple[tuple[AMEnum.ErrorCode, str], bool]:
        """
        Check if path exists
        """
    def is_dir(self, path: str) -> tuple[tuple[AMEnum.ErrorCode, str], bool]:
        """
        Check if path is a directory
        """
    def iwalk(self, path: str, ignore_special_file: bool = True) -> list[AMData.PathInfo]:
        """
        Deep walk to get all leaf paths
        """
    def listdir(self, path: str, max_time_ms: int = -1) -> tuple[tuple[AMEnum.ErrorCode, str], list[AMData.PathInfo]]:
        """
        List directory contents
        """
    def mkdir(self, path: str) -> tuple[AMEnum.ErrorCode, str]:
        """
        Create a directory
        """
    def mkdirs(self, path: str) -> tuple[AMEnum.ErrorCode, str]:
        """
        Create directories recursively
        """
    def move(self, src: str, dst: str, need_mkdir: bool, force_write: bool) -> tuple[AMEnum.ErrorCode, str]:
        """
        Move file/directory to destination folder
        """
    def remove(self, path: str) -> tuple[tuple[AMEnum.ErrorCode, str], list[tuple[str, tuple[AMEnum.ErrorCode, str]]]]:
        """
        Remove file or directory recursively
        """
    def rename(self, src: str, dst: str, overwrite: bool = False) -> tuple[AMEnum.ErrorCode, str]:
        ...
    def rmdir(self, path: str) -> tuple[AMEnum.ErrorCode, str]:
        """
        Remove an empty directory
        """
    def rmfile(self, path: str) -> tuple[AMEnum.ErrorCode, str]:
        """
        Remove a file permanently
        """
    def stat(self, path: str) -> tuple[tuple[AMEnum.ErrorCode, str], AMData.PathInfo]:
        """
        Get file information
        """
    def walk(self, path: str, max_depth: int = -1, ignore_special_file: bool = True) -> tuple[tuple[AMEnum.ErrorCode, str], list[tuple[list[str], list[AMData.PathInfo]]]]:
        """
        Walk directory tree, returns list of (dirparts, [PathInfo]) tuples
        """
class AMSFTPClient(AMSession):
    """
    An SFTP Client Class Based on libssh2
    """
    def Check(self, need_trace: bool = False) -> tuple[AMEnum.ErrorCode, str]:
        """
        Check will force to update state, use GetState to get the cached state
        """
    def ConductCmd(self, cmd: str, max_time_s: int = -1) -> tuple[tuple[AMEnum.ErrorCode, str], tuple[str, int]]:
        """
        Execute shell command on remote server
        """
    def Connect(self, force: bool = False) -> tuple[AMEnum.ErrorCode, str]:
        """
        if force=True, will disconnect and reconnect, else will check first, if wrong then reconnect
        """
    def EnsureTrashDir(self) -> tuple[AMEnum.ErrorCode, str]:
        """
        Ensure the trash directory exists, if not, create it. If path is empty, will use default trash directory
        """
    def GetHomeDir(self) -> str:
        ...
    def GetOSType(self, update: bool = False) -> AMEnum.OS_TYPE:
        """
        Get the OS type of the server
        """
    def GetRTT(self, times: int = 5) -> float:
        """
        Get round-trip time to server
        """
    def GetTrashDir(self) -> str:
        ...
    def SetTrashDir(self, trash_dir: str = '') -> tuple[AMEnum.ErrorCode, str]:
        """
        Set the trash directory and create it if it doesn't exist, if wrong, will return error
        """
    def TerminateCmd(self) -> None:
        """
        Terminate currently running command
        """
    def __init__(self, request: AMData.ConRequst, keys: list[str] = [], tracer_capacity: int = 10, trace_cb: typing.Any = None, auth_cb: typing.Any = None) -> None:
        ...
    def chmod(self, path: str, mode: str | int, recursive: bool = False) -> tuple[tuple[AMEnum.ErrorCode, str], dict[str, tuple[AMEnum.ErrorCode, str]]]:
        """
        Recursive change the mode of the file
        """
    def copy(self, src: str, dst: str, need_mkdir: bool = False) -> tuple[AMEnum.ErrorCode, str]:
        """
        Copy file/directory on remote server using shell command
        """
    def exists(self, path: str) -> tuple[tuple[AMEnum.ErrorCode, str], bool]:
        """
        Check if path exists
        """
    def get_path_type(self, path: str) -> tuple[tuple[AMEnum.ErrorCode, str], AMEnum.PathType]:
        """
        Get the type of the path
        """
    def getsize(self, path: str, ignore_special_file: bool = True) -> int:
        """
        Get total size of file or directory
        """
    def is_dir(self, path: str) -> tuple[tuple[AMEnum.ErrorCode, str], bool]:
        """
        Check if path is a directory
        """
    def is_regular(self, path: str) -> tuple[tuple[AMEnum.ErrorCode, str], bool]:
        """
        Check if path is a regular file
        """
    def is_symlink(self, path: str) -> tuple[tuple[AMEnum.ErrorCode, str], bool]:
        """
        Check if path is a symlink
        """
    def iwalk(self, path: str, ignore_special_file: bool = True) -> list[AMData.PathInfo]:
        """
        Deep walk to get all leaf paths
        """
    def listdir(self, path: str, max_time_ms: int = -1) -> tuple[tuple[AMEnum.ErrorCode, str], list[AMData.PathInfo]]:
        """
        List directory contents
        """
    def mkdir(self, path: str) -> tuple[AMEnum.ErrorCode, str]:
        """
        Create a directory
        """
    def mkdirs(self, path: str) -> tuple[AMEnum.ErrorCode, str]:
        """
        Create directories recursively
        """
    def move(self, src: str, dst: str, need_mkdir: bool, force_write: bool) -> tuple[AMEnum.ErrorCode, str]:
        """
        Move file/directory to destination folder
        """
    def realpath(self, path: str = '') -> tuple[tuple[AMEnum.ErrorCode, str], str]:
        """
        Use server to parse the path, ~ parsed in local, symlink parsed in server
        """
    def remove(self, path: str) -> tuple[tuple[AMEnum.ErrorCode, str], list[tuple[str, tuple[AMEnum.ErrorCode, str]]]]:
        """
        Remove file or directory recursively
        """
    def rename(self, src: str, dst: str, overwrite: bool = False) -> tuple[AMEnum.ErrorCode, str]:
        """
        Rename file/directory
        """
    def rmdir(self, path: str) -> tuple[AMEnum.ErrorCode, str]:
        """
        Remove an empty directory
        """
    def rmfile(self, path: str) -> tuple[AMEnum.ErrorCode, str]:
        """
        Remove a file permanently
        """
    def saferm(self, path: str) -> tuple[AMEnum.ErrorCode, str]:
        """
        Safely remove by moving to trash
        """
    def stat(self, path: str) -> tuple[tuple[AMEnum.ErrorCode, str], AMData.PathInfo]:
        """
        Get the detailed information about the file
        """
    def walk(self, path: str, max_depth: int = -1, ignore_special_file: bool = True) -> tuple[tuple[AMEnum.ErrorCode, str], list[tuple[list[str], list[AMData.PathInfo]]]]:
        """
        Walk directory tree, returns list of (dirpath, files) tuples
        """
class AMSFTPWorker:
    """
    High-performance file transfer worker
    """
    def EraseOverlapTasks(self, tasks: list[AMData.TransferTask]) -> list[AMData.TransferTask]:
        """
        Remove duplicate tasks from list
        """
    def GetState(self) -> AMEnum.TransferControl:
        """
        Get current transfer state
        """
    def SetState(self, state: AMEnum.TransferControl) -> None:
        """
        Set transfer state
        """
    def __init__(self, callback: AMData.TransferCallback, cb_interval_s: float = 0.20000000298023224) -> None:
        """
        Create transfer worker with callback
        """
    def load_tasks(self, src: str, dst: str, hostm: ClientMaintainer, src_host: str = '', dst_host: str = '', overwrite: bool = False, mkdir: bool = True, ignore_special_file: bool = True) -> tuple[tuple[AMEnum.ErrorCode, str], list[AMData.TransferTask]]:
        """
        Load tasks from source and destination
        """
    def transfer(self, tasks: list[AMData.TransferTask], hostm: ClientMaintainer, buffer_size: int = -1) -> list[AMData.TransferTask]:
        """
        Execute batch file transfers
        """
    @property
    def callback(self) -> AMData.TransferCallback:
        """
        Transfer callback object
        """
    @callback.setter
    def callback(self, arg0: AMData.TransferCallback) -> None:
        ...
class AMSession(BaseClient):
    """
    An intermediate class between BaseClient and SFTP Client, Manage SSH Connection and Session
    """
    def BaseCheck(self) -> tuple[AMEnum.ErrorCode, str]:
        """
        Attemp to stat home path to test the connection
        """
    def BaseConnect(self, force: bool = False) -> tuple[AMEnum.ErrorCode, str]:
        """
        Establish ssh ssesion and sftp, if force=True, will disconnect and reconnect, else will check first, if wrong then reconnect
        """
    def GetKeys(self) -> list[str]:
        """
        Get the list of the keys
        """
    def GetLastEC(self) -> AMEnum.ErrorCode:
        """
        Get the last error code of the session
        """
    def GetLastErrorMsg(self) -> str:
        """
        Get the last error message of the session
        """
    def GetLibssh2Version(self) -> str:
        """
        Get the version of the libssh2 library
        """
    def GetState(self) -> tuple[AMEnum.ErrorCode, str]:
        """
        Get the cached state of the session
        """
    def IsValidKey(self, key: str) -> bool:
        """
        Check if the keyfile is valid
        """
    def SetAuthCallback(self, auth_cb: typing.Any) -> None:
        """
        Set the authentication callback function, callable[AuthCBInfo, None], if none, won't callback to python
        """
    def SetKeys(self, keys: list[str]) -> None:
        """
        Set the list of the keys
        """
    def __init__(self, request: AMData.ConRequst, keys: list[str], error_num: int = 10, trace_cb: typing.Any = None, auth_cb: typing.Any = None) -> None:
        ...
class AMTracer:
    """
    Base of the Client, Manage Trace action and record
    """
    def ClearPublicVar(self) -> None:
        ...
    def ClearTracer(self) -> None:
        ...
    def DelPublicVar(self, key: str) -> bool:
        ...
    def GetAllPublicVars(self) -> dict:
        ...
    def GetAllTraces(self) -> list[AMData.TraceInfo]:
        ...
    def GetNickname(self) -> str:
        ...
    def GetPublicVar(self, key: str, default_value: typing.Any = None) -> typing.Any:
        ...
    def GetRequest(self) -> AMData.ConRequst:
        ...
    def GetTraceNum(self) -> int:
        ...
    def LastTrace(self) -> AMData.TraceInfo:
        ...
    def SetPublicVar(self, key: str, value: typing.Any, overwrite: bool = False) -> tuple[AMEnum.ErrorCode, str]:
        ...
    def SetPyTrace(self, trace_cb: typing.Any = None) -> None:
        """
        callable[TraceInfo, None], if none, disable py trace
        """
    def SetTraceState(self, is_pause: bool) -> None:
        ...
    def TracerCapacity(self, size: int = -1) -> int:
        """
        Give Negative Number to Get Capacity, Give Positive Number to Set Capacity
        """
    def __init__(self, request: AMData.ConRequst, buffer_capacity: int = 10, trace_cb: typing.Any = None) -> None:
        ...
    @typing.overload
    def trace(self, level: AMEnum.TraceLevel, error_code: AMEnum.ErrorCode, target: str, action: str, msg: str) -> None:
        ...
    @typing.overload
    def trace(self, trace_info: AMData.TraceInfo) -> None:
        ...
class BaseClient(AMTracer, BasePathMatch):
    """
    Abstract Base Client Class, Implement by FTP, SFTP Client
    """
    def BufferSize(self, size: int = -1) -> int:
        """
        Buffer Size is restricted between 524288 and 67108864
        """
    def GetProtocol(self) -> AMEnum.ClientProtocol:
        """
        Get the protocol of the client, Base and Unknown are not valid
        """
    def GetProtocolName(self) -> str:
        """
        Get the string name of the protocol of the client
        """
class BasePathMatch:
    """
    Base Path Match Class
    """
    def find(self, path: str, type: AMEnum.SearchType = ...) -> list[AMData.PathInfo]:
        """
        Path Match Function, support * and <> , greater and less sign equal to [] in regex
        """
    def name_match(self, name: str, pattern: str) -> bool:
        """
        Internal Function, preprocess the pattern and match the name
        """
    def str_match(self, name: str, pattern: str) -> bool:
        """
        Internal Function, use wregex to match the string
        """
    def walk_match(self, parts: list[str], match_parts: list[str]) -> bool:
        """
        Internal Function, directly decides whether two paths match
        """
class ClientMaintainer:
    """
    Client Connection Manager with Heartbeat
    """
    def __init__(self, heartbeat_interval_s: int = 60, disconnect_cb: typing.Any = None) -> None:
        """
        Create client maintainer with heartbeat monitoring
        """
    @typing.overload
    def add_client(self, nickname: str, client: AMSFTPClient, overwrite: bool = False) -> None:
        """
        Add a SFTP client to the maintainer
        """
    @typing.overload
    def add_client(self, nickname: str, client: AMFTPClient, overwrite: bool = False) -> None:
        """
        Add a FTP client to the maintainer
        """
    def get_client(self, nickname: str) -> AMSFTPClient | AMFTPClient | None:
        """
        Get a client by nickname
        """
    def get_clients(self) -> list[AMSFTPClient | AMFTPClient]:
        """
        Get list of all registered clients
        """
    def get_nicknames(self) -> list[str]:
        """
        Get list of all registered client nicknames
        """
    def remove_client(self, nickname: str) -> None:
        """
        Remove a client from the maintainer
        """
    def test_client(self, nickname: str, update: bool = False) -> tuple[AMEnum.ErrorCode, str]:
        """
        Test client connection status
        """
class PathMatch(BasePathMatch):
    """
    Local Path Match Class, using AMFS IO function to override Core Function
    """
_cleanup: typing.Any  # value = <capsule object>
