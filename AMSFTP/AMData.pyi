"""
Data Classes
"""
import AMSFTP.AMEnum
from __future__ import annotations
import typing
__all__ = ['AuthCBInfo', 'ConRequst', 'ErrorCBInfo', 'PathInfo', 'ProgressCBInfo', 'TraceInfo', 'TransferCallback', 'TransferTask']
class AuthCBInfo:
    """
    Authentication Callback Information
    """
    request: ConRequst
    def __init__(self, NeedPassword: bool = False, request: ConRequst = ..., trial_times: int = 0) -> None:
        ...
    @property
    def NeedPassword(self) -> bool:
        """
        If true, python password callback need to return password, if false, callback function just tells you the password is wrong
        """
    @NeedPassword.setter
    def NeedPassword(self, arg0: bool) -> None:
        ...
    @property
    def trial_times(self) -> int:
        """
        Number of times the password has been tried
        """
    @trial_times.setter
    def trial_times(self, arg0: int) -> None:
        ...
class ConRequst:
    password: str
    port: int
    timeout_s: int
    username: str
    def __init__(self, nickname: str = '', hostname: str = '', username: str = '', port: int = 22, password: str = '', keyfile: str = '', compression: bool = False, timeout_s: int = 3, trash_dir: str = '') -> None:
        ...
    @property
    def compression(self) -> bool:
        """
        Enable compression
        """
    @compression.setter
    def compression(self, arg0: bool) -> None:
        ...
    @property
    def hostname(self) -> str:
        """
        Hostname or IP address of the remote server
        """
    @hostname.setter
    def hostname(self, arg0: str) -> None:
        ...
    @property
    def keyfile(self) -> str:
        """
        Dedicated key file for this authentication
        """
    @keyfile.setter
    def keyfile(self, arg0: str) -> None:
        ...
    @property
    def nickname(self) -> str:
        """
        Unique nickname for the host and connection
        """
    @nickname.setter
    def nickname(self, arg0: str) -> None:
        ...
    @property
    def trash_dir(self) -> str:
        """
        Trash directory for saferm function
        """
    @trash_dir.setter
    def trash_dir(self, arg0: str) -> None:
        ...
class ErrorCBInfo:
    """
    Error Callback Information
    """
    def __init__(self, ecm: tuple[AMSFTP.AMEnum.ErrorCode, str] = ..., src: str = '', dst: str = '', src_host: str = '', dst_host: str = '') -> None:
        ...
    @property
    def dst(self) -> str:
        """
        Destination path
        """
    @dst.setter
    def dst(self, arg0: str) -> None:
        ...
    @property
    def dst_host(self) -> str:
        """
        Destination host
        """
    @dst_host.setter
    def dst_host(self, arg0: str) -> None:
        ...
    @property
    def ecm(self) -> tuple[AMSFTP.AMEnum.ErrorCode, str]:
        """
        Error Code and Message
        """
    @ecm.setter
    def ecm(self, arg0: tuple[AMSFTP.AMEnum.ErrorCode, str]) -> None:
        ...
    @property
    def src(self) -> str:
        """
        Source path
        """
    @src.setter
    def src(self, arg0: str) -> None:
        ...
    @property
    def src_host(self) -> str:
        """
        Source host
        """
    @src_host.setter
    def src_host(self, arg0: str) -> None:
        ...
class PathInfo:
    """
    Path Information DataClass
    """
    def __init__(self, name: str, path: str, dir: str, owner: str, size: int, create_time: float, access_time: float, modify_time: float, type: AMSFTP.AMEnum.PathType, mode_int: int, mode_str: str) -> None:
        ...
    @property
    def access_time(self) -> float:
        """
        Access time of the path
        """
    @access_time.setter
    def access_time(self, arg0: float) -> None:
        ...
    @property
    def create_time(self) -> float:
        """
        Create time of the path
        """
    @create_time.setter
    def create_time(self, arg0: float) -> None:
        ...
    @property
    def dir(self) -> str:
        """
        Parent directory of the path
        """
    @dir.setter
    def dir(self, arg0: str) -> None:
        ...
    @property
    def mode_int(self) -> int:
        """
        Mode of the path as integer
        """
    @mode_int.setter
    def mode_int(self, arg0: int) -> None:
        ...
    @property
    def mode_str(self) -> str:
        """
        Mode of the path as string
        """
    @mode_str.setter
    def mode_str(self, arg0: str) -> None:
        ...
    @property
    def modify_time(self) -> float:
        """
        Modify time of the path
        """
    @modify_time.setter
    def modify_time(self, arg0: float) -> None:
        ...
    @property
    def name(self) -> str:
        """
        Basename of the path
        """
    @name.setter
    def name(self, arg0: str) -> None:
        ...
    @property
    def owner(self) -> str:
        """
        Owner of the path
        """
    @owner.setter
    def owner(self, arg0: str) -> None:
        ...
    @property
    def path(self) -> str:
        """
        Full path
        """
    @path.setter
    def path(self, arg0: str) -> None:
        ...
    @property
    def size(self) -> int:
        """
        Size of the path
        """
    @size.setter
    def size(self, arg0: int) -> None:
        ...
    @property
    def type(self) -> AMSFTP.AMEnum.PathType:
        """
        Type of the path
        """
    @type.setter
    def type(self, arg0: AMSFTP.AMEnum.PathType) -> None:
        ...
class ProgressCBInfo:
    """
    Progress Callback Information
    """
    def __init__(self, src: str = '', dst: str = '', src_host: str = '', dst_host: str = '', this_size: int = 0, file_size: int = 0, accumulated_size: int = 0, total_size: int = 0) -> None:
        ...
    @property
    def accumulated_size(self) -> int:
        """
        Size of the total files transfered
        """
    @accumulated_size.setter
    def accumulated_size(self, arg0: int) -> None:
        ...
    @property
    def dst(self) -> str:
        """
        Destination path
        """
    @dst.setter
    def dst(self, arg0: str) -> None:
        ...
    @property
    def dst_host(self) -> str:
        """
        Destination host
        """
    @dst_host.setter
    def dst_host(self, arg0: str) -> None:
        ...
    @property
    def file_size(self) -> int:
        """
        This file size
        """
    @file_size.setter
    def file_size(self, arg0: int) -> None:
        ...
    @property
    def src(self) -> str:
        """
        Source path
        """
    @src.setter
    def src(self, arg0: str) -> None:
        ...
    @property
    def src_host(self) -> str:
        """
        Source host
        """
    @src_host.setter
    def src_host(self, arg0: str) -> None:
        ...
    @property
    def this_size(self) -> int:
        """
        Size of the current file transfered
        """
    @this_size.setter
    def this_size(self, arg0: int) -> None:
        ...
    @property
    def total_size(self) -> int:
        """
        Total size of the transfer
        """
    @total_size.setter
    def total_size(self, arg0: int) -> None:
        ...
class TraceInfo:
    """
    Trace Information
    """
    error_code: AMSFTP.AMEnum.ErrorCode
    level: AMSFTP.AMEnum.TraceLevel
    def __init__(self, level: AMSFTP.AMEnum.TraceLevel, error_code: AMSFTP.AMEnum.ErrorCode, nickname: str, target: str, action: str, message: str) -> None:
        ...
    @property
    def action(self) -> str:
        """
        Name of the action function
        """
    @action.setter
    def action(self, arg0: str) -> None:
        ...
    @property
    def message(self) -> str:
        """
        Inform message or Error message
        """
    @message.setter
    def message(self, arg0: str) -> None:
        ...
    @property
    def nickname(self) -> str:
        """
        Nickname of the connection client
        """
    @nickname.setter
    def nickname(self, arg0: str) -> None:
        ...
    @property
    def target(self) -> str:
        """
        Target of the operation
        """
    @target.setter
    def target(self, arg0: str) -> None:
        ...
class TransferCallback:
    """
    Callback function Gather
    """
    def SetErrorCB(self, error: typing.Any = None) -> None:
        ...
    def SetProgressCB(self, progress: typing.Any = None) -> None:
        ...
    def SetTotalSizeCB(self, total_size: typing.Any = None) -> None:
        ...
    def __init__(self, total_size: typing.Any = None, error: typing.Any = None, progress: typing.Any = None) -> None:
        ...
class TransferTask:
    """
    Transfer Task
    """
    def __init__(self, src: str, dst: str, src_host: str, dst_host: str, size: int, path_type: AMSFTP.AMEnum.PathType = ...) -> None:
        ...
    @property
    def dst(self) -> str:
        """
        Destination path
        """
    @dst.setter
    def dst(self, arg0: str) -> None:
        ...
    @property
    def dst_host(self) -> str:
        """
        Destination host
        """
    @dst_host.setter
    def dst_host(self, arg0: str) -> None:
        ...
    @property
    def size(self) -> int:
        """
        Size of the src
        """
    @size.setter
    def size(self, arg0: int) -> None:
        ...
    @property
    def src(self) -> str:
        """
        Source path
        """
    @src.setter
    def src(self, arg0: str) -> None:
        ...
    @property
    def src_host(self) -> str:
        """
        Source host
        """
    @src_host.setter
    def src_host(self, arg0: str) -> None:
        ...
