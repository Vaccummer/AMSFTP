"""
Data Classes
"""
import AMSFTP
import AMSFTP.AMEnum
from __future__ import annotations
import typing
__all__ = ['AuthCBInfo', 'ConRequst', 'ErrorCBInfo', 'Hostd', 'PathInfo', 'ProgressCBInfo', 'TraceInfo', 'TransferCallback', 'TransferTask']
class AuthCBInfo:
    def __init__(self, NeedPassword: bool, request: ConRequst, trial_times: int) -> None:
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
    def request(self) -> ConRequst:
        """
        Connection request data
        """
    @request.setter
    def request(self, arg0: ConRequst) -> None:
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
    """
    Connection Request DataClass
    """
    def __init__(self, nickname: str, hostname: str, username: str, port: int, password: str = '', keyfile: str = '', compression: bool = False, timeout_s: int = 3, trash_dir: str = '') -> None:
        ...
    @property
    def compression(self) -> bool:
        """
        Whether to use compression, default is false
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
        Dedicated key file for this host
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
    def password(self) -> str:
        """
        Password for authentication, if not provided, public key authentication will be used
        """
    @password.setter
    def password(self, arg0: str) -> None:
        ...
    @property
    def port(self) -> int:
        """
        Port number of the remote server, default is 22
        """
    @port.setter
    def port(self, arg0: int) -> None:
        ...
    @property
    def timeout_s(self) -> int:
        """
        Timeout in seconds, default is 3
        """
    @timeout_s.setter
    def timeout_s(self, arg0: int) -> None:
        ...
    @property
    def trash_dir(self) -> str:
        """
        Trash directory for failed transfers, default is empty
        """
    @trash_dir.setter
    def trash_dir(self, arg0: str) -> None:
        ...
    @property
    def username(self) -> str:
        """
        Username for authentication
        """
    @username.setter
    def username(self, arg0: str) -> None:
        ...
class ErrorCBInfo:
    dst: str
    dst_host: str
    ecm: tuple[AMSFTP.AMEnum.ErrorCode, str]
    src: str
    src_host: str
    def __init__(self, ecm: tuple[AMSFTP.AMEnum.ErrorCode, str], src: str, dst: str, src_host: str, dst_host: str) -> None:
        ...
class Hostd:
    """
    A dictionary for storing clients
    """
    def __init__(self) -> None:
        ...
    def add_host(self, hostname: str, client: AMSFTP.AMSFTPClient, overwrite: bool = False) -> None:
        ...
    def get_host(self, hostname: str) -> AMSFTP.AMSFTPClient:
        ...
    def get_hosts(self) -> list[str]:
        """
        Just return all hostnames
        """
    def remove_host(self, hostname: str) -> None:
        ...
    def reset(self) -> None:
        """
        Clear ths host status record
        """
    def test_host(self, hostname: str) -> tuple[AMSFTP.AMEnum.ErrorCode, str]:
        """
        Test the host connection, return (ErrorCode, str)
        """
class PathInfo:
    """
    Path Information DataClass
    """
    access_time: float
    dir: str
    mode_int: int
    modify_time: float
    name: str
    owner: str
    path: str
    size: int
    type: AMSFTP.AMEnum.PathType
    def __init__(self, name: str, path: str, dir: str, owner: str, size: int, create_time: float, access_time: float, modify_time: float, path_type: AMSFTP.AMEnum.PathType = ..., mode_int: int = 511, mode_str: str = 'rwxrwxrwx') -> None:
        ...
    @property
    def create_time(self) -> float:
        """
        Only Windows and MacOS has this attribute
        """
    @create_time.setter
    def create_time(self, arg0: float) -> None:
        ...
    @property
    def mode_str(self) -> str:
        """
        The mode of the path, like [rwxrwxrwx], [onwer、group、others]
        """
    @mode_str.setter
    def mode_str(self, arg0: str) -> None:
        ...
class ProgressCBInfo:
    """
    Progress Callback Info DataClass
    """
    dst: str
    dst_host: str
    file_size: int
    src: str
    src_host: str
    total_size: int
    def __init__(self, src: str, dst: str, src_host: str, dst_host: str, this_size: int, file_size: int, accumulated_size: int, total_size: int) -> None:
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
    def this_size(self) -> int:
        """
        Size of the current file transfered
        """
    @this_size.setter
    def this_size(self, arg0: int) -> None:
        ...
class TraceInfo:
    """
    Trace Information DataClass
    """
    action: str
    error_code: AMSFTP.AMEnum.ErrorCode
    level: AMSFTP.AMEnum.TraceLevel
    message: str
    nickname: str
    target: str
    timestamp: float
    def __init__(self, level: AMSFTP.AMEnum.TraceLevel, error_code: AMSFTP.AMEnum.ErrorCode, nickname: str, target: str, action: str, message: str) -> None:
        ...
class TransferCallback:
    """
    Callback function Gather
    """
    def SetErrorCB(self, error: typing.Any = None) -> None:
        """
        callable[[ErrorCBInfo], None]
        """
    def SetProgressCB(self, progress: typing.Any = None) -> None:
        """
        callable[[ProgressCBInfo], Optional[TransferControl]]
        """
    def SetTotalSizeCB(self, total_size: typing.Any = None) -> None:
        """
        callable[[int], None]
        """
    def __init__(self, total_size: typing.Any = None, error: typing.Any = None, progress: typing.Any = None) -> None:
        ...
class TransferTask:
    IsSuccess: bool
    dst: str
    dst_host: str
    overwrite: bool
    path_type: AMSFTP.AMEnum.PathType
    rc: tuple[AMSFTP.AMEnum.ErrorCode, str]
    size: int
    src: str
    src_host: str
    def __init__(self, src: str, src_host: str, dst: str, dst_host: str, size: int, path_type: AMSFTP.AMEnum.PathType = ..., overwrite: bool = False) -> None:
        ...
