from __future__ import annotations
import typing
__all__ = ['AMSFTPWorker', 'ConRequst', 'ErrorInfo', 'PathInfo', 'PathType', 'TransferCallback', 'TransferErrorCode', 'TransferTask']
class AMSFTPWorker:
    def SetPyTrace(self, trace_cb: typing.Any = None) -> None:
        ...
    def SetSessionPyTrace(self, trace_cb: typing.Any = None) -> None:
        ...
    def SetWorkerPyTrace(self, trace_cb: typing.Any = None) -> None:
        ...
    def __init__(self, private_keys: list[str], request: ConRequst, error_info_buffer_size: int = 10) -> None:
        ...
    def check(self) -> tuple[TransferErrorCode, str]:
        ...
    def copy(self, src: str, dst: str, need_mkdir: bool = False) -> tuple[TransferErrorCode, str]:
        ...
    def download(self, tasks: list[TransferTask], cb_set: TransferCallback = ..., chunk_size: int = 262144) -> list[tuple[tuple[str, str], tuple[TransferErrorCode, str]]] | tuple[TransferErrorCode, str]:
        ...
    def ensure(self) -> tuple[TransferErrorCode, str]:
        ...
    def ensure_trash_dir(self) -> tuple[TransferErrorCode, str]:
        ...
    def exists(self, path: str) -> bool | tuple[TransferErrorCode, str]:
        ...
    def get(self, src: str, dst: str, cb_set: TransferCallback = ..., ignore_link: bool = True, chunk_size: int = 262144) -> list[tuple[tuple[str, str], tuple[TransferErrorCode, str]]] | tuple[TransferErrorCode, str]:
        ...
    def get_all_error_info(self) -> list[ErrorInfo]:
        ...
    def get_last_error_info(self) -> ErrorInfo:
        ...
    def get_nickname(self) -> str:
        ...
    def get_size(self, path: str) -> int | tuple[TransferErrorCode, str]:
        ...
    def get_trash_dir(self) -> str:
        ...
    def init(self, pycb: typing.Any = None) -> tuple[TransferErrorCode, str]:
        ...
    def is_dir(self, path: str) -> bool | tuple[TransferErrorCode, str]:
        ...
    def is_file(self, path: str) -> bool | tuple[TransferErrorCode, str]:
        ...
    def is_running(self) -> bool:
        ...
    def is_symlink(self, path: str) -> bool | tuple[TransferErrorCode, str]:
        ...
    def listdir(self, path: str, max_num: int = -1) -> list[PathInfo] | tuple[TransferErrorCode, str]:
        ...
    def mkdir(self, path: str) -> tuple[TransferErrorCode, str]:
        ...
    def mkdirs(self, path: str) -> tuple[TransferErrorCode, str]:
        ...
    def move(self, src: str, dst: str, need_mkdir: bool = False, force_write: bool = False) -> tuple[TransferErrorCode, str]:
        ...
    def pause(self) -> None:
        ...
    def put(self, src: str, dst: str, cb_set: TransferCallback = ..., ignore_link: bool = True, chunk_size: int = 262144) -> list[tuple[tuple[str, str], tuple[TransferErrorCode, str]]] | tuple[TransferErrorCode, str]:
        ...
    def realpath(self, path: str) -> str | tuple[TransferErrorCode, str]:
        ...
    def reconnect(self) -> tuple[TransferErrorCode, str]:
        ...
    def rename(self, src: str, newname: str) -> tuple[TransferErrorCode, str]:
        ...
    def resume(self) -> None:
        ...
    def rm(self, path: str) -> list[tuple[str, tuple[TransferErrorCode, str]]]:
        ...
    def rmdir(self, path: str) -> tuple[TransferErrorCode, str]:
        ...
    def rmfile(self, path: str) -> tuple[TransferErrorCode, str]:
        ...
    def saferm(self, path: str) -> tuple[TransferErrorCode, str]:
        ...
    def set_trash_dir(self, trash_dir_f: str = '') -> tuple[TransferErrorCode, str]:
        ...
    def stat(self, path: str) -> PathInfo | tuple[TransferErrorCode, str]:
        ...
    def terminate(self) -> None:
        ...
    def toAnotherHost(self, tasks: list[TransferTask], another_worker: AMSFTPWorker, cb_set: TransferCallback = ..., chunk_size: int = 262144) -> list[tuple[tuple[str, str], tuple[TransferErrorCode, str]]] | tuple[TransferErrorCode, str]:
        ...
    def transmit(self, src: str, dst: str, another_worker: AMSFTPWorker, cb_set: TransferCallback = ..., ignore_link: bool = True, chunk_size: int = 262144) -> list[tuple[tuple[str, str], tuple[TransferErrorCode, str]]] | tuple[TransferErrorCode, str]:
        ...
    def upload(self, tasks: list[TransferTask], cb_set: TransferCallback = ..., chunk_size: int = 262144) -> list[tuple[tuple[str, str], tuple[TransferErrorCode, str]]] | tuple[TransferErrorCode, str]:
        ...
    def walk(self, path: str) -> list[PathInfo]:
        ...
class ConRequst:
    compression: bool
    hostname: str
    keyfile: str
    nickname: str
    password: str
    port: int
    timeout_s: int
    trash_dir: str
    username: str
    def __init__(self, nickname: str, hostname: str, username: str, port: int, password: str = '', keyfile: str = '', compression: bool = False, timeout_s: int = 3, trash_dir: str = '') -> None:
        ...
class ErrorInfo:
    dst: str
    error_code: TransferErrorCode
    function_name: str
    msg: str
    src: str
    def __init__(self, error_code: TransferErrorCode, src: str, dst: str, function_name: str, msg: str) -> None:
        ...
class PathInfo:
    atime: int
    dir: str
    mtime: int
    name: str
    path: str
    path_type: PathType
    permission: int
    size: int
    uname: str
    def __init__(self, name: str, path: str, dir: str, uname: str, size: int, atime: int, mtime: int, path_type: PathType = ..., permission: int = 0) -> None:
        ...
class PathType:
    """
    Members:
    
      DIR
    
      FILE
    
      SYMLINK
    """
    DIR: typing.ClassVar[PathType]  # value = <PathType.DIR: 0>
    FILE: typing.ClassVar[PathType]  # value = <PathType.FILE: 1>
    SYMLINK: typing.ClassVar[PathType]  # value = <PathType.SYMLINK: 2>
    __members__: typing.ClassVar[dict[str, PathType]]  # value = {'DIR': <PathType.DIR: 0>, 'FILE': <PathType.FILE: 1>, 'SYMLINK': <PathType.SYMLINK: 2>}
    def __eq__(self, other: typing.Any) -> bool:
        ...
    def __getstate__(self) -> int:
        ...
    def __hash__(self) -> int:
        ...
    def __index__(self) -> int:
        ...
    def __init__(self, value: int) -> None:
        ...
    def __int__(self) -> int:
        ...
    def __ne__(self, other: typing.Any) -> bool:
        ...
    def __repr__(self) -> str:
        ...
    def __setstate__(self, state: int) -> None:
        ...
    def __str__(self) -> str:
        ...
    @property
    def name(self) -> str:
        ...
    @property
    def value(self) -> int:
        ...
class TransferCallback:
    def __init__(self, interval: float, total_size: typing.Any = None, error: typing.Any = None, progress: typing.Any = None) -> None:
        ...
class TransferErrorCode:
    """
    Members:
    
      Success
    
      PassCheck
    
      FailedCheck
    
      SessionCreateError
    
      SftpCreateError
    
      SessionEstablishError
    
      SftpEstablishError
    
      ConnectionAuthorizeError
    
      LocalFileMapError
    
      RemoteFileOpenError
    
      RemoteFileStatError
    
      LocalFileCreateError
    
      LocalFileAllocError
    
      NetworkError
    
      NetworkDisconnect
    
      NetworkTimeout
    
      LocalFileFlushError
    
      SegmentationFault
    
      SessionBroken
    
      SftpBroken
    
      ChannelCreateError
    
      ConnectionCheckFailed
    
      RemoteFileWriteError
    
      RemoteFileReadError
    
      Terminate
    
      LocalFileExists
    
      RemoteFileExists
    
      PathNotExist
    
      PermissionDenied
    
      RemotePathOpenError
    
      NotDirectory
    
      ParentDirectoryNotExist
    
      TargetNotAFile
    
      RemoteFileDeleteError
    
      RemoteDirDeleteError
    
      UnknownError
    
      DirNotEmpty
    
      EmptyDirRemoveError
    
      TargetNotADirectory
    
      InvalidTrashDir
    
      MoveError
    
      TargetExists
    
      CopyError
    
      EndOfFile
    
      EAgain
    
      SocketNone
    
      SocketSend
    
      SocketTimeout
    
      SocketRecv
    
      SocketAccept
    
      WriteProtected
    
      UnenoughSpace
    
      UserSpaceQuotaExceeded
    
      BannerRecvError
    
      BannerSendError
    
      SocketSendError
    
      SocketDisconnect
    
      AuthFailed
    
      PublicKeyAuthFailed
    
      PasswordExpired
    
      KeyfileAuthFailed
    
      ChannelFailure
    
      ChannelWindowFull
    
      ChannelWindowExceeded
    
      MACAuthFailed
    
      KexFailure
    
      AlgoUnsupported
    
      MemoryAllocError
    
      FileOperationError
    
      ScpProtocolError
    
      SftpProtocolError
    
      KnownHostAuthFailed
    
      InvalidParameter
    
      NoSFTPConnection
    
      SFTPConnectionLost
    
      SFTPBadMessage
    
      SFTPLockConflict
    
      SymlinkLoop
    
      InvalidFilename
    
      UnsupportedSFTPOperation
    
      MediaUnavailable
    
      SftpNotInitialized
    
      SessionNotInitialized
    
      DirAlreadyExists
    
      PathAlreadyExists
    
      UnexpectedEOF
    """
    AlgoUnsupported: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.AlgoUnsupported: -64>
    AuthFailed: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.AuthFailed: -55>
    BannerRecvError: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.BannerRecvError: -51>
    BannerSendError: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.BannerSendError: -52>
    ChannelCreateError: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.ChannelCreateError: -18>
    ChannelFailure: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.ChannelFailure: -59>
    ChannelWindowExceeded: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.ChannelWindowExceeded: -61>
    ChannelWindowFull: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.ChannelWindowFull: -60>
    ConnectionAuthorizeError: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.ConnectionAuthorizeError: -5>
    ConnectionCheckFailed: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.ConnectionCheckFailed: -19>
    CopyError: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.CopyError: -40>
    DirAlreadyExists: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.DirAlreadyExists: -82>
    DirNotEmpty: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.DirNotEmpty: -34>
    EAgain: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.EAgain: -42>
    EmptyDirRemoveError: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.EmptyDirRemoveError: -35>
    EndOfFile: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.EndOfFile: -41>
    FailedCheck: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.FailedCheck: 2>
    FileOperationError: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.FileOperationError: -66>
    InvalidFilename: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.InvalidFilename: -77>
    InvalidParameter: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.InvalidParameter: -70>
    InvalidTrashDir: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.InvalidTrashDir: -37>
    KexFailure: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.KexFailure: -63>
    KeyfileAuthFailed: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.KeyfileAuthFailed: -58>
    KnownHostAuthFailed: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.KnownHostAuthFailed: -69>
    LocalFileAllocError: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.LocalFileAllocError: -10>
    LocalFileCreateError: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.LocalFileCreateError: -9>
    LocalFileExists: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.LocalFileExists: -23>
    LocalFileFlushError: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.LocalFileFlushError: -14>
    LocalFileMapError: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.LocalFileMapError: -6>
    MACAuthFailed: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.MACAuthFailed: -62>
    MediaUnavailable: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.MediaUnavailable: -79>
    MemoryAllocError: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.MemoryAllocError: -65>
    MoveError: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.MoveError: -38>
    NetworkDisconnect: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.NetworkDisconnect: -12>
    NetworkError: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.NetworkError: -11>
    NetworkTimeout: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.NetworkTimeout: -13>
    NoSFTPConnection: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.NoSFTPConnection: -71>
    NotDirectory: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.NotDirectory: -28>
    ParentDirectoryNotExist: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.ParentDirectoryNotExist: -29>
    PassCheck: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.PassCheck: 1>
    PasswordExpired: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.PasswordExpired: -57>
    PathAlreadyExists: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.PathAlreadyExists: -84>
    PathNotExist: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.PathNotExist: -25>
    PermissionDenied: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.PermissionDenied: -26>
    PublicKeyAuthFailed: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.PublicKeyAuthFailed: -56>
    RemoteDirDeleteError: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.RemoteDirDeleteError: -32>
    RemoteFileDeleteError: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.RemoteFileDeleteError: -31>
    RemoteFileExists: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.RemoteFileExists: -24>
    RemoteFileOpenError: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.RemoteFileOpenError: -7>
    RemoteFileReadError: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.RemoteFileReadError: -21>
    RemoteFileStatError: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.RemoteFileStatError: -8>
    RemoteFileWriteError: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.RemoteFileWriteError: -20>
    RemotePathOpenError: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.RemotePathOpenError: -27>
    SFTPBadMessage: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.SFTPBadMessage: -73>
    SFTPConnectionLost: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.SFTPConnectionLost: -72>
    SFTPLockConflict: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.SFTPLockConflict: -75>
    ScpProtocolError: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.ScpProtocolError: -67>
    SegmentationFault: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.SegmentationFault: -15>
    SessionBroken: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.SessionBroken: -16>
    SessionCreateError: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.SessionCreateError: -1>
    SessionEstablishError: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.SessionEstablishError: -3>
    SessionNotInitialized: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.SessionNotInitialized: -81>
    SftpBroken: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.SftpBroken: -17>
    SftpCreateError: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.SftpCreateError: -2>
    SftpEstablishError: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.SftpEstablishError: -4>
    SftpNotInitialized: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.SftpNotInitialized: -80>
    SftpProtocolError: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.SftpProtocolError: -68>
    SocketAccept: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.SocketAccept: -47>
    SocketDisconnect: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.SocketDisconnect: -54>
    SocketNone: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.SocketNone: -43>
    SocketRecv: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.SocketRecv: -46>
    SocketSend: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.SocketSend: -44>
    SocketSendError: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.SocketSendError: -53>
    SocketTimeout: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.SocketTimeout: -45>
    Success: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.Success: 0>
    SymlinkLoop: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.SymlinkLoop: -76>
    TargetExists: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.TargetExists: -39>
    TargetNotADirectory: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.TargetNotADirectory: -36>
    TargetNotAFile: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.TargetNotAFile: -30>
    Terminate: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.Terminate: -22>
    UnenoughSpace: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.UnenoughSpace: -49>
    UnexpectedEOF: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.UnexpectedEOF: -85>
    UnknownError: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.UnknownError: -33>
    UnsupportedSFTPOperation: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.UnsupportedSFTPOperation: -78>
    UserSpaceQuotaExceeded: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.UserSpaceQuotaExceeded: -50>
    WriteProtected: typing.ClassVar[TransferErrorCode]  # value = <TransferErrorCode.WriteProtected: -48>
    __members__: typing.ClassVar[dict[str, TransferErrorCode]]  # value = {'Success': <TransferErrorCode.Success: 0>, 'PassCheck': <TransferErrorCode.PassCheck: 1>, 'FailedCheck': <TransferErrorCode.FailedCheck: 2>, 'SessionCreateError': <TransferErrorCode.SessionCreateError: -1>, 'SftpCreateError': <TransferErrorCode.SftpCreateError: -2>, 'SessionEstablishError': <TransferErrorCode.SessionEstablishError: -3>, 'SftpEstablishError': <TransferErrorCode.SftpEstablishError: -4>, 'ConnectionAuthorizeError': <TransferErrorCode.ConnectionAuthorizeError: -5>, 'LocalFileMapError': <TransferErrorCode.LocalFileMapError: -6>, 'RemoteFileOpenError': <TransferErrorCode.RemoteFileOpenError: -7>, 'RemoteFileStatError': <TransferErrorCode.RemoteFileStatError: -8>, 'LocalFileCreateError': <TransferErrorCode.LocalFileCreateError: -9>, 'LocalFileAllocError': <TransferErrorCode.LocalFileAllocError: -10>, 'NetworkError': <TransferErrorCode.NetworkError: -11>, 'NetworkDisconnect': <TransferErrorCode.NetworkDisconnect: -12>, 'NetworkTimeout': <TransferErrorCode.NetworkTimeout: -13>, 'LocalFileFlushError': <TransferErrorCode.LocalFileFlushError: -14>, 'SegmentationFault': <TransferErrorCode.SegmentationFault: -15>, 'SessionBroken': <TransferErrorCode.SessionBroken: -16>, 'SftpBroken': <TransferErrorCode.SftpBroken: -17>, 'ChannelCreateError': <TransferErrorCode.ChannelCreateError: -18>, 'ConnectionCheckFailed': <TransferErrorCode.ConnectionCheckFailed: -19>, 'RemoteFileWriteError': <TransferErrorCode.RemoteFileWriteError: -20>, 'RemoteFileReadError': <TransferErrorCode.RemoteFileReadError: -21>, 'Terminate': <TransferErrorCode.Terminate: -22>, 'LocalFileExists': <TransferErrorCode.LocalFileExists: -23>, 'RemoteFileExists': <TransferErrorCode.RemoteFileExists: -24>, 'PathNotExist': <TransferErrorCode.PathNotExist: -25>, 'PermissionDenied': <TransferErrorCode.PermissionDenied: -26>, 'RemotePathOpenError': <TransferErrorCode.RemotePathOpenError: -27>, 'NotDirectory': <TransferErrorCode.NotDirectory: -28>, 'ParentDirectoryNotExist': <TransferErrorCode.ParentDirectoryNotExist: -29>, 'TargetNotAFile': <TransferErrorCode.TargetNotAFile: -30>, 'RemoteFileDeleteError': <TransferErrorCode.RemoteFileDeleteError: -31>, 'RemoteDirDeleteError': <TransferErrorCode.RemoteDirDeleteError: -32>, 'UnknownError': <TransferErrorCode.UnknownError: -33>, 'DirNotEmpty': <TransferErrorCode.DirNotEmpty: -34>, 'EmptyDirRemoveError': <TransferErrorCode.EmptyDirRemoveError: -35>, 'TargetNotADirectory': <TransferErrorCode.TargetNotADirectory: -36>, 'InvalidTrashDir': <TransferErrorCode.InvalidTrashDir: -37>, 'MoveError': <TransferErrorCode.MoveError: -38>, 'TargetExists': <TransferErrorCode.TargetExists: -39>, 'CopyError': <TransferErrorCode.CopyError: -40>, 'EndOfFile': <TransferErrorCode.EndOfFile: -41>, 'EAgain': <TransferErrorCode.EAgain: -42>, 'SocketNone': <TransferErrorCode.SocketNone: -43>, 'SocketSend': <TransferErrorCode.SocketSend: -44>, 'SocketTimeout': <TransferErrorCode.SocketTimeout: -45>, 'SocketRecv': <TransferErrorCode.SocketRecv: -46>, 'SocketAccept': <TransferErrorCode.SocketAccept: -47>, 'WriteProtected': <TransferErrorCode.WriteProtected: -48>, 'UnenoughSpace': <TransferErrorCode.UnenoughSpace: -49>, 'UserSpaceQuotaExceeded': <TransferErrorCode.UserSpaceQuotaExceeded: -50>, 'BannerRecvError': <TransferErrorCode.BannerRecvError: -51>, 'BannerSendError': <TransferErrorCode.BannerSendError: -52>, 'SocketSendError': <TransferErrorCode.SocketSendError: -53>, 'SocketDisconnect': <TransferErrorCode.SocketDisconnect: -54>, 'AuthFailed': <TransferErrorCode.AuthFailed: -55>, 'PublicKeyAuthFailed': <TransferErrorCode.PublicKeyAuthFailed: -56>, 'PasswordExpired': <TransferErrorCode.PasswordExpired: -57>, 'KeyfileAuthFailed': <TransferErrorCode.KeyfileAuthFailed: -58>, 'ChannelFailure': <TransferErrorCode.ChannelFailure: -59>, 'ChannelWindowFull': <TransferErrorCode.ChannelWindowFull: -60>, 'ChannelWindowExceeded': <TransferErrorCode.ChannelWindowExceeded: -61>, 'MACAuthFailed': <TransferErrorCode.MACAuthFailed: -62>, 'KexFailure': <TransferErrorCode.KexFailure: -63>, 'AlgoUnsupported': <TransferErrorCode.AlgoUnsupported: -64>, 'MemoryAllocError': <TransferErrorCode.MemoryAllocError: -65>, 'FileOperationError': <TransferErrorCode.FileOperationError: -66>, 'ScpProtocolError': <TransferErrorCode.ScpProtocolError: -67>, 'SftpProtocolError': <TransferErrorCode.SftpProtocolError: -68>, 'KnownHostAuthFailed': <TransferErrorCode.KnownHostAuthFailed: -69>, 'InvalidParameter': <TransferErrorCode.InvalidParameter: -70>, 'NoSFTPConnection': <TransferErrorCode.NoSFTPConnection: -71>, 'SFTPConnectionLost': <TransferErrorCode.SFTPConnectionLost: -72>, 'SFTPBadMessage': <TransferErrorCode.SFTPBadMessage: -73>, 'SFTPLockConflict': <TransferErrorCode.SFTPLockConflict: -75>, 'SymlinkLoop': <TransferErrorCode.SymlinkLoop: -76>, 'InvalidFilename': <TransferErrorCode.InvalidFilename: -77>, 'UnsupportedSFTPOperation': <TransferErrorCode.UnsupportedSFTPOperation: -78>, 'MediaUnavailable': <TransferErrorCode.MediaUnavailable: -79>, 'SftpNotInitialized': <TransferErrorCode.SftpNotInitialized: -80>, 'SessionNotInitialized': <TransferErrorCode.SessionNotInitialized: -81>, 'DirAlreadyExists': <TransferErrorCode.DirAlreadyExists: -82>, 'PathAlreadyExists': <TransferErrorCode.PathAlreadyExists: -84>, 'UnexpectedEOF': <TransferErrorCode.UnexpectedEOF: -85>}
    def __eq__(self, other: typing.Any) -> bool:
        ...
    def __getstate__(self) -> int:
        ...
    def __hash__(self) -> int:
        ...
    def __index__(self) -> int:
        ...
    def __init__(self, value: int) -> None:
        ...
    def __int__(self) -> int:
        ...
    def __ne__(self, other: typing.Any) -> bool:
        ...
    def __repr__(self) -> str:
        ...
    def __setstate__(self, state: int) -> None:
        ...
    def __str__(self) -> str:
        ...
    @property
    def name(self) -> str:
        ...
    @property
    def value(self) -> int:
        ...
class TransferTask:
    dst: str
    path_type: PathType
    size: int
    src: str
    def __init__(self, src: str, dst: str, size: int, path_type: PathType = ...) -> None:
        ...
_cleanup: typing.Any  # value = <capsule object>
