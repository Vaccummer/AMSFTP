from __future__ import annotations
import typing
from . import AMFS
__all__ = ['AMFS', 'AMSFTPClient', 'AMSFTPWorker', 'AuthCBInfo', 'BaseSFTPClient', 'ConRequst', 'ErrorCBInfo', 'ErrorCode', 'Hostd', 'OS_TYPE', 'ProgressCBInfo', 'TransferCallback', 'TransferControl', 'TransferTask']
class AMSFTPClient(BaseSFTPClient):
    def EnsureTrashDir(self) -> tuple[ErrorCode, str]:
        ...
    def SetTrashDir(self, trash_dir: str = '') -> tuple[ErrorCode, str]:
        ...
    def __init__(self, request: ConRequst, keys: list[str], error_num: int = 10, trace_cb: typing.Any = None, auth_cb: typing.Any = None) -> None:
        ...
    def chmod(self, path: str, mode: str | int, recursive: bool = False) -> dict[str, tuple[ErrorCode, str]] | tuple[ErrorCode, str]:
        ...
    def copy(self, src: str, dst: str, need_mkdir: bool = False) -> tuple[ErrorCode, str]:
        ...
    def exists(self, path: str) -> bool | tuple[ErrorCode, str]:
        ...
    def get_path_type(self, path: str) -> AMFS.PathType | tuple[ErrorCode, str]:
        ...
    def getsize(self, path: str, ignore_sepcial_file: bool = True) -> int | tuple[ErrorCode, str]:
        ...
    def is_dir(self, path: str) -> bool | tuple[ErrorCode, str]:
        ...
    def is_regular(self, path: str) -> bool | tuple[ErrorCode, str]:
        ...
    def is_symlink(self, path: str) -> bool | tuple[ErrorCode, str]:
        ...
    def iwalk(self, path: str, ignore_sepcial_file: bool = True) -> list[...]:
        ...
    def listdir(self, path: str, max_time_ms: int = -1) -> list[...] | tuple[ErrorCode, str]:
        ...
    def mkdir(self, path: str) -> tuple[ErrorCode, str]:
        ...
    def mkdirs(self, path: str) -> tuple[ErrorCode, str]:
        ...
    def move(self, src: str, dst: str, need_mkdir: bool = False, force_write: bool = False) -> tuple[ErrorCode, str]:
        ...
    def realpath(self, path: str) -> str | tuple[ErrorCode, str]:
        ...
    def remove(self, path: str) -> list[tuple[str, tuple[ErrorCode, str]]] | tuple[ErrorCode, str]:
        ...
    def rename(self, src: str, new_name: str) -> tuple[ErrorCode, str]:
        ...
    def rmdir(self, path: str) -> tuple[ErrorCode, str]:
        ...
    def rmfile(self, path: str) -> tuple[ErrorCode, str]:
        ...
    def saferm(self, path: str) -> tuple[ErrorCode, str]:
        ...
    def stat(self, path: str) -> ... | tuple[ErrorCode, str]:
        ...
    def walk(self, path: str, max_depth: int = -1, ignore_sepcial_file: bool = True) -> list[tuple[list[str], ...]] | tuple[ErrorCode, str]:
        ...
class AMSFTPWorker:
    def IsPause(self) -> bool:
        ...
    def IsRunning(self) -> bool:
        ...
    def IsTerminate(self) -> bool:
        ...
    def __init__(self, callback: TransferCallback = ..., cb_interval_s: float = 0.1) -> None:
        ...
    def load_tasks(self, src: str, dst: str, hostd: Hostd, src_hostname: str = '', dst_hostname: str = '', overwrite: bool = False, ignore_sepcial_file: bool = True) -> tuple[list[TransferTask], tuple[ErrorCode, str]]:
        ...
    def pause(self) -> None:
        ...
    def reset(self) -> None:
        ...
    def resume(self) -> None:
        ...
    def set_cb_interval(self, interval_s: float) -> None:
        ...
    def terminate(self) -> None:
        ...
    def transfer(self, tasks: list[TransferTask], hostd: Hostd, chunk_large: int = 16777216, chunk_middle: int = 2097152, chunk_small: int = 262144) -> list[TransferTask]:
        ...
class AuthCBInfo:
    NeedPassword: bool
    request: ConRequst
    trial_times: int
    def __init__(self, NeedPassword: bool, request: ConRequst, trial_times: int) -> None:
        ...
class BaseSFTPClient:
    def Check(self) -> tuple[ErrorCode, str]:
        ...
    def Connect(self) -> tuple[ErrorCode, str]:
        ...
    def Disconnect(self) -> None:
        ...
    def EnsureConnect(self) -> tuple[ErrorCode, str]:
        ...
    def GetAllTraceErrors(self) -> list[dict[str, str | ErrorCode]]:
        ...
    def GetOSType(self) -> OS_TYPE:
        ...
    def GetTraceCapacity(self) -> int:
        ...
    def GetTraceNum(self) -> int:
        ...
    def GetTrashDir(self) -> str:
        ...
    def IsValidKey(self, key: str) -> bool:
        ...
    def LastTraceError(self) -> typing.Any | dict[str, str | ErrorCode]:
        ...
    def Nickname(self) -> str:
        ...
    def SetAuthCallback(self, auth_cb: typing.Any = None) -> None:
        ...
    def SetPyTrace(self, trace_cb: typing.Any = None) -> None:
        ...
    def __init__(self, request: ConRequst, keys: list[str], error_num: int = 10, trace_cb: typing.Any = None, auth_cb: typing.Any = None) -> None:
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
class ErrorCBInfo:
    dst: str
    dst_host: str
    ecm: tuple[ErrorCode, str]
    src: str
    src_host: str
    def __init__(self, ecm: tuple[ErrorCode, str], src: str, dst: str, src_host: str, dst_host: str) -> None:
        ...
class ErrorCode:
    """
    Members:
    
      Success
    
      SessionCreateError
    
      NoBannerRecv
    
      BannerSendError
    
      InvalidMacAdress
    
      KeyExchangeMethodNegotiationFailed
    
      MemAllocError
    
      SocketSendError
    
      KeyExchangeFailed
    
      OperationTimeout
    
      HostkeyInitFailed
    
      HostkeySignFailed
    
      DataDecryptError
    
      SocketDisconnect
    
      SSHProtocolError
    
      PasswordExpired
    
      LocalFileError
    
      NoAuthMethod
    
      AuthFailed
    
      PublickeyAuthFailed
    
      ChannelOrderError
    
      ChannelOperationError
    
      ChannelRequestDenied
    
      ChannelWindowExceeded
    
      ChannelPacketOversize
    
      ChannelClosed
    
      ChannelAlreadySendEOF
    
      SCPProtocolError
    
      ZlibCompressError
    
      SocketOperationTimeout
    
      SftpProtocolError
    
      RequestDenied
    
      InvalidArg
    
      InvalidPollType
    
      PublicKeyProtocolError
    
      SSHEAGAIN
    
      BufferTooSmall
    
      BadOperationOrder
    
      CompressionError
    
      PointerOverflow
    
      SSHAgentProtocolError
    
      SocketRecvError
    
      DataEncryptError
    
      InvalidSocketType
    
      HostFingerprintMismatch
    
      ChannelWindowFull
    
      PrivateKeyAuthFailed
    
      RandomGenError
    
      MissingUserAuthBanner
    
      AlgorithmUnsupported
    
      MacAuthFailed
    
      HashInitError
    
      HashCalculateError
    
      EndOfFile
    
      FileNotExist
    
      PermissionDenied
    
      CommonFailure
    
      BadMessageFormat
    
      NoConnection
    
      ConnectionLost
    
      OperationUnsupported
    
      InvalidHandle
    
      PathNotExist
    
      FileAlreadyExists
    
      FileWriteProtected
    
      StorageMediaUnavailable
    
      FilesystemNoSpace
    
      SpaceQuotaExceed
    
      UsernameNotExists
    
      PathUsingByOthers
    
      DirNotEmpty
    
      NotADirectory
    
      InvalidFilename
    
      SymlinkLoop
    
      UnknownError
    
      SocketCreateError
    
      SocketConnectTimeout
    
      SocketConnectFailed
    
      SessionCreateFailed
    
      SessionHandshakeFailed
    
      NoSession
    
      NotAFile
    
      ParentDirectoryNotExist
    
      InhostCopyFailed
    
      LocalFileMapError
    
      UnexpectedEOF
    
      Terminate
    
      UnImplentedMethod
    
      NoPermissionAttribute
    
      LocalStatError
    
      TransferPause
    
      DNSResolveError
    """
    AlgorithmUnsupported: typing.ClassVar[ErrorCode]  # value = <ErrorCode.AlgorithmUnsupported: -51>
    AuthFailed: typing.ClassVar[ErrorCode]  # value = <ErrorCode.AuthFailed: -18>
    BadMessageFormat: typing.ClassVar[ErrorCode]  # value = <ErrorCode.BadMessageFormat: 5>
    BadOperationOrder: typing.ClassVar[ErrorCode]  # value = <ErrorCode.BadOperationOrder: -39>
    BannerSendError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.BannerSendError: -3>
    BufferTooSmall: typing.ClassVar[ErrorCode]  # value = <ErrorCode.BufferTooSmall: -38>
    ChannelAlreadySendEOF: typing.ClassVar[ErrorCode]  # value = <ErrorCode.ChannelAlreadySendEOF: -27>
    ChannelClosed: typing.ClassVar[ErrorCode]  # value = <ErrorCode.ChannelClosed: -26>
    ChannelOperationError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.ChannelOperationError: -21>
    ChannelOrderError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.ChannelOrderError: -20>
    ChannelPacketOversize: typing.ClassVar[ErrorCode]  # value = <ErrorCode.ChannelPacketOversize: -25>
    ChannelRequestDenied: typing.ClassVar[ErrorCode]  # value = <ErrorCode.ChannelRequestDenied: -22>
    ChannelWindowExceeded: typing.ClassVar[ErrorCode]  # value = <ErrorCode.ChannelWindowExceeded: -24>
    ChannelWindowFull: typing.ClassVar[ErrorCode]  # value = <ErrorCode.ChannelWindowFull: -47>
    CommonFailure: typing.ClassVar[ErrorCode]  # value = <ErrorCode.CommonFailure: 4>
    CompressionError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.CompressionError: -40>
    ConnectionLost: typing.ClassVar[ErrorCode]  # value = <ErrorCode.ConnectionLost: 7>
    DNSResolveError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.DNSResolveError: 39>
    DataDecryptError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.DataDecryptError: -12>
    DataEncryptError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.DataEncryptError: -44>
    DirNotEmpty: typing.ClassVar[ErrorCode]  # value = <ErrorCode.DirNotEmpty: 18>
    EndOfFile: typing.ClassVar[ErrorCode]  # value = <ErrorCode.EndOfFile: 1>
    FileAlreadyExists: typing.ClassVar[ErrorCode]  # value = <ErrorCode.FileAlreadyExists: 11>
    FileNotExist: typing.ClassVar[ErrorCode]  # value = <ErrorCode.FileNotExist: 2>
    FileWriteProtected: typing.ClassVar[ErrorCode]  # value = <ErrorCode.FileWriteProtected: 12>
    FilesystemNoSpace: typing.ClassVar[ErrorCode]  # value = <ErrorCode.FilesystemNoSpace: 14>
    HashCalculateError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.HashCalculateError: -54>
    HashInitError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.HashInitError: -53>
    HostFingerprintMismatch: typing.ClassVar[ErrorCode]  # value = <ErrorCode.HostFingerprintMismatch: -46>
    HostkeyInitFailed: typing.ClassVar[ErrorCode]  # value = <ErrorCode.HostkeyInitFailed: -10>
    HostkeySignFailed: typing.ClassVar[ErrorCode]  # value = <ErrorCode.HostkeySignFailed: -11>
    InhostCopyFailed: typing.ClassVar[ErrorCode]  # value = <ErrorCode.InhostCopyFailed: 31>
    InvalidArg: typing.ClassVar[ErrorCode]  # value = <ErrorCode.InvalidArg: -34>
    InvalidFilename: typing.ClassVar[ErrorCode]  # value = <ErrorCode.InvalidFilename: 20>
    InvalidHandle: typing.ClassVar[ErrorCode]  # value = <ErrorCode.InvalidHandle: 9>
    InvalidMacAdress: typing.ClassVar[ErrorCode]  # value = <ErrorCode.InvalidMacAdress: -4>
    InvalidPollType: typing.ClassVar[ErrorCode]  # value = <ErrorCode.InvalidPollType: -35>
    InvalidSocketType: typing.ClassVar[ErrorCode]  # value = <ErrorCode.InvalidSocketType: -45>
    KeyExchangeFailed: typing.ClassVar[ErrorCode]  # value = <ErrorCode.KeyExchangeFailed: -8>
    KeyExchangeMethodNegotiationFailed: typing.ClassVar[ErrorCode]  # value = <ErrorCode.KeyExchangeMethodNegotiationFailed: -5>
    LocalFileError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.LocalFileError: -16>
    LocalFileMapError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.LocalFileMapError: 32>
    LocalStatError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.LocalStatError: 37>
    MacAuthFailed: typing.ClassVar[ErrorCode]  # value = <ErrorCode.MacAuthFailed: -52>
    MemAllocError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.MemAllocError: -6>
    MissingUserAuthBanner: typing.ClassVar[ErrorCode]  # value = <ErrorCode.MissingUserAuthBanner: -50>
    NoAuthMethod: typing.ClassVar[ErrorCode]  # value = <ErrorCode.NoAuthMethod: -17>
    NoBannerRecv: typing.ClassVar[ErrorCode]  # value = <ErrorCode.NoBannerRecv: -2>
    NoConnection: typing.ClassVar[ErrorCode]  # value = <ErrorCode.NoConnection: 6>
    NoPermissionAttribute: typing.ClassVar[ErrorCode]  # value = <ErrorCode.NoPermissionAttribute: 36>
    NoSession: typing.ClassVar[ErrorCode]  # value = <ErrorCode.NoSession: 28>
    NotADirectory: typing.ClassVar[ErrorCode]  # value = <ErrorCode.NotADirectory: 19>
    NotAFile: typing.ClassVar[ErrorCode]  # value = <ErrorCode.NotAFile: 29>
    OperationTimeout: typing.ClassVar[ErrorCode]  # value = <ErrorCode.OperationTimeout: -9>
    OperationUnsupported: typing.ClassVar[ErrorCode]  # value = <ErrorCode.OperationUnsupported: 8>
    ParentDirectoryNotExist: typing.ClassVar[ErrorCode]  # value = <ErrorCode.ParentDirectoryNotExist: 30>
    PasswordExpired: typing.ClassVar[ErrorCode]  # value = <ErrorCode.PasswordExpired: -15>
    PathNotExist: typing.ClassVar[ErrorCode]  # value = <ErrorCode.PathNotExist: 10>
    PathUsingByOthers: typing.ClassVar[ErrorCode]  # value = <ErrorCode.PathUsingByOthers: 17>
    PermissionDenied: typing.ClassVar[ErrorCode]  # value = <ErrorCode.PermissionDenied: 3>
    PointerOverflow: typing.ClassVar[ErrorCode]  # value = <ErrorCode.PointerOverflow: -41>
    PrivateKeyAuthFailed: typing.ClassVar[ErrorCode]  # value = <ErrorCode.PrivateKeyAuthFailed: -48>
    PublicKeyProtocolError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.PublicKeyProtocolError: -36>
    PublickeyAuthFailed: typing.ClassVar[ErrorCode]  # value = <ErrorCode.PublickeyAuthFailed: -19>
    RandomGenError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.RandomGenError: -49>
    RequestDenied: typing.ClassVar[ErrorCode]  # value = <ErrorCode.RequestDenied: -32>
    SCPProtocolError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.SCPProtocolError: -28>
    SSHAgentProtocolError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.SSHAgentProtocolError: -42>
    SSHEAGAIN: typing.ClassVar[ErrorCode]  # value = <ErrorCode.SSHEAGAIN: -37>
    SSHProtocolError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.SSHProtocolError: -14>
    SessionCreateError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.SessionCreateError: -1>
    SessionCreateFailed: typing.ClassVar[ErrorCode]  # value = <ErrorCode.SessionCreateFailed: 26>
    SessionHandshakeFailed: typing.ClassVar[ErrorCode]  # value = <ErrorCode.SessionHandshakeFailed: 27>
    SftpProtocolError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.SftpProtocolError: -31>
    SocketConnectFailed: typing.ClassVar[ErrorCode]  # value = <ErrorCode.SocketConnectFailed: 25>
    SocketConnectTimeout: typing.ClassVar[ErrorCode]  # value = <ErrorCode.SocketConnectTimeout: 24>
    SocketCreateError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.SocketCreateError: 23>
    SocketDisconnect: typing.ClassVar[ErrorCode]  # value = <ErrorCode.SocketDisconnect: -13>
    SocketOperationTimeout: typing.ClassVar[ErrorCode]  # value = <ErrorCode.SocketOperationTimeout: -30>
    SocketRecvError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.SocketRecvError: -43>
    SocketSendError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.SocketSendError: -7>
    SpaceQuotaExceed: typing.ClassVar[ErrorCode]  # value = <ErrorCode.SpaceQuotaExceed: 15>
    StorageMediaUnavailable: typing.ClassVar[ErrorCode]  # value = <ErrorCode.StorageMediaUnavailable: 13>
    Success: typing.ClassVar[ErrorCode]  # value = <ErrorCode.Success: 0>
    SymlinkLoop: typing.ClassVar[ErrorCode]  # value = <ErrorCode.SymlinkLoop: 21>
    Terminate: typing.ClassVar[ErrorCode]  # value = <ErrorCode.Terminate: 34>
    TransferPause: typing.ClassVar[ErrorCode]  # value = <ErrorCode.TransferPause: 38>
    UnImplentedMethod: typing.ClassVar[ErrorCode]  # value = <ErrorCode.UnImplentedMethod: 35>
    UnexpectedEOF: typing.ClassVar[ErrorCode]  # value = <ErrorCode.UnexpectedEOF: 33>
    UnknownError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.UnknownError: 22>
    UsernameNotExists: typing.ClassVar[ErrorCode]  # value = <ErrorCode.UsernameNotExists: 16>
    ZlibCompressError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.ZlibCompressError: -29>
    __members__: typing.ClassVar[dict[str, ErrorCode]]  # value = {'Success': <ErrorCode.Success: 0>, 'SessionCreateError': <ErrorCode.SessionCreateError: -1>, 'NoBannerRecv': <ErrorCode.NoBannerRecv: -2>, 'BannerSendError': <ErrorCode.BannerSendError: -3>, 'InvalidMacAdress': <ErrorCode.InvalidMacAdress: -4>, 'KeyExchangeMethodNegotiationFailed': <ErrorCode.KeyExchangeMethodNegotiationFailed: -5>, 'MemAllocError': <ErrorCode.MemAllocError: -6>, 'SocketSendError': <ErrorCode.SocketSendError: -7>, 'KeyExchangeFailed': <ErrorCode.KeyExchangeFailed: -8>, 'OperationTimeout': <ErrorCode.OperationTimeout: -9>, 'HostkeyInitFailed': <ErrorCode.HostkeyInitFailed: -10>, 'HostkeySignFailed': <ErrorCode.HostkeySignFailed: -11>, 'DataDecryptError': <ErrorCode.DataDecryptError: -12>, 'SocketDisconnect': <ErrorCode.SocketDisconnect: -13>, 'SSHProtocolError': <ErrorCode.SSHProtocolError: -14>, 'PasswordExpired': <ErrorCode.PasswordExpired: -15>, 'LocalFileError': <ErrorCode.LocalFileError: -16>, 'NoAuthMethod': <ErrorCode.NoAuthMethod: -17>, 'AuthFailed': <ErrorCode.AuthFailed: -18>, 'PublickeyAuthFailed': <ErrorCode.PublickeyAuthFailed: -19>, 'ChannelOrderError': <ErrorCode.ChannelOrderError: -20>, 'ChannelOperationError': <ErrorCode.ChannelOperationError: -21>, 'ChannelRequestDenied': <ErrorCode.ChannelRequestDenied: -22>, 'ChannelWindowExceeded': <ErrorCode.ChannelWindowExceeded: -24>, 'ChannelPacketOversize': <ErrorCode.ChannelPacketOversize: -25>, 'ChannelClosed': <ErrorCode.ChannelClosed: -26>, 'ChannelAlreadySendEOF': <ErrorCode.ChannelAlreadySendEOF: -27>, 'SCPProtocolError': <ErrorCode.SCPProtocolError: -28>, 'ZlibCompressError': <ErrorCode.ZlibCompressError: -29>, 'SocketOperationTimeout': <ErrorCode.SocketOperationTimeout: -30>, 'SftpProtocolError': <ErrorCode.SftpProtocolError: -31>, 'RequestDenied': <ErrorCode.RequestDenied: -32>, 'InvalidArg': <ErrorCode.InvalidArg: -34>, 'InvalidPollType': <ErrorCode.InvalidPollType: -35>, 'PublicKeyProtocolError': <ErrorCode.PublicKeyProtocolError: -36>, 'SSHEAGAIN': <ErrorCode.SSHEAGAIN: -37>, 'BufferTooSmall': <ErrorCode.BufferTooSmall: -38>, 'BadOperationOrder': <ErrorCode.BadOperationOrder: -39>, 'CompressionError': <ErrorCode.CompressionError: -40>, 'PointerOverflow': <ErrorCode.PointerOverflow: -41>, 'SSHAgentProtocolError': <ErrorCode.SSHAgentProtocolError: -42>, 'SocketRecvError': <ErrorCode.SocketRecvError: -43>, 'DataEncryptError': <ErrorCode.DataEncryptError: -44>, 'InvalidSocketType': <ErrorCode.InvalidSocketType: -45>, 'HostFingerprintMismatch': <ErrorCode.HostFingerprintMismatch: -46>, 'ChannelWindowFull': <ErrorCode.ChannelWindowFull: -47>, 'PrivateKeyAuthFailed': <ErrorCode.PrivateKeyAuthFailed: -48>, 'RandomGenError': <ErrorCode.RandomGenError: -49>, 'MissingUserAuthBanner': <ErrorCode.MissingUserAuthBanner: -50>, 'AlgorithmUnsupported': <ErrorCode.AlgorithmUnsupported: -51>, 'MacAuthFailed': <ErrorCode.MacAuthFailed: -52>, 'HashInitError': <ErrorCode.HashInitError: -53>, 'HashCalculateError': <ErrorCode.HashCalculateError: -54>, 'EndOfFile': <ErrorCode.EndOfFile: 1>, 'FileNotExist': <ErrorCode.FileNotExist: 2>, 'PermissionDenied': <ErrorCode.PermissionDenied: 3>, 'CommonFailure': <ErrorCode.CommonFailure: 4>, 'BadMessageFormat': <ErrorCode.BadMessageFormat: 5>, 'NoConnection': <ErrorCode.NoConnection: 6>, 'ConnectionLost': <ErrorCode.ConnectionLost: 7>, 'OperationUnsupported': <ErrorCode.OperationUnsupported: 8>, 'InvalidHandle': <ErrorCode.InvalidHandle: 9>, 'PathNotExist': <ErrorCode.PathNotExist: 10>, 'FileAlreadyExists': <ErrorCode.FileAlreadyExists: 11>, 'FileWriteProtected': <ErrorCode.FileWriteProtected: 12>, 'StorageMediaUnavailable': <ErrorCode.StorageMediaUnavailable: 13>, 'FilesystemNoSpace': <ErrorCode.FilesystemNoSpace: 14>, 'SpaceQuotaExceed': <ErrorCode.SpaceQuotaExceed: 15>, 'UsernameNotExists': <ErrorCode.UsernameNotExists: 16>, 'PathUsingByOthers': <ErrorCode.PathUsingByOthers: 17>, 'DirNotEmpty': <ErrorCode.DirNotEmpty: 18>, 'NotADirectory': <ErrorCode.NotADirectory: 19>, 'InvalidFilename': <ErrorCode.InvalidFilename: 20>, 'SymlinkLoop': <ErrorCode.SymlinkLoop: 21>, 'UnknownError': <ErrorCode.UnknownError: 22>, 'SocketCreateError': <ErrorCode.SocketCreateError: 23>, 'SocketConnectTimeout': <ErrorCode.SocketConnectTimeout: 24>, 'SocketConnectFailed': <ErrorCode.SocketConnectFailed: 25>, 'SessionCreateFailed': <ErrorCode.SessionCreateFailed: 26>, 'SessionHandshakeFailed': <ErrorCode.SessionHandshakeFailed: 27>, 'NoSession': <ErrorCode.NoSession: 28>, 'NotAFile': <ErrorCode.NotAFile: 29>, 'ParentDirectoryNotExist': <ErrorCode.ParentDirectoryNotExist: 30>, 'InhostCopyFailed': <ErrorCode.InhostCopyFailed: 31>, 'LocalFileMapError': <ErrorCode.LocalFileMapError: 32>, 'UnexpectedEOF': <ErrorCode.UnexpectedEOF: 33>, 'Terminate': <ErrorCode.Terminate: 34>, 'UnImplentedMethod': <ErrorCode.UnImplentedMethod: 35>, 'NoPermissionAttribute': <ErrorCode.NoPermissionAttribute: 36>, 'LocalStatError': <ErrorCode.LocalStatError: 37>, 'TransferPause': <ErrorCode.TransferPause: 38>, 'DNSResolveError': <ErrorCode.DNSResolveError: 39>}
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
class Hostd:
    def __init__(self) -> None:
        ...
    def add_host(self, hostname: str, client: AMSFTPClient, overwrite: bool = False) -> None:
        ...
    def get_host(self, hostname: str) -> AMSFTPClient:
        ...
    def get_hosts(self) -> list[str]:
        ...
    def remove_host(self, hostname: str) -> None:
        ...
    def reset(self) -> None:
        ...
    def test_host(self, hostname: str) -> tuple[ErrorCode, str]:
        ...
class OS_TYPE:
    """
    Members:
    
      Windows
    
      Linux
    
      MacOS
    
      FreeBSD
    
      Unix
    
      Unknown
    
      Uncertain
    """
    FreeBSD: typing.ClassVar[OS_TYPE]  # value = <OS_TYPE.FreeBSD: 3>
    Linux: typing.ClassVar[OS_TYPE]  # value = <OS_TYPE.Linux: 1>
    MacOS: typing.ClassVar[OS_TYPE]  # value = <OS_TYPE.MacOS: 2>
    Uncertain: typing.ClassVar[OS_TYPE]  # value = <OS_TYPE.Uncertain: 0>
    Unix: typing.ClassVar[OS_TYPE]  # value = <OS_TYPE.Unix: 4>
    Unknown: typing.ClassVar[OS_TYPE]  # value = <OS_TYPE.Unknown: -2>
    Windows: typing.ClassVar[OS_TYPE]  # value = <OS_TYPE.Windows: -1>
    __members__: typing.ClassVar[dict[str, OS_TYPE]]  # value = {'Windows': <OS_TYPE.Windows: -1>, 'Linux': <OS_TYPE.Linux: 1>, 'MacOS': <OS_TYPE.MacOS: 2>, 'FreeBSD': <OS_TYPE.FreeBSD: 3>, 'Unix': <OS_TYPE.Unix: 4>, 'Unknown': <OS_TYPE.Unknown: -2>, 'Uncertain': <OS_TYPE.Uncertain: 0>}
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
class ProgressCBInfo:
    accumulated_size: int
    dst: str
    dst_host: str
    file_size: int
    src: str
    src_host: str
    this_size: int
    total_size: int
    def __init__(self, src: str, dst: str, src_host: str, dst_host: str, this_size: int, file_size: int, accumulated_size: int, total_size: int) -> None:
        ...
class TransferCallback:
    def __init__(self, total_size: typing.Any = None, error: typing.Any = None, progress: typing.Any = None) -> None:
        ...
class TransferControl:
    """
    Members:
    
      Pause
    
      Terminate
    """
    Pause: typing.ClassVar[TransferControl]  # value = <TransferControl.Pause: 0>
    Terminate: typing.ClassVar[TransferControl]  # value = <TransferControl.Terminate: 1>
    __members__: typing.ClassVar[dict[str, TransferControl]]  # value = {'Pause': <TransferControl.Pause: 0>, 'Terminate': <TransferControl.Terminate: 1>}
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
    dst_host: str
    path_type: AMFS.PathType
    size: int
    src: str
    src_host: str
    def __init__(self, src: str, src_host: str, dst: str, dst_host: str, size: int, path_type: AMFS.PathType = ...) -> None:
        ...
_cleanup: typing.Any  # value = <capsule object>
