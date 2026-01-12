"""
Enum Classes
"""
from __future__ import annotations
import typing
__all__ = ['ErrorCode', 'OS_TYPE', 'PathType', 'SearchType', 'TraceLevel', 'TransferControl']
class ErrorCode:
    """
    Uniform Error Code for the whole module
    
    Members:
    
      Success
    
      SessionCreateError : Negative code represent libssh2 session error
    
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
    
      EndOfFile : Positive code represent libssh2 sftp error
    
      FileNotExist
    
      PermissionDenied
    
      CommonFailure
    
      BadMessageFormat
    
      NoConnection
    
      ConnectionLost
    
      OperationUnsupported
    
      InvalidHandle
    
      PathNotExist
    
      PathAlreadyExists
    
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
    
      UnknownError : Code greater than 22 are AM Custom Error
    
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
    PathAlreadyExists: typing.ClassVar[ErrorCode]  # value = <ErrorCode.PathAlreadyExists: 11>
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
    __members__: typing.ClassVar[dict[str, ErrorCode]]  # value = {'Success': <ErrorCode.Success: 0>, 'SessionCreateError': <ErrorCode.SessionCreateError: -1>, 'NoBannerRecv': <ErrorCode.NoBannerRecv: -2>, 'BannerSendError': <ErrorCode.BannerSendError: -3>, 'InvalidMacAdress': <ErrorCode.InvalidMacAdress: -4>, 'KeyExchangeMethodNegotiationFailed': <ErrorCode.KeyExchangeMethodNegotiationFailed: -5>, 'MemAllocError': <ErrorCode.MemAllocError: -6>, 'SocketSendError': <ErrorCode.SocketSendError: -7>, 'KeyExchangeFailed': <ErrorCode.KeyExchangeFailed: -8>, 'OperationTimeout': <ErrorCode.OperationTimeout: -9>, 'HostkeyInitFailed': <ErrorCode.HostkeyInitFailed: -10>, 'HostkeySignFailed': <ErrorCode.HostkeySignFailed: -11>, 'DataDecryptError': <ErrorCode.DataDecryptError: -12>, 'SocketDisconnect': <ErrorCode.SocketDisconnect: -13>, 'SSHProtocolError': <ErrorCode.SSHProtocolError: -14>, 'PasswordExpired': <ErrorCode.PasswordExpired: -15>, 'LocalFileError': <ErrorCode.LocalFileError: -16>, 'NoAuthMethod': <ErrorCode.NoAuthMethod: -17>, 'AuthFailed': <ErrorCode.AuthFailed: -18>, 'PublickeyAuthFailed': <ErrorCode.PublickeyAuthFailed: -19>, 'ChannelOrderError': <ErrorCode.ChannelOrderError: -20>, 'ChannelOperationError': <ErrorCode.ChannelOperationError: -21>, 'ChannelRequestDenied': <ErrorCode.ChannelRequestDenied: -22>, 'ChannelWindowExceeded': <ErrorCode.ChannelWindowExceeded: -24>, 'ChannelPacketOversize': <ErrorCode.ChannelPacketOversize: -25>, 'ChannelClosed': <ErrorCode.ChannelClosed: -26>, 'ChannelAlreadySendEOF': <ErrorCode.ChannelAlreadySendEOF: -27>, 'SCPProtocolError': <ErrorCode.SCPProtocolError: -28>, 'ZlibCompressError': <ErrorCode.ZlibCompressError: -29>, 'SocketOperationTimeout': <ErrorCode.SocketOperationTimeout: -30>, 'SftpProtocolError': <ErrorCode.SftpProtocolError: -31>, 'RequestDenied': <ErrorCode.RequestDenied: -32>, 'InvalidArg': <ErrorCode.InvalidArg: -34>, 'InvalidPollType': <ErrorCode.InvalidPollType: -35>, 'PublicKeyProtocolError': <ErrorCode.PublicKeyProtocolError: -36>, 'SSHEAGAIN': <ErrorCode.SSHEAGAIN: -37>, 'BufferTooSmall': <ErrorCode.BufferTooSmall: -38>, 'BadOperationOrder': <ErrorCode.BadOperationOrder: -39>, 'CompressionError': <ErrorCode.CompressionError: -40>, 'PointerOverflow': <ErrorCode.PointerOverflow: -41>, 'SSHAgentProtocolError': <ErrorCode.SSHAgentProtocolError: -42>, 'SocketRecvError': <ErrorCode.SocketRecvError: -43>, 'DataEncryptError': <ErrorCode.DataEncryptError: -44>, 'InvalidSocketType': <ErrorCode.InvalidSocketType: -45>, 'HostFingerprintMismatch': <ErrorCode.HostFingerprintMismatch: -46>, 'ChannelWindowFull': <ErrorCode.ChannelWindowFull: -47>, 'PrivateKeyAuthFailed': <ErrorCode.PrivateKeyAuthFailed: -48>, 'RandomGenError': <ErrorCode.RandomGenError: -49>, 'MissingUserAuthBanner': <ErrorCode.MissingUserAuthBanner: -50>, 'AlgorithmUnsupported': <ErrorCode.AlgorithmUnsupported: -51>, 'MacAuthFailed': <ErrorCode.MacAuthFailed: -52>, 'HashInitError': <ErrorCode.HashInitError: -53>, 'HashCalculateError': <ErrorCode.HashCalculateError: -54>, 'EndOfFile': <ErrorCode.EndOfFile: 1>, 'FileNotExist': <ErrorCode.FileNotExist: 2>, 'PermissionDenied': <ErrorCode.PermissionDenied: 3>, 'CommonFailure': <ErrorCode.CommonFailure: 4>, 'BadMessageFormat': <ErrorCode.BadMessageFormat: 5>, 'NoConnection': <ErrorCode.NoConnection: 6>, 'ConnectionLost': <ErrorCode.ConnectionLost: 7>, 'OperationUnsupported': <ErrorCode.OperationUnsupported: 8>, 'InvalidHandle': <ErrorCode.InvalidHandle: 9>, 'PathNotExist': <ErrorCode.PathNotExist: 10>, 'PathAlreadyExists': <ErrorCode.PathAlreadyExists: 11>, 'FileWriteProtected': <ErrorCode.FileWriteProtected: 12>, 'StorageMediaUnavailable': <ErrorCode.StorageMediaUnavailable: 13>, 'FilesystemNoSpace': <ErrorCode.FilesystemNoSpace: 14>, 'SpaceQuotaExceed': <ErrorCode.SpaceQuotaExceed: 15>, 'UsernameNotExists': <ErrorCode.UsernameNotExists: 16>, 'PathUsingByOthers': <ErrorCode.PathUsingByOthers: 17>, 'DirNotEmpty': <ErrorCode.DirNotEmpty: 18>, 'NotADirectory': <ErrorCode.NotADirectory: 19>, 'InvalidFilename': <ErrorCode.InvalidFilename: 20>, 'SymlinkLoop': <ErrorCode.SymlinkLoop: 21>, 'UnknownError': <ErrorCode.UnknownError: 22>, 'SocketCreateError': <ErrorCode.SocketCreateError: 23>, 'SocketConnectTimeout': <ErrorCode.SocketConnectTimeout: 24>, 'SocketConnectFailed': <ErrorCode.SocketConnectFailed: 25>, 'SessionCreateFailed': <ErrorCode.SessionCreateFailed: 26>, 'SessionHandshakeFailed': <ErrorCode.SessionHandshakeFailed: 27>, 'NoSession': <ErrorCode.NoSession: 28>, 'NotAFile': <ErrorCode.NotAFile: 29>, 'ParentDirectoryNotExist': <ErrorCode.ParentDirectoryNotExist: 30>, 'InhostCopyFailed': <ErrorCode.InhostCopyFailed: 31>, 'LocalFileMapError': <ErrorCode.LocalFileMapError: 32>, 'UnexpectedEOF': <ErrorCode.UnexpectedEOF: 33>, 'Terminate': <ErrorCode.Terminate: 34>, 'UnImplentedMethod': <ErrorCode.UnImplentedMethod: 35>, 'NoPermissionAttribute': <ErrorCode.NoPermissionAttribute: 36>, 'LocalStatError': <ErrorCode.LocalStatError: 37>, 'TransferPause': <ErrorCode.TransferPause: 38>, 'DNSResolveError': <ErrorCode.DNSResolveError: 39>}
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
class OS_TYPE:
    """
    System OS Type Enum
    
    Members:
    
      Windows
    
      Linux
    
      MacOS
    
      FreeBSD
    
      Unix
    
      Unknown
    
      Uncertain : Set when get OS type failed
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
class PathType:
    """
    Members:
    
      DIR
    
      FILE
    
      SYMLINK
    
      BLOCK_DEVICE
    
      CHARACTER_DEVICE
    
      SOCKET
    
      FIFO
    
      UNKNOWN
    """
    BLOCK_DEVICE: typing.ClassVar[PathType]  # value = <PathType.BLOCK_DEVICE: -1>
    CHARACTER_DEVICE: typing.ClassVar[PathType]  # value = <PathType.CHARACTER_DEVICE: -2>
    DIR: typing.ClassVar[PathType]  # value = <PathType.DIR: 0>
    FIFO: typing.ClassVar[PathType]  # value = <PathType.FIFO: -4>
    FILE: typing.ClassVar[PathType]  # value = <PathType.FILE: 1>
    SOCKET: typing.ClassVar[PathType]  # value = <PathType.SOCKET: -3>
    SYMLINK: typing.ClassVar[PathType]  # value = <PathType.SYMLINK: 2>
    UNKNOWN: typing.ClassVar[PathType]  # value = <PathType.UNKNOWN: -5>
    __members__: typing.ClassVar[dict[str, PathType]]  # value = {'DIR': <PathType.DIR: 0>, 'FILE': <PathType.FILE: 1>, 'SYMLINK': <PathType.SYMLINK: 2>, 'BLOCK_DEVICE': <PathType.BLOCK_DEVICE: -1>, 'CHARACTER_DEVICE': <PathType.CHARACTER_DEVICE: -2>, 'SOCKET': <PathType.SOCKET: -3>, 'FIFO': <PathType.FIFO: -4>, 'UNKNOWN': <PathType.UNKNOWN: -5>}
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
class SearchType:
    """
    Search Type Enum
    
    Members:
    
      All
    
      File
    
      Directory
    """
    All: typing.ClassVar[SearchType]  # value = <SearchType.All: 0>
    Directory: typing.ClassVar[SearchType]  # value = <SearchType.Directory: 2>
    File: typing.ClassVar[SearchType]  # value = <SearchType.File: 1>
    __members__: typing.ClassVar[dict[str, SearchType]]  # value = {'All': <SearchType.All: 0>, 'File': <SearchType.File: 1>, 'Directory': <SearchType.Directory: 2>}
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
class TraceLevel:
    """
    Members:
    
      Info
    
      Debug
    
      Warning
    
      Error
    
      Critical
    """
    Critical: typing.ClassVar[TraceLevel]  # value = <TraceLevel.Critical: -2>
    Debug: typing.ClassVar[TraceLevel]  # value = <TraceLevel.Debug: 2>
    Error: typing.ClassVar[TraceLevel]  # value = <TraceLevel.Error: -1>
    Info: typing.ClassVar[TraceLevel]  # value = <TraceLevel.Info: 1>
    Warning: typing.ClassVar[TraceLevel]  # value = <TraceLevel.Warning: 0>
    __members__: typing.ClassVar[dict[str, TraceLevel]]  # value = {'Info': <TraceLevel.Info: 1>, 'Debug': <TraceLevel.Debug: 2>, 'Warning': <TraceLevel.Warning: 0>, 'Error': <TraceLevel.Error: -1>, 'Critical': <TraceLevel.Critical: -2>}
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
class TransferControl:
    """
    Using in progress callback to control the transfer task
    
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
