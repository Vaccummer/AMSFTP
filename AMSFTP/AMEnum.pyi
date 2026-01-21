"""
Enum Classes
"""
from __future__ import annotations
import typing
__all__ = ['ClientProtocol', 'ErrorCode', 'OS_TYPE', 'PathType', 'SearchType', 'SepType', 'TraceLevel', 'TransferControl']
class ClientProtocol:
    """
    
    
    Members:
    
      Unknown
    
      Base
    
      SFTP
    
      FTP
    
      LOCAL
    """
    Base: typing.ClassVar[ClientProtocol]  # value = <ClientProtocol.Base: 0>
    FTP: typing.ClassVar[ClientProtocol]  # value = <ClientProtocol.FTP: 2>
    LOCAL: typing.ClassVar[ClientProtocol]  # value = <ClientProtocol.LOCAL: 3>
    SFTP: typing.ClassVar[ClientProtocol]  # value = <ClientProtocol.SFTP: 1>
    Unknown: typing.ClassVar[ClientProtocol]  # value = <ClientProtocol.Unknown: -1>
    __members__: typing.ClassVar[dict[str, ClientProtocol]]  # value = {'Unknown': <ClientProtocol.Unknown: -1>, 'Base': <ClientProtocol.Base: 0>, 'SFTP': <ClientProtocol.SFTP: 1>, 'FTP': <ClientProtocol.FTP: 2>, 'LOCAL': <ClientProtocol.LOCAL: 3>}
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
class ErrorCode:
    """
    
    
    Members:
    
      HashCalculateError
    
      HashInitError
    
      MacAuthFailed
    
      AlgorithmUnsupported
    
      MissingUserAuthBanner
    
      RandomGenError
    
      PrivateKeyAuthFailed
    
      ChannelWindowFull
    
      HostFingerprintMismatch
    
      InvalidSocketType
    
      DataEncryptError
    
      SocketRecvError
    
      SSHAgentProtocolError
    
      PointerOverflow
    
      CompressionError
    
      BadOperationOrder
    
      BufferTooSmall
    
      SSHEAGAIN
    
      PublicKeyProtocolError
    
      InvalidPollType
    
      InvalidArg
    
      RequestDenied
    
      SftpProtocolError
    
      SocketOperationTimeout
    
      ZlibCompressError
    
      SCPProtocolError
    
      ChannelAlreadySendEOF
    
      ChannelClosed
    
      ChannelPacketOversize
    
      ChannelWindowExceeded
    
      ChannelRequestDenied
    
      ChannelOperationError
    
      ChannelOrderError
    
      PublickeyAuthFailed
    
      AuthFailed
    
      NoAuthMethod
    
      LocalFileError
    
      PasswordExpired
    
      SSHProtocolError
    
      SocketDisconnect
    
      DataDecryptError
    
      HostkeySignFailed
    
      HostkeyInitFailed
    
      OperationTimeout
    
      KeyExchangeFailed
    
      SocketSendError
    
      MemAllocError
    
      KeyExchangeMethodNegotiationFailed
    
      InvalidMacAdress
    
      BannerSendError
    
      NoBannerRecv
    
      SessionGenericError
    
      Success
    
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
    
      LocalFileOpenError
    
      LocalFileReadError
    
      LocalFileWriteError
    
      UnexpectedEOF
    
      Terminate
    
      UnImplentedMethod
    
      NoPermissionAttribute
    
      LocalStatError
    
      TransferPause
    
      DNSResolveError
    
      ClientNotFound
    
      ConnectionAlreadyExists
    
      DeepcopyFunctionNotAvailable
    
      KeyAlreadyExists
    
      DeepcopyFailed
    
      FTPConnectFailed
    
      FTPMkdirFailed
    
      FTPRenameFailed
    
      FTPUploadFailed
    
      FTPDownloadFailed
    
      FTPListFailed
    
      BufferWriteError
    
      BufferReadError
    
      PyCBError
    
      IllegealURLFormat
    
      NetworkError
    
      FTPSendError
    
      FTPRecvError
    
      IllegealSeverReply
    
      FTPReadError
    """
    AlgorithmUnsupported: typing.ClassVar[ErrorCode]  # value = <ErrorCode.AlgorithmUnsupported: -51>
    AuthFailed: typing.ClassVar[ErrorCode]  # value = <ErrorCode.AuthFailed: -18>
    BadMessageFormat: typing.ClassVar[ErrorCode]  # value = <ErrorCode.BadMessageFormat: 5>
    BadOperationOrder: typing.ClassVar[ErrorCode]  # value = <ErrorCode.BadOperationOrder: -39>
    BannerSendError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.BannerSendError: -3>
    BufferReadError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.BufferReadError: 71>
    BufferTooSmall: typing.ClassVar[ErrorCode]  # value = <ErrorCode.BufferTooSmall: -38>
    BufferWriteError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.BufferWriteError: 70>
    ChannelAlreadySendEOF: typing.ClassVar[ErrorCode]  # value = <ErrorCode.ChannelAlreadySendEOF: -27>
    ChannelClosed: typing.ClassVar[ErrorCode]  # value = <ErrorCode.ChannelClosed: -26>
    ChannelOperationError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.ChannelOperationError: -21>
    ChannelOrderError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.ChannelOrderError: -20>
    ChannelPacketOversize: typing.ClassVar[ErrorCode]  # value = <ErrorCode.ChannelPacketOversize: -25>
    ChannelRequestDenied: typing.ClassVar[ErrorCode]  # value = <ErrorCode.ChannelRequestDenied: -22>
    ChannelWindowExceeded: typing.ClassVar[ErrorCode]  # value = <ErrorCode.ChannelWindowExceeded: -24>
    ChannelWindowFull: typing.ClassVar[ErrorCode]  # value = <ErrorCode.ChannelWindowFull: -47>
    ClientNotFound: typing.ClassVar[ErrorCode]  # value = <ErrorCode.ClientNotFound: 43>
    CommonFailure: typing.ClassVar[ErrorCode]  # value = <ErrorCode.CommonFailure: 4>
    CompressionError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.CompressionError: -40>
    ConnectionAlreadyExists: typing.ClassVar[ErrorCode]  # value = <ErrorCode.ConnectionAlreadyExists: 44>
    ConnectionLost: typing.ClassVar[ErrorCode]  # value = <ErrorCode.ConnectionLost: 7>
    DNSResolveError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.DNSResolveError: 42>
    DataDecryptError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.DataDecryptError: -12>
    DataEncryptError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.DataEncryptError: -44>
    DeepcopyFailed: typing.ClassVar[ErrorCode]  # value = <ErrorCode.DeepcopyFailed: 47>
    DeepcopyFunctionNotAvailable: typing.ClassVar[ErrorCode]  # value = <ErrorCode.DeepcopyFunctionNotAvailable: 45>
    DirNotEmpty: typing.ClassVar[ErrorCode]  # value = <ErrorCode.DirNotEmpty: 18>
    EndOfFile: typing.ClassVar[ErrorCode]  # value = <ErrorCode.EndOfFile: 1>
    FTPConnectFailed: typing.ClassVar[ErrorCode]  # value = <ErrorCode.FTPConnectFailed: 48>
    FTPDownloadFailed: typing.ClassVar[ErrorCode]  # value = <ErrorCode.FTPDownloadFailed: 52>
    FTPListFailed: typing.ClassVar[ErrorCode]  # value = <ErrorCode.FTPListFailed: 53>
    FTPMkdirFailed: typing.ClassVar[ErrorCode]  # value = <ErrorCode.FTPMkdirFailed: 49>
    FTPReadError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.FTPReadError: 96>
    FTPRecvError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.FTPRecvError: 92>
    FTPRenameFailed: typing.ClassVar[ErrorCode]  # value = <ErrorCode.FTPRenameFailed: 50>
    FTPSendError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.FTPSendError: 91>
    FTPUploadFailed: typing.ClassVar[ErrorCode]  # value = <ErrorCode.FTPUploadFailed: 51>
    FileNotExist: typing.ClassVar[ErrorCode]  # value = <ErrorCode.FileNotExist: 2>
    FileWriteProtected: typing.ClassVar[ErrorCode]  # value = <ErrorCode.FileWriteProtected: 12>
    FilesystemNoSpace: typing.ClassVar[ErrorCode]  # value = <ErrorCode.FilesystemNoSpace: 14>
    HashCalculateError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.HashCalculateError: -54>
    HashInitError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.HashInitError: -53>
    HostFingerprintMismatch: typing.ClassVar[ErrorCode]  # value = <ErrorCode.HostFingerprintMismatch: -46>
    HostkeyInitFailed: typing.ClassVar[ErrorCode]  # value = <ErrorCode.HostkeyInitFailed: -10>
    HostkeySignFailed: typing.ClassVar[ErrorCode]  # value = <ErrorCode.HostkeySignFailed: -11>
    IllegealSeverReply: typing.ClassVar[ErrorCode]  # value = <ErrorCode.IllegealSeverReply: 93>
    IllegealURLFormat: typing.ClassVar[ErrorCode]  # value = <ErrorCode.IllegealURLFormat: 81>
    InhostCopyFailed: typing.ClassVar[ErrorCode]  # value = <ErrorCode.InhostCopyFailed: 31>
    InvalidArg: typing.ClassVar[ErrorCode]  # value = <ErrorCode.InvalidArg: -34>
    InvalidFilename: typing.ClassVar[ErrorCode]  # value = <ErrorCode.InvalidFilename: 20>
    InvalidHandle: typing.ClassVar[ErrorCode]  # value = <ErrorCode.InvalidHandle: 9>
    InvalidMacAdress: typing.ClassVar[ErrorCode]  # value = <ErrorCode.InvalidMacAdress: -4>
    InvalidPollType: typing.ClassVar[ErrorCode]  # value = <ErrorCode.InvalidPollType: -35>
    InvalidSocketType: typing.ClassVar[ErrorCode]  # value = <ErrorCode.InvalidSocketType: -45>
    KeyAlreadyExists: typing.ClassVar[ErrorCode]  # value = <ErrorCode.KeyAlreadyExists: 46>
    KeyExchangeFailed: typing.ClassVar[ErrorCode]  # value = <ErrorCode.KeyExchangeFailed: -8>
    KeyExchangeMethodNegotiationFailed: typing.ClassVar[ErrorCode]  # value = <ErrorCode.KeyExchangeMethodNegotiationFailed: -5>
    LocalFileError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.LocalFileError: -16>
    LocalFileMapError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.LocalFileMapError: 32>
    LocalFileOpenError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.LocalFileOpenError: 33>
    LocalFileReadError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.LocalFileReadError: 34>
    LocalFileWriteError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.LocalFileWriteError: 35>
    LocalStatError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.LocalStatError: 40>
    MacAuthFailed: typing.ClassVar[ErrorCode]  # value = <ErrorCode.MacAuthFailed: -52>
    MemAllocError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.MemAllocError: -6>
    MissingUserAuthBanner: typing.ClassVar[ErrorCode]  # value = <ErrorCode.MissingUserAuthBanner: -50>
    NetworkError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.NetworkError: 82>
    NoAuthMethod: typing.ClassVar[ErrorCode]  # value = <ErrorCode.NoAuthMethod: -17>
    NoBannerRecv: typing.ClassVar[ErrorCode]  # value = <ErrorCode.NoBannerRecv: -2>
    NoConnection: typing.ClassVar[ErrorCode]  # value = <ErrorCode.NoConnection: 6>
    NoPermissionAttribute: typing.ClassVar[ErrorCode]  # value = <ErrorCode.NoPermissionAttribute: 39>
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
    PyCBError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.PyCBError: 72>
    RandomGenError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.RandomGenError: -49>
    RequestDenied: typing.ClassVar[ErrorCode]  # value = <ErrorCode.RequestDenied: -32>
    SCPProtocolError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.SCPProtocolError: -28>
    SSHAgentProtocolError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.SSHAgentProtocolError: -42>
    SSHEAGAIN: typing.ClassVar[ErrorCode]  # value = <ErrorCode.SSHEAGAIN: -37>
    SSHProtocolError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.SSHProtocolError: -14>
    SessionCreateFailed: typing.ClassVar[ErrorCode]  # value = <ErrorCode.SessionCreateFailed: 26>
    SessionGenericError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.SessionGenericError: -1>
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
    Terminate: typing.ClassVar[ErrorCode]  # value = <ErrorCode.Terminate: 37>
    TransferPause: typing.ClassVar[ErrorCode]  # value = <ErrorCode.TransferPause: 41>
    UnImplentedMethod: typing.ClassVar[ErrorCode]  # value = <ErrorCode.UnImplentedMethod: 38>
    UnexpectedEOF: typing.ClassVar[ErrorCode]  # value = <ErrorCode.UnexpectedEOF: 36>
    UnknownError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.UnknownError: 22>
    UsernameNotExists: typing.ClassVar[ErrorCode]  # value = <ErrorCode.UsernameNotExists: 16>
    ZlibCompressError: typing.ClassVar[ErrorCode]  # value = <ErrorCode.ZlibCompressError: -29>
    __members__: typing.ClassVar[dict[str, ErrorCode]]  # value = {'HashCalculateError': <ErrorCode.HashCalculateError: -54>, 'HashInitError': <ErrorCode.HashInitError: -53>, 'MacAuthFailed': <ErrorCode.MacAuthFailed: -52>, 'AlgorithmUnsupported': <ErrorCode.AlgorithmUnsupported: -51>, 'MissingUserAuthBanner': <ErrorCode.MissingUserAuthBanner: -50>, 'RandomGenError': <ErrorCode.RandomGenError: -49>, 'PrivateKeyAuthFailed': <ErrorCode.PrivateKeyAuthFailed: -48>, 'ChannelWindowFull': <ErrorCode.ChannelWindowFull: -47>, 'HostFingerprintMismatch': <ErrorCode.HostFingerprintMismatch: -46>, 'InvalidSocketType': <ErrorCode.InvalidSocketType: -45>, 'DataEncryptError': <ErrorCode.DataEncryptError: -44>, 'SocketRecvError': <ErrorCode.SocketRecvError: -43>, 'SSHAgentProtocolError': <ErrorCode.SSHAgentProtocolError: -42>, 'PointerOverflow': <ErrorCode.PointerOverflow: -41>, 'CompressionError': <ErrorCode.CompressionError: -40>, 'BadOperationOrder': <ErrorCode.BadOperationOrder: -39>, 'BufferTooSmall': <ErrorCode.BufferTooSmall: -38>, 'SSHEAGAIN': <ErrorCode.SSHEAGAIN: -37>, 'PublicKeyProtocolError': <ErrorCode.PublicKeyProtocolError: -36>, 'InvalidPollType': <ErrorCode.InvalidPollType: -35>, 'InvalidArg': <ErrorCode.InvalidArg: -34>, 'RequestDenied': <ErrorCode.RequestDenied: -32>, 'SftpProtocolError': <ErrorCode.SftpProtocolError: -31>, 'SocketOperationTimeout': <ErrorCode.SocketOperationTimeout: -30>, 'ZlibCompressError': <ErrorCode.ZlibCompressError: -29>, 'SCPProtocolError': <ErrorCode.SCPProtocolError: -28>, 'ChannelAlreadySendEOF': <ErrorCode.ChannelAlreadySendEOF: -27>, 'ChannelClosed': <ErrorCode.ChannelClosed: -26>, 'ChannelPacketOversize': <ErrorCode.ChannelPacketOversize: -25>, 'ChannelWindowExceeded': <ErrorCode.ChannelWindowExceeded: -24>, 'ChannelRequestDenied': <ErrorCode.ChannelRequestDenied: -22>, 'ChannelOperationError': <ErrorCode.ChannelOperationError: -21>, 'ChannelOrderError': <ErrorCode.ChannelOrderError: -20>, 'PublickeyAuthFailed': <ErrorCode.PublickeyAuthFailed: -19>, 'AuthFailed': <ErrorCode.AuthFailed: -18>, 'NoAuthMethod': <ErrorCode.NoAuthMethod: -17>, 'LocalFileError': <ErrorCode.LocalFileError: -16>, 'PasswordExpired': <ErrorCode.PasswordExpired: -15>, 'SSHProtocolError': <ErrorCode.SSHProtocolError: -14>, 'SocketDisconnect': <ErrorCode.SocketDisconnect: -13>, 'DataDecryptError': <ErrorCode.DataDecryptError: -12>, 'HostkeySignFailed': <ErrorCode.HostkeySignFailed: -11>, 'HostkeyInitFailed': <ErrorCode.HostkeyInitFailed: -10>, 'OperationTimeout': <ErrorCode.OperationTimeout: -9>, 'KeyExchangeFailed': <ErrorCode.KeyExchangeFailed: -8>, 'SocketSendError': <ErrorCode.SocketSendError: -7>, 'MemAllocError': <ErrorCode.MemAllocError: -6>, 'KeyExchangeMethodNegotiationFailed': <ErrorCode.KeyExchangeMethodNegotiationFailed: -5>, 'InvalidMacAdress': <ErrorCode.InvalidMacAdress: -4>, 'BannerSendError': <ErrorCode.BannerSendError: -3>, 'NoBannerRecv': <ErrorCode.NoBannerRecv: -2>, 'SessionGenericError': <ErrorCode.SessionGenericError: -1>, 'Success': <ErrorCode.Success: 0>, 'EndOfFile': <ErrorCode.EndOfFile: 1>, 'FileNotExist': <ErrorCode.FileNotExist: 2>, 'PermissionDenied': <ErrorCode.PermissionDenied: 3>, 'CommonFailure': <ErrorCode.CommonFailure: 4>, 'BadMessageFormat': <ErrorCode.BadMessageFormat: 5>, 'NoConnection': <ErrorCode.NoConnection: 6>, 'ConnectionLost': <ErrorCode.ConnectionLost: 7>, 'OperationUnsupported': <ErrorCode.OperationUnsupported: 8>, 'InvalidHandle': <ErrorCode.InvalidHandle: 9>, 'PathNotExist': <ErrorCode.PathNotExist: 10>, 'PathAlreadyExists': <ErrorCode.PathAlreadyExists: 11>, 'FileWriteProtected': <ErrorCode.FileWriteProtected: 12>, 'StorageMediaUnavailable': <ErrorCode.StorageMediaUnavailable: 13>, 'FilesystemNoSpace': <ErrorCode.FilesystemNoSpace: 14>, 'SpaceQuotaExceed': <ErrorCode.SpaceQuotaExceed: 15>, 'UsernameNotExists': <ErrorCode.UsernameNotExists: 16>, 'PathUsingByOthers': <ErrorCode.PathUsingByOthers: 17>, 'DirNotEmpty': <ErrorCode.DirNotEmpty: 18>, 'NotADirectory': <ErrorCode.NotADirectory: 19>, 'InvalidFilename': <ErrorCode.InvalidFilename: 20>, 'SymlinkLoop': <ErrorCode.SymlinkLoop: 21>, 'UnknownError': <ErrorCode.UnknownError: 22>, 'SocketCreateError': <ErrorCode.SocketCreateError: 23>, 'SocketConnectTimeout': <ErrorCode.SocketConnectTimeout: 24>, 'SocketConnectFailed': <ErrorCode.SocketConnectFailed: 25>, 'SessionCreateFailed': <ErrorCode.SessionCreateFailed: 26>, 'SessionHandshakeFailed': <ErrorCode.SessionHandshakeFailed: 27>, 'NoSession': <ErrorCode.NoSession: 28>, 'NotAFile': <ErrorCode.NotAFile: 29>, 'ParentDirectoryNotExist': <ErrorCode.ParentDirectoryNotExist: 30>, 'InhostCopyFailed': <ErrorCode.InhostCopyFailed: 31>, 'LocalFileMapError': <ErrorCode.LocalFileMapError: 32>, 'LocalFileOpenError': <ErrorCode.LocalFileOpenError: 33>, 'LocalFileReadError': <ErrorCode.LocalFileReadError: 34>, 'LocalFileWriteError': <ErrorCode.LocalFileWriteError: 35>, 'UnexpectedEOF': <ErrorCode.UnexpectedEOF: 36>, 'Terminate': <ErrorCode.Terminate: 37>, 'UnImplentedMethod': <ErrorCode.UnImplentedMethod: 38>, 'NoPermissionAttribute': <ErrorCode.NoPermissionAttribute: 39>, 'LocalStatError': <ErrorCode.LocalStatError: 40>, 'TransferPause': <ErrorCode.TransferPause: 41>, 'DNSResolveError': <ErrorCode.DNSResolveError: 42>, 'ClientNotFound': <ErrorCode.ClientNotFound: 43>, 'ConnectionAlreadyExists': <ErrorCode.ConnectionAlreadyExists: 44>, 'DeepcopyFunctionNotAvailable': <ErrorCode.DeepcopyFunctionNotAvailable: 45>, 'KeyAlreadyExists': <ErrorCode.KeyAlreadyExists: 46>, 'DeepcopyFailed': <ErrorCode.DeepcopyFailed: 47>, 'FTPConnectFailed': <ErrorCode.FTPConnectFailed: 48>, 'FTPMkdirFailed': <ErrorCode.FTPMkdirFailed: 49>, 'FTPRenameFailed': <ErrorCode.FTPRenameFailed: 50>, 'FTPUploadFailed': <ErrorCode.FTPUploadFailed: 51>, 'FTPDownloadFailed': <ErrorCode.FTPDownloadFailed: 52>, 'FTPListFailed': <ErrorCode.FTPListFailed: 53>, 'BufferWriteError': <ErrorCode.BufferWriteError: 70>, 'BufferReadError': <ErrorCode.BufferReadError: 71>, 'PyCBError': <ErrorCode.PyCBError: 72>, 'IllegealURLFormat': <ErrorCode.IllegealURLFormat: 81>, 'NetworkError': <ErrorCode.NetworkError: 82>, 'FTPSendError': <ErrorCode.FTPSendError: 91>, 'FTPRecvError': <ErrorCode.FTPRecvError: 92>, 'IllegealSeverReply': <ErrorCode.IllegealSeverReply: 93>, 'FTPReadError': <ErrorCode.FTPReadError: 96>}
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
    
    
    Members:
    
      Unknown
    
      Windows
    
      Uncertain
    
      Linux
    
      MacOS
    
      FreeBSD
    
      Unix
    """
    FreeBSD: typing.ClassVar[OS_TYPE]  # value = <OS_TYPE.FreeBSD: 3>
    Linux: typing.ClassVar[OS_TYPE]  # value = <OS_TYPE.Linux: 1>
    MacOS: typing.ClassVar[OS_TYPE]  # value = <OS_TYPE.MacOS: 2>
    Uncertain: typing.ClassVar[OS_TYPE]  # value = <OS_TYPE.Uncertain: 0>
    Unix: typing.ClassVar[OS_TYPE]  # value = <OS_TYPE.Unix: 4>
    Unknown: typing.ClassVar[OS_TYPE]  # value = <OS_TYPE.Unknown: -2>
    Windows: typing.ClassVar[OS_TYPE]  # value = <OS_TYPE.Windows: -1>
    __members__: typing.ClassVar[dict[str, OS_TYPE]]  # value = {'Unknown': <OS_TYPE.Unknown: -2>, 'Windows': <OS_TYPE.Windows: -1>, 'Uncertain': <OS_TYPE.Uncertain: 0>, 'Linux': <OS_TYPE.Linux: 1>, 'MacOS': <OS_TYPE.MacOS: 2>, 'FreeBSD': <OS_TYPE.FreeBSD: 3>, 'Unix': <OS_TYPE.Unix: 4>}
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
    
      Unknown
    
      FIFO
    
      Socket
    
      CharacterDevice
    
      BlockDevice
    
      DIR
    
      FILE
    
      SYMLINK
    """
    BlockDevice: typing.ClassVar[PathType]  # value = <PathType.BlockDevice: -1>
    CharacterDevice: typing.ClassVar[PathType]  # value = <PathType.CharacterDevice: -2>
    DIR: typing.ClassVar[PathType]  # value = <PathType.DIR: 0>
    FIFO: typing.ClassVar[PathType]  # value = <PathType.FIFO: -4>
    FILE: typing.ClassVar[PathType]  # value = <PathType.FILE: 1>
    SYMLINK: typing.ClassVar[PathType]  # value = <PathType.SYMLINK: 2>
    Socket: typing.ClassVar[PathType]  # value = <PathType.Socket: -3>
    Unknown: typing.ClassVar[PathType]  # value = <PathType.Unknown: -5>
    __members__: typing.ClassVar[dict[str, PathType]]  # value = {'Unknown': <PathType.Unknown: -5>, 'FIFO': <PathType.FIFO: -4>, 'Socket': <PathType.Socket: -3>, 'CharacterDevice': <PathType.CharacterDevice: -2>, 'BlockDevice': <PathType.BlockDevice: -1>, 'DIR': <PathType.DIR: 0>, 'FILE': <PathType.FILE: 1>, 'SYMLINK': <PathType.SYMLINK: 2>}
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
class SepType:
    """
    
    
    Members:
    
      Unix
    
      Windows
    """
    Unix: typing.ClassVar[SepType]  # value = <SepType.Unix: 0>
    Windows: typing.ClassVar[SepType]  # value = <SepType.Windows: 1>
    __members__: typing.ClassVar[dict[str, SepType]]  # value = {'Unix': <SepType.Unix: 0>, 'Windows': <SepType.Windows: 1>}
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
    
      Critical
    
      Error
    
      Warning
    
      Info
    
      Debug
    """
    Critical: typing.ClassVar[TraceLevel]  # value = <TraceLevel.Critical: -2>
    Debug: typing.ClassVar[TraceLevel]  # value = <TraceLevel.Debug: 2>
    Error: typing.ClassVar[TraceLevel]  # value = <TraceLevel.Error: -1>
    Info: typing.ClassVar[TraceLevel]  # value = <TraceLevel.Info: 1>
    Warning: typing.ClassVar[TraceLevel]  # value = <TraceLevel.Warning: 0>
    __members__: typing.ClassVar[dict[str, TraceLevel]]  # value = {'Critical': <TraceLevel.Critical: -2>, 'Error': <TraceLevel.Error: -1>, 'Warning': <TraceLevel.Warning: 0>, 'Info': <TraceLevel.Info: 1>, 'Debug': <TraceLevel.Debug: 2>}
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
    
    
    Members:
    
      Terminate
    
      Pause
    
      Running
    """
    Pause: typing.ClassVar[TransferControl]  # value = <TransferControl.Pause: 0>
    Running: typing.ClassVar[TransferControl]  # value = <TransferControl.Running: 1>
    Terminate: typing.ClassVar[TransferControl]  # value = <TransferControl.Terminate: -1>
    __members__: typing.ClassVar[dict[str, TransferControl]]  # value = {'Terminate': <TransferControl.Terminate: -1>, 'Pause': <TransferControl.Pause: 0>, 'Running': <TransferControl.Running: 1>}
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
