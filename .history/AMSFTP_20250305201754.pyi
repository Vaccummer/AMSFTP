from typing import Callable, Literal
from enum import Enum
from dataclasses import dataclass


class TransferErrorCode(Enum):
    Success = 0,
    PassCheck = 1,
    FailedCheck = 2,
    SessionCreateError = -1,
    SftpCreateError = -2,
    SessionEstablishError = -3,
    SftpEstablishError = -4,
    ConnectionAuthorizeError = -5,
    LocalFileMapError = -6,
    RemoteFileOpenError = -7,
    RemoteFileStatError = -8,
    LocalFileCreateError = -9,
    LocalFileAllocError = -10,
    NetworkError = -11,
    NetworkDisconnect = -12,
    NetworkTimeout = -13,
    LocalFileFlushError = -14,
    SegmentationFault = -15,
    SessionBroken = -16,
    SftpBroken = -17,
    ChannelCreateError = -18,
    ConnectionCheckFailed = -19,
    RemoteFileWriteError = -20,
    RemoteFileReadError = -21,
    Terminate = -22,
    LocalFileExists = -23,
    RemoteFileExists = -24,
    PathNotExist = -25,
    PermissionDenied = -26,
    RemotePathOpenError = -27,
    NotDirectory = -28,
    ParentDirectoryNotExist = -29,
    TargetNotAFile = -30,
    RemoteFileDeleteError = -31,
    RemoteDirDeleteError = -32,
    UnknownError = -33,
    DirNotEmpty = -34,
    EmptyDirRemoveError = -35,
    TargetNotADirectory = -36,
    InvalidTrashDir = -37,
    MoveError = -38,
    TargetExists = -39,
    CopyError = -40,
    EndOfFile = -41,
    EAgain = -42,
    SocketNone = -43,
    SocketSend = -44,
    SocketTimeout = -45,
    SocketRecv = -46,
    SocketAccept = -47,
    WriteProtected = -48,
    UnenoughSpace = -49,
    UserSpaceQuotaExceeded = -50,
    BannerRecvError = -51,
    BannerSendError = -52,
    SocketSendError = -53,
    SocketDisconnect = -54,
    AuthFailed = -55,
    PublicKeyAuthFailed = -56,
    PasswordExpired = -57,
    KeyfileAuthFailed = -58,
    ChannelFailure = -59,
    ChannelWindowFull = -60,
    ChannelWindowExceeded = -61,
    MACAuthFailed = -62,
    KexFailure = -63,
    AlgoUnsupported = -64,
    MemoryAllocError = -65,
    FileOperationError = -66,
    ScpProtocolError = -67,
    SftpProtocolError = -68,
    KnownHostAuthFailed = -69,
    InvalidParameter = -70,
    NoSFTPConnection = -71,
    SFTPConnectionLost = -72,
    SFTPBadMessage = -73,
    InvalidHandle = -74,
    SFTPLockConflict = -75,
    SymlinkLoop = -76,
    InvalidFilename = -77,
    UnsupportedSFTPOperation = -78,
    MediaUnavailable = -79,
    SftpNotInitialized = -80,
    SessionNotInitialized = -81,
    DirAlreadyExists = -82

class TarSystemType(Enum):
    Unix = 0,
    Windows = 1,

class PathType(Enum):
    DIR = 0,
    FILE = 1

class TransferType(Enum):
    RemoteToLocal = -1,
    LocalToRemote = 1,
    RemoteToRemote = 0,

@dataclass
class ConRequst:
    hostname: str
    username: str
    password: str
    port: int
    tar_system: TarSystemType
    compression: bool


@dataclass
class TransferSet:
    transfer_type: TransferType
    force_write: bool

@dataclass
class TransferCallback:
    trace_level: int
    cb_interval_ms: int
    total_bytes: int
    need_error_cb: bool
    need_progress_cb: bool
    need_filename_cb: bool
    progress_cb: Callable[[int, int], None]
    filename_cb: Callable[[str], None]
    error_cb: Callable[[str, TransferErrorCode], None]

@dataclass
class TransferTask:
    src: str
    dst: str
    path_type: PathType
    size: int
    
@dataclass
class BufferSet:
    A_buffer: int
    A_size: int
    B_buffer: int
    B_size: int
    C_buffer: int
    C_size: int
    D_buffer: int
    D_size: int
    E_buffer: int
    E_size: int
    F_buffer: int
    F_size: int
    G_buffer: int
    G_size: int

class AMSFTPWorker:
    def __init__(self, ID:int, private_keys:list[str], request: ConRequst, set: TransferSet, callback: TransferCallback, tasks:list[TransferTask]):
        ...

    def terminate(self):
        ...
    
    def pause(self):
        ...

    def resume(self):
        ...

    def start(self):
        ...

@dataclass
class PathInfo:
    name: str
    path: str
    size: int
    atime: int
    mtime: int
    path_type: PathType

@dataclass
class BufferSizePair:
    buffer: int
    size: int

@dataclass
class BufferSizePair:
    buffer_size: list[BufferSizePair]

class AMSFTPClient:
    def __init__(self, ID:int, private_keys:list[str], request: ConRequst, set: TransferSet, callback: TransferCallback, tasks:list[TransferTask]):
        ...

    def stat(self, path: str):
        ...

    def listdir(self, path: str):
        ...

    def mkdir(self, path: str):
        ...





