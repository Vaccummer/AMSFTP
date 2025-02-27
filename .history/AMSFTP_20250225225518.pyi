from typing import Callable, Literal
from enum import Enum
from dataclasses import dataclass


class TransferErrorCode(Enum):
    Success = 0,
    SessionCreateError = 1,
    SftpCreateError = 2,
    SessionEstablishError = 3,
    SftpEstablishError = 4,
    ConnectionAuthorizeError = 5,
    LocalFileMapError = 6,
    RemoteFileOpenError = 7,
    RemoteFileStatError = 8,
    LocalFileCreateError = 9,
    LocalFileAllocError = 10,
    NetworkError = 11,
    NetworkDisconnect = 12,
    NetworkTimeout = 13,
    LocalFileFlushError = 14,
    SegmentationFault = 15,
    SessionBroken = 16,
    SftpBroken = 17,
    ChannelCreateError = 18,
    ConnectionCheckFailed = 19,
    RemoteFileWriteError = 20,
    RemoteFileReadError = 21,
    Terminate = 22,
    LocalFileExists = 23,
    RemoteFileExists = 24,

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
    tar_system: TarSystemType
    compression: bool
    port: int

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
    
class 
    
