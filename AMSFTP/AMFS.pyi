from __future__ import annotations
import typing
__all__ = ['CWD', 'HomePath', 'IsAbs', 'PathInfo', 'PathType', 'UnifyPathSep', 'basename', 'dirname', 'extname', 'getsize', 'iwalk', 'listdir', 'mkdirs', 'realpath', 'resplit', 'split', 'stat', 'walk']
class PathInfo:
    access_time: float
    create_time: float
    dir: str
    mode_int: int
    mode_str: str
    modify_time: float
    name: str
    owner: str
    path: str
    size: int
    type: PathType
    def FormatTime(self, time: int, format: str = '%Y-%m-%d %H:%M:%S') -> str:
        ...
    def __init__(self, name: str, path: str, dir: str, owner: str, size: int, create_time: float, access_time: float, modify_time: float, path_type: PathType = ..., mode_int: int = 511, mode_str: str = 'rwxrwxrwx') -> None:
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
def CWD() -> str:
    ...
def HomePath() -> str:
    ...
def IsAbs(path: str, sep: str = '') -> bool:
    ...
def UnifyPathSep(path: str, sep: str = '') -> str:
    ...
def basename(path: str) -> str:
    ...
def dirname(path: str) -> str:
    ...
@typing.overload
def extname(path: str) -> str:
    ...
@typing.overload
def extname(path: str) -> str:
    ...
def getsize(path: str, trace_link: bool = False) -> int:
    ...
def iwalk(path: str, ignore_sepcial_file: bool = True) -> list[...]:
    ...
def listdir(path: str) -> list[...]:
    ...
def mkdirs(path: str) -> str:
    ...
def realpath(path: str, force_parsing: bool = False, cwd: str = '', sep: str = '') -> str:
    ...
def resplit(path: str, front_esc: str, back_esc: str, head: str = '') -> list[str]:
    ...
def split(path: str) -> list[str]:
    ...
def stat(path: str, trace_link: bool = False) -> tuple[str, ...]:
    ...
def walk(path: str, max_depth: int = -1, ignore_sepcial_file: bool = True) -> list[tuple[list[str], ...]]:
    ...
