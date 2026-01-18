"""
Local Filesystem Operations
"""
import AMSFTP.AMData
from __future__ import annotations
import typing
__all__ = ['CWD', 'GetPathSep', 'HomePath', 'IsAbs', 'IsModeValid', 'IsModeValidH', 'MergeModeStr', 'ModeTrans', 'UnifyPathSep', 'abspath', 'basename', 'dirname', 'extname', 'getsize', 'iwalk', 'listdir', 'mkdirs', 'split', 'split_basename', 'stat', 'timenow', 'walk']
def CWD() -> str:
    """
    Get the current working directory 
    """
def GetPathSep(path: str) -> str:
    """
    Get the path separator of the path, if def #AMForceUsingUnixSep during compile, will return "/" all the time
    """
def HomePath() -> str:
    """
    Get the home path of the current user
    """
def IsAbs(path: str, sep: str = '') -> bool:
    """
    Check if the path is an absolute path, unify the path separator first
    """
def IsModeValid(mode_str: str) -> bool:
    """
    Check if the mode string is valid
    """
def IsModeValidH(mode_int: int) -> bool:
    """
    Check if the mode int is valid
    """
def MergeModeStr(base_mode_str: str, new_mode_str: str) -> str:
    """
    Merge the mode string
    """
@typing.overload
def ModeTrans(mode_int: int) -> str:
    """
    Translate the mode int to string
    """
@typing.overload
def ModeTrans(mode_str: str) -> int:
    """
    Translate the mode string to int
    """
def UnifyPathSep(path: str, sep: str = '') -> str:
    """
    Unify the path separator of the path, if sep is empty, will use GetPathSep to get the path separator
    """
def abspath(path: str, parsing_home: bool = True, home: str = '', cwd: str = '', sep: str = '') -> str:
    """
    Convert path to absolute path(won't check if path exists), support parsing ~ . .. symbol, unify the path separator first
    """
def basename(path: str) -> str:
    """
    Get the base name of the path
    """
def dirname(path: str) -> str:
    """
    Get the directory name of the path
    """
def extname(path: str) -> str:
    """
    Just string seperation, return the extension of the path without.
    """
def getsize(path: str, trace_link: bool = False) -> int:
    """
    Get total size of file or directory
    """
def iwalk(path: str, ignore_special_file: bool = True) -> list[AMSFTP.AMData.PathInfo]:
    """
    Deep walk to get all leaf paths, return list[PathInfo]
    """
def listdir(path: str, max_time_s: float = -1) -> list[AMSFTP.AMData.PathInfo]:
    """
    List directory contents, if max_time_s >0 ,will end action and directly return after max_time_s seconds
    """
def mkdirs(path: str) -> str:
    """
    Create directories recursively. If error, will return the error message
    """
def split(path: str) -> list[str]:
    """
    Split the path, return list[str], the path is split by separator 
    """
def split_basename(basename: str) -> tuple[str, str]:
    """
    Split the basename of the path, return tuple[str, str], the first is the basename without extension, the second is the extension(no .)
    """
def stat(path: str, trace_link: bool = False) -> tuple[str, AMSFTP.AMData.PathInfo]:
    """
    Get the detailed information about the file, if error, the firt string is error message
    """
def timenow() -> float:
    """
    Get the current time in seconds
    """
def walk(path: str, max_depth: int = -1, ignore_special_file: bool = True) -> list[tuple[list[str], list[AMSFTP.AMData.PathInfo]]]:
    """
    Walk directory tree, returns list of (list[path parts], [PathInfo]) tuples
    """
