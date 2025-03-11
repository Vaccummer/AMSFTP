from distutils.core import setup, Extension
import pybind11
import sys
import os

in_path = os.path.dirname(sys.executable)

module = Extension(
    "AMSFTP",
    sources=[
        "amsftp.cpp",
    ],
    include_dirs=[
        pybind11.get_include(),
        "E:\\Softwares\\Anaconda\\envs\\Launcher\\include",
        "C:\\Program Files (x86)\\Windows Kits\\10\\Include\\10.0.22000.0\\ucrt",
        "E:\\vcpkg\\installed\\x64-windows\\include",
        "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Tools\\MSVC\\14.43.34808\\atlmfc\\include",
        "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Tools\\MSVC\\14.43.34808\\include",
    ],
    language="c++",
    extra_compile_args=["/std:c++17", "/utf-8"],
    # library_dirs=["E:\\vcpkg\\installed\\x64-windows\\lib", r'E:\Softwares\Anaconda\envs\Launcher\libs'],
    library_dirs=[
        "E:\\vcpkg\\installed\\x64-windows\\lib",
        r"E:\Softwares\Anaconda\envs\Launcher\libs",
    ],
    libraries=["libssh2", "libcrypto", "zlib", "libssl", "ws2_32", "fmt"],
)

setup(
    name="AMSFTP",
    version="0.1",
    description="AMSCP, a python wrapper for AMSCPServer, SFTP Transfer with callback function",
    ext_modules=[module],
)
