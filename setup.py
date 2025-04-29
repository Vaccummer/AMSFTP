from distutils.core import setup, Extension
import pybind11
import sys
import os

in_path = os.path.dirname(sys.executable)

module = Extension(
    "AMSFTP",
    sources=[
        "amsftp.cpp",
        "AMPath.cpp",
        "AMEnum.cpp",
        r"D:\CodeLib\CPP\AMTracer\AMTracer.cpp",
    ],
    include_dirs=[
        pybind11.get_include(),
        "D:\\Windows Kits\\10\\Include\\10.0.20348.0\\ucrt",
        "D:\\Windows Kits\\10\\Include\\10.0.20348.0\\um",
        "E:\\vcpkg\\installed\\x64-windows\\include",
        "D:\\Compiler\\VS2022\\IDE\\VC\\Tools\\MSVC\\14.44.35109\\include",
        "E:\\Softwares\\Anaconda3_LEGACY\\envs\\Launcher\\include",
        r"D:\CodeLib\CPP\AMTracer",
    ],
    language="c++",
    extra_compile_args=["/std:c++17", "/utf-8", "/Zc:__cplusplus"],
    # library_dirs=["E:\\vcpkg\\installed\\x64-windows\\lib", r'E:\Softwares\Anaconda\envs\Launcher\libs'],
    library_dirs=[
        r"E:\vcpkg\installed\x64-windows\lib",
        "D:\\Windows Kits\\10\\Lib\\10.0.20348.0\\um\\x64",
        "D:\\Compiler\\vcpkg\\installed\\x64-windows\\lib",
        "D:\\Compiler\\VS2022\\IDE\\VC\\Tools\\MSVC\\14.44.35109\\lib\\x64",
        "D:\\Softwares\\Anaconda3_LEGACY\\envs\\Launcher\\libs",
    ],
    libraries=[
        "libssh2",
        "libcrypto",
        "zlib",
        "libssl",
        "ws2_32",
        "fmt",
        "Advapi32",
    ],
)

setup(
    name="AMSFTP",
    version="0.1",
    description="AMSCP, a python wrapper for AMSCPServer, SFTP Transfer with callback function",
    ext_modules=[module],
)
