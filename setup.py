from distutils.core import setup, Extension
import pybind11
import sys
import os
import time

# python setup.py build_ext --inplace
# python -m pybind11_stubgen AMSFTP --ignore-all-errors -o .
in_path = os.path.dirname(sys.executable)

module = Extension(
    "AMSFTP",
    sources=["amsftp.cpp"],
    language="c++",
    extra_compile_args=["/std:c++17", "/utf-8", "/Zc:__cplusplus"],
    # library_dirs=["E:\\vcpkg\\installed\\x64-windows\\lib", r'E:\Softwares\Anaconda\envs\Launcher\libs'],
    libraries=[
        "libssh2",
        "libcrypto",
        "zlib",
        "libssl",
        "shell32",
        "ws2_32",
        "fmt",
        "Advapi32",
    ],
)

# 版本号格式：YYYY-MM-DD:HHMMSS
time_n = time.strftime("%Y-%m-%d:%H:%M:%S", time.localtime())
setup(
    name="AMSFTP",
    version="2.0",
    description=time_n,
    long_description="AMSCP, a python wrapper for AMSCPServer, SFTP Transfer with callback function",
    ext_modules=[module],
)
