from distutils.core import setup, Extension
import sys
import os
import time

# python setup.py build_ext --inplace --debug
# python -m pybind11_stubgen AMSFTP --ignore-all-errors -o .
in_path = os.path.dirname(sys.executable)

module = Extension(
    "AMSFTP",
    sources=["AMBinding.cpp", "AMCore.cpp"],
    language="c++",
    extra_compile_args=[
        "/std:c++17",
        "/utf-8",
        "/Zc:__cplusplus",
        "/Zi",
        "/Od",
        "/MD",  # 多线程调试版本，不能用MDd
        "/RTC1",  # 运行时检查（检测栈溢出、未初始化变量等）
        "/GS",  # 缓冲区安全检查
        "/W3",  # 警告级别
    ],
    extra_link_args=[
        "/DEBUG:FULL",  # 生成完整调试信息
        "/INCREMENTAL:NO",  # 禁用增量链接
    ],
    include_dirs=[
        "D:\\Compiler\\vcpkg\\installed\\x64-windows\\include",
    ],
    library_dirs=[
        "D:\\Compiler\\vcpkg\\installed\\x64-windows\\lib",
    ],
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
    name="AMSFTPd",
    version="2.0",
    description=time_n,
    long_description="AMSCP, a python wrapper for AMSCPServer, SFTP Transfer with callback function",
    ext_modules=[module],
)
