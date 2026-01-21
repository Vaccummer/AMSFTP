from distutils.core import setup, Extension
from distutils.command.build_ext import build_ext
import pybind11
import sys
import os
import time

# python setup_debugg.py build_ext --inplace
# python -m pybind11_stubgen AMSFTP --ignore-all-errors -o .

in_path = os.path.dirname(sys.executable)


class DebugBuildExt(build_ext):
    """自定义编译命令，强制使用 Release CRT (/MD) 并保留调试信息"""

    def build_extensions(self):
        # 获取编译器对象
        compiler = self.compiler

        # 强制移除 /MDd，添加 /MD（确保与 Python 和依赖库的 CRT 匹配）
        # 这是关键：/MDd 会导致与 Release 版 Python 不兼容
        if hasattr(compiler, "compile_options"):
            compiler.compile_options = [
                opt for opt in compiler.compile_options if "/MDd" not in opt
            ]
            if "/MD" not in compiler.compile_options:
                compiler.compile_options.append("/MD")

        if hasattr(compiler, "compile_options_debug"):
            # 调试模式也使用 /MD，因为我们的依赖库是 Release 版本
            compiler.compile_options_debug = [
                opt for opt in compiler.compile_options_debug if "/MDd" not in opt
            ]
            if "/MD" not in compiler.compile_options_debug:
                compiler.compile_options_debug.append("/MD")

        # 调用父类的构建方法
        super().build_extensions()


module = Extension(
    "AMSFTP",
    sources=["AMBinding.cpp"],
    language="c++",
    extra_compile_args=[
        "/std:c++17",
        "/utf-8",
        "/Zc:__cplusplus",
        "/Zi",  # 生成调试信息（PDB文件）- 可以打断点
        "/Od",  # 禁用优化 - 变量不会被优化掉，调试更清晰
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
        "libcurl",
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
    cmdclass={"build_ext": DebugBuildExt},  # 使用自定义的编译命令
)
