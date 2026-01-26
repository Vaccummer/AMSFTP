cmake_minimum_required(VERSION 3.20)
project(AMSFTP LANGUAGES CXX)

# ========= C++ 标准 =========
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ========= vcpkg 包（MSVC / x64-windows） =========
find_package(tomlplusplus CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)
find_package(CURL CONFIG REQUIRED)
find_package(fmt CONFIG REQUIRED)
find_package(replxx CONFIG REQUIRED)
find_package(libssh2 CONFIG REQUIRED)
find_package(Threads REQUIRED)

# ========= MSVC 运行库（/MD /MDd） =========
if (MSVC)
  set(CMAKE_MSVC_RUNTIME_LIBRARY
      "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
endif()

# ========= 源文件 =========
file(GLOB_RECURSE AMSFTP_SOURCES CONFIGURE_DEPENDS
  "${PROJECT_SOURCE_DIR}/main.cpp"
  "${PROJECT_SOURCE_DIR}/src/*.cpp"
  "${PROJECT_SOURCE_DIR}/src/*.cc"
  "${PROJECT_SOURCE_DIR}/src/*.cxx"
)

add_executable(amsftp ${AMSFTP_SOURCES})

target_include_directories(amsftp PRIVATE
  "${PROJECT_SOURCE_DIR}/include"
)

# ========= 链接（全部用 vcpkg target） =========
target_link_libraries(amsftp PRIVATE
  tomlplusplus::tomlplusplus
  OpenSSL::SSL
  OpenSSL::Crypto
  ZLIB::ZLIB
  CURL::libcurl
  fmt::fmt
  replxx::replxx
  libssh2::libssh2
  shell32
  ws2_32
  Advapi32
)

# ========= 测试程序 =========
file(GLOB_RECURSE AMTEST_SOURCES CONFIGURE_DEPENDS
  "${PROJECT_SOURCE_DIR}/test/*.cpp"
  "${PROJECT_SOURCE_DIR}/test/*.cc"
  "${PROJECT_SOURCE_DIR}/src/*.cpp"
  "${PROJECT_SOURCE_DIR}/src/*.cc"
  "${PROJECT_SOURCE_DIR}/src/*.cxx"
)

add_executable(amtest ${AMTEST_SOURCES})

target_include_directories(amtest PRIVATE
  "${PROJECT_SOURCE_DIR}/include"
)

target_link_libraries(amtest PRIVATE
  tomlplusplus::tomlplusplus
  OpenSSL::SSL
  OpenSSL::Crypto
  ZLIB::ZLIB
  CURL::libcurl
  fmt::fmt
  replxx::replxx
  libssh2::libssh2
  shell32
  ws2_32
  Advapi32
)

# ========= 编译选项 =========
target_compile_options(amsftp PRIVATE
  $<$<CXX_COMPILER_ID:MSVC>:/Zi /Od /W4>
)

target_compile_options(amtest PRIVATE
  $<$<CXX_COMPILER_ID:MSVC>:/Zi /Od /W4>
)
