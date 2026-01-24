cmake_minimum_required(VERSION 3.20)
project(AMSFTP LANGUAGES CXX)
# cmake_policy(SET CMP0102 NEW)  # 告诉 CMake：“允许忽略未识别参数”
# 生成 compile_commands.json（给 clangd 用）
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

file(GLOB_RECURSE AMSFTP_SOURCES CONFIGURE_DEPENDS
  "${PROJECT_SOURCE_DIR}/src/*.cpp"
  "${PROJECT_SOURCE_DIR}/src/*.cc"
  "${PROJECT_SOURCE_DIR}/src/*.cxx"
)

add_executable(amsftp ${AMSFTP_SOURCES})

target_include_directories(amsftp PRIVATE
  "${PROJECT_SOURCE_DIR}/include"
)

# 调试更稳定：Debug + -g + -O0（大多数情况下 Debug 会自动带，但这里兜底）
target_compile_options(amsftp PRIVATE
  $<$<CXX_COMPILER_ID:Clang>:-g -O0 -Wall -Wextra -Wpedantic>
  $<$<CXX_COMPILER_ID:GNU>:-g -O0 -Wall -Wextra -Wpedantic>
  $<$<CXX_COMPILER_ID:MSVC>:/Zi /Od /W4>
)

# test（如果 test/ 下有 cpp）
option(AMSFTP_BUILD_TESTS "Build tests" ON)
if (AMSFTP_BUILD_TESTS)
  enable_testing()
  file(GLOB_RECURSE AMSFTP_TEST_SOURCES CONFIGURE_DEPENDS
    "${PROJECT_SOURCE_DIR}/test/*.cpp"
    "${PROJECT_SOURCE_DIR}/test/*.cc"
    "${PROJECT_SOURCE_DIR}/test/*.cxx"
  )
  if (AMSFTP_TEST_SOURCES)
    add_executable(amsftp_tests ${AMSFTP_TEST_SOURCES})
    target_include_directories(amsftp_tests PRIVATE "${PROJECT_SOURCE_DIR}/include")
    add_test(NAME amsftp_tests COMMAND amsftp_tests)
  endif()
endif()

# add_executable(amsimpletest/amscratch.cpp)