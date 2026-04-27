cmake_minimum_required(VERSION 3.20)
project(AMSFTP LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(AMSFTP_LINK_MODE "static" CACHE STRING "Link mode: static or dynamic")
set_property(CACHE AMSFTP_LINK_MODE PROPERTY STRINGS static dynamic)

if(MSVC AND AMSFTP_LINK_MODE STREQUAL "static" AND NOT DEFINED CMAKE_MSVC_RUNTIME_LIBRARY)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# -- Platform auto-detection --------------------------------------------------
if(APPLE)
  set(AMSFTP_BUILD_OS "darwin")
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")
    set(CMAKE_PREFIX_PATH "/opt/homebrew")
  else()
    set(CMAKE_PREFIX_PATH "/usr/local")
  endif()
elseif(UNIX)
  set(AMSFTP_BUILD_OS "linux")
elseif(WIN32)
  set(AMSFTP_BUILD_OS "windows")
else()
  set(AMSFTP_BUILD_OS "${CMAKE_SYSTEM_NAME}")
endif()

if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")
  set(AMSFTP_BUILD_ARCH "arm64")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "amd64|x86_64|AMD64")
  set(AMSFTP_BUILD_ARCH "x86_64")
else()
  set(AMSFTP_BUILD_ARCH "${CMAKE_SYSTEM_PROCESSOR}")
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang" AND CMAKE_CXX_SIMULATE_ID STREQUAL "MSVC")
  set(AMSFTP_BUILD_COMPILER "clang-cl")
else()
  string(TOLOWER "${CMAKE_CXX_COMPILER_ID}" AMSFTP_BUILD_COMPILER)
endif()

set(AMSFTP_BUILD_LINKAGE "${AMSFTP_LINK_MODE}")

set(AMSFTP_PROGRAM_NAME "AMSFTP")
set(AMSFTP_PROGRAM_VERSION "1.0")

set(AMSFTP_APP_DESCRIPTION_TEXT
    "${AMSFTP_PROGRAM_NAME}\\nthis program is a CLI program for multi-host SFTP/FTP/HTTP file management and SSH sessions.")
set(AMSFTP_APP_VERSION_TEXT
    "${AMSFTP_PROGRAM_NAME} ${AMSFTP_PROGRAM_VERSION}\\ncompiler: ${AMSFTP_BUILD_COMPILER} ${CMAKE_CXX_COMPILER_VERSION}\\ntarget: ${AMSFTP_BUILD_OS}/${AMSFTP_BUILD_ARCH}\\nlinkage: ${AMSFTP_BUILD_LINKAGE}")

# -- Dependencies -------------------------------------------------------------
find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)
if(WIN32)
  find_package(CURL CONFIG REQUIRED)
else()
  find_package(CURL REQUIRED)
endif()
find_package(nlohmann_json CONFIG REQUIRED)
find_package(Lua REQUIRED)
if(WIN32)
  find_package(libssh2 CONFIG REQUIRED)
else()
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(LIBSSH2 REQUIRED IMPORTED_TARGET libssh2)
endif()
find_package(Threads REQUIRED)
find_package(CLI11 CONFIG REQUIRED)

# -- Sources ------------------------------------------------------------------
file(GLOB_RECURSE AMSFTP_SOURCES CONFIGURE_DEPENDS
  "${PROJECT_SOURCE_DIR}/src/*.cpp"
  "${PROJECT_SOURCE_DIR}/src/*.cc"
  "${PROJECT_SOURCE_DIR}/src/*.cxx"
)
list(APPEND AMSFTP_SOURCES "${PROJECT_SOURCE_DIR}/src/third_party/Isocline/isocline.c")
set_source_files_properties(
  "${PROJECT_SOURCE_DIR}/src/third_party/Isocline/isocline.c"
  PROPERTIES COMPILE_OPTIONS $<$<C_COMPILER_ID:MSVC>:/W0>$<$<NOT:$<C_COMPILER_ID:MSVC>>:-w>
)

# -- Executable ---------------------------------------------------------------
if(WIN32)
  add_executable(amsftp resource/app.rc ${AMSFTP_SOURCES})
else()
  add_executable(amsftp ${AMSFTP_SOURCES})
endif()
target_include_directories(amsftp PRIVATE
  "${PROJECT_SOURCE_DIR}/src"
  "${PROJECT_SOURCE_DIR}/src/third_party"
  ${LUA_INCLUDE_DIR}
)
target_link_libraries(amsftp PRIVATE
  OpenSSL::SSL
  OpenSSL::Crypto
  ZLIB::ZLIB
  CURL::libcurl
  nlohmann_json::nlohmann_json
  ${LUA_LIBRARIES}
  Threads::Threads
  CLI11::CLI11
)
if(WIN32)
  target_link_libraries(amsftp PRIVATE
    libssh2::libssh2
    shell32
    ws2_32
    Advapi32
  )
else()
  target_link_libraries(amsftp PRIVATE PkgConfig::LIBSSH2)
endif()
target_compile_definitions(amsftp PRIVATE
  AMSFTP_PASSWORD_KEY="AMSFTP_Static_Key_Change_Me_2026"
  AMSFTP_APP_DESCRIPTION="${AMSFTP_APP_DESCRIPTION_TEXT}"
  AMSFTP_APP_VERSION="${AMSFTP_APP_VERSION_TEXT}"
)
if(MSVC)
  target_compile_definitions(amsftp PRIVATE NOMINMAX)
  target_compile_options(amsftp PRIVATE /W4 /Zi
    $<$<CONFIG:Release>:/O2>
    $<$<CONFIG:Release>:/Ob2>
    $<$<CONFIG:Release>:/Oi>
    $<$<CONFIG:Release>:/arch:AVX2>
    $<$<CONFIG:Release>:/guard:cf>
  )
  target_link_options(amsftp PRIVATE /DEBUG:FULL
    $<$<CONFIG:Release>:/guard:cf>
  )
else()
  target_compile_options(amsftp PRIVATE
    -Wall -Wextra -Wpedantic
    $<$<CONFIG:Release>:-O3>
  )
endif()
set_property(TARGET amsftp PROPERTY INTERPROCEDURAL_OPTIMIZATION $<CONFIG:Release>)

# -- Platform-specific libraries ----------------------------------------------
if(APPLE)
  find_library(SECURITY_FRAMEWORK Security REQUIRED)
  find_library(COREFOUNDATION_FRAMEWORK CoreFoundation REQUIRED)
  target_link_libraries(amsftp PRIVATE
    ${SECURITY_FRAMEWORK}
    ${COREFOUNDATION_FRAMEWORK}
  )
endif()

if(UNIX AND NOT APPLE)
  find_library(UTIL_LIBRARY util)
  if(UTIL_LIBRARY)
    target_link_libraries(amsftp PRIVATE ${UTIL_LIBRARY})
  endif()
endif()

if(WIN32)
  target_link_libraries(amsftp PRIVATE
    ntdll
    userenv
    dbghelp
    legacy_stdio_definitions
  )
endif()

# -- Rust FFI -----------------------------------------------------------------
set(AMSFTP_RUST_DIR "${PROJECT_SOURCE_DIR}/src/foreign/amsrust")
find_program(CARGO_EXECUTABLE cargo)
if(NOT CARGO_EXECUTABLE)
  message(FATAL_ERROR "cargo executable not found; Rust FFI crate is required.")
endif()
if(WIN32)
  set(AMSFTP_RUST_LIB_PATH "${AMSFTP_RUST_DIR}/target/release/amsftp_rust.lib")
else()
  set(AMSFTP_RUST_LIB_PATH "${AMSFTP_RUST_DIR}/target/release/libamsftp_rust.a")
endif()
add_custom_command(
  OUTPUT "${AMSFTP_RUST_LIB_PATH}"
  COMMAND "${CARGO_EXECUTABLE}" build --release --locked
  WORKING_DIRECTORY "${AMSFTP_RUST_DIR}"
  DEPENDS
    "${AMSFTP_RUST_DIR}/Cargo.toml"
    "${AMSFTP_RUST_DIR}/Cargo.lock"
    "${AMSFTP_RUST_DIR}/src/lib.rs"
    "${AMSFTP_RUST_DIR}/src/toml.rs"
    "${AMSFTP_RUST_DIR}/src/vt.rs"
  COMMENT "Building Rust FFI crate"
  VERBATIM
)
add_custom_target(amsftp_rust_build DEPENDS "${AMSFTP_RUST_LIB_PATH}")
add_library(amsftp_rust STATIC IMPORTED GLOBAL)
set_target_properties(amsftp_rust PROPERTIES
  IMPORTED_LOCATION "${AMSFTP_RUST_LIB_PATH}"
)
add_dependencies(amsftp_rust amsftp_rust_build)
target_link_libraries(amsftp PRIVATE amsftp_rust)
