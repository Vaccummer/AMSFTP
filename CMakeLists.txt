cmake_minimum_required(VERSION 3.20)
project(AMSFTP LANGUAGES C CXX)


set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")

if (CMAKE_SIZEOF_VOID_P EQUAL 8)
  set(AMSFTP_BUILD_ARCH "x86_64")
elseif (CMAKE_SIZEOF_VOID_P EQUAL 4)
  set(AMSFTP_BUILD_ARCH "x86")
else()
  set(AMSFTP_BUILD_ARCH "${CMAKE_SYSTEM_PROCESSOR}")
endif()

if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang" AND
    CMAKE_CXX_SIMULATE_ID STREQUAL "MSVC")
  set(AMSFTP_BUILD_COMPILER "clang-cl")
else()
  string(TOLOWER "${CMAKE_CXX_COMPILER_ID}" AMSFTP_BUILD_COMPILER)
endif()

if (CMAKE_MSVC_RUNTIME_LIBRARY MATCHES "DLL")
  set(AMSFTP_BUILD_LINKAGE "dynamic")
else()
  set(AMSFTP_BUILD_LINKAGE "static")
endif()
string(TOLOWER "${CMAKE_SYSTEM_NAME}" AMSFTP_BUILD_OS)

set(AMSFTP_PROGRAM_NAME "AMSFTP")
set(AMSFTP_PROGRAM_VERSION "1.0")

set(AMSFTP_APP_DESCRIPTION_TEXT
    "${AMSFTP_PROGRAM_NAME}\\nthis program is a CLI program for multi-host SFTP/FTP/HTTP file management and SSH sessions.")
set(AMSFTP_APP_VERSION_TEXT
    "${AMSFTP_PROGRAM_NAME} ${AMSFTP_PROGRAM_VERSION}\\ncompiler: ${AMSFTP_BUILD_COMPILER} ${CMAKE_CXX_COMPILER_VERSION}\\ntarget: ${AMSFTP_BUILD_OS}/${AMSFTP_BUILD_ARCH}\\nlinkage: ${AMSFTP_BUILD_LINKAGE}")

find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)
find_package(CURL CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(Lua REQUIRED)
find_package(libssh2 CONFIG REQUIRED)
find_package(Threads REQUIRED)
find_package(CLI11 CONFIG REQUIRED)

file(GLOB_RECURSE AMSFTP_SOURCES CONFIGURE_DEPENDS
  "${PROJECT_SOURCE_DIR}/src/*.cpp"
  "${PROJECT_SOURCE_DIR}/src/*.cc"
  "${PROJECT_SOURCE_DIR}/src/*.cxx"
)
list(APPEND AMSFTP_SOURCES "${PROJECT_SOURCE_DIR}/src/third_party/Isocline/isocline.c")
set_source_files_properties(
  "${PROJECT_SOURCE_DIR}/src/third_party/Isocline/isocline.c"
  PROPERTIES COMPILE_OPTIONS "/W0"
)

add_executable(amsftp resource/app.rc ${AMSFTP_SOURCES})
target_include_directories(amsftp PRIVATE
  "${PROJECT_SOURCE_DIR}/src"
  "${PROJECT_SOURCE_DIR}/src/third_party"
)
target_link_libraries(amsftp PRIVATE
  OpenSSL::SSL
  OpenSSL::Crypto
  ZLIB::ZLIB
  CURL::libcurl
  nlohmann_json::nlohmann_json
  ${LUA_LIBRARIES}
  libssh2::libssh2
  shell32
  ws2_32
  Advapi32
  CLI11::CLI11
)
target_compile_definitions(amsftp PRIVATE
  NOMINMAX
  AMSFTP_PASSWORD_KEY="AMSFTP_Static_Key_Change_Me_2026"
  AMSFTP_APP_DESCRIPTION="${AMSFTP_APP_DESCRIPTION_TEXT}"
  AMSFTP_APP_VERSION="${AMSFTP_APP_VERSION_TEXT}"
)
target_compile_options(amsftp PRIVATE /W4 /Zi)
target_link_options(amsftp PRIVATE /DEBUG:FULL)

set(AMSFTP_RUST_DIR "${PROJECT_SOURCE_DIR}/src/foreign/amsrust")
find_program(CARGO_EXECUTABLE cargo)
if (NOT CARGO_EXECUTABLE)
  message(FATAL_ERROR "cargo executable not found; Rust FFI crate is required.")
endif()
if (WIN32)
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
target_link_libraries(amsftp PRIVATE
  amsftp_rust
  ntdll
  userenv
  dbghelp
  legacy_stdio_definitions
)
