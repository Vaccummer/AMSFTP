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

set(AMSFTP_RUST_TOMLREAD_DIR "${PROJECT_SOURCE_DIR}/src/foreign/tomlread")
find_file(RUST_TOML_READ_STATIC_LIB
  NAMES rust_toml_read.lib
  PATHS "${AMSFTP_RUST_TOMLREAD_DIR}/target/release"
  NO_DEFAULT_PATH
)
if (RUST_TOML_READ_STATIC_LIB)
  target_link_libraries(amsftp PRIVATE
    ${RUST_TOML_READ_STATIC_LIB}
    ntdll
    userenv
    dbghelp
    legacy_stdio_definitions
  )
  target_compile_definitions(amsftp PRIVATE RUST_TOML_READ_STATIC)
else()
  message(WARNING "rust_toml_read static library not found; build may fail if not linked elsewhere.")
endif()
