cmake_minimum_required(VERSION 3.20)
project(AMSFTP LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(AMSFTP_LINK_MODE "static" CACHE STRING "Link mode: static or dynamic")
set_property(CACHE AMSFTP_LINK_MODE PROPERTY STRINGS static dynamic)

if(MSVC AND AMSFTP_LINK_MODE STREQUAL "static" AND NOT DEFINED CMAKE_MSVC_RUNTIME_LIBRARY)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

if(AMSFTP_LINK_MODE STREQUAL "static")
  set(OPENSSL_USE_STATIC_LIBS TRUE)
  if(NOT WIN32)
    list(INSERT CMAKE_FIND_LIBRARY_SUFFIXES 0 .a)
    set(BUILD_SHARED_LIBS OFF)
    set(ENV{PKG_CONFIG_ALL_STATIC} 1)
    if(APPLE)
      execute_process(COMMAND brew --prefix zlib OUTPUT_VARIABLE ZLIB_ROOT OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
      execute_process(COMMAND brew --prefix curl OUTPUT_VARIABLE CURL_ROOT OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
      foreach(_prefix IN LISTS ZLIB_ROOT CURL_ROOT)
        if(_prefix)
          list(PREPEND CMAKE_PREFIX_PATH "${_prefix}")
          list(PREPEND CMAKE_LIBRARY_PATH "${_prefix}/lib")
          list(PREPEND CMAKE_INCLUDE_PATH "${_prefix}/include")
          if(EXISTS "${_prefix}/lib/pkgconfig")
            if(DEFINED ENV{PKG_CONFIG_PATH} AND NOT "$ENV{PKG_CONFIG_PATH}" STREQUAL "")
              set(ENV{PKG_CONFIG_PATH} "${_prefix}/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
            else()
              set(ENV{PKG_CONFIG_PATH} "${_prefix}/lib/pkgconfig")
            endif()
          endif()
        endif()
      endforeach()
    endif()
  endif()
endif()

# -- Platform auto-detection --------------------------------------------------
if(APPLE)
  set(AMSFTP_BUILD_OS "darwin")
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")
    list(PREPEND CMAKE_PREFIX_PATH "/opt/homebrew")
  else()
    list(PREPEND CMAKE_PREFIX_PATH "/usr/local")
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
if(NOT WIN32)
  find_package(PkgConfig REQUIRED)
endif()

if(NOT WIN32 AND AMSFTP_LINK_MODE STREQUAL "static")
  function(amsftp_define_static_pkg_target target_name pkg_name archive_name)
    pkg_get_variable(_pkg_libdir ${pkg_name} libdir)
    pkg_get_variable(_pkg_includedir ${pkg_name} includedir)
    if(NOT _pkg_libdir)
      message(FATAL_ERROR "pkg-config did not return libdir for ${pkg_name}")
    endif()

    execute_process(
      COMMAND "${PKG_CONFIG_EXECUTABLE}" --static --libs "${pkg_name}"
      OUTPUT_VARIABLE _pkg_flags
      OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    separate_arguments(_pkg_flags UNIX_COMMAND "${_pkg_flags}")

    set(_pkg_link_libs "")
    set(_pkg_link_options "")
    set(_pkg_library_dirs "${_pkg_libdir}")
    foreach(_prefix IN LISTS CMAKE_PREFIX_PATH)
      if(_prefix)
        list(APPEND _pkg_library_dirs "${_prefix}/lib")
      endif()
    endforeach()
    foreach(_dir IN LISTS CMAKE_LIBRARY_PATH)
      if(_dir)
        list(APPEND _pkg_library_dirs "${_dir}")
      endif()
    endforeach()
    list(REMOVE_DUPLICATES _pkg_library_dirs)

    set(_expect_framework_name FALSE)
    set(_expect_wl_framework_name FALSE)
    foreach(_flag IN LISTS _pkg_flags)
      if(_expect_framework_name)
        list(APPEND _pkg_link_options "SHELL:-framework ${_flag}")
        set(_expect_framework_name FALSE)
      elseif(_expect_wl_framework_name)
        list(APPEND _pkg_link_options "SHELL:-framework ${_flag}")
        set(_expect_wl_framework_name FALSE)
      elseif(_flag MATCHES "^-L(.+)$")
        list(APPEND _pkg_library_dirs "${CMAKE_MATCH_1}")
        list(REMOVE_DUPLICATES _pkg_library_dirs)
      elseif(_flag MATCHES "^-l(.+)$")
        set(_lib_name "${CMAKE_MATCH_1}")
        set(_static_lib "")
        foreach(_dir IN LISTS _pkg_library_dirs)
          if(EXISTS "${_dir}/lib${_lib_name}.a")
            set(_static_lib "${_dir}/lib${_lib_name}.a")
            break()
          endif()
        endforeach()
        if(_static_lib)
          list(APPEND _pkg_link_libs "${_static_lib}")
        else()
          list(APPEND _pkg_link_libs "${_flag}")
        endif()
      elseif(_flag STREQUAL "-framework")
        set(_expect_framework_name TRUE)
      elseif(_flag STREQUAL "-Wl,-framework")
        set(_expect_wl_framework_name TRUE)
      elseif(_flag MATCHES "^-Wl,-framework,(.+)$")
        list(APPEND _pkg_link_options "SHELL:-framework ${CMAKE_MATCH_1}")
      elseif(_flag MATCHES "^-R.+$")
        # Static builds should not carry Homebrew runtime search paths.
      elseif(_flag MATCHES "^-Wl,-rpath.*$")
        # Static builds should not carry Homebrew runtime search paths.
      else()
        list(APPEND _pkg_link_libs "${_flag}")
      endif()
    endforeach()
    if(_expect_framework_name)
      message(FATAL_ERROR "Malformed pkg-config flags for ${pkg_name}: trailing -framework without name")
    endif()
    if(_expect_wl_framework_name)
      message(FATAL_ERROR "Malformed pkg-config flags for ${pkg_name}: trailing -Wl,-framework without name")
    endif()

    add_library(${target_name} INTERFACE IMPORTED)
    set_target_properties(${target_name} PROPERTIES
      INTERFACE_INCLUDE_DIRECTORIES "${_pkg_includedir}"
      INTERFACE_LINK_LIBRARIES "${_pkg_link_libs}"
      INTERFACE_LINK_OPTIONS "${_pkg_link_options}"
    )
  endfunction()
endif()

if(WIN32 OR NOT AMSFTP_LINK_MODE STREQUAL "static")
  find_package(ZLIB REQUIRED)
else()
  amsftp_define_static_pkg_target(ZLIB::ZLIB zlib z)
endif()

if(WIN32)
  find_package(CURL CONFIG REQUIRED)
elseif(AMSFTP_LINK_MODE STREQUAL "static")
  amsftp_define_static_pkg_target(CURL::libcurl libcurl curl)
else()
  pkg_check_modules(libcurl REQUIRED IMPORTED_TARGET libcurl)
  add_library(CURL::libcurl ALIAS PkgConfig::libcurl)
endif()
find_package(nlohmann_json CONFIG REQUIRED)
if(WIN32)
  find_package(unofficial-lua CONFIG REQUIRED)
else()
  pkg_check_modules(LUA REQUIRED IMPORTED_TARGET lua)
  add_library(lua ALIAS PkgConfig::LUA)
endif()
if(WIN32)
  find_package(libssh2 CONFIG REQUIRED)
elseif(AMSFTP_LINK_MODE STREQUAL "static")
  amsftp_define_static_pkg_target(LIBSSH2::LIBSSH2 libssh2 ssh2)
else()
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
)
target_link_libraries(amsftp PRIVATE
  OpenSSL::SSL
  OpenSSL::Crypto
  ZLIB::ZLIB
  CURL::libcurl
  nlohmann_json::nlohmann_json
  lua
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
elseif(AMSFTP_LINK_MODE STREQUAL "static")
  target_link_libraries(amsftp PRIVATE LIBSSH2::LIBSSH2)
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
  find_library(CORESERVICES_FRAMEWORK CoreServices REQUIRED)
  find_library(SYSTEMCONFIGURATION_FRAMEWORK SystemConfiguration REQUIRED)
  target_link_libraries(amsftp PRIVATE
    ${SECURITY_FRAMEWORK}
    ${COREFOUNDATION_FRAMEWORK}
    ${CORESERVICES_FRAMEWORK}
    ${SYSTEMCONFIGURATION_FRAMEWORK}
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
