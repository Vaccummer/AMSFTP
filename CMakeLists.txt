cmake_minimum_required(VERSION 3.20)
project(AMSFTP LANGUAGES C CXX)

option(AMSFTP_ENABLE_LAYER_CHECK
       "Enable Workflow-0 layered include dependency check target"
       ON)
set(AMSFTP_LINK_MODE "dynamic" CACHE STRING
    "Link mode for AMSFTP dependencies: dynamic or static")
set_property(CACHE AMSFTP_LINK_MODE PROPERTY STRINGS dynamic static)

# ========= C++ Standard =========
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ========= vcpkg Packages (MSVC / x64-windows) =========
find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)
find_package(CURL CONFIG REQUIRED)
find_package(fmt CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(Lua REQUIRED)
find_package(replxx CONFIG REQUIRED)
find_package(libssh2 CONFIG REQUIRED)
find_package(Threads REQUIRED)
find_package(CLI11 CONFIG REQUIRED)

# ========= MSVC Runtime (/MD /MDd or /MT /MTd) =========
if (MSVC)
  if (AMSFTP_LINK_MODE STREQUAL "static")
    set(CMAKE_MSVC_RUNTIME_LIBRARY
        "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  else()
    set(CMAKE_MSVC_RUNTIME_LIBRARY
        "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
  endif()
endif()

# ========= Source Files =========
file(GLOB_RECURSE AMSFTP_SOURCES CONFIGURE_DEPENDS
  "${PROJECT_SOURCE_DIR}/main.cpp"
  "${PROJECT_SOURCE_DIR}/src/*.cpp"
  "${PROJECT_SOURCE_DIR}/src/*.cc"
  "${PROJECT_SOURCE_DIR}/src/*.cxx"
)
# Exclude legacy trees from active build.
list(FILTER AMSFTP_SOURCES EXCLUDE REGEX ".*/legacy/.*\\.(cpp|cc|cxx)$")
list(FILTER AMSFTP_SOURCES EXCLUDE REGEX ".*/\\.legacy/.*\\.(cpp|cc|cxx)$")
# Exclude deprecated implementation slices from active build.
list(FILTER AMSFTP_SOURCES EXCLUDE REGEX ".*/dep/.*\\.(cpp|cc|cxx)$")
list(FILTER AMSFTP_SOURCES EXCLUDE REGEX ".*/.*\\.dep\\.(cpp|cc|cxx)$")
list(APPEND AMSFTP_SOURCES
  "${PROJECT_SOURCE_DIR}/src/third_party/Isocline/isocline.c"
)

add_executable(amsftp ${AMSFTP_SOURCES})

target_include_directories(amsftp PRIVATE
  "${PROJECT_SOURCE_DIR}/src"
  "${PROJECT_SOURCE_DIR}/src/third_party"
)

# ========= Link (all via vcpkg targets) =========
target_link_libraries(amsftp PRIVATE
  OpenSSL::SSL
  OpenSSL::Crypto
  ZLIB::ZLIB
  CURL::libcurl
  fmt::fmt
  nlohmann_json::nlohmann_json
  ${LUA_LIBRARIES}
  replxx::replxx
  libssh2::libssh2
  shell32
  ws2_32
  Advapi32
  CLI11::CLI11
  
)
target_compile_definitions(amsftp PRIVATE
  NOMINMAX
  AMSFTP_PASSWORD_KEY="AMSFTP_Static_Key_Change_Me_2026"
)
# ========= Console Ctrl-C trigger tool =========
# add_executable(ctrlc_trigger
#   "${PROJECT_SOURCE_DIR}/src/tools/ConsoleCtrlTrigger.cpp"
# )

# target_compile_options(ctrlc_trigger PRIVATE
#   $<$<CXX_COMPILER_ID:MSVC>:/Zi /Od /W4>
# )
# # ========= Test Program =========
# file(GLOB_RECURSE AMTEST_SOURCES CONFIGURE_DEPENDS
#   "${PROJECT_SOURCE_DIR}/test/*.cpp"
#   "${PROJECT_SOURCE_DIR}/test/*.cc"
#   "${PROJECT_SOURCE_DIR}/src/*.cpp"
#   "${PROJECT_SOURCE_DIR}/src/*.cc"
#   "${PROJECT_SOURCE_DIR}/src/*.cxx"
# )
# list(APPEND AMTEST_SOURCES "${PROJECT_SOURCE_DIR}/src/third_party/Isocline/isocline.c")

# add_executable(amtest ${AMTEST_SOURCES})

# target_include_directories(amtest PRIVATE
#   "${PROJECT_SOURCE_DIR}/src"
#   "${PROJECT_SOURCE_DIR}/src/third_party"
# )

# target_link_libraries(amtest PRIVATE
#   OpenSSL::SSL
#   OpenSSL::Crypto
#   ZLIB::ZLIB
#   CURL::libcurl
#   fmt::fmt
#   nlohmann_json::nlohmann_json
#   replxx::replxx
#   libssh2::libssh2
#   CLI11::CLI11
#   shell32
#   ws2_32
#   Advapi32
# )

# ========= Rust cfgffi library (optional discovery) =========
find_library(CFGFFI_LIB NAMES cfgffi
  PATHS
    "${PROJECT_SOURCE_DIR}/tomlread/target/release"
    "${PROJECT_SOURCE_DIR}/tomlread/target/debug"
  NO_DEFAULT_PATH
)
if (NOT CFGFFI_LIB)
  # Rust cdylib on Windows commonly emits import library as cfgffi.dll.lib.
  find_file(CFGFFI_LIB NAMES cfgffi.dll.lib cfgffi.lib
    PATHS
      "${PROJECT_SOURCE_DIR}/tomlread/target/release"
      "${PROJECT_SOURCE_DIR}/tomlread/target/debug"
    NO_DEFAULT_PATH
  )
endif()
find_file(CFGFFI_DLL NAMES cfgffi.dll
  PATHS
    "${PROJECT_SOURCE_DIR}/tomlread/target/release"
    "${PROJECT_SOURCE_DIR}/tomlread/target/debug"
  NO_DEFAULT_PATH
)

if (CFGFFI_LIB)
  target_link_libraries(amsftp PRIVATE ${CFGFFI_LIB})
  if (CFGFFI_DLL)
    add_custom_command(TARGET amsftp POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
              "${CFGFFI_DLL}"
              "$<TARGET_FILE_DIR:amsftp>/cfgffi.dll"
      COMMENT "Copy cfgffi.dll to runtime output directory"
      VERBATIM
    )
  else()
    message(WARNING "cfgffi library found but cfgffi.dll not found; runtime may fail to start.")
  endif()
  # target_link_libraries(amtest PRIVATE ${CFGFFI_LIB})
else()
  message(WARNING "cfgffi library not found; build may fail if not linked elsewhere.")
endif()

# ========= Compile Options =========
target_compile_options(amsftp PRIVATE
  $<$<CXX_COMPILER_ID:MSVC>:/Zi /Od /W4>
)

# target_compile_options(amtest PRIVATE
#   $<$<CXX_COMPILER_ID:MSVC>:/Zi /Od /W4>
# )

# ========= Architecture Guardrail (Workflow-0) =========
if (AMSFTP_ENABLE_LAYER_CHECK)
  find_program(POWERSHELL_EXECUTABLE NAMES pwsh powershell)
  if (POWERSHELL_EXECUTABLE)
    add_custom_target(check_layers
      COMMAND "${POWERSHELL_EXECUTABLE}"
              -NoProfile
              -ExecutionPolicy Bypass
              -File "${PROJECT_SOURCE_DIR}/tools/check_layers.ps1"
              -RepoRoot "${PROJECT_SOURCE_DIR}"
      WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
      COMMENT "Run layered include dependency checks (Workflow-0 guardrail)"
      VERBATIM
    )

    add_custom_target(check_wf7_cutover
      COMMAND "${POWERSHELL_EXECUTABLE}"
              -NoProfile
              -ExecutionPolicy Bypass
              -File "${PROJECT_SOURCE_DIR}/tools/check_wf7_cutover.ps1"
              -RepoRoot "${PROJECT_SOURCE_DIR}"
      WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
      COMMENT "Run WF-7 bridged-header cutover regression check (default phase)"
      VERBATIM
    )

    add_custom_target(check_wf7_cutover_strict
      COMMAND "${POWERSHELL_EXECUTABLE}"
              -NoProfile
              -ExecutionPolicy Bypass
              -File "${PROJECT_SOURCE_DIR}/tools/check_wf7_cutover.ps1"
              -RepoRoot "${PROJECT_SOURCE_DIR}"
              -IncludeSingletonCompat
      WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
      COMMENT "Run WF-7 strict cutover check including singleton-compat headers"
      VERBATIM
    )

    add_custom_target(check_wf7_cutover_manager
      COMMAND "${POWERSHELL_EXECUTABLE}"
              -NoProfile
              -ExecutionPolicy Bypass
              -File "${PROJECT_SOURCE_DIR}/tools/check_wf7_cutover.ps1"
              -RepoRoot "${PROJECT_SOURCE_DIR}"
              -IncludeManagerCompat
      WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
      COMMENT "Run WF-7 manager-compat cutover check (fail on AMManager/* includes)"
      VERBATIM
    )

    add_custom_target(report_legacy_includes
      COMMAND "${POWERSHELL_EXECUTABLE}"
              -NoProfile
              -ExecutionPolicy Bypass
              -File "${PROJECT_SOURCE_DIR}/tools/report_legacy_includes.ps1"
              -RepoRoot "${PROJECT_SOURCE_DIR}"
      WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
      COMMENT "Report legacy include usage counts (Workflow-7 metric)"
      VERBATIM
    )
  else()
    message(WARNING
      "PowerShell executable not found; check_layers/check_wf7_cutover/check_wf7_cutover_strict/check_wf7_cutover_manager/report_legacy_includes targets are unavailable.")
  endif()
endif()
