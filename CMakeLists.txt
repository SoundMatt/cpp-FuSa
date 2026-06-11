cmake_minimum_required(VERSION 3.21)

project(cpfusa
    VERSION 0.9.2
    DESCRIPTION "C++ Functional Safety Toolkit"
    HOMEPAGE_URL "https://github.com/SoundMatt/cpp-FuSa"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Export compile commands for clang-tidy integration.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Strict warnings — we dogfood our own lint rules.
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    add_compile_options(
        -Wall -Wextra -Wpedantic
        -Wshadow -Wnon-virtual-dtor
        -Wold-style-cast -Wcast-align
        -Wunused -Woverloaded-virtual
        -Wno-unused-parameter
    )
endif()
if(MSVC)
    add_compile_options(
        /W4 /WX
        /wd4100   # unreferenced formal parameter (matches -Wno-unused-parameter)
        /wd4996   # deprecated CRT functions (gmtime safe for internal timestamps)
    )
endif()

# ── Optional: libclang for AST analysis ──────────────────────────────────────
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(LibClang QUIET)
if(LibClang_FOUND)
    message(STATUS "libclang found — AST analysis enabled (${LibClang_LIBRARY})")
else()
    message(STATUS "libclang not found — AST analysis will run in stub mode")
    message(STATUS "  Install: brew install llvm  |  apt install libclang-dev")
endif()

# ── Fetch dependencies ────────────────────────────────────────────────────────
include(cmake/FetchDeps.cmake)

# ── Library target ────────────────────────────────────────────────────────────
add_library(cpfusa_lib STATIC
    src/config/config.cpp
    src/engine/engine.cpp
    src/engine/rules.cpp
    src/report/report.cpp
    src/lint/lint.cpp
    src/analyze/analyze.cpp
    src/trace/trace.cpp
    src/template/template_gen.cpp
    src/cyber/cyber.cpp
    src/verify/verify.cpp
    src/qualify/qualify.cpp
    src/release/release.cpp
    src/auditpack/auditpack.cpp
    src/badge/badge.cpp
    src/diff/diff.cpp
    src/sign/sign.cpp
    src/hooks/hooks.cpp
    src/tara/tara.cpp
    src/fmea/fmea.cpp
    src/safety_case/safety_case.cpp
    src/hara/hara.cpp
    src/iso26262/iso26262.cpp
    src/iec61508/iec61508.cpp
    src/boundary/boundary.cpp
    src/metrics/metrics.cpp
    src/vuln/vuln.cpp
    src/coverage/coverage.cpp
    src/disposition/disposition.cpp
    src/impact/impact.cpp
    src/do178/do178.cpp
    src/sas/sas.cpp
    src/sci/sci.cpp
    src/pr/pr.cpp
    src/fix/fix.cpp
    src/misra/misra.cpp
    src/coupling/coupling.cpp
    src/iec62443/iec62443.cpp
    src/slsa/slsa.cpp
    src/iso21434/iso21434.cpp
    src/unece/unece.cpp
    src/ast/ast.cpp
    src/cmd/cli.cpp
)

target_include_directories(cpfusa_lib
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(cpfusa_lib
    PUBLIC
        nlohmann_json::nlohmann_json
        CLI11::CLI11
)

# Thread support required by runtime headers.
find_package(Threads REQUIRED)
target_link_libraries(cpfusa_lib PUBLIC Threads::Threads)

# Wire libclang when available.
if(LibClang_FOUND)
    target_compile_definitions(cpfusa_lib PUBLIC CPFUSA_HAS_LIBCLANG)
    target_include_directories(cpfusa_lib PRIVATE ${LibClang_INCLUDE_DIRS})
    target_link_libraries(cpfusa_lib PUBLIC LibClang::LibClang)
endif()

# ── CLI binary ────────────────────────────────────────────────────────────────
add_executable(cpfusa src/main.cpp)
target_link_libraries(cpfusa PRIVATE cpfusa_lib)

install(TARGETS cpfusa RUNTIME DESTINATION bin)

# ── Tests ─────────────────────────────────────────────────────────────────────
option(CPFUSA_BUILD_TESTS "Build tests" ON)
if(CPFUSA_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# ── CPack packaging ───────────────────────────────────────────────────────────
set(CPACK_PACKAGE_NAME              "cpfusa")
set(CPACK_PACKAGE_VENDOR            "SoundMatt")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "C++ Functional Safety Enablement Toolkit")
set(CPACK_PACKAGE_VERSION           ${PROJECT_VERSION})
set(CPACK_PACKAGE_VERSION_MAJOR     ${PROJECT_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR     ${PROJECT_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH     ${PROJECT_VERSION_PATCH})
set(CPACK_PACKAGE_HOMEPAGE_URL      "https://github.com/SoundMatt/cpp-FuSa")
set(CPACK_RESOURCE_FILE_LICENSE     "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_PACKAGE_INSTALL_DIRECTORY "cpp-FuSa")
set(CPACK_STRIP_FILES               ON)

# NSIS — Windows installer
set(CPACK_NSIS_DISPLAY_NAME    "cpp-FuSa ${PROJECT_VERSION}")
set(CPACK_NSIS_PACKAGE_NAME    "cpp-FuSa")
set(CPACK_NSIS_URL_INFO_ABOUT  "https://github.com/SoundMatt/cpp-FuSa")
set(CPACK_NSIS_CONTACT         "https://github.com/SoundMatt/cpp-FuSa/issues")
set(CPACK_NSIS_MODIFY_PATH     ON)
set(CPACK_NSIS_ENABLE_UNINSTALL_BEFORE_INSTALL ON)

# WiX — Windows MSI (alternative to NSIS)
set(CPACK_WIX_UPGRADE_GUID "3F8A2B1C-4D5E-6F70-89AB-CDEF01234567")
set(CPACK_WIX_PRODUCT_NAME "cpp-FuSa ${PROJECT_VERSION}")

# DEB — Debian/Ubuntu
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "SoundMatt <https://github.com/SoundMatt>")
set(CPACK_DEBIAN_PACKAGE_SECTION    "devel")
set(CPACK_DEBIAN_PACKAGE_DEPENDS    "libc6 (>= 2.17), libstdc++6 (>= 10)")
set(CPACK_DEBIAN_FILE_NAME          DEB-DEFAULT)

# RPM — Fedora/RHEL
set(CPACK_RPM_PACKAGE_LICENSE   "MPL-2.0")
set(CPACK_RPM_PACKAGE_GROUP     "Development/Tools")
set(CPACK_RPM_PACKAGE_URL       "https://github.com/SoundMatt/cpp-FuSa")
set(CPACK_RPM_FILE_NAME         RPM-DEFAULT)

include(CPack)

# ── Package info ──────────────────────────────────────────────────────────────
message(STATUS "cpfusa v${PROJECT_VERSION} — C++${CMAKE_CXX_STANDARD} / ${CMAKE_BUILD_TYPE}")
message(STATUS "  Compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
