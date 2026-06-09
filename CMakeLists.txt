cmake_minimum_required(VERSION 3.21)

project(cpfusa
    VERSION 0.6.0
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

# ── Package info ──────────────────────────────────────────────────────────────
message(STATUS "cpfusa v${PROJECT_VERSION} — C++${CMAKE_CXX_STANDARD} / ${CMAKE_BUILD_TYPE}")
message(STATUS "  Compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
