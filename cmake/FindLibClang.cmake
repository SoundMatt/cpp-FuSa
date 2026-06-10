# FindLibClang.cmake — optional libclang detection for AST analysis
#
# Exports:
#   LibClang_FOUND        — TRUE when both library and headers are present
#   LibClang_INCLUDE_DIRS — directories containing clang-c/Index.h
#   LibClang_LIBRARIES    — libclang shared library
#   LibClang::LibClang    — imported target (SHARED_LIBRARY)
#
# Search hints (append your own via CMAKE_PREFIX_PATH or LLVM_DIR):
#   brew install llvm     → /opt/homebrew/opt/llvm  (macOS arm64)
#                        → /usr/local/opt/llvm      (macOS x86_64)
#   apt install libclang-dev → /usr/lib/llvm-XX/

# ── Prefer LLVM cmake package if available ────────────────────────────────────
find_package(LLVM QUIET CONFIG)
if(LLVM_FOUND)
    set(_llvm_inc ${LLVM_INCLUDE_DIRS})
    set(_llvm_lib ${LLVM_LIBRARY_DIRS})
endif()

# ── Header search ─────────────────────────────────────────────────────────────
find_path(LibClang_INCLUDE_DIR
    NAMES clang-c/Index.h
    HINTS
        ${_llvm_inc}
        $ENV{LLVM_DIR}/include
        $ENV{LLVM_DIR}/../include
    PATHS
        /usr/lib/llvm-20/include
        /usr/lib/llvm-19/include
        /usr/lib/llvm-18/include
        /usr/lib/llvm-17/include
        /usr/lib/llvm-16/include
        /usr/lib/llvm-15/include
        /usr/lib/llvm-14/include
        /usr/local/opt/llvm/include
        /opt/homebrew/opt/llvm/include
        /usr/include
        /usr/local/include
    DOC "Directory containing clang-c/Index.h"
)

# ── Library search ────────────────────────────────────────────────────────────
find_library(LibClang_LIBRARY
    NAMES clang libclang
    HINTS
        ${_llvm_lib}
        $ENV{LLVM_DIR}/lib
        $ENV{LLVM_DIR}/../lib
    PATHS
        /usr/lib/llvm-20/lib
        /usr/lib/llvm-19/lib
        /usr/lib/llvm-18/lib
        /usr/lib/llvm-17/lib
        /usr/lib/llvm-16/lib
        /usr/lib/llvm-15/lib
        /usr/lib/llvm-14/lib
        /usr/local/opt/llvm/lib
        /opt/homebrew/opt/llvm/lib
        /usr/lib
        /usr/local/lib
        /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib
    DOC "libclang shared library"
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibClang
    REQUIRED_VARS LibClang_LIBRARY LibClang_INCLUDE_DIR
    VERSION_VAR   LibClang_VERSION
)

if(LibClang_FOUND AND NOT TARGET LibClang::LibClang)
    set(LibClang_INCLUDE_DIRS ${LibClang_INCLUDE_DIR})
    set(LibClang_LIBRARIES    ${LibClang_LIBRARY})
    add_library(LibClang::LibClang UNKNOWN IMPORTED)
    set_target_properties(LibClang::LibClang PROPERTIES
        IMPORTED_LOCATION             "${LibClang_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${LibClang_INCLUDE_DIR}"
    )
endif()

mark_as_advanced(LibClang_INCLUDE_DIR LibClang_LIBRARY)
