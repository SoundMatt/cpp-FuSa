//fusa:req REQ-AST001 REQ-AST002 REQ-AST003 REQ-AST004 REQ-AST005
#pragma once

#include "cpfusa/fusa.hpp"
#include "../config/config.hpp"
#include <filesystem>
#include <vector>

namespace cpfusa::ast {

// Returns true when the binary was built with libclang support.
// When false, run() returns a single AST000 INFO finding.
[[nodiscard]] bool libclang_available() noexcept;

// Run AST-based safety checks on all C++ source files under dir.
//
// When built with libclang (cmake finds clang-c/Index.h + libclang):
//   AST001 — class with virtual methods but non-virtual destructor (UB risk)
//   AST002 — variable or parameter shadowing outer-scope name
//   AST003 — function returning raw pointer without [[nodiscard]]
//   AST004 — empty class body (no members, no methods) used as base
//   AST005 — bitfield in safety-critical struct without width annotation
//
// When built without libclang:
//   AST000 INFO — "AST analysis unavailable; install libclang to enable"
[[nodiscard]] std::vector<Finding> run(
    const std::filesystem::path& dir,
    const config::ProjectConfig& cfg);

} // namespace cpfusa::ast
