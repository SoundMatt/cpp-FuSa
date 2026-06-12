//fusa:req REQ-LINT001 REQ-LINT002 REQ-LINT003 REQ-LINT004 REQ-LINT005 REQ-LINT006 REQ-LINT007 REQ-LINT008 REQ-LINT009 REQ-LINT010 REQ-LINT011 REQ-LINT012 REQ-LINT013 REQ-LINT014 REQ-LINT015 REQ-LINT016 REQ-LINT017 REQ-LINT018 REQ-LINT019 REQ-LINT020 REQ-LINT021 REQ-LINT022 REQ-LINT023 REQ-LINT024 REQ-LINT025 REQ-LINT026 REQ-LINT027 REQ-LINT028 REQ-LINT029 REQ-LINT030
#pragma once

#include "cpfusa/fusa.hpp"
#include "../config/config.hpp"
#include <filesystem>
#include <vector>

namespace cpfusa::lint {

// Runs all MISRA/AUTOSAR-inspired lint rules over C++ source in dir.
// Returns one Finding per violation.
[[nodiscard]] std::vector<Finding> run(
    const std::filesystem::path&  dir,
    const config::ProjectConfig&  cfg);

// Individual rule runners (exposed for testing).
[[nodiscard]] std::vector<Finding> check_raw_new_delete(const std::filesystem::path& dir);
[[nodiscard]] std::vector<Finding> check_goto(const std::filesystem::path& dir);
[[nodiscard]] std::vector<Finding> check_reinterpret_cast(const std::filesystem::path& dir);
[[nodiscard]] std::vector<Finding> check_abort_exit(const std::filesystem::path& dir);
[[nodiscard]] std::vector<Finding> check_global_mutable(const std::filesystem::path& dir);
[[nodiscard]] std::vector<Finding> check_define_constant(const std::filesystem::path& dir);
[[nodiscard]] std::vector<Finding> check_c_style_cast(const std::filesystem::path& dir);
[[nodiscard]] std::vector<Finding> check_recursion(const std::filesystem::path& dir);
[[nodiscard]] std::vector<Finding> check_printf(const std::filesystem::path& dir);
[[nodiscard]] std::vector<Finding> check_exception_spec(const std::filesystem::path& dir);

// MISRA C++:2023 extended rules — LINT011–030
[[nodiscard]] std::vector<Finding> check_null_literal(const std::filesystem::path& dir);
[[nodiscard]] std::vector<Finding> check_missing_override(const std::filesystem::path& dir);
[[nodiscard]] std::vector<Finding> check_switch_default(const std::filesystem::path& dir);
[[nodiscard]] std::vector<Finding> check_empty_catch(const std::filesystem::path& dir);
[[nodiscard]] std::vector<Finding> check_throw_in_destructor(const std::filesystem::path& dir);
[[nodiscard]] std::vector<Finding> check_function_like_macro(const std::filesystem::path& dir);
[[nodiscard]] std::vector<Finding> check_setjmp(const std::filesystem::path& dir);
[[nodiscard]] std::vector<Finding> check_dynamic_cast(const std::filesystem::path& dir);
[[nodiscard]] std::vector<Finding> check_union(const std::filesystem::path& dir);
[[nodiscard]] std::vector<Finding> check_volatile(const std::filesystem::path& dir);
[[nodiscard]] std::vector<Finding> check_variadic(const std::filesystem::path& dir);
[[nodiscard]] std::vector<Finding> check_unsafe_string_fn(const std::filesystem::path& dir);
[[nodiscard]] std::vector<Finding> check_unsafe_numeric_conv(const std::filesystem::path& dir);
[[nodiscard]] std::vector<Finding> check_missing_braces(const std::filesystem::path& dir);
[[nodiscard]] std::vector<Finding> check_errno(const std::filesystem::path& dir);
[[nodiscard]] std::vector<Finding> check_c_headers(const std::filesystem::path& dir);
[[nodiscard]] std::vector<Finding> check_undef(const std::filesystem::path& dir);
[[nodiscard]] std::vector<Finding> check_asm(const std::filesystem::path& dir);
[[nodiscard]] std::vector<Finding> check_magic_numbers(const std::filesystem::path& dir);
[[nodiscard]] std::vector<Finding> check_include_guard(const std::filesystem::path& dir);
[[nodiscard]] std::vector<Finding> check_float_equality(const std::filesystem::path& dir);

} // namespace cpfusa::lint
