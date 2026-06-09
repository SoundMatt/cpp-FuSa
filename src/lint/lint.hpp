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

} // namespace cpfusa::lint
