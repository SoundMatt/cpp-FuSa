#pragma once

#include "cpfusa/fusa.hpp"
#include "../config/config.hpp"
#include <filesystem>
#include <vector>
#include <string>

namespace cpfusa::analyze {

struct AnalyzeOptions {
    bool run_clang_tidy{true};
    bool run_cppcheck{true};
    bool run_own_passes{true};
    std::string clang_tidy_bin{"clang-tidy"};
    std::string cppcheck_bin{"cppcheck"};
};

// Top-level: runs all configured analyzers and returns merged findings.
[[nodiscard]] std::vector<Finding> run(
    const std::filesystem::path&  dir,
    const config::ProjectConfig&  cfg,
    const AnalyzeOptions&         opts = {});

// clang-tidy integration (parses JSON output, requires compile_commands.json).
[[nodiscard]] std::vector<Finding> run_clang_tidy(
    const std::filesystem::path& dir,
    const std::string& bin);

// cppcheck integration (parses XML output).
[[nodiscard]] std::vector<Finding> run_cppcheck(
    const std::filesystem::path& dir,
    const std::string& bin);

// Own analysis passes (regex-based, no external tool dependency).
[[nodiscard]] std::vector<Finding> run_own_passes(
    const std::filesystem::path& dir);

// Individual own passes.
[[nodiscard]] std::vector<Finding> check_thread_unsafe_global(const std::filesystem::path& dir);
[[nodiscard]] std::vector<Finding> check_raw_ptr_arithmetic(const std::filesystem::path& dir);
[[nodiscard]] std::vector<Finding> check_unbounded_loop(const std::filesystem::path& dir);
[[nodiscard]] std::vector<Finding> check_large_stack_alloc(const std::filesystem::path& dir);
[[nodiscard]] std::vector<Finding> check_memcpy_on_class(const std::filesystem::path& dir);

} // namespace cpfusa::analyze
