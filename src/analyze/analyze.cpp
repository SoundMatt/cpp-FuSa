#include "analyze.hpp"
#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>
#include <regex>
#include <sstream>
#include <array>
#include <cstdio>
#include <stdexcept>
#include <string>

namespace fs = std::filesystem;
using json   = nlohmann::json;

namespace cpfusa::analyze {

namespace {

using Lines = std::vector<std::pair<int, std::string>>;

[[nodiscard]] Lines read_lines(const fs::path& p) {
    Lines result;
    std::ifstream f(p);
    std::string line;
    int n = 0;
    while (std::getline(f, line)) result.emplace_back(++n, line);
    return result;
}

void for_each_source(const fs::path& dir,
                     const std::function<void(const fs::path&, const Lines&)>& fn) {
    if (!fs::exists(dir)) return;
    static const std::regex ext_re(R"(\.(cpp|hpp|h|hxx|cxx|cc|c\+\+)$)");
    for (const auto& entry : fs::recursive_directory_iterator(
             dir, fs::directory_options::skip_permission_denied)) {
        if (!entry.is_regular_file()) continue;
        if (!std::regex_search(entry.path().string(), ext_re)) continue;
        fn(entry.path(), read_lines(entry.path()));
    }
}

// Run a shell command and return its stdout (empty on failure).
[[nodiscard]] std::string exec_capture(const std::string& cmd) {
    std::array<char, 256> buf{};
    std::string result;
    // NOLINTNEXTLINE(cert-env33-c) — intentional external tool invocation
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) return {};
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe.get())) {
        result += buf.data();
    }
    return result;
}

[[nodiscard]] bool tool_available(const std::string& bin) {
    return std::system(("command -v " + bin + " >/dev/null 2>&1").c_str()) == 0;
}

} // anonymous namespace

// ── clang-tidy integration ──────────────────────────────────────────────────

std::vector<Finding> run_clang_tidy(const fs::path& dir, const std::string& bin) {
    std::vector<Finding> out;
    if (!tool_available(bin)) {
        out.push_back({"ANAL000", Severity::INFO,
                       "clang-tidy not found — install to enable deep static analysis",
                       "", 0, "brew install llvm  # or: apt install clang-tidy"});
        return out;
    }

    auto db = dir / "compile_commands.json";
    if (!fs::exists(db)) {
        out.push_back({"ANAL000", Severity::INFO,
                       "compile_commands.json not found — run cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
                       "", 0, "cmake -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON"});
        return out;
    }

    // Run clang-tidy with JSON output on all source files.
    std::string cmd = bin + " -p " + dir.string()
                    + " --format-style=none"
                    + " $(find " + dir.string() + " -name '*.cpp' | head -200)"
                    + " 2>/dev/null";
    auto raw = exec_capture(cmd);

    // Parse diagnostic lines (clang-tidy text format).
    static const std::regex diag_re(R"((.+):(\d+):\d+:\s+(error|warning|note):\s+(.+)\s+\[(.+)\])");
    std::istringstream ss(raw);
    std::string line;
    while (std::getline(ss, line)) {
        std::smatch m;
        if (!std::regex_search(line, m, diag_re) || m.size() < 6) continue;
        Severity sev = (m[3] == "error") ? Severity::ERROR
                     : (m[3] == "warning") ? Severity::WARNING : Severity::INFO;
        out.push_back({"ANAL001", sev,
                       "[clang-tidy:" + m[5].str() + "] " + m[4].str(),
                       m[1].str(), std::stoi(m[2].str()), ""});
    }
    return out;
}

// ── cppcheck integration ────────────────────────────────────────────────────

std::vector<Finding> run_cppcheck(const fs::path& dir, const std::string& bin) {
    std::vector<Finding> out;
    if (!tool_available(bin)) {
        out.push_back({"ANAL000", Severity::INFO,
                       "cppcheck not found — install to enable additional static analysis",
                       "", 0, "brew install cppcheck  # or: apt install cppcheck"});
        return out;
    }

    std::string cmd = bin + " --enable=all --xml --xml-version=2 "
                    + "--suppress=missingIncludeSystem "
                    + dir.string() + " 2>&1";
    auto raw = exec_capture(cmd);

    // Parse <error> elements from cppcheck XML output.
    static const std::regex err_re(
        R"re(<error\s[^>]*id="([^"]*)"[^>]*severity="([^"]*)"[^>]*msg="([^"]*)"[^>]*/?>)re");
    static const std::regex loc_re(
        R"re(<location\s[^>]*file="([^"]*)"[^>]*line="(\d+)"[^>]*/?>)re");

    std::istringstream ss(raw);
    std::string block;
    std::string xml_content(raw);

    std::sregex_iterator it(xml_content.begin(), xml_content.end(), err_re);
    std::sregex_iterator end;
    for (; it != end; ++it) {
        const std::smatch& em = *it;
        std::string id  = em[1].str();
        std::string sev = em[2].str();
        std::string msg = em[3].str();
        Severity severity = (sev == "error") ? Severity::ERROR
                          : (sev == "warning") ? Severity::WARNING : Severity::INFO;
        out.push_back({"ANAL002", severity,
                       "[cppcheck:" + id + "] " + msg,
                       "", 0, ""});
    }
    return out;
}

// ── Own analysis passes ─────────────────────────────────────────────────────

// ANAL003 – Write to global variable in function without mutex/lock_guard
std::vector<Finding> check_thread_unsafe_global(const fs::path& dir) {
    std::vector<Finding> out;
    // Heuristic: assignment to a known global pattern without adjacent lock.
    // We look for `g_<name> =` or `<name>_ =` patterns without lock_guard nearby.
    static const std::regex global_write(R"(\b(g_\w+|[a-z]\w+_)\s*[+\-\*\/]?=)");
    static const std::regex lock_pat(R"(\b(lock_guard|unique_lock|scoped_lock|mutex)\b)");
    for_each_source(dir, [&](const fs::path& p, const Lines& lines) {
        for (int i = 0; i < static_cast<int>(lines.size()); ++i) {
            const auto& [n, line] = lines[i];
            if (!std::regex_search(line, global_write)) continue;
            if (line.find("fusa:shared") != std::string::npos) continue;
            // Check surrounding 10 lines for a lock.
            bool locked = false;
            for (int j = std::max(0, i-10); j < std::min(static_cast<int>(lines.size()), i+3); ++j) {
                if (std::regex_search(lines[j].second, lock_pat)) { locked = true; break; }
            }
            if (!locked) {
                out.push_back({"ANAL003", Severity::WARNING,
                               "Potential unguarded write to shared variable",
                               p.string(), n,
                               "Protect with std::lock_guard or std::scoped_lock"});
            }
        }
    });
    return out;
}

// ANAL004 – Raw pointer arithmetic
std::vector<Finding> check_raw_ptr_arithmetic(const fs::path& dir) {
    std::vector<Finding> out;
    static const std::regex pat(R"(\w+\s*[\+\-]\s*\d+\s*(?!=)|\w+\[\w+[\+\-]\w+\])");
    static const std::regex smart_ptr(R"(\b(unique_ptr|shared_ptr|span|array)\b)");
    for_each_source(dir, [&](const fs::path& p, const Lines& lines) {
        for (const auto& [n, line] : lines) {
            if (line.find("fusa:unsafe") != std::string::npos) continue;
            if (!std::regex_search(line, pat)) continue;
            if (std::regex_search(line, smart_ptr)) continue;
            // Only flag if there's a * somewhere indicating pointer context.
            if (line.find('*') == std::string::npos && line.find("ptr") == std::string::npos) continue;
            out.push_back({"ANAL004", Severity::WARNING,
                           "Raw pointer arithmetic — prefer std::span or indexed access",
                           p.string(), n,
                           "Use std::span<T> for range-checked pointer + length pairs"});
        }
    });
    return out;
}

// ANAL005 – Loop with no obvious bound or counter
std::vector<Finding> check_unbounded_loop(const fs::path& dir) {
    std::vector<Finding> out;
    // Flag `while (true)` and `for (;;)` without a nearby break/return.
    static const std::regex inf_loop(R"(\bwhile\s*\(\s*(true|1)\s*\)|\bfor\s*\(\s*;\s*;\s*\))");
    for_each_source(dir, [&](const fs::path& p, const Lines& lines) {
        for (int i = 0; i < static_cast<int>(lines.size()); ++i) {
            const auto& [n, line] = lines[i];
            if (!std::regex_search(line, inf_loop)) continue;
            if (line.find("fusa:bounded") != std::string::npos) continue;
            // Check next 20 lines for break/return/timeout.
            bool has_exit = false;
            static const std::regex exit_re(R"(\b(break|return|throw)\b)");
            for (int j = i+1; j < static_cast<int>(lines.size()) && j < i+20; ++j) {
                if (std::regex_search(lines[j].second, exit_re)) { has_exit = true; break; }
            }
            if (!has_exit) {
                out.push_back({"ANAL005", Severity::WARNING,
                               "Potentially unbounded loop — no break/return visible within 20 lines",
                               p.string(), n,
                               "Add // fusa:bounded <max-iterations> annotation or add explicit exit condition"});
            }
        }
    });
    return out;
}

// ANAL006 – Large stack allocation
std::vector<Finding> check_large_stack_alloc(const fs::path& dir) {
    std::vector<Finding> out;
    static const std::regex pat(R"(\bchar\s+\w+\s*\[\s*(\d+)\s*\])");
    constexpr int stack_limit = 4096;
    for_each_source(dir, [&](const fs::path& p, const Lines& lines) {
        for (const auto& [n, line] : lines) {
            std::smatch m;
            if (!std::regex_search(line, m, pat) || m.size() < 2) continue;
            int sz = std::stoi(m[1].str());
            if (sz > stack_limit) {
                out.push_back({"ANAL006", Severity::WARNING,
                               "Large stack allocation (" + std::to_string(sz) + " bytes) — risk of stack overflow",
                               p.string(), n,
                               "Move large buffers to heap (std::vector) or static storage"});
            }
        }
    });
    return out;
}

// ANAL007 – memcpy/memset on non-trivial types
std::vector<Finding> check_memcpy_on_class(const fs::path& dir) {
    std::vector<Finding> out;
    static const std::regex pat(R"(\b(memcpy|memset|memmove)\s*\()");
    for_each_source(dir, [&](const fs::path& p, const Lines& lines) {
        for (const auto& [n, line] : lines) {
            if (!std::regex_search(line, pat)) continue;
            if (line.find("fusa:unsafe") != std::string::npos) continue;
            out.push_back({"ANAL007", Severity::INFO,
                           "memcpy/memset — ensure target type is trivially copyable",
                           p.string(), n,
                           "Use std::copy or assignment operator for non-trivial types"});
        }
    });
    return out;
}

std::vector<Finding> run_own_passes(const fs::path& dir) {
    std::vector<Finding> all;
    auto append = [&](std::vector<Finding> v) {
        all.insert(all.end(), std::make_move_iterator(v.begin()),
                              std::make_move_iterator(v.end()));
    };
    append(check_thread_unsafe_global(dir));
    append(check_raw_ptr_arithmetic(dir));
    append(check_unbounded_loop(dir));
    append(check_large_stack_alloc(dir));
    append(check_memcpy_on_class(dir));
    return all;
}

std::vector<Finding> run(const fs::path& dir,
                         const config::ProjectConfig& /*cfg*/,
                         const AnalyzeOptions& opts) {
    std::vector<Finding> all;
    auto append = [&](std::vector<Finding> v) {
        all.insert(all.end(), std::make_move_iterator(v.begin()),
                              std::make_move_iterator(v.end()));
    };
    if (opts.run_clang_tidy) append(run_clang_tidy(dir, opts.clang_tidy_bin));
    if (opts.run_cppcheck)   append(run_cppcheck(dir, opts.cppcheck_bin));
    if (opts.run_own_passes) append(run_own_passes(dir));
    return all;
}

} // namespace cpfusa::analyze
