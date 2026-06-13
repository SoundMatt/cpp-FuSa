#include "analyze.hpp"
#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>
#include <regex>
#include <sstream>
#include <array>
#include <cstdio>
#include <string>
#ifdef _WIN32
#  define popen  _popen
#  define pclose _pclose
#endif

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

//fusa:req REQ-ANAL013
void for_each_source(const fs::path& dir,
                     const std::function<void(const fs::path&, const Lines&)>& fn) {
    if (!fs::exists(dir)) return;
    static const std::regex ext_re(R"(\.(cpp|hpp|h|hxx|cxx|cc|c\+\+)$)");
    for (const auto& entry : fs::recursive_directory_iterator(
             dir, fs::directory_options::skip_permission_denied)) {
        if (!entry.is_regular_file()) continue;
        if (!std::regex_search(entry.path().string(), ext_re)) continue;
        // §4 MUST: emit project-relative paths so findings are portable.
        fs::path rel = fs::relative(entry.path(), dir);
        fn(rel, read_lines(entry.path()));
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

// Lightweight function-body extractor shared by ANAL008/009/012.
struct FuncBlock { std::string name; int start_line; std::string body; };

[[nodiscard]] std::vector<FuncBlock> extract_func_blocks(const Lines& lines) {
    std::vector<FuncBlock> out;
    static const std::regex sig_re(
        R"(^[\w:~<>\*&\s]+\s+(\w+)\s*\([^)]*\)\s*(?:const\s*)?(?:noexcept\s*)?(?:override\s*)?\{)"
    );
    static const std::regex keyword_re(R"(\b(if|else|for|while|do|switch|catch)\b)");

    int brace_depth = 0;
    bool in_func = false;
    std::string func_name;
    int func_start = 0;
    std::string func_body;

    for (const auto& [n, line] : lines) {
        if (!in_func) {
            std::smatch m;
            if (std::regex_search(line, m, sig_re) &&
                !std::regex_search(m[1].str(), keyword_re)) {
                func_name  = m[1].str();
                func_start = n;
                brace_depth = 0;
                func_body.clear();
                for (char c : line) {
                    if (c == '{') { ++brace_depth; in_func = true; }
                    else if (c == '}') { --brace_depth; }
                }
            }
        } else {
            func_body += line + "\n";
            for (char c : line) {
                if (c == '{') { ++brace_depth; }
                else if (c == '}') {
                    if (--brace_depth == 0) {
                        out.push_back({func_name, func_start, func_body});
                        in_func = false;
                        func_body.clear();
                        break;
                    }
                }
            }
        }
    }
    return out;
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
        // §4 MUST: relativize clang-tidy's absolute file path.
        std::string rel_file;
        try { rel_file = fs::relative(fs::path(m[1].str()), dir).generic_string(); }
        catch (...) { rel_file = m[1].str(); }
        out.push_back({"ANAL001", sev,
                       "[clang-tidy:" + m[5].str() + "] " + m[4].str(),
                       rel_file, std::stoi(m[2].str()), ""});
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
//fusa:req REQ-ANAL001 REQ-ANAL003
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
//fusa:req REQ-ANAL002 REQ-ANAL004
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
//fusa:req REQ-ANAL005
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

// ANAL008 – Function body > 60 lines
//fusa:req REQ-ANAL008
std::vector<Finding> check_function_length(const fs::path& dir) {
    std::vector<Finding> out;
    constexpr int MAX_LINES = 60;
    for_each_source(dir, [&](const fs::path& p, const Lines& lines) {
        for (const auto& fn : extract_func_blocks(lines)) {
            int count = static_cast<int>(
                std::count(fn.body.begin(), fn.body.end(), '\n'));
            if (count > MAX_LINES) {
                out.push_back({"ANAL008", Severity::WARNING,
                    "Function '" + fn.name + "' is " + std::to_string(count) +
                    " lines (max: " + std::to_string(MAX_LINES) + ")",
                    p.string(), fn.start_line,
                    "Refactor into smaller functions with single responsibility"});
            }
        }
    });
    return out;
}

// ANAL009 – Nesting depth > 5 within a function body
//fusa:req REQ-ANAL009
std::vector<Finding> check_nesting_depth(const fs::path& dir) {
    std::vector<Finding> out;
    constexpr int MAX_DEPTH = 5;
    for_each_source(dir, [&](const fs::path& p, const Lines& lines) {
        for (const auto& fn : extract_func_blocks(lines)) {
            int depth = 0;
            int body_line = fn.start_line;
            bool flagged = false;
            std::istringstream ss(fn.body);
            std::string line;
            while (!flagged && std::getline(ss, line)) {
                ++body_line;
                for (char c : line) {
                    if (c == '{') {
                        if (++depth > MAX_DEPTH) {
                            out.push_back({"ANAL009", Severity::WARNING,
                                "Nesting depth " + std::to_string(depth) +
                                " in '" + fn.name + "' exceeds limit of " +
                                std::to_string(MAX_DEPTH),
                                p.string(), body_line,
                                "Reduce nesting via early returns or helper functions"});
                            flagged = true;
                            break;
                        }
                    } else if (c == '}') {
                        --depth;
                    }
                }
            }
        }
    });
    return out;
}

// ANAL010 – Function with more than 7 parameters
//fusa:req REQ-ANAL010
std::vector<Finding> check_parameter_count(const fs::path& dir) {
    std::vector<Finding> out;
    constexpr int MAX_PARAMS = 7;
    static const std::regex sig_re(
        R"(^\s*[\w:~<>\*&\s]+\s+(\w+)\s*\(([^)]+)\)\s*(?:const\s*)?(?:noexcept\s*)?\s*[{;])"
    );
    static const std::regex keyword_re(R"(\b(if|else|for|while|do|switch|catch|return)\b)");
    for_each_source(dir, [&](const fs::path& p, const Lines& lines) {
        for (const auto& [n, line] : lines) {
            std::smatch m;
            if (!std::regex_search(line, m, sig_re)) continue;
            if (std::regex_search(m[1].str(), keyword_re)) continue;
            std::string params = m[2].str();
            // Trim and check for (void)
            auto trim_start = params.find_first_not_of(" \t");
            if (trim_start == std::string::npos) continue;
            std::string trimmed = params.substr(trim_start);
            if (trimmed == "void" || trimmed == "void ") continue;
            // Count commas outside template angle brackets
            int depth = 0;
            int commas = 0;
            for (char c : params) {
                if (c == '<') ++depth;
                else if (c == '>') { if (depth > 0) --depth; }
                else if (c == ',' && depth == 0) ++commas;
            }
            if (commas + 1 > MAX_PARAMS) {
                out.push_back({"ANAL010", Severity::WARNING,
                    "Function '" + m[1].str() + "' has " +
                    std::to_string(commas + 1) +
                    " parameters (max: " + std::to_string(MAX_PARAMS) + ")",
                    p.string(), n,
                    "Bundle parameters into a config struct to reduce interface complexity"});
            }
        }
    });
    return out;
}

// ANAL011 – C-style narrowing integer cast (silent truncation)
//fusa:req REQ-ANAL011
std::vector<Finding> check_integer_truncating_cast(const fs::path& dir) {
    std::vector<Finding> out;
    static const std::regex cast_re(
        R"X(\(\s*(?:u?int(?:8|16)_t|unsigned\s+char|(?:unsigned\s+)?short)\s*\)\s*\w)X"
    );
    for_each_source(dir, [&](const fs::path& p, const Lines& lines) {
        for (const auto& [n, line] : lines) {
            if (line.find("fusa:unsafe") != std::string::npos) continue;
            if (std::regex_search(line, cast_re)) {
                out.push_back({"ANAL011", Severity::WARNING,
                    "Narrowing integer cast — silent truncation may lose data",
                    p.string(), n,
                    "Use static_cast with a range check, or annotate // fusa:unsafe if intentional"});
            }
        }
    });
    return out;
}

// ANAL012 – More than 3 explicit return points in a function
//fusa:req REQ-ANAL012
std::vector<Finding> check_multiple_returns(const fs::path& dir) {
    std::vector<Finding> out;
    constexpr int MAX_RETURNS = 3;
    static const std::regex ret_re(R"(\breturn\b)");
    for_each_source(dir, [&](const fs::path& p, const Lines& lines) {
        for (const auto& fn : extract_func_blocks(lines)) {
            int count = 0;
            for (std::sregex_iterator it(fn.body.begin(), fn.body.end(), ret_re), end;
                 it != end; ++it) {
                ++count;
            }
            if (count > MAX_RETURNS) {
                out.push_back({"ANAL012", Severity::INFO,
                    "Function '" + fn.name + "' has " + std::to_string(count) +
                    " return points (max: " + std::to_string(MAX_RETURNS) + ")",
                    p.string(), fn.start_line,
                    "Consider restructuring to reduce exit points for clarity"});
            }
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
    append(check_function_length(dir));
    append(check_nesting_depth(dir));
    append(check_parameter_count(dir));
    append(check_integer_truncating_cast(dir));
    append(check_multiple_returns(dir));
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
