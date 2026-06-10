#include "lint.hpp"
#include <filesystem>
#include <fstream>
#include <regex>
#include <string>
#include <algorithm>

namespace fs = std::filesystem;

namespace cpfusa::lint {

namespace {

using Lines = std::vector<std::pair<int, std::string>>; // line_number, content

// Read all lines from a file.
[[nodiscard]] Lines read_lines(const fs::path& p) {
    Lines result;
    std::ifstream f(p);
    std::string line;
    int n = 0;
    while (std::getline(f, line)) {
        result.emplace_back(++n, line);
    }
    return result;
}

// Iterate every C++ source file under dir, calling fn(path, lines).
void for_each_source(const fs::path& dir,
                     const std::function<void(const fs::path&, const Lines&)>& fn) {
    if (!fs::exists(dir)) return;
    static const std::regex ext_re(R"(\.(cpp|hpp|h|hxx|cxx|cc|c\+\+)$)");
    for (const auto& entry : fs::recursive_directory_iterator(
             dir, fs::directory_options::skip_permission_denied)) {
        if (!entry.is_regular_file()) continue;
        std::string s = entry.path().string();
        if (!std::regex_search(s, ext_re)) continue;
        fn(entry.path(), read_lines(entry.path()));
    }
}

// Checks if a line has a suppression annotation for a rule.
bool suppressed(const std::string& line, const std::string& rule_id) {
    return line.find("// fusa:suppress " + rule_id) != std::string::npos
        || line.find("// NOLINT") != std::string::npos;
}

// Checks if the file has a file-level suppression for a rule (scans first 20 lines).
bool file_suppressed(const Lines& lines, const std::string& rule_id) {
    int limit = std::min(static_cast<int>(lines.size()), 20);
    for (int i = 0; i < limit; ++i)
        if (lines[i].second.find("// fusa:file-suppress " + rule_id) != std::string::npos)
            return true;
    return false;
}

// Checks if the previous line is a fusa:safe-state annotation.
bool has_safe_state_above(const Lines& lines, int idx) {
    if (idx <= 0) return false;
    const auto& prev = lines[idx - 1].second;
    return prev.find("fusa:safe-state") != std::string::npos;
}

} // anonymous namespace

// LINT001 – Raw new/delete usage (MISRA C++:2023 A18-5-2) //fusa:req REQ-LINT001
std::vector<Finding> check_raw_new_delete(const fs::path& dir) {
    std::vector<Finding> out;
    // Matches `new` or `delete` as standalone keywords (not part of identifiers).
    static const std::regex pat(R"(\bnew\b|\bdelete\b)");
    // Allowlist: placement new, operator new/delete, deleted functions (= delete), string literals.
    static const std::regex allow(R"((operator\s+(new|delete)|=\s*delete|"[^"]*\b(new|delete)\b[^"]*"|//\s*fusa:unsafe))");
    for_each_source(dir, [&](const fs::path& p, const Lines& lines) {
        for (const auto& [n, line] : lines) {
            if (suppressed(line, "LINT001")) continue;
            if (!std::regex_search(line, pat)) continue;
            if (std::regex_search(line, allow)) continue;
            // Skip comment lines.
            auto trimmed = line.find_first_not_of(" \t");
            if (trimmed != std::string::npos && line[trimmed] == '/') continue;
            out.push_back({"LINT001", Severity::WARNING,
                           "Raw new/delete usage — prefer std::make_unique / std::make_shared",
                           p.string(), n,
                           "Replace with smart pointer factory or container"});
        }
    });
    return out;
}

// LINT002 – goto statement (MISRA C++:2023 A6-6-1) //fusa:req REQ-LINT002
std::vector<Finding> check_goto(const fs::path& dir) {
    std::vector<Finding> out;
    static const std::regex pat(R"(\bgoto\b)");
    static const std::regex allow_str(R"("[^"]*\bgoto\b[^"]*")");
    for_each_source(dir, [&](const fs::path& p, const Lines& lines) {
        for (const auto& [n, line] : lines) {
            if (suppressed(line, "LINT002")) continue;
            // Skip comment lines and string literals containing 'goto'.
            auto trimmed = line.find_first_not_of(" \t");
            if (trimmed != std::string::npos && line[trimmed] == '/') continue;
            if (std::regex_search(line, allow_str)) continue;
            if (std::regex_search(line, pat)) {
                out.push_back({"LINT002", Severity::ERROR,
                               "goto statement is prohibited (MISRA C++ A6-6-1)", // fusa:suppress LINT002
                               p.string(), n,
                               "Refactor control flow using structured constructs"});
            }
        }
    });
    return out;
}

// LINT003 – reinterpret_cast without justification (MISRA C++:2023 A5-2-4) //fusa:req REQ-LINT003
std::vector<Finding> check_reinterpret_cast(const fs::path& dir) {
    std::vector<Finding> out;
    static const std::regex pat(R"(\breinterpret_cast\b)");
    static const std::regex allow_str(R"("[^"]*\breinterpret_cast\b[^"]*")");
    for_each_source(dir, [&](const fs::path& p, const Lines& lines) {
        for (int i = 0; i < static_cast<int>(lines.size()); ++i) {
            const auto& [n, line] = lines[i];
            if (suppressed(line, "LINT003")) continue;
            if (std::regex_search(line, allow_str)) continue;
            // Skip comment lines.
            auto trimmed = line.find_first_not_of(" \t");
            if (trimmed != std::string::npos && line[trimmed] == '/') continue;
            if (!std::regex_search(line, pat)) continue;
            // Require a justification comment on the same or previous line.
            bool justified = line.find("fusa:unsafe") != std::string::npos
                          || (i > 0 && lines[i-1].second.find("fusa:unsafe") != std::string::npos);
            if (!justified) {
                out.push_back({"LINT003", Severity::WARNING,
                               "reinterpret_cast without justification (MISRA A5-2-4)", // fusa:suppress LINT003
                               p.string(), n,
                               "Add // fusa:unsafe <justification> comment above or inline"});
            }
        }
    });
    return out;
}

// LINT004 – abort()/exit() without safe-state transition (MISRA C++:2023 A15-5-3) //fusa:req REQ-LINT004
std::vector<Finding> check_abort_exit(const fs::path& dir) {
    std::vector<Finding> out;
    static const std::regex pat(R"(\b(std::abort|::abort|abort|std::exit|::exit|exit|_Exit|quick_exit)\s*\()");
    static const std::regex in_str(R"("[^"]*\b(abort|exit)\s*\([^"]*")");
    for_each_source(dir, [&](const fs::path& p, const Lines& lines) {
        if (file_suppressed(lines, "LINT004")) return;
        for (int i = 0; i < static_cast<int>(lines.size()); ++i) {
            const auto& [n, line] = lines[i];
            if (suppressed(line, "LINT004")) continue;
            if (std::regex_search(line, in_str)) continue;
            // Skip comment lines.
            auto trimmed = line.find_first_not_of(" \t");
            if (trimmed != std::string::npos && line[trimmed] == '/') continue;
            if (!std::regex_search(line, pat)) continue;
            if (!has_safe_state_above(lines, i)) {
                out.push_back({"LINT004", Severity::ERROR,
                               "abort()/exit() without preceding safe-state transition",
                               p.string(), n,
                               "Add // fusa:safe-state comment and call safe-state handler before abort"});
            }
        }
    });
    return out;
}

// LINT005 – Global mutable variable without sync annotation (AUTOSAR A3-3-2) //fusa:req REQ-LINT005
std::vector<Finding> check_global_mutable(const fs::path& dir) {
    std::vector<Finding> out;
    // Heuristic: non-const, non-static-local variable at file scope.
    // Matches lines that look like global definitions: no indent, has type keyword.
    static const std::regex pat(
        R"(^(int|long|short|char|bool|float|double|unsigned|size_t|uint\w+|int\w+)\s+\w+\s*[=;])");
    static const std::regex const_pat(R"(\bconst\b|\bconstexpr\b|\bextern\b)");
    for_each_source(dir, [&](const fs::path& p, const Lines& lines) {
        for (const auto& [n, line] : lines) {
            if (suppressed(line, "LINT005")) continue;
            if (!std::regex_search(line, pat)) continue;
            if (std::regex_search(line, const_pat)) continue;
            if (line.find("fusa:shared") != std::string::npos) continue;
            out.push_back({"LINT005", Severity::WARNING,
                           "Global mutable variable without synchronisation annotation (AUTOSAR A3-3-2)",
                           p.string(), n,
                           "Mark with // fusa:shared or make const/constexpr/thread_local"});
        }
    });
    return out;
}

// LINT006 – #define used for numeric/string constant (MISRA C++:2023 A2-13-1) //fusa:req REQ-LINT006
std::vector<Finding> check_define_constant(const fs::path& dir) {
    std::vector<Finding> out;
    static const std::regex pat(R"(^\s*#\s*define\s+\w+\s+[\d"'.])");
    for_each_source(dir, [&](const fs::path& p, const Lines& lines) {
        for (const auto& [n, line] : lines) {
            if (suppressed(line, "LINT006")) continue;
            if (std::regex_search(line, pat)) {
                out.push_back({"LINT006", Severity::WARNING,
                               "#define used for constant — prefer constexpr (MISRA A2-13-1)",
                               p.string(), n,
                               "Replace #define with constexpr variable"});
            }
        }
    });
    return out;
}

// LINT007 – C-style cast (MISRA C++:2023 A5-2-2) //fusa:req REQ-LINT007
std::vector<Finding> check_c_style_cast(const fs::path& dir) {
    std::vector<Finding> out;
    // Matches (type)expr patterns — avoids false-positives on function calls.
    static const std::regex pat(
        R"(\((\s*)(int|long|short|char|bool|float|double|unsigned|void\s*\*|size_t)\s*\)\s*\w)");
    static const std::regex in_str(R"("[^"]*\([^")]*\)[^"]*")");
    for_each_source(dir, [&](const fs::path& p, const Lines& lines) {
        for (const auto& [n, line] : lines) {
            if (suppressed(line, "LINT007")) continue;
            if (std::regex_search(line, in_str)) continue;
            if (std::regex_search(line, pat)) {
                out.push_back({"LINT007", Severity::WARNING,
                               "C-style cast detected — use static_cast/reinterpret_cast/const_cast (MISRA A5-2-2)", // fusa:suppress LINT003
                               p.string(), n,
                               "Replace with appropriate named cast"});
            }
        }
    });
    return out;
}

// LINT008 – Recursive function (MISRA C++:2023 A7-1-1 / JSF++ 119) //fusa:req REQ-LINT008
std::vector<Finding> check_recursion(const fs::path& dir) {
    std::vector<Finding> out;
    // Heuristic: find function definitions then check if they call themselves.
    static const std::regex fn_def(R"(^(\w[\w\s\*\&:<>]*)\s+(\w+)\s*\([^)]*\)\s*(const)?\s*\{?)");
    for_each_source(dir, [&](const fs::path& p, const Lines& lines) {
        std::string current_fn;
        int depth = 0;
        int fn_entry_depth = -1; // brace depth just before the function's own '{'
        for (const auto& [n, line] : lines) {
            // Match function definition BEFORE counting braces so fn_entry_depth
            // records the depth at which the function's opening '{' sits.
            std::smatch m;
            if (std::regex_search(line, m, fn_def) && m.size() > 2) {
                current_fn = m[2].str();
                fn_entry_depth = depth;
            }
            // Track brace depth; when we return to fn_entry_depth the body has closed.
            for (char c : line) {
                if (c == '{') ++depth;
                else if (c == '}' && depth > 0) {
                    --depth;
                    if (!current_fn.empty() && depth == fn_entry_depth) {
                        current_fn.clear();
                        fn_entry_depth = -1;
                    }
                }
            }
            if (suppressed(line, "LINT008")) continue;
            if (current_fn.empty()) continue;
            if (line.find("fusa:recursive") != std::string::npos) continue;
            // Simple self-call detection — skip the definition line itself.
            // Exclude member access (foo.fn()) and qualified calls (ns::fn()).
            std::regex self_call("\\b" + current_fn + "\\s*\\(");
            std::smatch sc_match;
            if (std::regex_search(line, sc_match, self_call)
                    && !std::regex_search(line, fn_def)) {
                auto pos = sc_match.position();
                bool qualified = pos >= 1 && (line[pos-1] == '.' || line[pos-1] == ':');
                if (!qualified) {
                    out.push_back({"LINT008", Severity::WARNING,
                                   "Recursive call to '" + current_fn + "' — add depth-bound guard (JSF++ 119)",
                                   p.string(), n,
                                   "Add // fusa:recursive <max-depth> annotation or refactor iteratively"});
                }
            }
        }
    });
    return out;
}

// LINT009 – printf/scanf family usage (type-unsafe I/O) //fusa:req REQ-LINT009
std::vector<Finding> check_printf(const fs::path& dir) {
    std::vector<Finding> out;
    static const std::regex pat(
        R"(\b(printf|fprintf|sprintf|snprintf|scanf|fscanf|sscanf|vprintf|vsprintf|vsnprintf)\s*\()");
    static const std::regex in_str(R"("[^"]*\b(printf|fprintf|sprintf|snprintf|scanf|fscanf|sscanf|vprintf|vsprintf|vsnprintf)\b[^"]*")");
    for_each_source(dir, [&](const fs::path& p, const Lines& lines) {
        for (const auto& [n, line] : lines) {
            if (suppressed(line, "LINT009")) continue;
            if (std::regex_search(line, in_str)) continue;
            // Skip comment lines.
            auto trimmed = line.find_first_not_of(" \t");
            if (trimmed != std::string::npos && line[trimmed] == '/') continue;
            if (std::regex_search(line, pat)) {
                out.push_back({"LINT009", Severity::INFO,
                               "printf/scanf family — prefer type-safe I/O (std::format, std::ostream)",
                               p.string(), n,
                               "Replace with std::format (C++20) or std::ostringstream"});
            }
        }
    });
    return out;
}

// LINT010 – Function throwing exceptions without noexcept or documented spec //fusa:req REQ-LINT010
std::vector<Finding> check_exception_spec(const fs::path& dir) {
    std::vector<Finding> out;
    // Look for function definitions that might throw but have no noexcept.
    static const std::regex fn_def(
        R"(^\s*[\w\*\&:<>]+\s+\w+\s*\([^;]*\)\s*\{)");
    static const std::regex noexcept_re(R"(\bnoexcept\b)");
    for_each_source(dir, [&](const fs::path& p, const Lines& lines) {
        for (int i = 0; i < static_cast<int>(lines.size()); ++i) {
            const auto& [n, line] = lines[i];
            if (suppressed(line, "LINT010")) continue;
            if (!std::regex_search(line, fn_def)) continue;
            if (std::regex_search(line, noexcept_re)) continue;
            // If the function body contains 'throw', flag it.
            bool has_throw = false;
            static const std::regex throw_re(R"(\bthrow\b)");
            for (int j = i; j < static_cast<int>(lines.size()) && j < i + 30; ++j) {
                if (std::regex_search(lines[j].second, throw_re)) { has_throw = true; break; }
                if (lines[j].second.find('}') != std::string::npos) break;
            }
            if (has_throw) {
                out.push_back({"LINT010", Severity::INFO,
                               "Function uses throw without noexcept specification",
                               p.string(), n,
                               "Mark non-throwing functions noexcept; document throwing ones"});
            }
        }
    });
    return out;
}

std::vector<Finding> run(const fs::path& dir,
                         const config::ProjectConfig& cfg) {
    std::vector<Finding> all;
    auto append = [&](std::vector<Finding> v) {
        all.insert(all.end(), std::make_move_iterator(v.begin()),
                              std::make_move_iterator(v.end()));
    };
    append(check_raw_new_delete(dir));
    append(check_goto(dir));
    append(check_reinterpret_cast(dir));
    append(check_abort_exit(dir));
    append(check_global_mutable(dir));
    append(check_define_constant(dir));
    append(check_c_style_cast(dir));
    append(check_recursion(dir));
    append(check_printf(dir));
    append(check_exception_spec(dir));

    // Remove findings from paths that match any exclude pattern.
    if (!cfg.exclude_patterns.empty()) {
        all.erase(std::remove_if(all.begin(), all.end(), [&](const Finding& f) {
            for (const auto& pat : cfg.exclude_patterns)
                if (f.file.find(pat) != std::string::npos) return true;
            return false;
        }), all.end());
    }
    return all;
}

} // namespace cpfusa::lint
