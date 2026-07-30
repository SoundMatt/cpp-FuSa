#include "lint.hpp"
#include <filesystem>
#include <functional>
#include <fstream>
#include <regex>
#include <string>
#include <algorithm>

namespace fs = std::filesystem;

namespace cpfusa::lint {

namespace {

using Lines = std::vector<std::pair<int, std::string>>; // line_number, content

// Canonical standard ids (§2.4.1 of the x-FuSa spec).
constexpr const char* kAutosarCpp14 = "autosar-cpp14";
constexpr const char* kMisraCpp     = "misra-cpp";

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

// Builds a Finding and stamps it with its canonical standard id (§2.4.1).
// Every check_* function funnels its Finding construction through this so
// production lint output always carries a real `standard_id` — see
// cpp-FuSa-06/07: AUTOSAR-C++14 rules are "A"-numbered, MISRA-C++:2008
// rules (imported into the AUTOSAR C++14 guideline set, and also cited
// bare as "Rule N-N-N") are "M"-numbered; neither family is MISRA C++:2023.
Finding make_finding(std::string rule_id, Severity sev, std::string msg,
                     std::string file, int line, std::string remediation,
                     std::string standard_id) {
    Finding f{std::move(rule_id), sev, std::move(msg), std::move(file), line,
              std::move(remediation), "lint"};
    f.standard_id = std::move(standard_id);
    return f;
}

} // anonymous namespace

// LINT001 – Raw new/delete usage (AUTOSAR C++14 A18-5-2) //fusa:req REQ-LINT001
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
            out.push_back(make_finding("LINT001", Severity::WARNING,
                           "Raw new/delete usage — prefer std::make_unique / std::make_shared (AUTOSAR C++14 A18-5-2)",
                           fs::relative(p, dir).generic_string(), n,
                           "Replace with smart pointer factory or container", kAutosarCpp14));
        }
    });
    return out;
}

// LINT002 – goto statement (AUTOSAR C++14 A6-6-1) //fusa:req REQ-LINT002
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
                out.push_back(make_finding("LINT002", Severity::ERROR,
                               "goto statement is prohibited (AUTOSAR C++14 A6-6-1)", // fusa:suppress LINT002
                               fs::relative(p, dir).generic_string(), n,
                               "Refactor control flow using structured constructs", kAutosarCpp14));
            }
        }
    });
    return out;
}

// LINT003 – reinterpret_cast without justification (AUTOSAR C++14 A5-2-4) //fusa:req REQ-LINT003
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
                out.push_back(make_finding("LINT003", Severity::WARNING,
                               "reinterpret_cast without justification (AUTOSAR C++14 A5-2-4)", // fusa:suppress LINT003
                               fs::relative(p, dir).generic_string(), n,
                               "Add // fusa:unsafe <justification> comment above or inline", kAutosarCpp14));
            }
        }
    });
    return out;
}

// LINT004 – abort()/exit() without safe-state transition (AUTOSAR C++14 A15-5-3) //fusa:req REQ-LINT004
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
                out.push_back(make_finding("LINT004", Severity::ERROR,
                               "abort()/exit() without preceding safe-state transition (AUTOSAR C++14 A15-5-3)",
                               fs::relative(p, dir).generic_string(), n,
                               "Add // fusa:safe-state comment and call safe-state handler before abort", kAutosarCpp14));
            }
        }
    });
    return out;
}

// LINT005 – Global mutable variable without sync annotation (AUTOSAR C++14 A3-3-2) //fusa:req REQ-LINT005
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
            out.push_back(make_finding("LINT005", Severity::WARNING,
                           "Global mutable variable without synchronisation annotation (AUTOSAR C++14 A3-3-2)",
                           fs::relative(p, dir).generic_string(), n,
                           "Mark with // fusa:shared or make const/constexpr/thread_local", kAutosarCpp14));
        }
    });
    return out;
}

// LINT006 – #define used for numeric/string constant (AUTOSAR C++14 A2-13-1) //fusa:req REQ-LINT006
std::vector<Finding> check_define_constant(const fs::path& dir) {
    std::vector<Finding> out;
    static const std::regex pat(R"(^\s*#\s*define\s+\w+\s+[\d"'.])");
    for_each_source(dir, [&](const fs::path& p, const Lines& lines) {
        for (const auto& [n, line] : lines) {
            if (suppressed(line, "LINT006")) continue;
            if (std::regex_search(line, pat)) {
                out.push_back(make_finding("LINT006", Severity::WARNING,
                               "#define used for constant — prefer constexpr (AUTOSAR C++14 A2-13-1)",
                               fs::relative(p, dir).generic_string(), n,
                               "Replace #define with constexpr variable", kAutosarCpp14));
            }
        }
    });
    return out;
}

// LINT007 – C-style cast (AUTOSAR C++14 A5-2-2) //fusa:req REQ-LINT007
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
                out.push_back(make_finding("LINT007", Severity::WARNING,
                               "C-style cast detected — use static_cast/reinterpret_cast/const_cast (AUTOSAR C++14 A5-2-2)", // fusa:suppress LINT003
                               fs::relative(p, dir).generic_string(), n,
                               "Replace with appropriate named cast", kAutosarCpp14));
            }
        }
    });
    return out;
}

// LINT008 – Recursive function (AUTOSAR C++14 A7-1-1 / JSF++ 119) //fusa:req REQ-LINT008
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
                    out.push_back(make_finding("LINT008", Severity::WARNING,
                                   "Recursive call to '" + current_fn + "' — add depth-bound guard (AUTOSAR C++14 A7-1-1 / JSF++ 119)",
                                   fs::relative(p, dir).generic_string(), n,
                                   "Add // fusa:recursive <max-depth> annotation or refactor iteratively", kAutosarCpp14));
                }
            }
        }
    });
    return out;
}

// LINT009 – printf/scanf family usage (type-unsafe I/O) — cpp-FuSa custom
// rule, not derived from a MISRA/AUTOSAR clause, so no standard_id is set.
//fusa:req REQ-LINT009
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
                               fs::relative(p, dir).generic_string(), n,
                               "Replace with std::format (C++20) or std::ostringstream", "lint"});
            }
        }
    });
    return out;
}

// LINT010 – Function throwing exceptions without noexcept or documented spec
// — cpp-FuSa custom rule, not derived from a MISRA/AUTOSAR clause, so no
// standard_id is set. //fusa:req REQ-LINT010
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
                               fs::relative(p, dir).generic_string(), n,
                               "Mark non-throwing functions noexcept; document throwing ones", "lint"});
            }
        }
    });
    return out;
}

// ── AUTOSAR C++14-guideline extended rules — LINT011–030 ──────────────────────
// (individually A-numbered = AUTOSAR-authored, or M-numbered = imported
// verbatim from MISRA C++:2008 — see cpp-FuSa-07)

// LINT011 – NULL used instead of nullptr (MISRA C++:2008 M4-10-2) //fusa:req REQ-LINT011
std::vector<Finding> check_null_literal(const fs::path& dir) {
    std::vector<Finding> out;
    static const std::regex pat(R"(\bNULL\b)");
    static const std::regex in_str(R"("[^"]*\bNULL\b[^"]*")");
    for_each_source(dir, [&](const fs::path& p, const Lines& lines) {
        if (file_suppressed(lines, "LINT011")) return;
        for (const auto& [n, line] : lines) {
            if (suppressed(line, "LINT011")) continue;
            auto t = line.find_first_not_of(" \t");
            if (t != std::string::npos && line[t] == '/') continue;
            if (std::regex_search(line, in_str)) continue;
            if (std::regex_search(line, pat))
                out.push_back(make_finding("LINT011", Severity::WARNING,
                    "NULL used — prefer nullptr (MISRA C++:2008 M4-10-2)",
                    fs::relative(p, dir).generic_string(), n,
                    "Replace NULL with nullptr", kMisraCpp));
        }
    });
    return out;
}

// LINT012 – Virtual function override missing override/final specifier (AUTOSAR C++14 A10-3-2) //fusa:req REQ-LINT012
std::vector<Finding> check_missing_override(const fs::path& dir) {
    std::vector<Finding> out;
    // Heuristic: `virtual` function declaration without override, final, or = 0.
    static const std::regex virt(R"(\bvirtual\b)");
    static const std::regex ok_re(R"(\b(override|final)\b|=\s*0\b)");
    for_each_source(dir, [&](const fs::path& p, const Lines& lines) {
        if (file_suppressed(lines, "LINT012")) return;
        for (const auto& [n, line] : lines) {
            if (suppressed(line, "LINT012")) continue;
            auto t = line.find_first_not_of(" \t");
            if (t != std::string::npos && line[t] == '/') continue;
            if (!std::regex_search(line, virt)) continue;
            if (std::regex_search(line, ok_re)) continue;
            out.push_back(make_finding("LINT012", Severity::WARNING,
                "Virtual function without override/final/= 0 (AUTOSAR C++14 A10-3-2)",
                fs::relative(p, dir).generic_string(), n,
                "Add 'override' or 'final' to the overriding function declaration", kAutosarCpp14));
        }
    });
    return out;
}

// LINT013 – switch without default case (MISRA C++:2008 M6-4-6) //fusa:req REQ-LINT013
std::vector<Finding> check_switch_default(const fs::path& dir) {
    std::vector<Finding> out;
    static const std::regex sw_re(R"(\bswitch\s*\()");
    static const std::regex def_re(R"(\bdefault\s*:)");
    // Scans forward from the switch statement's own line for a default: case
    // before the switch's enclosing braces close. A structured early-return
    // (not goto — LINT002 prohibits goto, including in this tool's own
    // source) breaks out of the nested char/line loops the moment the
    // closing brace count goes negative.
    auto has_default_ahead = [](const Lines& lines, int i) {
        int depth = 0;
        for (int j = i; j < static_cast<int>(lines.size()) && j < i + 200; ++j) {
            const auto& body = lines[j].second;
            for (char c : body) {
                if (c == '{') ++depth;
                if (c == '}') { --depth; if (depth < 0) return false; }
            }
            if (std::regex_search(body, def_re)) return true;
        }
        return false;
    };
    for_each_source(dir, [&](const fs::path& p, const Lines& lines) {
        if (file_suppressed(lines, "LINT013")) return;
        for (int i = 0; i < static_cast<int>(lines.size()); ++i) {
            const auto& [n, line] = lines[i];
            if (suppressed(line, "LINT013")) continue;
            if (!std::regex_search(line, sw_re)) continue;
            if (!has_default_ahead(lines, i))
                out.push_back(make_finding("LINT013", Severity::WARNING,
                    "switch statement without default case (MISRA C++:2008 M6-4-6)",
                    fs::relative(p, dir).generic_string(), n,
                    "Add a default: case (even if just a comment or assertion)", kMisraCpp));
        }
    });
    return out;
}

// LINT014 – Empty catch block (MISRA C++:2008 M15-3-4) //fusa:req REQ-LINT014
std::vector<Finding> check_empty_catch(const fs::path& dir) {
    std::vector<Finding> out;
    static const std::regex pat(R"(\bcatch\s*\([^)]*\)\s*\{\s*\})");
    for_each_source(dir, [&](const fs::path& p, const Lines& lines) {
        if (file_suppressed(lines, "LINT014")) return;
        for (const auto& [n, line] : lines) {
            if (suppressed(line, "LINT014")) continue;
            if (std::regex_search(line, pat))
                out.push_back(make_finding("LINT014", Severity::WARNING,
                    "Empty catch block silently swallows exceptions (MISRA C++:2008 M15-3-4)",
                    fs::relative(p, dir).generic_string(), n,
                    "Log, re-throw, or document why the exception is intentionally suppressed", kMisraCpp));
        }
    });
    return out;
}

// LINT015 – throw in destructor (MISRA C++:2008 M15-5-1) //fusa:req REQ-LINT015
//
// Scope tracking: `depth` counts braces from the destructor's own opening
// brace. It resets to 0 (closing the destructor's scope) purely from
// brace-matching arithmetic, on whichever line that happens to occur on —
// including the destructor's own line for a single-line body such as
// `~Foo() { ...; }`. Using `depth <= 0` (rather than requiring depth==0 on a
// *later* line, which a single-line body never reaches — see issue #59)
// closes the scope as soon as it is genuinely balanced, so a later, unrelated
// member function's own throw is never misattributed back to the destructor.
std::vector<Finding> check_throw_in_destructor(const fs::path& dir) {
    std::vector<Finding> out;
    static const std::regex dtor_re(R"(~\w+\s*\([^)]*\))");
    static const std::regex throw_re(R"(\bthrow\b)");
    for_each_source(dir, [&](const fs::path& p, const Lines& lines) {
        if (file_suppressed(lines, "LINT015")) return;
        bool in_dtor = false;
        int depth = 0;
        for (const auto& [n, line] : lines) {
            if (std::regex_search(line, dtor_re)) { in_dtor = true; depth = 0; }
            if (in_dtor) {
                for (char c : line) {
                    if (c == '{') ++depth;
                    if (c == '}') { --depth; if (depth <= 0) in_dtor = false; }
                }
                if (!suppressed(line, "LINT015") && std::regex_search(line, throw_re))
                    out.push_back(make_finding("LINT015", Severity::ERROR,
                        "throw in destructor may call std::terminate (MISRA C++:2008 M15-5-1)",
                        fs::relative(p, dir).generic_string(), n,
                        "Destructors must be noexcept; catch internally or use error flags", kMisraCpp));
            }
        }
    });
    return out;
}

// LINT016 – Function-like macro (AUTOSAR C++14 A16-0-1) //fusa:req REQ-LINT016
std::vector<Finding> check_function_like_macro(const fs::path& dir) {
    std::vector<Finding> out;
    static const std::regex pat(R"(^\s*#\s*define\s+\w+\s*\()");
    for_each_source(dir, [&](const fs::path& p, const Lines& lines) {
        if (file_suppressed(lines, "LINT016")) return;
        for (const auto& [n, line] : lines) {
            if (suppressed(line, "LINT016")) continue;
            if (std::regex_search(line, pat))
                out.push_back(make_finding("LINT016", Severity::WARNING,
                    "Function-like macro — use inline function or constexpr (AUTOSAR C++14 A16-0-1)",
                    fs::relative(p, dir).generic_string(), n,
                    "Replace with a constexpr function or template", kAutosarCpp14));
        }
    });
    return out;
}

// LINT017 – setjmp/longjmp usage (AUTOSAR C++14 A15-1-2) //fusa:req REQ-LINT017
std::vector<Finding> check_setjmp(const fs::path& dir) {
    std::vector<Finding> out;
    static const std::regex pat(R"(\b(setjmp|longjmp|_setjmp|siglongjmp)\s*\()");
    for_each_source(dir, [&](const fs::path& p, const Lines& lines) {
        if (file_suppressed(lines, "LINT017")) return;
        for (const auto& [n, line] : lines) {
            if (suppressed(line, "LINT017")) continue;
            auto t = line.find_first_not_of(" \t");
            if (t != std::string::npos && line[t] == '/') continue;
            if (std::regex_search(line, pat))
                out.push_back(make_finding("LINT017", Severity::ERROR,
                    "setjmp/longjmp bypasses C++ destructors and exception handling (AUTOSAR C++14 A15-1-2)",
                    fs::relative(p, dir).generic_string(), n,
                    "Replace with C++ exception handling or RAII", kAutosarCpp14));
        }
    });
    return out;
}

// LINT018 – dynamic_cast usage (AUTOSAR C++14 A5-2-3) //fusa:req REQ-LINT018
std::vector<Finding> check_dynamic_cast(const fs::path& dir) {
    std::vector<Finding> out;
    static const std::regex pat(R"(\bdynamic_cast\s*<)");
    for_each_source(dir, [&](const fs::path& p, const Lines& lines) {
        if (file_suppressed(lines, "LINT018")) return;
        for (const auto& [n, line] : lines) {
            if (suppressed(line, "LINT018")) continue;
            auto t = line.find_first_not_of(" \t");
            if (t != std::string::npos && line[t] == '/') continue;
            if (std::regex_search(line, pat))
                out.push_back(make_finding("LINT018", Severity::WARNING,
                    "dynamic_cast may return nullptr at runtime — prefer design without RTTI (AUTOSAR C++14 A5-2-3)",
                    fs::relative(p, dir).generic_string(), n,
                    "Redesign with virtual functions or std::variant; annotate with // fusa:suppress LINT018 if intentional", kAutosarCpp14));
        }
    });
    return out;
}

// LINT019 – union usage (AUTOSAR C++14 A9-5-1) //fusa:req REQ-LINT019
std::vector<Finding> check_union(const fs::path& dir) {
    std::vector<Finding> out;
    static const std::regex pat(R"(\bunion\s+\w)");
    static const std::regex allow_re(R"(\bstd::)"); // allow std internal unions
    for_each_source(dir, [&](const fs::path& p, const Lines& lines) {
        if (file_suppressed(lines, "LINT019")) return;
        for (const auto& [n, line] : lines) {
            if (suppressed(line, "LINT019")) continue;
            auto t = line.find_first_not_of(" \t");
            if (t != std::string::npos && line[t] == '/') continue;
            if (!std::regex_search(line, pat)) continue;
            if (std::regex_search(line, allow_re)) continue;
            out.push_back(make_finding("LINT019", Severity::WARNING,
                "union usage — prefer std::variant for type-safe discriminated union (AUTOSAR C++14 A9-5-1)",
                fs::relative(p, dir).generic_string(), n,
                "Replace with std::variant<...>", kAutosarCpp14));
        }
    });
    return out;
}

// LINT020 – volatile without justification (AUTOSAR C++14 A2-11-1) //fusa:req REQ-LINT020
std::vector<Finding> check_volatile(const fs::path& dir) {
    std::vector<Finding> out;
    static const std::regex pat(R"(\bvolatile\b)");
    static const std::regex ok_re(R"(//\s*fusa:volatile)");
    for_each_source(dir, [&](const fs::path& p, const Lines& lines) {
        if (file_suppressed(lines, "LINT020")) return;
        for (const auto& [n, line] : lines) {
            if (suppressed(line, "LINT020")) continue;
            auto t = line.find_first_not_of(" \t");
            if (t != std::string::npos && line[t] == '/') continue;
            if (!std::regex_search(line, pat)) continue;
            if (std::regex_search(line, ok_re)) continue;
            out.push_back(make_finding("LINT020", Severity::WARNING,
                "volatile without justification — document hardware/ISR necessity (AUTOSAR C++14 A2-11-1)",
                fs::relative(p, dir).generic_string(), n,
                "Add // fusa:volatile <reason> annotation, or replace with std::atomic", kAutosarCpp14));
        }
    });
    return out;
}

// LINT021 – variadic function (...) (AUTOSAR C++14 A8-4-1) //fusa:req REQ-LINT021
std::vector<Finding> check_variadic(const fs::path& dir) {
    std::vector<Finding> out;
    // Match function param lists containing `...` (but not in template packs or catch clauses).
    static const std::regex fn_va(R"(\w+\s*\([^)]*,\s*\.\.\.\s*\))");
    static const std::regex catch_re(R"(\bcatch\s*\(\s*\.\.\.)");
    for_each_source(dir, [&](const fs::path& p, const Lines& lines) {
        if (file_suppressed(lines, "LINT021")) return;
        for (const auto& [n, line] : lines) {
            if (suppressed(line, "LINT021")) continue;
            auto t = line.find_first_not_of(" \t");
            if (t != std::string::npos && line[t] == '/') continue;
            if (std::regex_search(line, catch_re)) continue;
            if (std::regex_search(line, fn_va))
                out.push_back(make_finding("LINT021", Severity::WARNING,
                    "Variadic function parameter (...) is not type-safe (AUTOSAR C++14 A8-4-1)",
                    fs::relative(p, dir).generic_string(), n,
                    "Replace with variadic templates or std::initializer_list", kAutosarCpp14));
        }
    });
    return out;
}

// LINT022 – unsafe C string functions (AUTOSAR C++14 A27-0-1) //fusa:req REQ-LINT022
std::vector<Finding> check_unsafe_string_fn(const fs::path& dir) {
    std::vector<Finding> out;
    static const std::regex pat(R"(\b(strcpy|strcat|gets|sprintf|wcscpy|wcscat)\s*\()");
    for_each_source(dir, [&](const fs::path& p, const Lines& lines) {
        if (file_suppressed(lines, "LINT022")) return;
        for (const auto& [n, line] : lines) {
            if (suppressed(line, "LINT022")) continue;
            auto t = line.find_first_not_of(" \t");
            if (t != std::string::npos && line[t] == '/') continue;
            if (std::regex_search(line, pat))
                out.push_back(make_finding("LINT022", Severity::ERROR,
                    "Unsafe C string function — buffer overflow risk (AUTOSAR C++14 A27-0-1 / CWE-120)",
                    fs::relative(p, dir).generic_string(), n,
                    "Use std::string, std::string_view, or bounded equivalents (strncpy_s, strlcpy)", kAutosarCpp14));
        }
    });
    return out;
}

// LINT023 – atoi/atof unsafe numeric conversion (AUTOSAR C++14 A27-0-2) //fusa:req REQ-LINT023
std::vector<Finding> check_unsafe_numeric_conv(const fs::path& dir) {
    std::vector<Finding> out;
    static const std::regex pat(R"(\b(atoi|atof|atol|atoll)\s*\()");
    for_each_source(dir, [&](const fs::path& p, const Lines& lines) {
        if (file_suppressed(lines, "LINT023")) return;
        for (const auto& [n, line] : lines) {
            if (suppressed(line, "LINT023")) continue;
            auto t = line.find_first_not_of(" \t");
            if (t != std::string::npos && line[t] == '/') continue;
            if (std::regex_search(line, pat))
                out.push_back(make_finding("LINT023", Severity::WARNING,
                    "atoi/atof provides no error detection on invalid input (AUTOSAR C++14 A27-0-2)",
                    fs::relative(p, dir).generic_string(), n,
                    "Use std::stoi/std::stof with exception handling, or std::from_chars", kAutosarCpp14));
        }
    });
    return out;
}

// LINT024 – missing braces on single-statement control flow (MISRA C++:2008 M6-3-1) //fusa:req REQ-LINT024
std::vector<Finding> check_missing_braces(const fs::path& dir) {
    std::vector<Finding> out;
    // Match if/for/while/else followed by a non-brace, non-comment continuation.
    static const std::regex ctrl_re(R"(^\s*(if|for|while|else)\s*(\([^)]*\))?\s*$)");
    for_each_source(dir, [&](const fs::path& p, const Lines& lines) {
        if (file_suppressed(lines, "LINT024")) return;
        for (int i = 0; i + 1 < static_cast<int>(lines.size()); ++i) {
            const auto& [n, line] = lines[i];
            if (suppressed(line, "LINT024")) continue;
            if (!std::regex_search(line, ctrl_re)) continue;
            // Next non-empty line must start with '{'.
            for (int j = i + 1; j < static_cast<int>(lines.size()); ++j) {
                const auto& next = lines[j].second;
                auto t = next.find_first_not_of(" \t");
                if (t == std::string::npos) continue;
                if (next[t] != '{')
                    out.push_back(make_finding("LINT024", Severity::WARNING,
                        "Control-flow statement without braces (MISRA C++:2008 M6-3-1)",
                        fs::relative(p, dir).generic_string(), n,
                        "Add braces {} to the body to prevent dangling-else and accidental scope issues", kMisraCpp));
                break;
            }
        }
    });
    return out;
}

// LINT025 – errno usage (AUTOSAR C++14 A19-3-1) //fusa:req REQ-LINT025
std::vector<Finding> check_errno(const fs::path& dir) {
    std::vector<Finding> out;
    static const std::regex pat(R"(\berrno\b)");
    static const std::regex in_str(R"("[^"]*\berrno\b[^"]*")");
    for_each_source(dir, [&](const fs::path& p, const Lines& lines) {
        if (file_suppressed(lines, "LINT025")) return;
        for (const auto& [n, line] : lines) {
            if (suppressed(line, "LINT025")) continue;
            auto t = line.find_first_not_of(" \t");
            if (t != std::string::npos && line[t] == '/') continue;
            if (std::regex_search(line, in_str)) continue;
            if (std::regex_search(line, pat))
                out.push_back(make_finding("LINT025", Severity::WARNING,
                    "errno usage — thread-unsafe and fragile error detection (AUTOSAR C++14 A19-3-1)",
                    fs::relative(p, dir).generic_string(), n,
                    "Use POSIX error-return codes, std::error_code, or exceptions instead", kAutosarCpp14));
        }
    });
    return out;
}

// LINT026 – deprecated C library headers (MISRA C++:2008 M17-0-5) //fusa:req REQ-LINT026
std::vector<Finding> check_c_headers(const fs::path& dir) {
    std::vector<Finding> out;
    static const std::regex pat(
        R"(#\s*include\s*<(stdio|stdlib|string|math|time|signal|locale|assert|errno|ctype|stdarg)\.h>)");
    for_each_source(dir, [&](const fs::path& p, const Lines& lines) {
        if (file_suppressed(lines, "LINT026")) return;
        for (const auto& [n, line] : lines) {
            if (suppressed(line, "LINT026")) continue;
            if (std::regex_search(line, pat))
                out.push_back(make_finding("LINT026", Severity::WARNING,
                    "Deprecated C library header included — use C++ equivalent (MISRA C++:2008 M17-0-5)",
                    fs::relative(p, dir).generic_string(), n,
                    "Replace <stdio.h> with <cstdio>, <string.h> with <cstring>, etc.", kMisraCpp));
        }
    });
    return out;
}

// LINT027 – #undef usage (MISRA C++:2008 M16-0-3) //fusa:req REQ-LINT027
std::vector<Finding> check_undef(const fs::path& dir) {
    std::vector<Finding> out;
    static const std::regex pat(R"(^\s*#\s*undef\b)");
    for_each_source(dir, [&](const fs::path& p, const Lines& lines) {
        if (file_suppressed(lines, "LINT027")) return;
        for (const auto& [n, line] : lines) {
            if (suppressed(line, "LINT027")) continue;
            if (std::regex_search(line, pat))
                out.push_back(make_finding("LINT027", Severity::WARNING,
                    "#undef alters the macro namespace unpredictably (MISRA C++:2008 M16-0-3)",
                    fs::relative(p, dir).generic_string(), n,
                    "Scope constants with namespaces or constexpr instead of macro redefinition", kMisraCpp));
        }
    });
    return out;
}

// LINT028 – asm/inline assembly (AUTOSAR C++14 A7-4-1) //fusa:req REQ-LINT028
std::vector<Finding> check_asm(const fs::path& dir) {
    std::vector<Finding> out;
    static const std::regex pat(R"(\b(__asm__|asm|__asm)\s*[\({"])");
    for_each_source(dir, [&](const fs::path& p, const Lines& lines) {
        if (file_suppressed(lines, "LINT028")) return;
        for (const auto& [n, line] : lines) {
            if (suppressed(line, "LINT028")) continue;
            auto t = line.find_first_not_of(" \t");
            if (t != std::string::npos && line[t] == '/') continue;
            if (std::regex_search(line, pat))
                out.push_back(make_finding("LINT028", Severity::WARNING,
                    "Inline assembly reduces portability and verifiability (AUTOSAR C++14 A7-4-1)",
                    fs::relative(p, dir).generic_string(), n,
                    "Replace with compiler intrinsics, std::atomic, or platform abstraction layer", kAutosarCpp14));
        }
    });
    return out;
}

// LINT029 – magic number literals (AUTOSAR C++14 A2-13-4) //fusa:req REQ-LINT029
std::vector<Finding> check_magic_numbers(const fs::path& dir) {
    std::vector<Finding> out;
    // Flag integer literals > 1 (i.e. not 0 or 1) that appear in expressions,
    // excluding array sizes, enum values, constexpr/const declarations, and line annotations.
    static const std::regex lit_re(R"(\b([2-9]\d*|[1-9]\d+)\b)");
    static const std::regex decl_re(R"(\b(constexpr|const|enum|case|static)\b)");
    static const std::regex arr_re(R"(\[\s*\d+\s*\])");
    for_each_source(dir, [&](const fs::path& p, const Lines& lines) {
        if (file_suppressed(lines, "LINT029")) return;
        for (const auto& [n, line] : lines) {
            if (suppressed(line, "LINT029")) continue;
            auto t = line.find_first_not_of(" \t");
            if (t != std::string::npos && line[t] == '/') continue;
            if (std::regex_search(line, decl_re)) continue; // skip named constants
            if (std::regex_search(line, arr_re)) continue;  // skip array size declarations
            if (std::regex_search(line, lit_re))
                out.push_back(make_finding("LINT029", Severity::INFO,
                    "Magic number literal — prefer named constant (AUTOSAR C++14 A2-13-4)",
                    fs::relative(p, dir).generic_string(), n,
                    "Replace with a constexpr named constant to document intent", kAutosarCpp14));
        }
    });
    return out;
}

// LINT030 – missing include guard or #pragma once in header (MISRA C++:2008 M16-2-1) //fusa:req REQ-LINT030
std::vector<Finding> check_include_guard(const fs::path& dir) {
    std::vector<Finding> out;
    static const std::regex hdr_ext(R"(\.(hpp|h|hxx|hh)$)");
    static const std::regex pragma_re(R"(#\s*pragma\s+once)");
    static const std::regex guard_re(R"(#\s*(ifndef|define)\s+\w+)");
    if (!fs::exists(dir)) return out;
    for (const auto& entry : fs::recursive_directory_iterator(
             dir, fs::directory_options::skip_permission_denied)) {
        if (!entry.is_regular_file()) continue;
        if (!std::regex_search(entry.path().string(), hdr_ext)) continue;
        std::ifstream f(entry.path());
        std::string content((std::istreambuf_iterator<char>(f)), {});
        if (std::regex_search(content, pragma_re)) continue;
        if (std::regex_search(content, guard_re))  continue;
        out.push_back(make_finding("LINT030", Severity::WARNING,
            "Header file missing include guard or #pragma once (MISRA C++:2008 M16-2-1)",
            fs::relative(entry.path(), dir).generic_string(), 1,
            "Add '#pragma once' at the top of the header", kMisraCpp));
    }
    return out;
}

// LINT031 – float/double literal in == or != comparison (MISRA C++:2008 Rule 6-2-2)
//fusa:req REQ-LINT031
std::vector<Finding> check_float_equality(const fs::path& dir) {
    std::vector<Finding> out;
    // Matches == or != adjacent to a float literal (decimal point required).
    static const std::regex float_eq_re(
        R"X([!=]=\s*[+\-]?(?:\d+\.\d*|\.\d+)(?:[eE][+\-]?\d+)?[fFlL]?\b|\b[+\-]?(?:\d+\.\d*|\.\d+)(?:[eE][+\-]?\d+)?[fFlL]?\s*[!=]=)X"
    );
    static const std::regex ext_re(R"(\.(cpp|cxx|cc|hpp|h)$)");
    if (!fs::exists(dir)) return out;
    for (const auto& entry : fs::recursive_directory_iterator(
             dir, fs::directory_options::skip_permission_denied)) {
        if (!entry.is_regular_file()) continue;
        if (!std::regex_search(entry.path().string(), ext_re)) continue;
        std::ifstream f(entry.path());
        std::string line;
        int lineno = 0;
        while (std::getline(f, line)) {
            ++lineno;
            if (line.find("// fusa:suppress LINT031") != std::string::npos) continue;
            auto code = line.substr(0, line.find("//"));
            if (std::regex_search(code, float_eq_re)) {
                out.push_back(make_finding("LINT031", Severity::WARNING,
                    "Float/double literal compared with == or != (MISRA C++:2008 Rule 6-2-2) — use epsilon comparison",
                    fs::relative(entry.path(), dir).generic_string(), lineno,
                    "Replace 'x == 3.14' with 'std::abs(x - 3.14) < eps'", kMisraCpp));
            }
        }
    }
    return out;
}

//fusa:req REQ-LINT032
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
    append(check_null_literal(dir));
    append(check_missing_override(dir));
    append(check_switch_default(dir));
    append(check_empty_catch(dir));
    append(check_throw_in_destructor(dir));
    append(check_function_like_macro(dir));
    append(check_setjmp(dir));
    append(check_dynamic_cast(dir));
    append(check_union(dir));
    append(check_volatile(dir));
    append(check_variadic(dir));
    append(check_unsafe_string_fn(dir));
    append(check_unsafe_numeric_conv(dir));
    append(check_missing_braces(dir));
    append(check_errno(dir));
    append(check_c_headers(dir));
    append(check_undef(dir));
    append(check_asm(dir));
    append(check_magic_numbers(dir));
    append(check_include_guard(dir));
    append(check_float_equality(dir));

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
