//fusa:req REQ-COMP001
#include "comp.hpp"
#include "cpfusa/fusa.hpp"
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <regex>
#include <sstream>
#include <nlohmann/json.hpp>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace cpfusa::comp {

namespace {

// Count branching nodes in a block of C++ code (V(G) = 1 + branches).
int count_complexity(const std::string& body) {
    // Each if/for/while/do/case/?: adds 1; logical && and || also add 1.
    static const std::regex branch_re(
        R"(\bif\b|\bfor\b|\bwhile\b|\bdo\b|\bcase\b)"
    );
    static const std::regex logical_re(R"(&&|\|\|)");
    static const std::regex ternary_re(R"(\?\s*[^:])");

    int count = 1; // base complexity
    for (std::sregex_iterator it(body.begin(), body.end(), branch_re), end; it != end; ++it)
        ++count;
    for (std::sregex_iterator it(body.begin(), body.end(), logical_re), end; it != end; ++it)
        ++count;
    for (std::sregex_iterator it(body.begin(), body.end(), ternary_re), end; it != end; ++it)
        ++count;
    return count;
}

struct FuncInfo { int line; std::string name; std::string body; };

// Simple heuristic function extractor.
// Looks for lines that look like function definitions (word(... ) {) and tracks braces.
std::vector<FuncInfo> extract_functions(const std::string& src) {
    std::vector<FuncInfo> out;
    // Match function-like lines: e.g. "ReturnType funcName(args) {"
    // or "ReturnType funcName(args) const {"
    // Avoid matching: if (, while (, for (, etc.
    static const std::regex sig_re(
        R"(^[\w:~<>\*& ]+\s+(\w+)\s*\([^)]*\)\s*(?:const\s*)?(?:noexcept\s*)?(?:override\s*)?\{)"
    );
    static const std::regex keyword_re(
        R"(\b(if|else|for|while|do|switch|catch|return)\b)"
    );

    std::istringstream ss(src);
    std::string line;
    int lineno = 0;
    int brace_depth = 0;
    bool in_func = false;
    std::string func_body;
    std::string func_name;
    int func_line = 0;

    while (std::getline(ss, line)) {
        ++lineno;
        if (!in_func) {
            std::smatch m;
            if (std::regex_search(line, m, sig_re)) {
                // Skip control-flow keywords
                if (!std::regex_search(m[1].str(), keyword_re)) {
                    func_name = m[1].str();
                    func_line = lineno;
                    brace_depth = 0;
                    in_func = false;
                    func_body.clear();
                    // Count braces on this line
                    for (char c : line) {
                        if (c == '{') { ++brace_depth; in_func = true; }
                        if (c == '}') --brace_depth;
                    }
                }
            }
        } else {
            func_body += line + "\n";
            for (char c : line) {
                if (c == '{') ++brace_depth;
                if (c == '}') {
                    --brace_depth;
                    if (brace_depth == 0) {
                        out.push_back({func_line, func_name, func_body});
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

//fusa:req REQ-COMP001
CompReport analyse(const fs::path& dir, const std::string& project, int threshold) {
    CompReport rep;
    rep.project   = project;
    rep.threshold = threshold;

    auto now = std::chrono::system_clock::now();
    auto t   = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ts;
    ts << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ");
    rep.generated_at = ts.str();

    static const std::regex cpp_ext(R"(\.(cpp|cxx|cc|c\+\+)$)");
    if (!fs::exists(dir)) return rep;

    for (const auto& entry : fs::recursive_directory_iterator(
             dir, fs::directory_options::skip_permission_denied)) {
        if (!entry.is_regular_file()) continue;
        if (!std::regex_search(entry.path().string(), cpp_ext)) continue;

        std::ifstream f(entry.path());
        std::string src((std::istreambuf_iterator<char>(f)), {});
        auto funcs = extract_functions(src);
        for (const auto& fn : funcs) {
            int cc = count_complexity(fn.body);
            FunctionResult fr;
            fr.file              = entry.path().string();
            fr.line              = fn.line;
            fr.name              = fn.name;
            fr.complexity        = cc;
            fr.exceeds_threshold = (cc > threshold);
            rep.total_functions++;
            if (fr.exceeds_threshold) rep.violations++;
            rep.results.push_back(fr);
        }
    }
    return rep;
}

void write_json(const fs::path& out, const CompReport& r) {
    json j;
    j["schemaVersion"]  = std::string(SpecVersion);
    j["kind"]           = "comp-report";
    j["tool"]           = "cpp-FuSa";
    j["generatedAt"]    = r.generated_at;
    j["project"]        = r.project;
    j["threshold"]      = r.threshold;
    j["totalFunctions"] = r.total_functions;
    j["violations"]     = r.violations;
    j["results"]        = json::array();
    for (const auto& fn : r.results) {
        j["results"].push_back({
            {"file",             fn.file},
            {"line",             fn.line},
            {"name",             fn.name},
            {"complexity",       fn.complexity},
            {"exceedsThreshold", fn.exceeds_threshold}
        });
    }
    std::ofstream f(out);
    f << j.dump(2) << "\n";
}

void render_text(const CompReport& r) {
    std::cout << "Cyclomatic Complexity Analysis -- threshold: " << r.threshold << "\n";
    std::cout << "Functions analysed: " << r.total_functions
              << "  violations: " << r.violations << "\n\n";
    for (const auto& fn : r.results) {
        if (!fn.exceeds_threshold) continue;
        std::cout << "  [V=" << fn.complexity << "] " << fn.name
                  << "  " << fn.file << ":" << fn.line << "\n";
    }
    if (r.violations == 0) std::cout << "  No violations found.\n";
}

} // namespace cpfusa::comp
