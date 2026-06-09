#include "fmea.hpp"
#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <regex>
#include <chrono>
#include <iomanip>
#include <ctime>
#include <algorithm>

namespace fs = std::filesystem;
using json   = nlohmann::json;

namespace cpfusa::fmea {

namespace {

std::string now_iso8601() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ss;
    ss << std::put_time(std::gmtime(&t), "%FT%TZ");
    return ss.str();
}

bool is_excluded(const fs::path& p, const config::ProjectConfig& cfg) {
    auto s = p.string();
    for (const auto& pat : cfg.exclude_patterns)
        if (s.find(pat) != std::string::npos) return true;
    return false;
}

// Default failure modes for classes and functions.
std::vector<std::string> class_failure_modes() {
    return {"Incorrect initialisation", "State corruption", "Memory leak", "Exception propagation"};
}
std::vector<std::string> func_failure_modes() {
    return {"Incorrect return value", "Unhandled error", "Buffer overflow", "Race condition"};
}

struct Declaration {
    std::string kind;   // "class" or "function"
    std::string name;
    std::string file;
    int         line;
};

std::vector<Declaration> scan_declarations(const fs::path& dir,
                                           const config::ProjectConfig& cfg) {
    std::vector<Declaration> decls;
    static const std::regex class_re(R"re(^\s*(?:class|struct)\s+(\w+)\s*[:{])re");
    // Simple pattern: "type name(" — avoids catastrophic backtracking on long lines.
    static const std::regex func_re(R"re(^\s*\w+\s+(\w+)\s*\()re");
    static const std::regex ext_re(R"(\.(hpp|hxx|h|cpp|cxx|cc)$)");

    for (const auto& entry : fs::recursive_directory_iterator(
             dir, fs::directory_options::skip_permission_denied)) {
        if (!entry.is_regular_file()) continue;
        if (!std::regex_search(entry.path().string(), ext_re)) continue;
        if (is_excluded(entry.path(), cfg)) continue;

        std::ifstream f(entry.path());
        std::string line;
        int lineno = 0;
        while (std::getline(f, line)) {
            ++lineno;
            std::smatch m;
            if (std::regex_search(line, m, class_re)) {
                decls.push_back({"class", m[1].str(), entry.path().string(), lineno});
            } else if (std::regex_search(line, m, func_re)) {
                auto name = m[1].str();
                // Skip very common non-function tokens
                if (name == "if" || name == "for" || name == "while" || name == "switch"
                 || name == "return" || name == "namespace" || name == "using") continue;
                decls.push_back({"function", name, entry.path().string(), lineno});
            }
        }
    }
    return decls;
}

} // namespace

//fusa:req REQ-FMEA001
Result<FMEAReport> generate(const fs::path& dir, const config::ProjectConfig& cfg) {
    FMEAReport rpt;
    rpt.generated_at = now_iso8601();
    rpt.project      = cfg.project;

    auto decls = scan_declarations(dir, cfg);
    int id_counter = 1;

    auto class_fms = class_failure_modes();
    auto func_fms  = func_failure_modes();

    for (const auto& d : decls) {
        const auto& fms = (d.kind == "class") ? class_fms : func_fms;
        for (const auto& fm : fms) {
            FmeaEntry e;
            e.id            = "FM-" + std::to_string(id_counter++);
            e.component     = d.name;
            e.failure_mode  = fm;
            // Assign default risk values based on failure mode severity.
            if (fm.find("overflow") != std::string::npos ||
                fm.find("corruption") != std::string::npos) {
                e.severity = 8; e.occurrence = 4; e.detectability = 5;
            } else if (fm.find("memory") != std::string::npos ||
                       fm.find("race") != std::string::npos) {
                e.severity = 7; e.occurrence = 3; e.detectability = 6;
            } else {
                e.severity = 5; e.occurrence = 3; e.detectability = 4;
            }
            e.rpn    = e.severity * e.occurrence * e.detectability;
            e.effect = "Incorrect system behaviour or safety function failure";
            e.action = "Add defensive checks, RAII ownership, and unit test coverage";
            e.file   = d.file;
            e.line   = d.line;
            rpt.entries.push_back(e);
        }
    }

    // Sort by RPN descending (highest risk first).
    std::sort(rpt.entries.begin(), rpt.entries.end(),
              [](const FmeaEntry& a, const FmeaEntry& b){ return a.rpn > b.rpn; });
    return rpt;
}

//fusa:req REQ-FMEA002
Result<std::monostate> write(const fs::path& dir, const FMEAReport& rpt) {
    try {
        // fmea.json
        {
            json j;
            j["format"]      = "cpp-FuSa FMEA v1";
            j["generatedAt"] = rpt.generated_at;
            j["project"]     = rpt.project;
            json ea = json::array();
            for (const auto& e : rpt.entries) {
                ea.push_back({
                    {"id",e.id},{"component",e.component},{"failureMode",e.failure_mode},
                    {"effect",e.effect},{"severity",e.severity},{"occurrence",e.occurrence},
                    {"detectability",e.detectability},{"rpn",e.rpn},
                    {"action",e.action},{"file",e.file},{"line",e.line}
                });
            }
            j["entries"] = ea;
            std::ofstream out(dir / FmeaJsonFile);
            out << j.dump(2) << "\n";
        }
        // fmea.csv
        {
            std::ofstream out(dir / FmeaCsvFile);
            out << "ID,Component,FailureMode,Effect,Severity,Occurrence,Detectability,RPN,Action,File,Line\n";
            for (const auto& e : rpt.entries) {
                // Escape commas in fields.
                auto esc = [](const std::string& s) {
                    if (s.find(',') == std::string::npos) return s;
                    return "\"" + s + "\"";
                };
                out << e.id << "," << esc(e.component) << "," << esc(e.failure_mode)
                    << "," << esc(e.effect) << "," << e.severity << ","
                    << e.occurrence << "," << e.detectability << "," << e.rpn
                    << "," << esc(e.action) << "," << esc(e.file) << "," << e.line << "\n";
            }
        }
    } catch (const std::exception& ex) {
        return std::string("fmea: write: ") + ex.what();
    }
    return std::monostate{};
}

} // namespace cpfusa::fmea
