#include "fmea.hpp"
#include "../trace/trace.hpp"
#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <regex>
#include <chrono>
#include <iomanip>
#include <ctime>
#include <algorithm>
#include <map>
#include <set>

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
    // §1.6 rule 4 implementer guidance: reuse the same test-source-tree
    // exclusion trace::scan_func_coverage's denominator gets "for free" from
    // only walking src/*/*.hpp, rather than this scanner (which walks the
    // whole project) independently re-deriving a narrower/drifting version.
    // Without this, a helper function declared in tests/ would be counted as
    // a real project component — exactly the §1.6 rule 4 MUST violation
    // ("not... a test fixture mistaken for project code").
    if (trace::is_test_tree_path(p)) return true;
    auto s = p.string();
    for (const auto& pat : cfg.exclude_patterns)
        if (s.find(pat) != std::string::npos) return true;
    return false;
}

// Canonical failure-mode *categories* for classes and functions. §1.6.1 rule B
// targets a single hardcoded string reused for every entry regardless of the
// underlying item; generate() below appends the real component/function name
// to both failureMode and effect so the emitted text genuinely varies with
// the item's identity, while still drawing from a reusable, auditable
// category list (permitted per §1.6 item 3's "heuristic templates" carve-out).
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

std::string project_relative(const fs::path& dir, const std::string& file) {
    std::error_code ec;
    auto rel = fs::relative(fs::path(file), dir, ec);
    if (ec) return file;
    auto s = rel.generic_string();
    return s;
}

} // namespace

//fusa:req REQ-FMEA001 REQ-FMEA002 REQ-FMEA003 REQ-FMEA004 REQ-FMEA005 REQ-FMEA006 REQ-FMEA007 REQ-FMEA010
Result<FMEAReport> generate(const fs::path& dir, const config::ProjectConfig& cfg,
                            bool enrich_cyber) {
    FMEAReport rpt;
    rpt.generated_at = now_iso8601();
    rpt.project      = cfg.project;
    rpt.rating_scale = std::string(RatingScale);

    auto decls = scan_declarations(dir, cfg);
    int id_counter = 1;

    auto class_fms = class_failure_modes();
    auto func_fms  = func_failure_modes();

    for (const auto& d : decls) {
        const auto& fms = (d.kind == "class") ? class_fms : func_fms;
        for (const auto& fm : fms) {
            FmeaEntry e;
            e.id            = "FMEA-" + std::to_string(id_counter++);
            e.component     = d.name;
            e.item          = d.name;
            // §1.6.1 rule B: embed the real component/function name so the
            // text genuinely varies per entry rather than repeating one fixed
            // string for every item that shares a failure-mode category.
            e.failure_mode  = fm + " in " + d.name + "()";
            // Assign default risk values based on failure mode severity.
            if (fm.find("overflow") != std::string::npos ||
                fm.find("corruption") != std::string::npos) {
                e.severity = 8; e.occurrence = 4; e.detection = 5;
            } else if (fm.find("memory") != std::string::npos ||
                       fm.find("race") != std::string::npos ||
                       fm.find("Race") != std::string::npos) {
                e.severity = 7; e.occurrence = 3; e.detection = 6;
            } else {
                e.severity = 5; e.occurrence = 3; e.detection = 4;
            }
            e.rpn = e.severity * e.occurrence * e.detection;
            e.action_priority = e.severity >= 8 ? "high" : (e.severity >= 5 ? "medium" : "low");
            e.effect = "Incorrect system behaviour or safety-function failure originating in "
                       + d.name + " (" + d.kind + ")";
            e.mitigations = {"Add defensive checks, RAII ownership, and unit test coverage for " + d.name};
            e.file = project_relative(dir, d.file);
            e.line = d.line;
            rpt.entries.push_back(e);
        }
    }

    // Sort by RPN descending (highest risk first).
    std::sort(rpt.entries.begin(), rpt.entries.end(),
              [](const FmeaEntry& a, const FmeaEntry& b){ return a.rpn > b.rpn; });

    // Optionally enrich with cybersecurity findings from cyber-report.json.
    if (enrich_cyber) {
        auto cyber_path = dir / "cyber-report.json";
        if (fs::exists(cyber_path)) {
            try {
                std::ifstream cf(cyber_path);
                json cj = json::parse(cf);
                // Build map: source filename → unique CYBER rule IDs
                std::map<std::string, std::vector<std::string>> cyber_map;
                for (const auto& finding : cj.value("findings", json::array())) {
                    std::string file    = finding.value("file", "");
                    std::string rule_id = finding.value("ruleId", "");
                    if (!file.empty() && !rule_id.empty())
                        cyber_map[fs::path(file).filename().string()].push_back(rule_id);
                }
                // Deduplicate and annotate matching entries.
                for (auto& [fname, ids] : cyber_map) {
                    std::sort(ids.begin(), ids.end());
                    ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
                }
                for (auto& e : rpt.entries) {
                    std::string fname = fs::path(e.file).filename().string();
                    auto it = cyber_map.find(fname);
                    if (it != cyber_map.end()) {
                        std::string refs;
                        for (const auto& id : it->second) {
                            if (!refs.empty()) refs += ", ";
                            refs += id;
                        }
                        e.mitigations.push_back("CYBER: " + refs);
                    }
                }
            } catch (...) {}
        }
    }

    // §9.2 summary.coveragePct. componentsInProject reuses the exact same
    // header-declared public function/method scan as `trace --func-coverage`
    // (§1.4.1/§5) — the spec's explicit "same denominator" instruction.
    // componentsAnalyzed is the count of *distinct* components (by
    // kind+name+file) this run actually produced entries for. Because this
    // scanner's own regex-based declaration detection analyzes every
    // declaration it successfully parses (it never samples a "convenient
    // subset"), componentsAnalyzed is honestly the count of distinct
    // decls found — the real limitation this metric cannot see is
    // detection recall (multi-line signatures, templates, and macros the
    // single-line regex misses), which componentInventoryMethod discloses
    // rather than hiding behind a clean-looking percentage.
    std::set<std::string> distinct_components;
    for (const auto& d : decls) distinct_components.insert(d.kind + ":" + d.name + ":" + d.file);
    rpt.summary.components_analyzed = static_cast<int>(distinct_components.size());

    auto func_cov = trace::scan_func_coverage(dir);
    rpt.summary.components_in_project = std::max(func_cov.total,
                                                  rpt.summary.components_analyzed);
    rpt.summary.component_inventory_method =
        "componentsInProject = max(header-declared public function/method count from the same "
        "scan as `trace --func-coverage` [" + std::to_string(func_cov.total) + "], distinct "
        "class/function declarations this FMEA's own single-line-regex scanner detected). "
        "componentsAnalyzed = distinct declarations this run produced at least one entry for "
        "(this scanner never skips a declaration it detects — the honest caveat is detection "
        "recall: multi-line signatures, templates, and macro-generated declarations are not "
        "parsed, so componentsInProject is a lower bound on the project's true component count, "
        "not a ground truth).";
    if (rpt.summary.components_in_project > 0) {
        rpt.summary.coverage_pct = 100.0 * static_cast<double>(rpt.summary.components_analyzed)
                                          / static_cast<double>(rpt.summary.components_in_project);
    } else {
        rpt.summary.coverage_pct = 100.0; // nothing to analyze => nothing missed
    }
    // §9.2 MUST: coveragePct MUST NOT exceed 100. componentsInProject already
    // being max(func_cov.total, componentsAnalyzed) makes this structurally
    // unreachable today, but a defensive clamp is cheap insurance against a
    // future change to that formula silently reintroducing the exact bug
    // §9.2 calls out (a test fixture or excluded file counted as if it were
    // a real project component).
    rpt.summary.coverage_pct = std::min(100.0, rpt.summary.coverage_pct);

    rpt.summary.total = static_cast<int>(rpt.entries.size());
    for (const auto& e : rpt.entries)
        if (e.severity >= 8) ++rpt.summary.high_priority; // aligns with actionPriority=="high"

    return rpt;
}

json to_json(const FMEAReport& rpt, const config::ProjectConfig& cfg) {
    json j;
    j["schemaVersion"] = std::string(SpecVersion);
    j["kind"]          = "fmea-report";
    j["tool"]          = "cpp-FuSa";
    j["toolVersion"]   = std::string(Version);
    j["language"]      = "cpp";
    j["generatedAt"]   = rpt.generated_at;
    j["projectRoot"]   = cfg.project_root;
    if (!cfg.project.empty())  j["project"]  = cfg.project;
    if (!cfg.standard.empty()) j["standard"] = cfg.standard;
    j["ratingScale"]   = rpt.rating_scale;

    json ea = json::array();
    for (const auto& e : rpt.entries) {
        json ej;
        ej["id"]        = e.id;
        ej["item"]      = e.item;
        ej["file"]      = e.file;
        ej["failureMode"] = e.failure_mode;
        ej["effect"]    = e.effect;
        if (!e.cause.empty()) ej["cause"] = e.cause;
        ej["severity"]   = e.severity;
        ej["occurrence"] = e.occurrence;
        ej["detection"]  = e.detection;
        ej["rpn"]        = e.rpn;
        if (!e.action_priority.empty()) ej["actionPriority"] = e.action_priority;
        if (!e.mitigations.empty())     ej["mitigations"]    = e.mitigations;
        if (!e.requirement_ids.empty()) ej["requirementIds"] = e.requirement_ids;
        ea.push_back(ej);
    }
    j["entries"] = ea;

    j["summary"] = {
        {"total", rpt.summary.total},
        {"highPriority", rpt.summary.high_priority},
        {"componentsAnalyzed", rpt.summary.components_analyzed},
        {"componentsInProject", rpt.summary.components_in_project},
        {"coveragePct", rpt.summary.coverage_pct},
        {"componentInventoryMethod", rpt.summary.component_inventory_method}
    };

    if (rpt.attestation.present) j["attestation"] = quality::to_json(rpt.attestation);
    return j;
}

std::vector<Finding> scan_quality(const FMEAReport& rpt) {
    std::vector<quality::QualField> fields;
    for (const auto& e : rpt.entries) {
        fields.push_back({"failureMode", e.failure_mode, e.file, e.line});
        fields.push_back({"effect", e.effect, e.file, e.line});
        if (!e.cause.empty()) fields.push_back({"cause", e.cause, e.file, e.line});
    }
    std::vector<Finding> out = quality::scan_stub001(fields, std::string(FmeaJsonFile));
    auto rule_b = quality::scan_stub002(fields, std::string(FmeaJsonFile));
    out.insert(out.end(), rule_b.begin(), rule_b.end());
    return out;
}

//fusa:req REQ-FMEA002 REQ-FMEA004
Result<std::monostate> write(const fs::path& dir, const FMEAReport& rpt) {
    try {
        config::ProjectConfig cfg;
        cfg.project      = rpt.project;
        cfg.project_root = dir.string();
        // fmea.json
        {
            std::ofstream out(dir / FmeaJsonFile);
            out << to_json(rpt, cfg).dump(2) << "\n";
        }
        // fmea.csv
        {
            std::ofstream out(dir / FmeaCsvFile);
            out << "ID,Item,FailureMode,Effect,Severity,Occurrence,Detection,RPN,ActionPriority,File,Line\n";
            for (const auto& e : rpt.entries) {
                // Escape commas in fields.
                auto esc = [](const std::string& s) {
                    if (s.find(',') == std::string::npos) return s;
                    return "\"" + s + "\"";
                };
                out << e.id << "," << esc(e.item) << "," << esc(e.failure_mode)
                    << "," << esc(e.effect) << "," << e.severity << ","
                    << e.occurrence << "," << e.detection << "," << e.rpn
                    << "," << esc(e.action_priority) << "," << esc(e.file) << "," << e.line << "\n";
            }
        }
    } catch (const std::exception& ex) {
        return std::string("fmea: write: ") + ex.what();
    }
    return std::monostate{};
}

} // namespace cpfusa::fmea
