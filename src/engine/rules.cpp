#include "rules.hpp"
#include "../config/config.hpp"
#include <filesystem>
#include <fstream>
#include <regex>
#include <string>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace fs = std::filesystem;

namespace cpfusa::engine {

namespace {

// Returns true if any file in the directory tree matches the predicate.
// §1.2.1 MUST: honours both sourceDirs and excludePatterns, so a stray
// build directory (or anything else outside the configured source tree)
// can never satisfy a project-wide existence check like FUSA002's.
bool any_file(const fs::path& dir, const config::ProjectConfig& cfg,
              const std::function<bool(const fs::path&)>& pred) {
    if (!fs::exists(dir)) return false;
    for (const auto& entry : fs::recursive_directory_iterator(
             dir, fs::directory_options::skip_permission_denied)) {
        if (!entry.is_regular_file()) continue;
        if (!config::under_source_dirs(entry.path(), dir, cfg)) continue;
        // generic_string() (always "/"-separated) — excludePatterns are
        // "/"-style gitignore globs (§1.2.1) regardless of platform;
        // .string() would use "\"-separated native form on Windows and
        // silently never match.
        auto s = entry.path().generic_string();
        bool excluded = false;
        for (const auto& pat : cfg.exclude_patterns) {
            if (s.find(pat) != std::string::npos) { excluded = true; break; }
        }
        if (excluded) continue;
        if (pred(entry.path())) return true;
    }
    return false;
}

// Searches all .cpp/.hpp/.h/.cxx/.cc files for a regex pattern.
bool source_contains(const fs::path& dir, const config::ProjectConfig& cfg,
                     const std::regex& pat) {
    static const std::regex cpp_ext(R"(\.(cpp|hpp|h|cxx|cc|hxx|c\+\+)$)");
    return any_file(dir, cfg, [&](const fs::path& p) {
        if (!std::regex_search(p.string(), cpp_ext)) return false;
        std::ifstream f(p);
        std::string line;
        while (std::getline(f, line)) {
            if (std::regex_search(line, pat)) return true;
        }
        return false;
    });
}

} // anonymous namespace

// FUSA001 – Project configuration file (.fusa.json) must exist.
//fusa:req REQ-FUSA001
Rule make_fusa001() {
    return Rule{
        RuleInfo{"FUSA001", "Project configuration",
                 "A .fusa.json configuration file must exist at the project root.",
                 Severity::ERROR},
        [](const fs::path& dir, const config::ProjectConfig&) -> std::vector<Finding> {
            if (fs::exists(dir / ".fusa.json")) return {};
            return {Finding{"FUSA001", Severity::ERROR,
                            ".fusa.json not found — run 'cpfusa init'",
                            ".fusa.json", 0,
                            "cpfusa init", "config"}};
        }};
}

// FUSA002 – At least one //fusa:req annotation must exist in source.
//fusa:req REQ-FUSA002
Rule make_fusa002() {
    return Rule{
        RuleInfo{"FUSA002", "Requirements annotations",
                 "Source must contain at least one //fusa:req annotation.",
                 Severity::WARNING},
        [](const fs::path& dir, const config::ProjectConfig& cfg) -> std::vector<Finding> {
            static const std::regex req_pat(R"(//\s*fusa:req\s+\S)");
            if (source_contains(dir, cfg, req_pat)) return {};
            return {Finding{"FUSA002", Severity::WARNING,
                            "No //fusa:req annotations found — traceability cannot be established",
                            "", 0,
                            "Add //fusa:req REQ-XXX comments above safety-critical functions",
                            "requirement"}};
        }};
}

// FUSA003 – The project version field must be set (not empty / not "0.0.0").
//fusa:req REQ-FUSA003
Rule make_fusa003() {
    return Rule{
        RuleInfo{"FUSA003", "Safety version declared",
                 "project.version must be set in .fusa.json.",
                 Severity::WARNING},
        [](const fs::path&, const config::ProjectConfig& cfg) -> std::vector<Finding> {
            if (!cfg.version.empty() && cfg.version != "0.0.0") return {};
            return {Finding{"FUSA003", Severity::WARNING,
                            "Safety version is not declared in .fusa.json",
                            ".fusa.json", 0,
                            "Set the \"version\" field in .fusa.json", "config"}};
        }};
}

// FUSA004 – Test evidence file must exist.
//fusa:req REQ-FUSA004
Rule make_fusa004() {
    return Rule{
        RuleInfo{"FUSA004", "Test evidence",
                 "A test evidence bundle (.fusa-evidence.json) must be present.",
                 Severity::WARNING},
        [](const fs::path& dir, const config::ProjectConfig&) -> std::vector<Finding> {
            if (fs::exists(dir / ".fusa-evidence.json")) return {};
            return {Finding{"FUSA004", Severity::WARNING,
                            ".fusa-evidence.json not found — run 'cpfusa verify' after tests pass",
                            ".fusa-evidence.json", 0,
                            "cpfusa verify", "safety"}};
        }};
}

// FUSA005 – CHANGELOG.md must exist and be non-empty.
//fusa:req REQ-FUSA005
Rule make_fusa005() {
    return Rule{
        RuleInfo{"FUSA005", "CHANGELOG present",
                 "CHANGELOG.md must exist and contain at least one release entry.",
                 Severity::INFO},
        [](const fs::path& dir, const config::ProjectConfig&) -> std::vector<Finding> {
            auto p = dir / "CHANGELOG.md";
            if (fs::exists(p) && fs::file_size(p) > 10) return {};
            return {Finding{"FUSA005", Severity::INFO,
                            "CHANGELOG.md missing or empty — add a release history",
                            "CHANGELOG.md", 0,
                            "Create CHANGELOG.md with at least one version entry", "config"}};
        }};
}

// COUP003 — coupling-report.json absent in DO-178C project
//fusa:req REQ-COUP003
Rule make_coup003() {
    return Rule{
        RuleInfo{"COUP003", "Coupling evidence missing",
                 "coupling-report.json absent — run 'cpfusa coupling' for DO-178C evidence.",
                 Severity::INFO},
        [](const fs::path& dir, const config::ProjectConfig& cfg) -> std::vector<Finding> {
            if (cfg.standard != "DO178C" && cfg.standard != "DO-178C") return {};
            if (fs::exists(dir / "coupling-report.json")) return {};
            return {Finding{"COUP003", Severity::INFO,
                            "coupling-report.json not found — run 'cpfusa coupling'",
                            "", 0, "cpfusa coupling", "traceability"}};
        }};
}

// HARA005 — highest ASIL in hara exceeds project ASIL
//fusa:req REQ-HARA005
Rule make_hara005() {
    return Rule{
        RuleInfo{"HARA005", "ASIL under-allocation",
                 "Highest hazard ASIL in .fusa-hara.json exceeds project ASIL in .fusa.json.",
                 Severity::WARNING},
        [](const fs::path& dir, const config::ProjectConfig& cfg) -> std::vector<Finding> {
            auto hara_path = dir / ".fusa-hara.json";
            if (!fs::exists(hara_path) || cfg.asil.empty()) return {};
            // ASIL ranking: QM<A<B<C<D
            auto rank = [](const std::string& a) -> int {
                if (a == "ASIL-D" || a == "D") return 4;
                if (a == "ASIL-C" || a == "C") return 3;
                if (a == "ASIL-B" || a == "B") return 2;
                if (a == "ASIL-A" || a == "A") return 1;
                return 0;
            };
            try {
                std::ifstream f(hara_path);
                json j = json::parse(f);
                int max_rank = 0;
                std::string max_asil;
                for (const auto& hz : j.value("hazards", json::array())) {
                    std::string ha = hz.value("risk", json{}).value("asil", "QM");
                    if (rank(ha) > max_rank) {
                        max_rank = rank(ha);
                        max_asil = ha;
                    }
                }
                if (max_rank > rank(cfg.asil)) {
                    return {Finding{"HARA005", Severity::WARNING,
                                    "Hazard ASIL " + max_asil + " exceeds project ASIL " + cfg.asil +
                                    " — update .fusa.json or re-evaluate hazard",
                                    ".fusa-hara.json", 0,
                                    "Raise project asil in .fusa.json or decompose the hazard",
                                    "safety"}};
                }
            } catch (...) {}
            return {};
        }};
}

// ISO26262002 — requirements without asil field in ISO 26262 project
//fusa:req REQ-ISO26262002
Rule make_iso26262002() {
    return Rule{
        RuleInfo{"ISO26262002", "Requirements missing ASIL field",
                 "Requirements in .fusa-reqs.json have no asil field (ISO 26262 project).",
                 Severity::INFO},
        [](const fs::path& dir, const config::ProjectConfig& cfg) -> std::vector<Finding> {
            if (cfg.standard != "ISO26262" && cfg.standard != "ISO 26262") return {};
            auto path = dir / ".fusa-reqs.json";
            if (!fs::exists(path)) return {};
            try {
                std::ifstream f(path);
                json j = json::parse(f);
                const json& arr = j.is_array() ? j : j.at("requirements");
                for (const auto& item : arr) {
                    std::string asil = item.value("asil", "");
                    if (asil.empty()) {
                        return {Finding{"ISO26262002", Severity::INFO,
                                        "One or more requirements lack an 'asil' field — add asil to .fusa-reqs.json",
                                        ".fusa-reqs.json", 0,
                                        "Add \"asil\": \"ASIL-B\" (or appropriate level) to each requirement",
                                        "requirement"}};
                    }
                }
            } catch (...) {}
            return {};
        }};
}

// ISO26262003 — qualify-report.json has failures
//fusa:req REQ-ISO26262003
Rule make_iso26262003() {
    return Rule{
        RuleInfo{"ISO26262003", "Tool qualification failures",
                 "qualify-report.json reports one or more test failures.",
                 Severity::WARNING},
        [](const fs::path& dir, const config::ProjectConfig&) -> std::vector<Finding> {
            auto path = dir / "qualify-report.json";
            if (!fs::exists(path)) return {};
            try {
                std::ifstream f(path);
                json j = json::parse(f);
                int failed = j.value("failed", 0);
                if (failed > 0) {
                    return {Finding{"ISO26262003", Severity::WARNING,
                                    std::to_string(failed) + " tool qualification case(s) failed — requalify before release",
                                    "qualify-report.json", 0,
                                    "Run 'cpfusa qualify' and ensure all cases pass",
                                    "safety"}};
                }
            } catch (...) {}
            return {};
        }};
}

// HARA002 — hazard missing S/E/C risk parameters
//fusa:req REQ-HARA002
Rule make_hara002() {
    return Rule{
        RuleInfo{"HARA002", "Hazard missing S/E/C risk parameters",
                 "A hazard in .fusa-hara.json has no severity, exposure, or controllability.",
                 Severity::WARNING},
        [](const fs::path& dir, const config::ProjectConfig&) -> std::vector<Finding> {
            auto hara_path = dir / ".fusa-hara.json";
            if (!fs::exists(hara_path)) return {};
            try {
                std::ifstream f(hara_path);
                json j = json::parse(f);
                for (const auto& hz : j.value("hazards", json::array())) {
                    const json& risk = hz.value("risk", json{});
                    std::string sev = risk.value("severity", "");
                    std::string exp = risk.value("exposure", "");
                    std::string con = risk.value("controllability", "");
                    if (sev.empty() || exp.empty() || con.empty()) {
                        return {Finding{"HARA002", Severity::WARNING,
                                        "Hazard '" + hz.value("id", "?") +
                                        "' is missing severity, exposure, or controllability (ISO 26262-3 §7)",
                                        ".fusa-hara.json", 0,
                                        "Add risk.severity, risk.exposure, risk.controllability to the hazard",
                                        "safety"}};
                    }
                }
            } catch (...) {}
            return {};
        }};
}

// HARA003 — hazard not linked to a safety goal
//fusa:req REQ-HARA003
Rule make_hara003() {
    return Rule{
        RuleInfo{"HARA003", "Hazard not linked to a safety goal",
                 "A hazard in .fusa-hara.json has an empty safetyGoals list.",
                 Severity::WARNING},
        [](const fs::path& dir, const config::ProjectConfig&) -> std::vector<Finding> {
            auto hara_path = dir / ".fusa-hara.json";
            if (!fs::exists(hara_path)) return {};
            try {
                std::ifstream f(hara_path);
                json j = json::parse(f);
                for (const auto& hz : j.value("hazards", json::array())) {
                    auto goals = hz.value("safetyGoals", json::array());
                    if (goals.empty()) {
                        return {Finding{"HARA003", Severity::WARNING,
                                        "Hazard '" + hz.value("id", "?") +
                                        "' has no linked safety goals (ISO 26262-3 §8)",
                                        ".fusa-hara.json", 0,
                                        "Add safetyGoals references to the hazard",
                                        "safety"}};
                    }
                }
            } catch (...) {}
            return {};
        }};
}

// HARA004 — safety goal missing ASIL assignment
//fusa:req REQ-HARA004
Rule make_hara004() {
    return Rule{
        RuleInfo{"HARA004", "Safety goal has no ASIL assigned",
                 "A safety goal in .fusa-hara.json has no asil field.",
                 Severity::WARNING},
        [](const fs::path& dir, const config::ProjectConfig&) -> std::vector<Finding> {
            auto hara_path = dir / ".fusa-hara.json";
            if (!fs::exists(hara_path)) return {};
            try {
                std::ifstream f(hara_path);
                json j = json::parse(f);
                for (const auto& sg : j.value("safetyGoals", json::array())) {
                    std::string asil = sg.value("asil", "");
                    if (asil.empty()) {
                        return {Finding{"HARA004", Severity::WARNING,
                                        "Safety goal '" + sg.value("id", "?") +
                                        "' has no ASIL assigned (ISO 26262-3 §8)",
                                        ".fusa-hara.json", 0,
                                        "Add an asil field (e.g. \"asil\": \"ASIL-B\") to the safety goal",
                                        "safety"}};
                    }
                }
            } catch (...) {}
            return {};
        }};
}

// VERIFY002 — test evidence reports failures
//fusa:req REQ-VERIFY006
Rule make_verify002() {
    return Rule{
        RuleInfo{"VERIFY002", "Test evidence reports failures",
                 ".fusa-evidence.json summary.failed > 0 — tests are not green.",
                 Severity::ERROR},
        [](const fs::path& dir, const config::ProjectConfig&) -> std::vector<Finding> {
            auto path = dir / ".fusa-evidence.json";
            if (!fs::exists(path)) return {};
            try {
                std::ifstream f(path);
                json j = json::parse(f);
                int failed = j.value("summary", json{}).value("failed", 0);
                if (failed > 0) {
                    return {Finding{"VERIFY002", Severity::ERROR,
                                    std::to_string(failed) + " test(s) failed in .fusa-evidence.json — all tests must pass before release",
                                    ".fusa-evidence.json", 0,
                                    "Run 'ctest --output-on-failure -j1' and fix failing tests",
                                    "verification"}};
                }
            } catch (...) {}
            return {};
        }};
}

} // namespace cpfusa::engine
