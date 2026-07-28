#include "safety_case.hpp"
#include "../release/release.hpp"
#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <ctime>

namespace fs = std::filesystem;
using json   = nlohmann::json;

namespace cpfusa::safety_case {

namespace {

std::string now_iso8601() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ss;
    ss << std::put_time(std::gmtime(&t), "%FT%TZ");
    return ss.str();
}

} // namespace

//fusa:req REQ-SAFETYCASE001 REQ-SAFETYCASE003 REQ-SAFETYCASE004 REQ-SAFETYCASE005
Result<SafetyCase> generate(const fs::path& dir, const config::ProjectConfig& cfg) {
    SafetyCase sc;
    sc.generated_at = now_iso8601();
    sc.project      = cfg.project;
    sc.standard     = cfg.standard;

    std::string project = cfg.project.empty() ? "this project" : cfg.project;
    std::string standard = cfg.standard.empty() ? "iso26262" : cfg.standard;
    std::string asil = cfg.asil.empty() ? "ASIL-B" : cfg.asil;

    // §9.2: nodes[].type is one of the six lowercase GSN node types.
    // node text is specific to this tool's actual claims (§1.6.1 rule B) —
    // no generic "the system is acceptably safe" boilerplate.
    sc.nodes = {
        {"G1",  "goal",     project + " produces conformant, non-fabricated safety evidence for "
                             + standard + " " + asil, "undeveloped", ""},
        {"G2",  "goal",     project + "'s own development process satisfies " + standard
                             + "'s tool-confidence-level requirements (ISO 26262-8 Clause 11)",
                             "undeveloped", ""},
        {"G3",  "goal",     "Every generated evidence artifact (fmea/tara/hara/safety-case/sas) "
                             "passes the §1.6 content-quality baseline (no placeholder text, no "
                             "blanket qualitative fallback)", "undeveloped", ""},
        {"G4",  "goal",     "Every requirement in .fusa-reqs.json is implemented and independently verified",
                             "undeveloped", ""},
        {"G5",  "goal",     "Static analysis (check/lint/analyze/cyber) reports no unmitigated ERROR findings",
                             "undeveloped", ""},
        {"G6",  "goal",     project + " itself is qualified as a verification tool per ISO 26262-8 Clause 11",
                             "undeveloped", ""},
        {"St1", "strategy", "Argument by direct inspection of generated evidence artifacts", ""},
        {"St2", "strategy", "Argument over independent verification and qualification records", ""},
        {"Sn1", "solution", "SAFETY_PLAN.md — documented development and evidence-generation plan",
                             "", "SAFETY_PLAN.md"},
        {"Sn2", "solution", ".fusa.json — declares the standard/ASIL this project is held to",
                             "", ".fusa.json"},
        {"Sn3", "solution", ".fusa-reqs.json — requirement registry with req/test traceability",
                             "", ".fusa-reqs.json"},
        {"Sn4", "solution", "qualify-report.json — tool qualification cases and pass/fail record",
                             "", "qualify-report.json"},
        {"Sn5", "solution", ".fusa-evidence.json — collected test execution evidence",
                             "", ".fusa-evidence.json"},
        {"Sn6", "solution", "check-report.json — the aggregated finding report `check` produced",
                             "", "check-report.json"},
        {"Sn7", "solution", "fmea.json / tara.json / .fusa-hara.json — pass the §1.6 quality baseline",
                             "", "fmea.json"},
        {"C1",  "context",  "Project: " + project + ", standard: " + standard + " " + asil, ""},
        {"A1",  "assumption","The compiler toolchain used to build " + project + " is itself qualified "
                              "or independently trusted for its intended use", ""},
        {"J1",  "justification", "§1.6.1's FUSA-STUB001/002 heuristics are an automatable proxy for "
                                  "content quality, not a substitute for a human reviewer's judgement — "
                                  "hence §1.6.2's attestation mechanism rather than a purely mechanical gate", ""},
    };

    sc.edges = {
        {"G1",  "St1", "supportedBy"},
        {"St1", "G3",  "inContextOf"},
        {"St1", "G5",  "inContextOf"},
        {"G1",  "St2", "supportedBy"},
        {"St2", "G2",  "inContextOf"},
        {"St2", "G4",  "inContextOf"},
        {"St2", "G6",  "inContextOf"},
        {"G2",  "Sn1", "supportedBy"},
        {"G2",  "Sn2", "supportedBy"},
        {"G4",  "Sn3", "supportedBy"},
        {"G4",  "Sn5", "supportedBy"},
        {"G5",  "Sn6", "supportedBy"},
        {"G6",  "Sn4", "supportedBy"},
        {"G3",  "Sn7", "supportedBy"},
        {"G1",  "C1",  "inContextOf"},
        {"St2", "A1",  "inContextOf"},
        {"G3",  "J1",  "inContextOf"},
    };

    // Collect evidence files present.
    for (const auto& name : release::EvidenceFiles) {
        if (fs::exists(dir / name)) sc.evidence.push_back(name);
    }

    // Mark goals as supported when their evidence file is present.
    auto has = [&](const std::string& name) {
        return fs::exists(dir / name);
    };
    for (auto& n : sc.nodes) {
        if (n.id == "G4" && has(".fusa-evidence.json")) n.status = "supported";
        if (n.id == "G5" && has("check-report.json"))   n.status = "supported";
        if (n.id == "G6" && has("qualify-report.json")) n.status = "supported";
        if (n.id == "G2" && has("SAFETY_PLAN.md"))      n.status = "supported";
        if (n.id == "G3" && has("fmea.json"))           n.status = "supported";
    }

    return sc;
}

//fusa:req REQ-SAFETYCASE007
Completeness compute_completeness(const SafetyCase& sc) {
    Completeness c;
    for (const auto& n : sc.nodes) {
        if (n.type != "goal") continue;
        ++c.total_goals;
        if (!n.evidence.empty()) ++c.goals_with_evidence;
        if (n.status == "undeveloped") ++c.undeveloped;
    }
    return c;
}

//fusa:req REQ-SAFETYCASE008
std::vector<Finding> scan_quality(const SafetyCase& sc) {
    std::vector<quality::QualField> fields;
    for (const auto& n : sc.nodes)
        fields.push_back({"nodes[].text", n.text, std::string(SafetyCaseJson), 0});
    std::vector<Finding> out = quality::scan_stub001(fields, std::string(SafetyCaseJson));
    auto rule_b = quality::scan_stub002(fields, std::string(SafetyCaseJson));
    out.insert(out.end(), rule_b.begin(), rule_b.end());
    return out;
}

//fusa:req REQ-SAFETYCASE006
json to_json(const SafetyCase& sc, const config::ProjectConfig& cfg) {
    json j;
    j["schemaVersion"] = std::string(SpecVersion);
    j["kind"]          = "safety-case";
    j["tool"]          = "cpp-FuSa";
    j["toolVersion"]   = std::string(Version);
    j["language"]      = "cpp";
    j["generatedAt"]   = sc.generated_at;
    j["projectRoot"]   = cfg.project_root;
    if (!sc.project.empty())  j["project"]  = sc.project;
    if (!sc.standard.empty()) j["standard"] = sc.standard;

    json na = json::array();
    for (const auto& n : sc.nodes) {
        json nj = {{"id", n.id}, {"type", n.type}, {"text", n.text}};
        if (!n.evidence.empty()) nj["evidence"] = n.evidence;
        if (!n.status.empty())   nj["status"]   = n.status; // tool-defined, additive to §9.2
        na.push_back(nj);
    }
    j["nodes"] = na;

    json ea = json::array();
    for (const auto& e : sc.edges)
        ea.push_back({{"from", e.from}, {"to", e.to}, {"type", e.type}});
    j["edges"] = ea;

    auto c = compute_completeness(sc);
    j["completeness"] = {
        {"totalGoals", c.total_goals},
        {"goalsWithEvidence", c.goals_with_evidence},
        {"undeveloped", c.undeveloped}
    };

    if (sc.attestation.present) j["attestation"] = quality::to_json(sc.attestation);
    return j;
}

//fusa:req REQ-SAFETYCASE002 REQ-SAFETYCASE005
Result<std::monostate> write(const fs::path& dir, const SafetyCase& sc) {
    try {
        config::ProjectConfig cfg;
        cfg.project      = sc.project;
        cfg.standard     = sc.standard;
        cfg.project_root = dir.string();
        // safety-case.json
        {
            std::ofstream out(dir / SafetyCaseJson);
            out << to_json(sc, cfg).dump(2) << "\n";
        }
        // safety-case.mermaid
        {
            std::ofstream out(dir / SafetyCaseMermaid);
            out << "graph TD\n";
            out << "%% cpp-FuSa Safety Case GSN — " << sc.project << "\n";
            for (const auto& n : sc.nodes) {
                std::string shape_open, shape_close;
                if (n.type == "goal")       { shape_open = "["; shape_close = "]"; }
                else if (n.type == "strategy"){ shape_open = "{"; shape_close = "}"; }
                else if (n.type == "solution"){ shape_open = "[("; shape_close = ")]"; }
                else if (n.type == "context") { shape_open = "(("; shape_close = "))"; }
                else                          { shape_open = "[/"; shape_close = "/]"; }
                // Truncate long text for the diagram
                auto txt = n.text;
                if (txt.size() > 50) txt = txt.substr(0, 47) + "...";
                // Escape special mermaid chars
                for (auto& c : txt) if (c == '"') c = '\'';
                out << "  " << n.id << shape_open << "\"" << n.type << ": " << txt << "\"" << shape_close << "\n";
            }
            for (const auto& e : sc.edges)
                out << "  " << e.from << " -->|\"" << e.type << "\"| " << e.to << "\n";
        }
        // safety-case.md
        {
            std::ofstream out(dir / SafetyCaseMd);
            out << "# Safety Case — " << sc.project << "\n\n";
            out << "**Standard:** " << sc.standard << "  \n";
            out << "**Generated:** " << sc.generated_at << "  \n\n";
            out << "## Goals\n\n";
            out << "| ID | Type | Status | Description |\n";
            out << "|----|------|--------|-------------|\n";
            for (auto& n : sc.nodes)
                out << "| " << n.id << " | " << n.type << " | " << n.status
                    << " | " << n.text << " |\n";
            out << "\n## Evidence (" << sc.evidence.size() << " files)\n\n";
            for (auto& e : sc.evidence)
                out << "- `" << e << "`\n";
        }
    } catch (const std::exception& e) {
        return std::string("safety-case: write: ") + e.what();
    }
    return std::monostate{};
}

} // namespace cpfusa::safety_case
