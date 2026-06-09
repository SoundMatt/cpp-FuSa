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

    // Top-level goal.
    sc.nodes = {
        {"G1",  "Goal",     cfg.project + " is acceptably safe for " + cfg.standard + " ASIL-" + cfg.asil, "undeveloped"},
        {"G2",  "Goal",     "Software development process meets " + cfg.standard + " requirements",         "undeveloped"},
        {"G3",  "Goal",     "No unacceptable residual risks remain",                                        "undeveloped"},
        {"G4",  "Goal",     "All requirements are implemented and verified",                                 "undeveloped"},
        {"G5",  "Goal",     "Static analysis reports no unmitigated errors",                                 "undeveloped"},
        {"G6",  "Goal",     "Tool is qualified per ISO 26262 Part 8",                                       "undeveloped"},
        {"S1",  "Strategy", "Argument over safety process evidence",                                         ""},
        {"S2",  "Strategy", "Argument over verification evidence",                                           ""},
        {"Sn1", "Solution", "SAFETY_PLAN.md — documented safety plan",                                      ""},
        {"Sn2", "Solution", ".fusa.json — project safety configuration",                                     ""},
        {"Sn3", "Solution", ".fusa-reqs.json — requirements register",                                      ""},
        {"Sn4", "Solution", "qualify-report.json — tool qualification evidence",                             ""},
        {"Sn5", "Solution", ".fusa-evidence.json — test execution evidence",                                 ""},
        {"Sn6", "Solution", "check-report.json — safety check report",                                      ""},
        {"C1",  "Context",  "Project: " + cfg.project + " standard: " + cfg.standard + " ASIL-" + cfg.asil, ""},
        {"A1",  "Assumption","Compiler toolchain is itself qualified",                                        ""},
    };

    sc.edges = {
        {"G1",  "S1",  "supported-by"},
        {"S1",  "G2",  "in-context-of"},
        {"S1",  "G3",  "in-context-of"},
        {"S1",  "G4",  "in-context-of"},
        {"S1",  "G5",  "in-context-of"},
        {"S1",  "G6",  "in-context-of"},
        {"G2",  "Sn1", "supported-by"},
        {"G2",  "Sn2", "supported-by"},
        {"G4",  "S2",  "supported-by"},
        {"S2",  "Sn3", "in-context-of"},
        {"S2",  "Sn5", "in-context-of"},
        {"G5",  "Sn6", "supported-by"},
        {"G6",  "Sn4", "supported-by"},
        {"G1",  "C1",  "in-context-of"},
        {"G2",  "A1",  "in-context-of"},
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
    }

    return sc;
}

//fusa:req REQ-SAFETYCASE002 REQ-SAFETYCASE005
Result<std::monostate> write(const fs::path& dir, const SafetyCase& sc) {
    try {
        // safety-case.json
        {
            json j;
            j["format"]      = "cpp-FuSa Safety Case v1 (GSN)";
            j["generatedAt"] = sc.generated_at;
            j["project"]     = sc.project;
            j["standard"]    = sc.standard;
            json na = json::array();
            for (const auto& n : sc.nodes)
                na.push_back({{"id",n.id},{"type",n.type},{"text",n.text},{"status",n.status}});
            j["nodes"] = na;
            json ea = json::array();
            for (const auto& e : sc.edges)
                ea.push_back({{"from",e.from},{"to",e.to},{"label",e.label}});
            j["edges"]    = ea;
            j["evidence"] = sc.evidence;
            std::ofstream out(dir / SafetyCaseJson);
            out << j.dump(2) << "\n";
        }
        // safety-case.mermaid
        {
            std::ofstream out(dir / SafetyCaseMermaid);
            out << "graph TD\n";
            out << "%% cpp-FuSa Safety Case GSN — " << sc.project << "\n";
            for (const auto& n : sc.nodes) {
                std::string shape_open, shape_close;
                if (n.type == "Goal")       { shape_open = "["; shape_close = "]"; }
                else if (n.type == "Strategy"){ shape_open = "{"; shape_close = "}"; }
                else if (n.type == "Solution"){ shape_open = "[("; shape_close = ")]"; }
                else if (n.type == "Context") { shape_open = "(("; shape_close = "))"; }
                else                          { shape_open = "[/"; shape_close = "/]"; }
                // Truncate long text for the diagram
                auto txt = n.text;
                if (txt.size() > 50) txt = txt.substr(0, 47) + "...";
                // Escape special mermaid chars
                for (auto& c : txt) if (c == '"') c = '\'';
                out << "  " << n.id << shape_open << "\"" << n.type << ": " << txt << "\"" << shape_close << "\n";
            }
            for (const auto& e : sc.edges)
                out << "  " << e.from << " -->|\"" << e.label << "\"| " << e.to << "\n";
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
