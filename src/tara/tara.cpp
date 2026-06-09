#include "tara.hpp"
#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <ctime>

namespace fs = std::filesystem;
using json   = nlohmann::json;

namespace cpfusa::tara {

namespace {

std::string now_iso8601() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ss;
    ss << std::put_time(std::gmtime(&t), "%FT%TZ");
    return ss.str();
}

std::string risk_level(int rv) {
    if (rv >= 13) return "critical";
    if (rv >= 9)  return "high";
    if (rv >= 5)  return "medium";
    return "low";
}

// Default threat scenarios covering the main attack surfaces of a C++ safety system.
std::vector<ThreatScenario> default_scenarios(const config::ProjectConfig& cfg) {
    std::string prj = cfg.project;
    return {
        {"TS-001", prj + " binary", "Tampering with build artifacts",
         "Attacker replaces signed binary with malicious version",
         2, 4, 8, "high", "mitigate", "Build integrity: sign all release artifacts"},
        {"TS-002", "Configuration (.fusa.json)", "Spoofing of safety configuration",
         "Attacker modifies ASIL level or safety standard to weaken enforcement",
         2, 3, 6, "medium", "mitigate", "Config integrity: store config in VCS and verify hash"},
        {"TS-003", prj + " CLI interface", "Information disclosure via verbose output",
         "Safety findings leaked to unprivileged process via stdout",
         1, 2, 2, "low", "accept", "Confidentiality: restrict CLI output in CI logs"},
        {"TS-004", "Third-party dependencies (FetchContent)", "Supply chain compromise",
         "Malicious dependency injected via compromised upstream",
         2, 4, 8, "high", "mitigate", "Integrity: pin dependency hashes in FetchDeps.cmake"},
        {"TS-005", "qualify-report.json", "Integrity violation of qualification evidence",
         "Attacker modifies qualify-report.json to hide failures",
         1, 4, 4, "medium", "mitigate", "Integrity: SHA-256 hash field in qualify-report.json"},
        {"TS-006", ".fusa-evidence.json", "Replay of stale test evidence",
         "Old passing evidence file reused after test suite degrades",
         2, 3, 6, "medium", "mitigate", "Freshness: timestamp + VCS revision in evidence bundle"},
        {"TS-007", "CI pipeline", "Denial of service to safety check gate",
         "Attacker disables cpfusa check step to bypass safety enforcement",
         2, 4, 8, "high", "mitigate", "Availability: branch protection requires CI passing"},
        {"TS-008", "Source code annotations (//fusa:req)", "Repudiation of requirement traceability",
         "Developer removes annotations to hide coverage gaps",
         1, 3, 3, "low", "mitigate", "Traceability: trace coverage gate enforced in CI"},
    };
}

} // namespace

//fusa:req REQ-TARA001
Result<TARAReport> generate(const fs::path& /*dir*/, const config::ProjectConfig& cfg) {
    TARAReport rpt;
    rpt.generated_at = now_iso8601();
    rpt.project      = cfg.project;
    rpt.standard     = "ISO 21434:2021 Ch.9";
    rpt.scenarios    = default_scenarios(cfg);
    for (auto& s : rpt.scenarios) {
        s.risk_value = s.feasibility * s.impact;
        s.risk_level = risk_level(s.risk_value);
    }
    return rpt;
}

//fusa:req REQ-TARA002
Result<std::monostate> write(const fs::path& dir, const TARAReport& rpt) {
    try {
        // tara.json
        {
            json j;
            j["format"]      = "cpp-FuSa TARA v1";
            j["generatedAt"] = rpt.generated_at;
            j["project"]     = rpt.project;
            j["standard"]    = rpt.standard;
            json sa = json::array();
            for (const auto& s : rpt.scenarios) {
                json sj;
                sj["id"]              = s.id;
                sj["asset"]           = s.asset;
                sj["threat"]          = s.threat;
                sj["damageScenario"]  = s.damage_scenario;
                sj["feasibility"]     = s.feasibility;
                sj["impact"]          = s.impact;
                sj["riskValue"]       = s.risk_value;
                sj["riskLevel"]       = s.risk_level;
                sj["treatment"]       = s.treatment;
                sj["cyberGoal"]       = s.cyber_goal;
                sa.push_back(sj);
            }
            j["scenarios"] = sa;
            std::ofstream out(dir / TaraJsonFile);
            out << j.dump(2) << "\n";
        }
        // tara.md
        {
            std::ofstream out(dir / TaraMdFile);
            out << "# TARA — " << rpt.project << "\n\n"
                << "Standard: " << rpt.standard << "  \n"
                << "Generated: " << rpt.generated_at << "\n\n"
                << "| ID | Asset | Threat | Feasibility | Impact | Risk | Level | Treatment |\n"
                << "|---|---|---|---|---|---|---|---|\n";
            for (const auto& s : rpt.scenarios) {
                out << "| " << s.id << " | " << s.asset << " | " << s.threat
                    << " | " << s.feasibility << " | " << s.impact
                    << " | " << s.risk_value << " | " << s.risk_level
                    << " | " << s.treatment << " |\n";
            }
            out << "\n## Cyber Goals\n\n";
            for (const auto& s : rpt.scenarios) {
                out << "- **" << s.id << "**: " << s.cyber_goal << "\n";
            }
        }
    } catch (const std::exception& e) {
        return std::string("tara: write: ") + e.what();
    }
    return std::monostate{};
}

} // namespace cpfusa::tara
