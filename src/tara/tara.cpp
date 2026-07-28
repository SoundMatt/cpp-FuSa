#include "tara.hpp"
#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <ctime>
#include <set>

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

int feasibility_rank(const std::string& f) {
    if (f == "high") return 3;
    if (f == "medium") return 2;
    if (f == "low") return 1;
    return 0; // very-low
}

int impact_rank(const std::string& i) {
    if (i == "high") return 2;
    if (i == "medium") return 1;
    return 0; // low
}

const std::string& highest_impact(const SFOPImpact& impact) {
    const std::string* best = &impact.safety;
    for (const auto* candidate : {&impact.financial, &impact.operational, &impact.privacy})
        if (impact_rank(*candidate) > impact_rank(*best)) best = candidate;
    return *best;
}

// ISO 21434 Clause 15's risk determination: attackFeasibility x the highest
// SFOP impact axis (§9.2 — "risk MUST be derived from attackFeasibility x the
// highest SFOP impact").
//
//fusa:req REQ-TARA006
std::string derive_risk(const std::string& feasibility, const SFOPImpact& impact) {
    int fr = feasibility_rank(feasibility);
    int ir = impact_rank(highest_impact(impact));
    if (ir == 2) { // high impact
        if (fr >= 2) return "critical";
        if (fr == 1) return "high";
        return "medium";
    }
    if (ir == 1) { // medium impact
        if (fr >= 2) return "high";
        return "medium";
    }
    // low impact
    if (fr >= 2) return "medium";
    return "low";
}

struct ScenarioSpec {
    std::string id;
    std::string asset;
    std::string threat;
    std::string attack_vector;
    std::string attack_feasibility;
    SFOPImpact  impact;
    std::string treatment;
    std::vector<std::string> mitigations;
};

// Default threat scenarios covering the main attack surfaces of a C++ safety
// tool's own evidence pipeline (this project's actual assets — cpp-FuSa
// itself is the analyzed system here, same as FuSaOps' own dogfooded TARA).
std::vector<ScenarioSpec> default_scenarios(const config::ProjectConfig& cfg) {
    std::string prj = cfg.project.empty() ? "cpp-FuSa" : cfg.project;
    return {
        {"TARA-001", prj + " release binary", "Attacker replaces a signed release binary with a "
         "trojaned build that suppresses safety findings before it reaches a downstream project's CI.",
         "Compromise of the GitHub release pipeline, a maintainer's signing key, or the container "
         "registry hosting the all-in-one image.",
         "low",
         {"high", "medium", "medium", "low"},
         "mitigate",
         {"sign — HMAC-SHA256 artifact signing", "SLSA provenance verification (slsa command)",
          "Release workflow requires branch-protected, reviewed PRs before tagging"}},
        {"TARA-002", ".fusa.json / .fusa-hara.json project config", "Attacker (or careless commit) "
         "weakens the configured ASIL or replaces genuine hazard analysis with a stale/placeholder "
         "template, silently lowering the safety bar a downstream project believes it is held to.",
         "Direct write access to the repository, or a merged PR that was not reviewed for "
         "safety-relevant configuration changes.",
         "medium",
         {"high", "medium", "low", "low"},
         "mitigate",
         {"FUSA-STUB001 deny-list scan flags untouched hazard/goal templates (§1.6.1)",
          "Code review required on any change to .fusa.json / .fusa-hara.json",
          "hara --format json's completeness block surfaces missing ASIL/fssrRefs"}},
        {"TARA-003", "Generated evidence artifacts (fmea.json, tara.json, safety-case.json, "
         "check-report.json)", "Insider or compromised CI step edits a generated evidence artifact "
         "after generation to hide a known defect from a certification reviewer.",
         "Write access to the CI runner's workspace or the artifact upload step between generation "
         "and audit-pack bundling.",
         "low",
         {"high", "medium", "medium", "low"},
         "mitigate",
         {"audit-pack — hashed manifest over every evidence artifact",
          "sign --verify re-checks HMAC signatures before submission",
          "sci — Software Configuration Index records a per-file sha256 at release time"}},
        {"TARA-004", "Third-party CMake dependencies (FetchContent: CLI11, nlohmann/json, Catch2)",
         "A compromised upstream dependency introduces malicious code that runs inside cpfusa's own "
         "analysis process, potentially tampering with the findings it produces.",
         "Supply-chain compromise of an upstream GitHub repository or its release tags fetched by "
         "FetchDeps.cmake.",
         "very-low",
         {"high", "medium", "medium", "low"},
         "mitigate",
         {"vuln — scans CMake dependency manifests for known vulnerabilities",
          "Dependency versions pinned to tagged releases in cmake/FetchDeps.cmake"}},
        {"TARA-005", "qualify-report.json tool-qualification evidence", "Attacker modifies "
         "qualify-report.json to hide a failing qualification case, making an unqualified tool "
         "appear qualified for its intended safety use (ISO 26262-8 Clause 11).",
         "Direct file modification between qualify run and audit-pack bundling, or a forged report "
         "committed directly to the repository.",
         "low",
         {"high", "medium", "low", "low"},
         "mitigate",
         {"qualify.hash — RFC 8785 canonical integrity hash over the report content",
          "audit-pack bundles qualify-report.json under the same hashed manifest as every other artifact"}},
        {"TARA-006", "CI pipeline (ci.yml / release.yml)", "Attacker disables or bypasses the `check` "
         "gate step in CI, allowing a change with open ERROR findings to merge and release.",
         "Compromise of repository settings, a maintainer token, or a malicious workflow-file change "
         "in an unreviewed PR.",
         "medium",
         {"medium", "low", "high", "low"},
         "mitigate",
         {"Branch protection requires the check/lint/test CI jobs to pass before merge",
          "dco.yml enforces signed-off commits, raising the bar for an anonymous malicious push"}},
        {"TARA-007", "Source requirement annotations (//fusa:req, //fusa:test)", "Developer removes "
         "or mistypes an annotation to hide a requirement-traceability gap from `trace`'s coverage gate.",
         "A code change that deletes or corrupts an annotation without the reviewer noticing, since "
         "the annotation itself is easy to overlook in a diff.",
         "medium",
         {"medium", "low", "medium", "low"},
         "mitigate",
         {"trace --req-coverage / --func-coverage gates CI on annotation density",
          "trace flags a dangling //fusa:test reference to a nonexistent requirement id"}},
        {"TARA-008", ".fusa-dispositions.json waiver log", "Attacker (or an over-broad legitimate "
         "waiver) adds a rule-level disposition that silently suppresses a real, currently-open "
         "safety finding project-wide.",
         "A merged PR that adds a disposition entry without the scrutiny a normal finding-fix PR "
         "would receive, since a waiver reads as \"already handled\".",
         "medium",
         {"high", "low", "medium", "low"},
         "mitigate",
         {"disposition add requires --reviewer and --rationale (no anonymous waivers)",
          "Code review required on any change to .fusa-dispositions.json",
          "FUSA-STUB001 is disposition-suppressible only per-finding, never blanket (§1.6.1)"}},
    };
}

} // namespace

//fusa:req REQ-TARA001 REQ-TARA002 REQ-TARA003 REQ-TARA004 REQ-TARA005
Result<TARAReport> generate(const fs::path& /*dir*/, const config::ProjectConfig& cfg) {
    TARAReport rpt;
    rpt.generated_at = now_iso8601();
    rpt.project      = cfg.project;
    rpt.standard     = "iso21434";

    std::set<std::string> assets;
    for (auto& spec : default_scenarios(cfg)) {
        ThreatScenario s;
        s.id                 = spec.id;
        s.asset              = spec.asset;
        s.threat             = spec.threat;
        s.attack_vector      = spec.attack_vector;
        s.attack_feasibility = spec.attack_feasibility;
        s.impact             = spec.impact;
        s.risk        = derive_risk(s.attack_feasibility, s.impact);
        s.treatment   = spec.treatment;
        s.mitigations = spec.mitigations;
        rpt.scenarios.push_back(s);
        assets.insert(spec.asset);
    }

    // §9.2 summary.coveragePct. This TARA does not yet perform automated
    // asset discovery (e.g. from CMake targets or SBOM components) — its
    // scenario catalogue is hand-curated, so assetsInProject can only
    // honestly count the distinct assets *this catalogue itself* names, not
    // an independently measured attack surface. coveragePct therefore
    // reflects internal consistency (every named asset has >=1 scenario), not
    // completeness against the project's true asset inventory.
    rpt.summary.assets_analyzed = static_cast<int>(assets.size());
    rpt.summary.assets_in_project = static_cast<int>(assets.size());
    // Trivially 100% by construction (see asset_inventory_method below for
    // why that is not the same claim as "complete asset coverage").
    rpt.summary.coverage_pct = 100.0;
    rpt.summary.asset_inventory_method =
        "assetsInProject counts the distinct `asset` values named in this TARA's own "
        "hand-curated scenario catalogue. cpp-FuSa does not yet perform automated asset "
        "discovery (e.g. from CMake targets, SBOM components, or data-flow analysis), so "
        "this metric shows internal consistency of the catalogue (every named asset has at "
        "least one scenario), not an independently measured attack surface — the honest gap "
        "this leaves open is any project asset the catalogue's author simply never listed.";

    return rpt;
}

json to_json(const TARAReport& rpt, const config::ProjectConfig& cfg) {
    json j;
    j["schemaVersion"] = std::string(SpecVersion);
    j["kind"]          = "tara-report";
    j["tool"]          = "cpp-FuSa";
    j["toolVersion"]   = std::string(Version);
    j["language"]      = "cpp";
    j["generatedAt"]   = rpt.generated_at;
    j["projectRoot"]   = cfg.project_root;
    if (!cfg.project.empty()) j["project"] = cfg.project;
    j["standard"] = rpt.standard;

    json ta = json::array();
    for (const auto& s : rpt.scenarios) {
        json sj;
        sj["id"]                = s.id;
        sj["asset"]             = s.asset;
        sj["threat"]            = s.threat;
        if (!s.cwe.empty()) sj["cwe"] = s.cwe;
        sj["attackVector"]      = s.attack_vector;
        sj["attackFeasibility"] = s.attack_feasibility;
        sj["impact"] = {
            {"safety", s.impact.safety}, {"financial", s.impact.financial},
            {"operational", s.impact.operational}, {"privacy", s.impact.privacy}
        };
        sj["risk"]      = s.risk;
        sj["treatment"] = s.treatment;
        if (!s.mitigations.empty()) sj["mitigations"] = s.mitigations;
        if (!s.location_file.empty())
            sj["location"] = {{"file", s.location_file}, {"line", s.location_line}};
        if (!s.cyber_rule_id.empty()) sj["cyberRuleId"] = s.cyber_rule_id;
        ta.push_back(sj);
    }
    j["threats"] = ta;

    j["summary"] = {
        {"assetsAnalyzed", rpt.summary.assets_analyzed},
        {"assetsInProject", rpt.summary.assets_in_project},
        {"coveragePct", rpt.summary.coverage_pct},
        {"assetInventoryMethod", rpt.summary.asset_inventory_method}
    };

    if (rpt.attestation.present) j["attestation"] = quality::to_json(rpt.attestation);
    return j;
}

std::vector<Finding> scan_quality(const TARAReport& rpt) {
    std::vector<quality::QualField> fields;
    for (const auto& s : rpt.scenarios)
        fields.push_back({"threat", s.threat, s.location_file, s.location_line});
    std::vector<Finding> out = quality::scan_stub001(fields, std::string(TaraJsonFile));
    auto rule_b = quality::scan_stub002(fields, std::string(TaraJsonFile));
    out.insert(out.end(), rule_b.begin(), rule_b.end());
    return out;
}

//fusa:req REQ-TARA002
Result<std::monostate> write(const fs::path& dir, const TARAReport& rpt) {
    try {
        config::ProjectConfig cfg;
        cfg.project      = rpt.project;
        cfg.project_root = dir.string();
        // tara.json
        {
            std::ofstream out(dir / TaraJsonFile);
            out << to_json(rpt, cfg).dump(2) << "\n";
        }
        // tara.md
        {
            std::ofstream out(dir / TaraMdFile);
            out << "# TARA — " << rpt.project << "\n\n"
                << "Standard: " << rpt.standard << "  \n"
                << "Generated: " << rpt.generated_at << "  \n"
                << "Coverage: " << rpt.summary.assets_analyzed << "/"
                << rpt.summary.assets_in_project << " assets ("
                << std::fixed << std::setprecision(1) << rpt.summary.coverage_pct << "%)\n\n"
                << "| ID | Asset | Threat | Feasibility | Risk | Treatment |\n"
                << "|---|---|---|---|---|---|\n";
            for (const auto& s : rpt.scenarios) {
                out << "| " << s.id << " | " << s.asset << " | " << s.threat
                    << " | " << s.attack_feasibility
                    << " | " << s.risk
                    << " | " << s.treatment << " |\n";
            }
            out << "\n## Impact (SFOP) & Mitigations\n\n";
            for (const auto& s : rpt.scenarios) {
                out << "- **" << s.id << "** — safety=" << s.impact.safety
                    << " financial=" << s.impact.financial
                    << " operational=" << s.impact.operational
                    << " privacy=" << s.impact.privacy << "\n";
                for (const auto& m : s.mitigations) out << "  - " << m << "\n";
            }
        }
    } catch (const std::exception& e) {
        return std::string("tara: write: ") + e.what();
    }
    return std::monostate{};
}

} // namespace cpfusa::tara
