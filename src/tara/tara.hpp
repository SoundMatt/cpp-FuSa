#pragma once
// tara generates a Threat Analysis and Risk Assessment (TARA) per ISO/SAE
// 21434:2021 Clause 15 (x-FuSa spec §9.2). Outputs: tara.json + tara.md
#include "cpfusa/fusa.hpp"
#include "../config/config.hpp"
#include "../quality/quality.hpp"
#include <nlohmann/json.hpp>
#include <filesystem>
#include <string>
#include <vector>

namespace cpfusa::tara {

constexpr std::string_view TaraJsonFile = "tara.json";
constexpr std::string_view TaraMdFile   = "tara.md";

// Impact rates one SFOP (Safety/Financial/Operational/Privacy) axis, ISO
// 21434 Clause 15.7 — a threat rates differently on each axis, so §9.2's
// `impact` is an object of four of these, not one generic severity.
// §9.2 closed enum (MUST): critical | major | moderate | negligible — a
// tool MUST NOT substitute the high|medium|low vocabulary used elsewhere
// (e.g. attackFeasibility) for these four fields; the two are deliberately
// distinct scales for distinct questions (likelihood vs. damage).
struct SFOPImpact {
    std::string safety{"negligible"};
    std::string financial{"negligible"};
    std::string operational{"negligible"};
    std::string privacy{"negligible"};
};

struct ThreatScenario {
    std::string id;
    std::string asset;              // MUST
    std::string threat;             // MUST — specific attack scenario, not a bare category
    std::string cwe;                // SHOULD when applicable
    std::string attack_vector;      // MUST
    std::string attack_feasibility; // MUST: high|medium|low|very-low
    SFOPImpact  impact;             // MUST
    std::string risk;               // MUST: derived from feasibility x highest SFOP impact
    std::string treatment;          // MUST: mitigate|accept|transfer|avoid
    std::vector<std::string> mitigations; // SHOULD
    std::string location_file;      // SHOULD when code-derived
    int         location_line{0};
    std::string cyber_rule_id;      // SHOULD — links to the triggering `cyber` finding
};

struct Summary {
    int    assets_analyzed{0};
    int    assets_in_project{0};
    double coverage_pct{0.0};
    // assetInventoryMethod (SHOULD) — honestly names how assets_in_project was
    // enumerated (§9.2: "asset discovery methodology varies more than
    // function enumeration does").
    std::string asset_inventory_method;
};

struct TARAReport {
    std::string                  generated_at;
    std::string                  project;
    std::string                  standard;
    std::vector<ThreatScenario>  scenarios;
    Summary                      summary;
    quality::Attestation         attestation;
};

// derive_risk implements the x-FuSa spec §9.2 TARA risk-combination table:
// looked up by attackFeasibility (high|medium|low|very-low) against the
// highest-ranked SFOP impact axis (critical|major|moderate|negligible).
// Exposed (rather than kept file-local) so the full 4x4 combination table
// can be unit-tested directly rather than only through the fixed default
// scenario catalogue, which does not exercise every cell.
//
//fusa:req REQ-TARA008
[[nodiscard]] std::string derive_risk(const std::string& attack_feasibility,
                                      const SFOPImpact& impact);

// generate creates a TARA with default threat scenarios for the project.
//
//fusa:req REQ-TARA001
Result<TARAReport> generate(const std::filesystem::path& dir,
                            const config::ProjectConfig& cfg);

// write serialises the TARA to tara.json and tara.md in dir.
//
//fusa:req REQ-TARA002
Result<std::monostate> write(const std::filesystem::path& dir, const TARAReport& rpt);

// to_json builds the §9.2 tara.json document.
//
//fusa:req REQ-TARA006
[[nodiscard]] nlohmann::json to_json(const TARAReport& rpt, const config::ProjectConfig& cfg);

// scan_quality runs §1.6.1 rule A/B over every qualitative field (threat).
//
//fusa:req REQ-TARA007
[[nodiscard]] std::vector<Finding> scan_quality(const TARAReport& rpt);

} // namespace cpfusa::tara
