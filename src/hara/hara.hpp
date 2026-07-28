#pragma once
#include "cpfusa/fusa.hpp"
#include "../quality/quality.hpp"
#include "../config/config.hpp"
#include <nlohmann/json.hpp>
#include <filesystem>
#include <string>
#include <vector>

namespace cpfusa::hara {

//fusa:req REQ-HARA001
constexpr const char* HARA_FILE = ".fusa-hara.json";

enum class Severity { S0, S1, S2, S3 };
enum class Exposure { E0, E1, E2, E3, E4 };
enum class Controllability { C0, C1, C2, C3 };

std::string determine_asil(Severity s, Exposure e, Controllability c);
Severity    parse_severity(const std::string& s);
Exposure    parse_exposure(const std::string& s);
Controllability parse_controllability(const std::string& s);

struct RiskRating {
    std::string severity;
    std::string exposure;
    std::string controllability;
    std::string asil;
};

// x-FuSa spec §1.2.5: a hazard manifests in operationalSituations[] and drives
// safetyGoals[] — cross-referenced by id, not embedded.
struct Hazard {
    std::string id;
    std::string description;
    std::string source;                     // SHOULD — which analysis/review surfaced it
    std::vector<std::string> situations;    // refs into operationalSituations[]
    RiskRating risk;
    std::vector<std::string> safety_goals;  // refs into safetyGoals[]
};

struct SafetyGoal {
    std::string id;
    std::string description;
    std::vector<std::string> hazards;   // refs back into hazards[] (spec key: "hazards")
    std::string asil;
    std::string safe_state;
    // fssrRefs (MUST, >=1 entry): the Functional Safety Requirement id(s) in
    // .fusa-reqs.json that decompose this goal (§1.2.5).
    std::vector<std::string> fssr_refs;
};

struct OperationalSituation {
    std::string id;
    std::string description;
};

struct HARA {
    std::string project;
    std::string standard;
    std::string created_at;
    std::vector<OperationalSituation> situations;
    std::vector<Hazard> hazards;
    std::vector<SafetyGoal> safety_goals;
    quality::Attestation attestation;
};

// Completeness rolls up §9.2 hara-report's `completeness` block.
struct Completeness {
    int total_hazards{0};
    int hazards_with_asil{0};
    int hazards_with_safety_goal{0};
    int total_safety_goals{0};
    int safety_goals_with_fssr_refs{0};
    int dangling_references{0};
};

// content_json builds the substantive (attestation-excluding) content of a
// HARA document — project/standard/createdAt/operationalSituations/hazards/
// safetyGoals — the same shape save() persists minus `attestation` itself.
// Used both by save() and by §1.6.2 attestation content-hash verification
// (a HARA file is author-edited, not auto-regenerated, so its "content" for
// hashing purposes is this shape, not a fresh generate() run's output).
//
//fusa:req REQ-HARA012
[[nodiscard]] nlohmann::json content_json(const HARA& h);

[[nodiscard]] bool load(const std::filesystem::path& dir, HARA& out, std::string& err);
[[nodiscard]] bool save(const std::filesystem::path& path, const HARA& h, std::string& err);
[[nodiscard]] bool init(const std::filesystem::path& dir, const std::string& project,
                        const std::string& standard, std::string& err);
void render_text(const HARA& h);

// completeness computes §9.2's completeness block. requirement_ids is the set
// of ids known to .fusa-reqs.json — used to detect a dangling fssrRefs entry
// alongside the file's own internal (situations/hazards/safetyGoals)
// cross-references (§1.2.5 referential-integrity rule).
//
//fusa:req REQ-HARA009
[[nodiscard]] Completeness compute_completeness(const HARA& h,
                                                const std::vector<std::string>& requirement_ids);

// scan_quality runs §1.6.1 rule A/B over every qualitative field this HARA
// carries (hazards[].description, safetyGoals[].description).
//
//fusa:req REQ-HARA010
[[nodiscard]] std::vector<Finding> scan_quality(const HARA& h);

// to_report_json builds the §9.2 hara-report document: the §3.1 header, the
// .fusa-hara.json content verbatim, `completeness`, and `attestation` passthrough.
//
//fusa:req REQ-HARA011
[[nodiscard]] nlohmann::json to_report_json(const HARA& h, const config::ProjectConfig& cfg,
                                            const std::vector<std::string>& requirement_ids);

} // namespace cpfusa::hara
