#pragma once
// safety_case generates a GSN (Goal Structuring Notation) safety case
// argument, per the GSN Community Standard (Assurance Case Working Group,
// v3, 2021) — x-FuSa spec §9.2. Outputs: safety-case.json + safety-case.mermaid
#include "cpfusa/fusa.hpp"
#include "../config/config.hpp"
#include "../quality/quality.hpp"
#include <nlohmann/json.hpp>
#include <filesystem>
#include <string>
#include <vector>

namespace cpfusa::safety_case {

constexpr std::string_view SafetyCaseJson    = "safety-case.json";
constexpr std::string_view SafetyCaseMermaid = "safety-case.mermaid";
constexpr std::string_view SafetyCaseMd      = "safety-case.md";

// §9.2: nodes[].type MUST be one of the six GSN node types, lowercase.
struct GSNNode {
    std::string id;
    std::string type;     // goal | strategy | solution | context | assumption | justification
    std::string text;
    std::string status;   // supported | undeveloped | defeated (tool-defined display state)
    std::string evidence;  // solution nodes SHOULD name a real artifact filename (§9.2)
};

// §9.2: edges[].type MUST be supportedBy (argument steps) or inContextOf
// (context/assumption/justification attachment).
struct GSNEdge {
    std::string from;
    std::string to;
    std::string type;   // supportedBy | inContextOf
};

struct Completeness {
    int total_goals{0};
    int goals_with_evidence{0};
    int undeveloped{0};
};

struct SafetyCase {
    std::string              generated_at;
    std::string              project;
    std::string              standard;
    std::vector<GSNNode>     nodes;
    std::vector<GSNEdge>     edges;
    std::vector<std::string> evidence;  // artifact filenames present in dir
    quality::Attestation     attestation;
};

// generate builds the GSN structure and collects evidence.
//
//fusa:req REQ-SAFETYCASE001
Result<SafetyCase> generate(const std::filesystem::path& dir,
                            const config::ProjectConfig& cfg);

// write serialises to safety-case.json, safety-case.mermaid and safety-case.md.
//
//fusa:req REQ-SAFETYCASE002
Result<std::monostate> write(const std::filesystem::path& dir, const SafetyCase& sc);

// to_json builds the §9.2 safety-case.json document.
//
//fusa:req REQ-SAFETYCASE006
[[nodiscard]] nlohmann::json to_json(const SafetyCase& sc, const config::ProjectConfig& cfg);

// compute_completeness rolls up §9.2's completeness block.
//
//fusa:req REQ-SAFETYCASE007
[[nodiscard]] Completeness compute_completeness(const SafetyCase& sc);

// scan_quality runs §1.6.1 rule A/B over every GSN node's text.
//
//fusa:req REQ-SAFETYCASE008
[[nodiscard]] std::vector<Finding> scan_quality(const SafetyCase& sc);

} // namespace cpfusa::safety_case
