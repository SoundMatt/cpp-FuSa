#pragma once
// safety_case generates a GSN (Goal Structuring Notation) safety case argument
// with evidence collected from project artifacts.
// Outputs: safety-case.json + safety-case.mermaid
#include "cpfusa/fusa.hpp"
#include "../config/config.hpp"
#include <filesystem>
#include <string>
#include <vector>

namespace cpfusa::safety_case {

constexpr std::string_view SafetyCaseJson    = "safety-case.json";
constexpr std::string_view SafetyCaseMermaid = "safety-case.mermaid";

struct GSNNode {
    std::string id;
    std::string type;     // Goal | Strategy | Solution | Context | Assumption
    std::string text;
    std::string status;   // supported | undeveloped | defeated
};

struct GSNEdge {
    std::string from;
    std::string to;
    std::string label;
};

struct SafetyCase {
    std::string              generated_at;
    std::string              project;
    std::string              standard;
    std::vector<GSNNode>     nodes;
    std::vector<GSNEdge>     edges;
    std::vector<std::string> evidence;  // artifact filenames present in dir
};

// generate builds the GSN structure and collects evidence.
//
//fusa:req REQ-SAFETYCASE001
Result<SafetyCase> generate(const std::filesystem::path& dir,
                            const config::ProjectConfig& cfg);

// write serialises to safety-case.json and safety-case.mermaid.
//
//fusa:req REQ-SAFETYCASE002
Result<std::monostate> write(const std::filesystem::path& dir, const SafetyCase& sc);

} // namespace cpfusa::safety_case
