#pragma once
// tara generates a Threat Analysis and Risk Assessment (TARA) per ISO 21434 Chapter 9.
// Outputs: tara.json + tara.md
#include "cpfusa/fusa.hpp"
#include "../config/config.hpp"
#include <filesystem>
#include <string>
#include <vector>

namespace cpfusa::tara {

constexpr std::string_view TaraJsonFile = "tara.json";
constexpr std::string_view TaraMdFile   = "tara.md";

struct ThreatScenario {
    std::string id;
    std::string asset;
    std::string threat;
    std::string damage_scenario;
    int         feasibility{1};   // 1–4 (ATTACK path factors)
    int         impact{1};        // 1–4 (Safety/Financial/Operational/Privacy)
    int         risk_value{0};    // feasibility * impact
    std::string risk_level;       // low/medium/high/critical
    std::string treatment;        // accept/mitigate/transfer/avoid
    std::string cyber_goal;
};

struct TARAReport {
    std::string                  generated_at;
    std::string                  project;
    std::string                  standard;
    std::vector<ThreatScenario>  scenarios;
};

// generate creates a TARA with default threat scenarios for the project.
//
//fusa:req REQ-TARA001
Result<TARAReport> generate(const std::filesystem::path& dir,
                            const config::ProjectConfig& cfg);

// write serialises the TARA to tara.json and tara.md in dir.
//
//fusa:req REQ-TARA002
Result<std::monostate> write(const std::filesystem::path& dir, const TARAReport& rpt);

} // namespace cpfusa::tara
