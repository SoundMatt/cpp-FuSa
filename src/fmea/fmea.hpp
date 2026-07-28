#pragma once
// fmea generates a Design FMEA from C++ class/function declarations, per
// IEC 60812:2018 / the AIAG & VDA FMEA Handbook (2019) methodology (x-FuSa
// spec §9.2). Outputs: fmea.json + fmea.csv
#include "cpfusa/fusa.hpp"
#include "../config/config.hpp"
#include "../quality/quality.hpp"
#include <nlohmann/json.hpp>
#include <filesystem>
#include <string>
#include <vector>

namespace cpfusa::fmea {

constexpr std::string_view FmeaJsonFile = "fmea.json";
constexpr std::string_view FmeaCsvFile  = "fmea.csv";

// RatingScale names the severity/occurrence/detection table in use (§9.2:
// "ratingScale MUST when occurrence/detection are emitted"). cpp-FuSa predates
// full AIAG-VDA 2019 adoption and derives its 1-10 ratings from its own
// heuristic buckets, so it is named rather than claiming a standard it does
// not implement verbatim.
constexpr std::string_view RatingScale = "cpp-fusa-1-10";

struct FmeaEntry {
    std::string id;
    std::string item;            // §9.2 MUST: "Component.Function" identity
    std::string component;       // class or function name
    std::string file;            // MUST, project-relative (§4 rule)
    int         line{0};
    std::string failure_mode;    // MUST — varies with item's real signature (§1.6.1 rule B)
    std::string effect;          // MUST
    std::string cause;           // SHOULD
    int         severity{5};     // 1-10
    int         occurrence{5};   // 1-10
    int         detection{5};    // 1-10
    int         rpn{0};          // severity * occurrence * detection (MAY, legacy metric)
    std::string action_priority; // SHOULD (AIAG-VDA): high|medium|low
    std::vector<std::string> mitigations;     // SHOULD
    std::vector<std::string> requirement_ids; // SHOULD
};

// Summary rolls up totals and the §9.2 analysis-coverage metrics.
struct Summary {
    int    total{0};
    int    high_priority{0};
    int    components_analyzed{0};
    int    components_in_project{0};
    double coverage_pct{0.0};
    // componentInventoryMethod (SHOULD) — honestly names how
    // components_in_project was counted, never inflated (§9.2).
    std::string component_inventory_method;
};

struct FMEAReport {
    std::string             generated_at;
    std::string             project;
    std::string             rating_scale{RatingScale};
    std::vector<FmeaEntry>  entries;
    Summary                 summary;
    quality::Attestation    attestation;
};

// generate scans source files for class/function declarations and creates FMEA entries.
// When enrich_cyber is true, cross-references cyber-report.json and appends CYBER
// finding rule IDs to each entry whose source file has cybersecurity findings.
//
//fusa:req REQ-FMEA001 REQ-FMEA007
Result<FMEAReport> generate(const std::filesystem::path& dir,
                            const config::ProjectConfig& cfg,
                            bool enrich_cyber = false);

// write serialises the FMEA to fmea.json and fmea.csv in dir.
//
//fusa:req REQ-FMEA002
Result<std::monostate> write(const std::filesystem::path& dir, const FMEAReport& rpt);

// to_json builds the §9.2 fmea.json document (§3.1 header + entries + summary
// + attestation passthrough) — the same shape write() persists, exposed so the
// CLI can also render it directly (e.g. for --format json without --output).
//
//fusa:req REQ-FMEA008
[[nodiscard]] nlohmann::json to_json(const FMEAReport& rpt, const config::ProjectConfig& cfg);

// scan_quality runs §1.6.1 rule A/B over every qualitative field
// (failureMode/effect/cause) this FMEA carries.
//
//fusa:req REQ-FMEA009
[[nodiscard]] std::vector<Finding> scan_quality(const FMEAReport& rpt);

} // namespace cpfusa::fmea
