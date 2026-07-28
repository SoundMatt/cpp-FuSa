#pragma once
// sas generates a Software Accomplishment Summary per DO-178C §11.20 —
// x-FuSa spec §9.3.
#include "cpfusa/fusa.hpp"
#include "../quality/quality.hpp"
#include <nlohmann/json.hpp>
#include <filesystem>
#include <string>
#include <vector>

namespace cpfusa::sas {

//fusa:req REQ-SAS001
constexpr const char* SAS_MD_FILE   = "sas.md";
constexpr const char* SAS_JSON_FILE = "sas.json";

// §9.3: checklist[] — item/clause/present/evidence.
struct ChecklistItem {
    std::string item;      // §11 data item name (e.g. "PSAC availability")
    std::string clause;    // DO-178C §11.x clause reference
    std::string artifact;  // the evidence file this item maps to, project-relative
    bool present{false};
};

struct SAS {
    std::string project;
    std::string version;
    std::string generated_at;
    std::string dal;
    std::vector<ChecklistItem> checklist;
    int total{0};
    int present{0};
    quality::Attestation attestation;
};

[[nodiscard]] SAS build(const std::filesystem::path& dir,
                         const std::string& project,
                         const std::string& version,
                         const std::string& dal);

// to_json builds the §9.3 sas.json document.
//
//fusa:req REQ-SAS005
[[nodiscard]] nlohmann::json to_json(const SAS& s, const std::string& project_root);

void write_json(const std::filesystem::path& out, const SAS& s, const std::string& project_root);
void write_markdown(const std::filesystem::path& out, const SAS& s);

// scan_quality runs §1.6.1 rule A/B over every checklist item's free-text name.
//
//fusa:req REQ-SAS006
[[nodiscard]] std::vector<Finding> scan_quality(const SAS& s);

} // namespace cpfusa::sas
