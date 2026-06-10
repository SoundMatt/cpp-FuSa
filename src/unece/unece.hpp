//fusa:req REQ-UNECE-001 REQ-UNECE-002 REQ-UNECE-003 REQ-UNECE-004 REQ-UNECE-005
#pragma once
#include <filesystem>
#include <string>
#include <vector>

namespace cpfusa::unece {

constexpr const char* UNECE_R155_FILE = "unece-r155-gap-report.json";
constexpr const char* UNECE_R156_FILE = "unece-r156-gap-report.json";

enum class Status { Satisfied, Partial, Gap };

struct Threat {
    std::string id;          // TC-1 … TC-9 (R155) or SU-1 … SU-6 (R156)
    std::string regulation;  // "R155" or "R156"
    std::string clause;      // UN regulation clause reference
    std::string iso21434_ref;// corresponding ISO 21434 clause
    std::string title;
    bool automatable{false};
    Status status{Status::Gap};
    std::string evidence_file;
    std::string notes;
};

struct Report {
    std::string project;
    std::string regulation;  // "UNECE-R155" or "UNECE-R156"
    std::string generated_at;
    std::vector<Threat> threats;
    int total{0};
    int satisfied{0};
    int partial{0};
    int gap{0};
};

[[nodiscard]] Report assess_r155(const std::filesystem::path& dir,
                                  const std::string& project);
[[nodiscard]] Report assess_r156(const std::filesystem::path& dir,
                                  const std::string& project);
void write_json(const std::filesystem::path& out, const Report& r);
void render_text(const Report& r);

} // namespace cpfusa::unece
