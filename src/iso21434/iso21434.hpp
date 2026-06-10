//fusa:req REQ-ISO21434-001 REQ-ISO21434-002 REQ-ISO21434-003 REQ-ISO21434-004 REQ-ISO21434-005
#pragma once
#include <filesystem>
#include <string>
#include <vector>

namespace cpfusa::iso21434 {

constexpr const char* ISO21434_REPORT_FILE = "iso21434-gap-report.json";

enum class CAL { CAL1, CAL2, CAL3, CAL4 };
CAL         parse_cal(const std::string& s);
std::string cal_str(CAL c);

enum class Status { Satisfied, Partial, Gap };

struct Objective {
    std::string id;
    std::string clause;
    std::string title;
    bool automatable{false};    // can tool check via file presence
    bool required_cal1{true};
    bool required_cal2{true};
    bool required_cal3{true};
    bool required_cal4{true};
    Status status{Status::Gap};
    std::string evidence_file;  // file whose presence indicates partial evidence
    std::string notes;
};

struct Report {
    std::string project;
    std::string cal;
    std::string generated_at;
    std::vector<Objective> objectives;
    int total{0};
    int satisfied{0};
    int partial{0};
    int gap{0};
};

[[nodiscard]] Report assess(const std::filesystem::path& dir,
                             const std::string& project, CAL cal);
void write_json(const std::filesystem::path& out, const Report& r);
void render_text(const Report& r);

} // namespace cpfusa::iso21434
