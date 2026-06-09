#pragma once
#include <filesystem>
#include <string>
#include <vector>

namespace cpfusa::iec61508 {

//fusa:req REQ-IEC61508-001
constexpr const char* IEC61508_REPORT_FILE = "iec61508-gap-report.json";

enum class SIL { SIL1, SIL2, SIL3, SIL4 };
SIL        parse_sil(const std::string& s);
std::string sil_str(SIL s);

enum class Status { Addressed, Partial, Gap };

struct Objective {
    std::string id;
    std::string part;
    std::string clause;
    std::string description;
    bool required_1{false};
    bool required_2{false};
    bool required_3{false};
    bool required_4{false};
    Status status{Status::Gap};
};

struct Report {
    std::string project;
    std::string sil;
    std::string generated_at;
    std::vector<Objective> objectives;
    int total{0};
    int addressed{0};
    int partial{0};
    int gap{0};
};

[[nodiscard]] Report assess(const std::filesystem::path& dir,
                             const std::string& project, SIL sil);
void write_json(const std::filesystem::path& out, const Report& r);
void render_text(const Report& r);

} // namespace cpfusa::iec61508
