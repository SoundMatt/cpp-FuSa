#pragma once
#include <filesystem>
#include <string>
#include <vector>

namespace cpfusa::slsa {

//fusa:req REQ-SLSA001
constexpr const char* SLSA_REPORT_FILE = "slsa-report.json";

enum class Level { L1, L2, L3, L4 };
Level       parse_level(const std::string& s);
std::string level_str(Level l);

enum class Status { Met, Gap };
std::string status_str(Status s);

struct Requirement {
    std::string id;
    std::string level_str_val;
    std::string description;
    bool required_l1{false};
    bool required_l2{false};
    bool required_l3{false};
    bool required_l4{false};
    Status status{Status::Gap};
    std::string evidence_path;
};

struct Report {
    std::string project;
    std::string level;
    std::string generated_at;
    std::vector<Requirement> requirements;
    int total{0};
    int met{0};
    int gap{0};
};

[[nodiscard]] Report assess(const std::filesystem::path& dir,
                             const std::string& project, Level lvl);
void write_json(const std::filesystem::path& out, const Report& r);
void render_text(const Report& r);

} // namespace cpfusa::slsa
