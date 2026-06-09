#pragma once
#include <filesystem>
#include <string>
#include <vector>

namespace cpfusa::iso26262 {

//fusa:req REQ-ISO26262-001
constexpr const char* ISO26262_REPORT_FILE = "iso26262-gap-report.json";

enum class ASIL { A, B, C, D };
ASIL   parse_asil(const std::string& s);
std::string asil_str(ASIL a);

enum class Status { Addressed, Partial, Gap };

struct Objective {
    std::string id;        // e.g. "6-5.1"
    std::string part;      // "Part 6"
    std::string clause;
    std::string description;
    bool required_a{false};
    bool required_b{false};
    bool required_c{false};
    bool required_d{false};
    Status status{Status::Gap};
    std::string evidence;
};

struct Report {
    std::string project;
    std::string asil;
    std::string generated_at;
    std::vector<Objective> objectives;
    int total{0};
    int addressed{0};
    int partial{0};
    int gap{0};
};

[[nodiscard]] Report assess(const std::filesystem::path& dir,
                             const std::string& project, ASIL asil);
void write_json(const std::filesystem::path& out, const Report& r);
void render_text(const Report& r);

} // namespace cpfusa::iso26262
