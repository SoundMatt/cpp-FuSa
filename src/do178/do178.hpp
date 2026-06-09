#pragma once
#include <filesystem>
#include <string>
#include <vector>

namespace cpfusa::do178 {

//fusa:req REQ-DO178-001
constexpr const char* DO178_REPORT_FILE = "do178-gap-report.json";

enum class DAL { A, B, C, D };
DAL        parse_dal(const std::string& s);
std::string dal_str(DAL d);

enum class Status { Addressed, Partial, Gap };

struct Objective {
    std::string id;
    std::string table;
    std::string description;
    bool required_a{false};
    bool required_b{false};
    bool required_c{false};
    bool required_d{false};
    Status status{Status::Gap};
};

struct Report {
    std::string project;
    std::string dal;
    std::string generated_at;
    std::vector<Objective> objectives;
    int total{0};
    int addressed{0};
    int partial{0};
    int gap{0};
};

[[nodiscard]] Report assess(const std::filesystem::path& dir,
                             const std::string& project, DAL dal);
void write_json(const std::filesystem::path& out, const Report& r);
void render_text(const Report& r);

} // namespace cpfusa::do178
