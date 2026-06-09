#pragma once
#include <filesystem>
#include <string>
#include <vector>

namespace cpfusa::coverage {

//fusa:req REQ-COV001
constexpr const char* COVERAGE_FILE        = "coverage.info";
constexpr const char* COVERAGE_REPORT_FILE = "coverage-report.json";

enum class DAL { A, B, C, D };
DAL         parse_dal(const std::string& s);
std::string dal_str(DAL d);

struct FileCoverage {
    std::string filename;
    int lines_total{0};
    int lines_hit{0};
    int branches_total{0};
    int branches_hit{0};
    double line_pct{0.0};
    double branch_pct{0.0};
};

struct CoverageReport {
    std::string generated_at;
    std::string dal;
    std::string profile;
    int total_lines{0};
    int hit_lines{0};
    int total_branches{0};
    int hit_branches{0};
    double line_pct{0.0};
    double branch_pct{0.0};
    double threshold_line{0.0};
    double threshold_branch{0.0};
    bool meets_dal{false};
    std::vector<FileCoverage> files;
};

[[nodiscard]] CoverageReport build_from_lcov(const std::filesystem::path& lcov_file, DAL dal);
void write_json(const std::filesystem::path& out, const CoverageReport& r);
void render_text(const CoverageReport& r);

} // namespace cpfusa::coverage
