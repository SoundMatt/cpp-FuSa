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

// MC/DC condition: each decision condition tracks true/false coverage counts.
//fusa:req REQ-COV004
struct MCDCCondition {
    int covered_true_count{0};
    int covered_false_count{0};
    // A condition is MC/DC covered if both true and false are exercised.
    [[nodiscard]] bool is_covered() const {
        return covered_true_count > 0 && covered_false_count > 0;
    }
};

// Per-function MC/DC record (maps to LLVM mcdc_records[] entry).
struct MCDCRecord {
    std::string function_name;
    std::vector<MCDCCondition> conditions;
    [[nodiscard]] int total_conditions()   const { return static_cast<int>(conditions.size()); }
    [[nodiscard]] int covered_conditions() const {
        int n = 0;
        for (const auto& c : conditions) if (c.is_covered()) ++n;
        return n;
    }
    [[nodiscard]] bool fully_covered() const {
        return !conditions.empty() && covered_conditions() == total_conditions();
    }
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

    // MC/DC fields (REQ-COV004, REQ-COV005)
    bool        mcdc_enabled{false};
    std::string mcdc_file;
    double      mcdc_threshold{100.0};
    int         mcdc_conditions_total{0};
    int         mcdc_conditions_covered{0};
    double      mcdc_pct{0.0};
    bool        meets_mcdc{false};
    std::vector<MCDCRecord> mcdc_records;
};

[[nodiscard]] CoverageReport build_from_lcov(const std::filesystem::path& lcov_file, DAL dal);
void write_json(const std::filesystem::path& out, const CoverageReport& r);
void render_text(const CoverageReport& r);

// Parse LLVM MC/DC JSON export and add MC/DC metrics to an existing report.
//fusa:req REQ-COV004
void apply_mcdc(CoverageReport& r, const std::filesystem::path& mcdc_json,
                double threshold = 100.0);

} // namespace cpfusa::coverage
