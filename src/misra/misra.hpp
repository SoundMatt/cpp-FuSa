#pragma once
#include <string>
#include <vector>

namespace cpfusa::misra {

//fusa:req REQ-MISRA001
constexpr const char* MISRA_REPORT_FILE = "misra-report.json";

enum class Status { Mapped, NA, Manual };
std::string status_str(Status s);

struct Rule {
    std::string id;          // e.g. "M8-4-1"
    std::string category;    // "Required", "Advisory"
    std::string description;
    Status      status{Status::Manual};
    std::string lint_rule;   // e.g. "LINT001" or ""
    std::string rationale;
};

struct Report {
    std::string generated_at;
    std::vector<Rule> rules;
    int total{0};
    int mapped{0};
    int na_count{0};
    int manual{0};
};

[[nodiscard]] std::vector<Rule> mapping_table();
[[nodiscard]] Report            build_report(bool gaps_only);
void write_json(const std::string& path, const Report& r);
void render_text(const Report& r, bool gaps_only);

} // namespace cpfusa::misra
