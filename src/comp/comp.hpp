#pragma once
#include <filesystem>
#include <string>
#include <vector>

namespace cpfusa::comp {

//fusa:req REQ-COMP001
constexpr const char* COMP_REPORT_FILE = "comp-report.json";

// DAL-level complexity thresholds (DO-178C):
constexpr int THRESHOLD_DAL_A = 4;
constexpr int THRESHOLD_DAL_B = 10;
constexpr int THRESHOLD_DAL_C = 15;
constexpr int THRESHOLD_DAL_D = 20;

struct FunctionResult {
    std::string file;
    int         line{0};
    std::string name;
    int         complexity{0};
    bool        exceeds_threshold{false};
};

struct CompReport {
    std::string generated_at;
    std::string project;
    int         threshold{10};
    int         total_functions{0};
    int         violations{0};
    std::vector<FunctionResult> results;
};

// Analyse C++ source files in dir for cyclomatic complexity.
// threshold: max allowed V(G) before flagging a violation.
[[nodiscard]] CompReport analyse(const std::filesystem::path& dir,
                                  const std::string& project,
                                  int threshold = THRESHOLD_DAL_B);

void write_json(const std::filesystem::path& out, const CompReport& r);
void render_text(const CompReport& r);

} // namespace cpfusa::comp
