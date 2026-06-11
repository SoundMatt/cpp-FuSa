#pragma once
#include <filesystem>
#include <string>
#include <vector>

namespace cpfusa::iec62443 {

//fusa:req REQ-IEC62443-001
constexpr const char* IEC62443_REPORT_FILE = "iec62443-report.json";

enum class SL { SL1, SL2, SL3, SL4 };
SL          parse_sl(const std::string& s);
std::string sl_str(SL sl);

enum class Status { Met, Partial, Gap };
std::string status_str(Status s);

struct Check {
    std::string id;
    std::string requirement;
    std::string description;
    bool required_sl1{false};
    bool required_sl2{false};
    bool required_sl3{false};
    bool required_sl4{false};
    Status status{Status::Gap};
    std::string evidence;
};

struct Report {
    std::string project;
    std::string sl;
    std::string generated_at;
    std::vector<Check> checks;
    int total{0};
    int satisfied{0};
    int partial{0};
    int gap{0};
};

[[nodiscard]] Report assess(const std::filesystem::path& dir,
                             const std::string& project, SL sl);
void write_json(const std::filesystem::path& out, const Report& r);
void render_text(const Report& r);

} // namespace cpfusa::iec62443
