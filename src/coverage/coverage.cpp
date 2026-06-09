#include "coverage.hpp"
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <regex>
#include <sstream>
#include <nlohmann/json.hpp>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace cpfusa::coverage {

DAL parse_dal(const std::string& s) {
    if (s == "DAL-A" || s == "A") return DAL::A;
    if (s == "DAL-B" || s == "B") return DAL::B;
    if (s == "DAL-C" || s == "C") return DAL::C;
    return DAL::D;
}
std::string dal_str(DAL d) {
    switch (d) {
        case DAL::A: return "DAL-A";
        case DAL::B: return "DAL-B";
        case DAL::C: return "DAL-C";
        default:     return "DAL-D";
    }
}

namespace {
// DO-178C structural coverage requirements per DAL
double line_threshold(DAL d) {
    switch (d) {
        case DAL::A: return 100.0;
        case DAL::B: return 100.0;
        case DAL::C: return 100.0;
        default:     return 75.0;
    }
}
double branch_threshold(DAL d) {
    switch (d) {
        case DAL::A: return 100.0; // MC/DC ≡ 100% branch for this model
        case DAL::B: return 100.0;
        case DAL::C: return 75.0;
        default:     return 0.0;
    }
}

std::string now_iso() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ss;
    ss << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}
} // anonymous namespace

//fusa:req REQ-COV002
CoverageReport build_from_lcov(const fs::path& lcov_file, DAL dal) {
    CoverageReport r;
    r.generated_at = now_iso();
    r.dal = dal_str(dal);
    r.profile = lcov_file.string();
    r.threshold_line   = line_threshold(dal);
    r.threshold_branch = branch_threshold(dal);

    std::ifstream f(lcov_file);
    if (!f) {
        throw std::runtime_error("Cannot open: " + lcov_file.string());
    }

    // LCOV format:
    // SF:<source file>
    // DA:<line>,<hit count>
    // BRDA:<line>,<block>,<branch>,<taken>
    // LH:<lines hit>
    // LF:<lines found>
    // BRH:<branches hit>
    // BRF:<branches found>
    // end_of_record
    FileCoverage current;
    bool in_record = false;
    std::string line;

    while (std::getline(f, line)) {
        if (line.substr(0, 3) == "SF:") {
            current = FileCoverage{};
            current.filename = line.substr(3);
            in_record = true;
        } else if (line == "end_of_record" && in_record) {
            if (current.lines_total > 0)
                current.line_pct = 100.0 * current.lines_hit / current.lines_total;
            if (current.branches_total > 0)
                current.branch_pct = 100.0 * current.branches_hit / current.branches_total;
            r.files.push_back(current);
            r.total_lines    += current.lines_total;
            r.hit_lines      += current.lines_hit;
            r.total_branches += current.branches_total;
            r.hit_branches   += current.branches_hit;
            in_record = false;
        } else if (in_record) {
            if (line.substr(0, 3) == "LF:") current.lines_total    = std::stoi(line.substr(3));
            else if (line.substr(0, 3) == "LH:") current.lines_hit = std::stoi(line.substr(3));
            else if (line.substr(0, 4) == "BRF:") current.branches_total = std::stoi(line.substr(4));
            else if (line.substr(0, 4) == "BRH:") current.branches_hit   = std::stoi(line.substr(4));
        }
    }

    r.line_pct = r.total_lines > 0
        ? 100.0 * r.hit_lines / r.total_lines : 0.0;
    r.branch_pct = r.total_branches > 0
        ? 100.0 * r.hit_branches / r.total_branches : 0.0;
    r.meets_dal = (r.line_pct >= r.threshold_line)
               && (r.branch_pct >= r.threshold_branch || r.threshold_branch == 0.0);
    return r;
}

void write_json(const fs::path& out, const CoverageReport& r) {
    json j;
    j["generatedAt"]      = r.generated_at;
    j["dal"]              = r.dal;
    j["profile"]          = r.profile;
    j["linePct"]          = r.line_pct;
    j["branchPct"]        = r.branch_pct;
    j["thresholdLine"]    = r.threshold_line;
    j["thresholdBranch"]  = r.threshold_branch;
    j["meetsDal"]         = r.meets_dal;
    j["summary"] = {
        {"totalLines", r.total_lines}, {"hitLines", r.hit_lines},
        {"totalBranches", r.total_branches}, {"hitBranches", r.hit_branches}
    };
    j["files"] = json::array();
    for (auto& fc : r.files) {
        j["files"].push_back({
            {"filename", fc.filename},
            {"linesTotal", fc.lines_total}, {"linesHit", fc.lines_hit},
            {"linePct", fc.line_pct},
            {"branchesTotal", fc.branches_total}, {"branchesHit", fc.branches_hit},
            {"branchPct", fc.branch_pct}
        });
    }
    std::ofstream f(out);
    f << j.dump(2);
}

void render_text(const CoverageReport& r) {
    std::cout << "Coverage Report [" << r.dal << "]\n";
    std::cout << std::string(70, '-') << "\n";
    std::cout << "Statement coverage: " << std::fixed << std::setprecision(1)
              << r.line_pct << "% (threshold: " << r.threshold_line << "%)\n";
    std::cout << "Branch coverage:    " << r.branch_pct
              << "% (threshold: " << r.threshold_branch << "%)\n";
    std::cout << "Meets DAL: " << (r.meets_dal ? "YES" : "NO") << "\n\n";
    if (!r.files.empty()) {
        std::cout << std::left << std::setw(50) << "File"
                  << std::setw(10) << "Lines%" << "Branches%\n";
        for (auto& fc : r.files) {
            std::cout << std::setw(50) << fc.filename
                      << std::setw(10) << std::fixed << std::setprecision(1) << fc.line_pct
                      << fc.branch_pct << "\n";
        }
    }
}

} // namespace cpfusa::coverage
