#include "coverage.hpp"
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
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
            // Guard std::stoi against malformed/empty LCOV values (e.g. "LF:"
            // or "LF:abc") which would otherwise throw and abort the process.
            auto parse_int = [](const std::string& s) -> int {
                try { return std::stoi(s); }
                catch (const std::exception&) { return 0; }
            };
            if (line.substr(0, 3) == "LF:") current.lines_total    = parse_int(line.substr(3));
            else if (line.substr(0, 3) == "LH:") current.lines_hit = parse_int(line.substr(3));
            else if (line.substr(0, 4) == "BRF:") current.branches_total = parse_int(line.substr(4));
            else if (line.substr(0, 4) == "BRH:") current.branches_hit   = parse_int(line.substr(4));
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

    // MC/DC report (REQ-COV004, REQ-COV005)
    if (r.mcdc_enabled) {
        json mcdc;
        mcdc["enabled"]            = true;
        mcdc["file"]               = r.mcdc_file;
        mcdc["threshold"]          = r.mcdc_threshold;
        mcdc["conditionsTotal"]    = r.mcdc_conditions_total;
        mcdc["conditionsCovered"]  = r.mcdc_conditions_covered;
        mcdc["mcdcPct"]            = r.mcdc_pct;
        mcdc["meetsMcdc"]          = r.meets_mcdc;
        json recs = json::array();
        for (const auto& rec : r.mcdc_records) {
            json rj;
            if (!rec.function_name.empty()) rj["functionName"] = rec.function_name;
            rj["conditionsTotal"]   = rec.total_conditions();
            rj["conditionsCovered"] = rec.covered_conditions();
            rj["fullyCovered"]      = rec.fully_covered();
            json conds = json::array();
            for (const auto& c : rec.conditions) {
                conds.push_back({
                    {"coveredTrueCount",  c.covered_true_count},
                    {"coveredFalseCount", c.covered_false_count},
                    {"covered",          c.is_covered()}
                });
            }
            rj["conditions"] = conds;
            recs.push_back(rj);
        }
        mcdc["records"] = recs;
        j["mcdc"] = mcdc;
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
    std::cout << "Meets DAL: " << (r.meets_dal ? "YES" : "NO") << "\n";
    if (r.mcdc_enabled) {
        std::cout << "MC/DC coverage:     " << r.mcdc_pct
                  << "% (threshold: " << r.mcdc_threshold << "%)"
                  << "  [" << r.mcdc_conditions_covered << "/"
                  << r.mcdc_conditions_total << " conditions]\n";
        std::cout << "Meets MC/DC: " << (r.meets_mcdc ? "YES" : "NO") << "\n";
    }
    std::cout << "\n";
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

//fusa:req REQ-COV004 REQ-COV005
void apply_mcdc(CoverageReport& r, const fs::path& mcdc_json, double threshold) {
    r.mcdc_enabled   = true;
    r.mcdc_file      = mcdc_json.string();
    r.mcdc_threshold = threshold;

    std::ifstream f(mcdc_json);
    if (!f) {
        throw std::runtime_error("Cannot open MC/DC JSON: " + mcdc_json.string());
    }

    json j;
    try {
        j = json::parse(f);
    } catch (const json::exception& ex) {
        throw std::runtime_error(std::string("MC/DC JSON parse error: ") + ex.what());
    }

    // Parse: {mcdc_records:[{function_name?, conditions:[{covered_true_count, covered_false_count}]}]}
    const json* records_ptr = nullptr;
    if (j.contains("mcdc_records") && j["mcdc_records"].is_array()) {
        records_ptr = &j["mcdc_records"];
    } else if (j.is_array()) {
        records_ptr = &j;
    }

    if (records_ptr) {
        for (const auto& rec : *records_ptr) {
            MCDCRecord mr;
            mr.function_name = rec.value("function_name", "");
            if (rec.contains("conditions") && rec["conditions"].is_array()) {
                for (const auto& cond : rec["conditions"]) {
                    MCDCCondition mc;
                    mc.covered_true_count  = cond.value("covered_true_count",  0);
                    mc.covered_false_count = cond.value("covered_false_count", 0);
                    mr.conditions.push_back(mc);
                }
            }
            r.mcdc_conditions_total   += mr.total_conditions();
            r.mcdc_conditions_covered += mr.covered_conditions();
            r.mcdc_records.push_back(std::move(mr));
        }
    }

    r.mcdc_pct = r.mcdc_conditions_total > 0
        ? 100.0 * r.mcdc_conditions_covered / r.mcdc_conditions_total : 0.0;
    r.meets_mcdc = (r.mcdc_pct >= threshold);
}

} // namespace cpfusa::coverage
