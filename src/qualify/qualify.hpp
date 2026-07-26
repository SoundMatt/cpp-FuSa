#pragma once
// Package qualify implements the cpp-FuSa tool qualification suite.
//
// Runs built-in positive/negative test cases for every engine rule against
// synthetic isolated project directories. Produces qualify-report.json with
// SHA-256 integrity hash — suitable as tool qualification evidence per
// ISO 26262 Part 8 / IEC 61508 Part 6 tool confidence requirements.
#include "cpfusa/fusa.hpp"
#include <filesystem>
#include <string>
#include <vector>

namespace cpfusa::qualify {

constexpr std::string_view ReportFile = "qualify-report.json";

struct Case {
    std::string name;
    std::string rule_id;
    std::string description;
    // project-relative path → content for the synthetic project
    std::vector<std::pair<std::string, std::string>> files;
    bool expect_finding{false};
};

struct CaseResult {
    Case        test_case;
    bool        passed{false};
    std::string error;
};

//fusa:req REQ-QUALIFY002
struct QualifyReport {
    std::string              generated_at;
    std::string              cpp_version;
    std::string              module;
    int                      total{0};
    int                      passed{0};
    int                      failed{0};
    std::vector<CaseResult>  results;
    std::string              hash; // SHA-256 of report sans hash field

    // Feature 2 — Tool Qualification Display (REQ-QUALIFY005..REQ-QUALIFY007)
    std::string              qualification_method;     // "self" | "independent" | ""
    std::string              qualification_record_uri; // URI to dossier
    std::string              qualifier_identity;       // name/org of qualifier

    // Feature 4 — V&V Independence (REQ-QUALIFY008..REQ-QUALIFY010)
    std::string              implementation_author;       // author of implementation
    std::string              independent_reviewer;        // reviewer (different from author = independent)
    std::string              independent_test_executor;   // independent test executor
    std::string              achievable_asil;             // achievable ASIL level

    // Derived: "independent" when reviewer != author (and both non-empty)
    [[nodiscard]] std::string independence_status() const {
        if (implementation_author.empty() || independent_reviewer.empty())
            return "unqualified";
        if (independent_reviewer != implementation_author)
            return "independent";
        return "self";
    }
};

// builtin_cases returns positive+negative cases for all engine rules.
//
//fusa:req REQ-QUALIFY001
std::vector<Case> builtin_cases();

// run executes cases and returns a QualifyReport with integrity hash.
//
//fusa:req REQ-QUALIFY003
Result<QualifyReport> run(const std::vector<Case>& cases);

// save writes the report as indented JSON to path.
Result<std::monostate> save(const std::filesystem::path& path,
                            const QualifyReport& report);

} // namespace cpfusa::qualify
