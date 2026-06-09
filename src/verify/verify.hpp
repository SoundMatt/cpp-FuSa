#pragma once
#include "cpfusa/fusa.hpp"
#include "../config/config.hpp"
#include <filesystem>
#include <string>
#include <vector>

namespace cpfusa::verify {

struct TestResult {
    std::string name;
    std::string file;
    std::string status;   // "passed" | "failed" | "skipped"
    double      elapsed_seconds{0.0};
};

struct TestSummary {
    int total{0};
    int passed{0};
    int failed{0};
    int skipped{0};
};

struct EvidenceBundle {
    std::string              generated_at;
    std::string              project_root;
    std::string              cpp_version;  // mirrors goVersion field name as cppVersion
    std::vector<TestResult>  results;
    TestSummary              summary;
};

// run_ctest executes ctest in build_dir and collects results.
// Returns error string if ctest cannot be invoked.
//
//fusa:req REQ-VERIFY001
Result<EvidenceBundle> run_ctest(const std::filesystem::path& project_dir,
                                 const config::ProjectConfig& cfg);

// write_evidence serialises the bundle to .fusa-evidence.json in dir.
//
//fusa:req REQ-VERIFY002
Result<std::monostate> write_evidence(const std::filesystem::path& dir,
                                      const EvidenceBundle& bundle);

} // namespace cpfusa::verify
