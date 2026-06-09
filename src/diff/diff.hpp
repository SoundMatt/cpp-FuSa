#pragma once
// diff compares two cpfusa check JSON reports and categorises findings as
// introduced, resolved, or unchanged.
#include "cpfusa/fusa.hpp"
#include <filesystem>
#include <string>
#include <vector>

namespace cpfusa::diff {

struct DiffFinding {
    std::string rule_id;
    std::string severity;
    std::string message;
    std::string file;
    int         line{0};
};

struct Diff {
    std::vector<DiffFinding> introduced;
    std::vector<DiffFinding> resolved;
    std::vector<DiffFinding> unchanged;
};

// load_findings reads findings from a JSON report file produced by
// cpfusa check --format json.
//
//fusa:req REQ-DIFF002
Result<std::vector<DiffFinding>> load_findings(const std::filesystem::path& report_path);

// compare returns the delta between baseline and current findings.
//
//fusa:req REQ-DIFF001
Diff compare(const std::vector<DiffFinding>& baseline,
             const std::vector<DiffFinding>& current);

// render_text writes a human-readable diff to stdout.
//
//fusa:req REQ-DIFF003
std::string render_text(const Diff& d);

// render_json serialises the diff to JSON.
std::string render_json(const Diff& d);

} // namespace cpfusa::diff
