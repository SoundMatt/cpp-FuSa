#pragma once

#include "cpfusa/fusa.hpp"
#include "../config/config.hpp"
#include <filesystem>
#include <string>
#include <vector>
#include <map>

namespace cpfusa::trace {

struct Requirement {
    std::string id;
    std::string title;
    std::string description;
    std::string standard_ref;
    std::string severity;  // safety / info / cybersecurity
    std::string asil;      // ASIL-A..D or empty
    std::string parent_id; // empty = HLR; non-empty = LLR pointing to parent HLR
};

struct Annotation {
    std::string req_id;
    std::string file;
    int         line;
    bool        is_test; // true = //fusa:test, false = //fusa:req
};

struct HLRViolation {
    std::string hlr_id;  // empty = LLR-references-unknown-HLR; non-empty = HLR-with-no-children
    std::string llr_id;  // populated when an LLR references unknown HLR
    std::string message;
};

// x-FuSa spec §1.4.1 item 3 — a //fusa:test <ID> tag whose <ID> does not exist
// in .fusa-reqs.json is a dangling reference; surfaced the same way a malformed
// annotation would be (a WARNING, never silently accepted).
struct DanglingTag {
    std::string req_id;
    std::string file;
    int         line;
    std::string message;
};

// x-FuSa spec §1.4.1 item 2 / §5 --func-coverage — density of header-declared
// public functions (with a matching .cpp definition) carrying a //fusa:req tag
// directly above their definition. Trivial enum/string converters and pure
// serialisation helpers (render_*, write_json, export_*, parse_*, *_str) are
// exempt — see is_func_exempt() in trace.cpp.
struct FuncCoverage {
    int total{0};
    int covered{0};
    double pct{0.0};
    std::vector<std::string> uncovered; // "path/file.hpp:name" for gap reporting
};

struct TraceResult {
    std::vector<Requirement>            requirements;
    std::vector<Annotation>             annotations;
    std::map<std::string, std::vector<Annotation>> by_req;
    int total{0};
    int annotated{0};
    int tested{0};
    int sec_tested{0};  // cybersecurity requirements with at least one //fusa:test annotation
    double annotation_coverage{0.0};
    double test_coverage{0.0};
    // HLR/LLR hierarchy metrics
    int hlr_count{0};
    int llr_count{0};
    int hlr_covered{0};   // HLRs that have at least one LLR child
    std::vector<HLRViolation> hlr_violations;
    // true when hlr_violations tripped the gate (--strict-hlr-llr or
    // project ASIL-C/D) — the caller MUST still render/emit the result
    // (spec §2.3: gate failure MUST NOT suppress the --format json artefact)
    // and is responsible for exiting non-zero.
    bool hlr_gate_failed{false};
    // §1.4.1 dangling //fusa:test references (test tag ID not in .fusa-reqs.json)
    std::vector<DanglingTag> dangling_tags;
    // §1.4.1 / §5 --func-coverage
    FuncCoverage func_coverage;
};

struct TraceOptions {
    bool show_gaps{false};
    int  min_annotation_pct{0};
    int  min_test_pct{0};
    int  min_func_pct{0};        // §5 --func-coverage N; 0 disables the gate
    std::string req_id;  // if non-empty, show only this req
    bool strict_hlr_llr{false}; // force HLR/LLR errors regardless of ASIL/DAL
};

[[nodiscard]] Result<TraceResult> run(
    const std::filesystem::path&  dir,
    const config::ProjectConfig&  cfg,
    const TraceOptions&           opts = {});

[[nodiscard]] Result<std::vector<Requirement>> load_requirements(
    const std::filesystem::path& dir);

[[nodiscard]] std::vector<Annotation> scan_annotations(
    const std::filesystem::path& dir);

// Overload filtered by cfg's sourceDirs/excludePatterns (§1.2.1 MUST) — used
// by run() to build the coverage matrix, so an out-of-scope directory (a
// stray build tree, vendor code, etc.) can never contribute to or dilute
// requirement coverage. The unfiltered overload above remains for direct,
// whole-project lookups (e.g. `req show`).
//
//fusa:req REQ-CFG006
[[nodiscard]] std::vector<Annotation> scan_annotations(
    const std::filesystem::path& dir, const config::ProjectConfig& cfg);

// §1.4.1 / §5 --func-coverage — scans src/*/*.hpp for header-declared public
// functions with a matching .cpp definition in the same directory, and reports
// how many carry a //fusa:req tag directly above that definition. Trivial
// enum/string converters and pure serialisation helpers are excluded — see
// is_func_exempt() in trace.cpp.
[[nodiscard]] FuncCoverage scan_func_coverage(const std::filesystem::path& dir);

// True when a function name is exempt from --func-coverage counting: trivial
// enum<->string converters and pure serialisation/export helpers, per this
// repo's existing tagging convention (render_text, render_json, write_json,
// parse_*, *_str, export_*, etc. are not expected to carry their own req tag).
[[nodiscard]] bool is_func_exempt(const std::string& name);

// is_test_tree_path reports whether `p` lies under a test-source-tree
// directory (a path component exactly "test" or "tests", this project's own
// `tests/` convention). scan_func_coverage() gets this exclusion "for free"
// by only walking src/*/*.hpp; a scanner that instead walks the whole
// project (e.g. fmea's component scan) needs it explicitly so a test helper
// function is never counted as a real project component — x-FuSa spec §1.6
// rule 4's implementer guidance: reuse this exclusion rather than each
// scanner maintaining its own, independently-drifting version.
//
//fusa:req REQ-TRACE021
[[nodiscard]] bool is_test_tree_path(const std::filesystem::path& p);

[[nodiscard]] std::string render_matrix(const TraceResult& result,
                                        const TraceOptions& opts);

// §5 JSON schema for cross-language traceability (FuSaOps).
[[nodiscard]] std::string render_json(const TraceResult& result,
                                      const config::ProjectConfig& cfg);

[[nodiscard]] std::string render_req(const Requirement& req,
                                     const std::vector<Annotation>& annotations);

// Import requirements from CSV (id,title,description,standard_ref,severity).
// Returns count of newly added requirements (duplicates are skipped).
[[nodiscard]] Result<int> import_csv(
    const std::filesystem::path& file,
    std::vector<Requirement>& reqs);

// Export requirements to CSV format.
[[nodiscard]] std::string export_csv(const std::vector<Requirement>& reqs);

// Save requirements back to .fusa-reqs.json in the canonical {requirements:[]} format.
[[nodiscard]] bool save_requirements(
    const std::filesystem::path& dir,
    const std::vector<Requirement>& reqs);

// Import requirements from DOORS ReqIF XML.
[[nodiscard]] Result<int> import_doors(
    const std::filesystem::path& file,
    std::vector<Requirement>& reqs);

// Export requirements to DOORS ReqIF XML.
[[nodiscard]] std::string export_doors(const std::vector<Requirement>& reqs);

// Import requirements from Polarion work-item XML.
[[nodiscard]] Result<int> import_polarion(
    const std::filesystem::path& file,
    std::vector<Requirement>& reqs);

// Export requirements to Polarion work-item XML.
[[nodiscard]] std::string export_polarion(const std::vector<Requirement>& reqs);

} // namespace cpfusa::trace
