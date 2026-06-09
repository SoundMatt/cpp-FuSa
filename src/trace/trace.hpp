#pragma once

#include "cpfusa/fusa.hpp"
#include "../config/config.hpp"
#include <filesystem>
#include <string>
#include <vector>
#include <map>
#include <optional>

namespace cpfusa::trace {

struct Requirement {
    std::string id;
    std::string title;
    std::string description;
    std::string standard_ref;
    std::string severity;  // safety / info / cybersecurity
};

struct Annotation {
    std::string req_id;
    std::string file;
    int         line;
    bool        is_test; // true = //fusa:test, false = //fusa:req
};

struct TraceResult {
    std::vector<Requirement>            requirements;
    std::vector<Annotation>             annotations;
    std::map<std::string, std::vector<Annotation>> by_req;
    int total{0};
    int annotated{0};
    int tested{0};
    double annotation_coverage{0.0};
    double test_coverage{0.0};
};

struct TraceOptions {
    bool show_gaps{false};
    int  min_annotation_pct{0};
    int  min_test_pct{0};
    std::string req_id; // if non-empty, show only this req
};

[[nodiscard]] Result<TraceResult> run(
    const std::filesystem::path&  dir,
    const config::ProjectConfig&  cfg,
    const TraceOptions&           opts = {});

[[nodiscard]] Result<std::vector<Requirement>> load_requirements(
    const std::filesystem::path& dir);

[[nodiscard]] std::vector<Annotation> scan_annotations(
    const std::filesystem::path& dir);

[[nodiscard]] std::string render_matrix(const TraceResult& result,
                                        const TraceOptions& opts);

[[nodiscard]] std::string render_req(const Requirement& req,
                                     const std::vector<Annotation>& annotations);

} // namespace cpfusa::trace
