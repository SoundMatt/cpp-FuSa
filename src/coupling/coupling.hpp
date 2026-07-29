#pragma once
#include "../config/config.hpp"
#include <filesystem>
#include <string>
#include <vector>

namespace cpfusa::coupling {

//fusa:req REQ-COUPLING001
constexpr const char* COUPLING_FILE = "coupling-report.json";

struct DataEdge {
    std::string from_file;
    std::string to_file;
    std::string symbol;
};

struct ControlEdge {
    std::string caller_file;
    std::string callee_file;
    std::string call_site;
};

struct CouplingReport {
    std::string generated_at;
    std::string project;
    std::vector<DataEdge>    data_edges;
    std::vector<ControlEdge> control_edges;
    int data_count{0};
    int control_count{0};
};

[[nodiscard]] CouplingReport analyse(const std::filesystem::path& dir);

// Overload filtered by cfg's excludePatterns (§1.2.1 MUST). The unfiltered
// overload above is retained for direct callers that intentionally want an
// unfiltered scan of dir/"src".
//
//fusa:req REQ-CFG005
[[nodiscard]] CouplingReport analyse(const std::filesystem::path& dir,
                                     const config::ProjectConfig& cfg);
void write_json(const std::filesystem::path& out, const CouplingReport& r);
void render_text(const CouplingReport& r);

} // namespace cpfusa::coupling
