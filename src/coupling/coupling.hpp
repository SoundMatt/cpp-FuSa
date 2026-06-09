#pragma once
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
void write_json(const std::filesystem::path& out, const CouplingReport& r);
void render_text(const CouplingReport& r);

} // namespace cpfusa::coupling
