#pragma once
#include <filesystem>
#include <string>
#include <vector>

namespace cpfusa::boundary {

//fusa:req REQ-BOUNDARY001
constexpr const char* BOUNDARY_FILE     = "boundary.mermaid";
constexpr const char* BOUNDARY_DOT_FILE = "boundary.dot";

struct Node {
    std::string id;
    std::string label;
    bool is_external{false};
};

struct Edge {
    std::string from;
    std::string to;
    std::string label;
};

struct Diagram {
    std::vector<Node> nodes;
    std::vector<Edge> edges;
};

[[nodiscard]] Diagram scan(const std::filesystem::path& dir);
void write_mermaid(const std::filesystem::path& out, const Diagram& d);
void write_dot(const std::filesystem::path& out, const Diagram& d);

} // namespace cpfusa::boundary
