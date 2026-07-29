#include "boundary.hpp"
#include <fstream>
#include <iostream>
#include <regex>
#include <set>
#include <string>

namespace fs = std::filesystem;

namespace cpfusa::boundary {

namespace {

bool is_excluded(const fs::path& p, const std::vector<std::string>& exclude_patterns) {
    auto s = p.string();
    for (const auto& pat : exclude_patterns)
        if (s.find(pat) != std::string::npos) return true;
    return false;
}

Diagram scan_impl(const fs::path& dir, const std::vector<std::string>& exclude_patterns) {
    Diagram d;
    std::set<std::string> seen_nodes;

    // Discover src/ subdirectories as components
    static const std::regex ext_re(R"(\.(cpp|hpp|h|hxx|cxx|cc)$)");
    static const std::regex include_re(R"(#include\s+[<"]([\w/]+)[>"])");

    auto add_node = [&](const std::string& id, const std::string& label, bool ext) {
        if (seen_nodes.insert(id).second)
            d.nodes.push_back({id, label, ext});
    };

    // Map file → component name
    auto component_of = [&](const fs::path& p) -> std::string {
        // Use first path component under dir/src/ as the component
        auto rel = fs::relative(p, dir);
        auto it = rel.begin();
        if (it == rel.end()) return "root";
        std::string first = it->string();
        if (first == "src" || first == "include") {
            ++it;
            if (it != rel.end()) return it->string();
        }
        return first;
    };

    std::set<std::pair<std::string,std::string>> seen_edges;

    if (fs::exists(dir / "src")) {
        for (const auto& entry : fs::recursive_directory_iterator(
                dir / "src", fs::directory_options::skip_permission_denied)) {
            if (!entry.is_regular_file()) continue;
            std::string s = entry.path().string();
            if (!std::regex_search(s, ext_re)) continue;
            if (is_excluded(entry.path(), exclude_patterns)) continue;

            std::string comp = component_of(entry.path());
            add_node(comp, comp, false);

            std::ifstream f(entry.path());
            std::string line;
            while (std::getline(f, line)) {
                std::smatch m;
                if (!std::regex_search(line, m, include_re)) continue;
                std::string inc = m[1].str();
                // Map well-known external headers to nodes
                std::string ext_node;
                if (inc.find("nlohmann") != std::string::npos) ext_node = "nlohmann_json";
                else if (inc == "CLI/CLI") ext_node = "CLI11";
                else if (inc.find("catch2") != std::string::npos ||
                         inc.find("Catch2") != std::string::npos) ext_node = "Catch2";
                else if (inc.find("filesystem") != std::string::npos) ext_node = "std::filesystem";
                else continue;

                add_node(ext_node, ext_node, true);
                auto key = std::make_pair(comp, ext_node);
                if (seen_edges.insert(key).second)
                    d.edges.push_back({comp, ext_node, "uses"});
            }
        }
    }

    // Internal include edges between src components
    if (fs::exists(dir / "src")) {
        for (const auto& entry : fs::recursive_directory_iterator(
                dir / "src", fs::directory_options::skip_permission_denied)) {
            if (!entry.is_regular_file()) continue;
            std::string s = entry.path().string();
            if (s.find(".cpp") == std::string::npos) continue;
            if (is_excluded(entry.path(), exclude_patterns)) continue;
            std::string from_comp = component_of(entry.path());
            std::ifstream f(entry.path());
            std::string line;
            while (std::getline(f, line)) {
                std::smatch m;
                if (!std::regex_search(line, m, include_re)) continue;
                std::string inc = m[1].str();
                // Check if this maps to a known src component
                for (const auto& n : d.nodes) {
                    if (!n.is_external && n.id != from_comp &&
                        inc.find(n.id) != std::string::npos) {
                        auto key = std::make_pair(from_comp, n.id);
                        if (seen_edges.insert(key).second)
                            d.edges.push_back({from_comp, n.id, "uses"});
                    }
                }
            }
        }
    }

    return d;
}

} // namespace

//fusa:req REQ-BOUNDARY001 REQ-BOUNDARY002 REQ-BOUNDARY003
Diagram scan(const fs::path& dir) {
    return scan_impl(dir, {});
}

//fusa:req REQ-CFG005
Diagram scan(const fs::path& dir, const config::ProjectConfig& cfg) {
    return scan_impl(dir, cfg.exclude_patterns);
}

void write_mermaid(const fs::path& out, const Diagram& d) {
    std::ofstream f(out);
    f << "graph TD\n";
    f << "    subgraph external[\"External Dependencies\"]\n";
    for (auto& n : d.nodes)
        if (n.is_external)
            f << "    " << n.id << "[\"" << n.label << "\"]\n";
    f << "    end\n\n";
    f << "    subgraph internal[\"cpp-FuSa Modules\"]\n";
    for (auto& n : d.nodes)
        if (!n.is_external)
            f << "    " << n.id << "[\"" << n.label << "\"]\n";
    f << "    end\n\n";
    for (auto& e : d.edges)
        f << "    " << e.from << " --> " << e.to << "\n";
}

void write_dot(const fs::path& out, const Diagram& d) {
    std::ofstream f(out);
    f << "digraph boundary {\n";
    f << "    rankdir=LR;\n";
    f << "    node [shape=box];\n";
    for (auto& n : d.nodes) {
        if (n.is_external)
            f << "    \"" << n.id << "\" [style=dashed];\n";
        else
            f << "    \"" << n.id << "\";\n";
    }
    for (auto& e : d.edges)
        f << "    \"" << e.from << "\" -> \"" << e.to << "\";\n";
    f << "}\n";
}

} // namespace cpfusa::boundary
