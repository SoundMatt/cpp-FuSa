#include "coupling.hpp"
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <regex>
#include <set>
#include <sstream>
#include <nlohmann/json.hpp>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace cpfusa::coupling {

namespace {
std::string now_iso() {
    auto now = std::chrono::system_clock::now();
    auto t   = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ss;
    ss << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

bool is_excluded(const fs::path& p, const std::vector<std::string>& exclude_patterns) {
    // generic_string() (always "/"-separated) — excludePatterns are "/"-style
    // gitignore globs (§1.2.1) regardless of platform; p.string() would use
    // "\"-separated native form on Windows and silently never match.
    auto s = p.generic_string();
    for (const auto& pat : exclude_patterns)
        if (s.find(pat) != std::string::npos) return true;
    return false;
}

CouplingReport analyse_impl(const fs::path& dir, const std::vector<std::string>& exclude_patterns) {
    CouplingReport r;
    r.generated_at = now_iso();
    r.project = dir.filename().string();

    static const std::regex ext_re(R"(\.(cpp|cxx|cc)$)");
    static const std::regex include_re(R"(#include\s+["<]([\w/\.]+)[">])");
    static const std::regex call_re(R"(\b(\w+)::\w+\s*\()");
    static const std::regex extern_re(R"(\bextern\b.+\b(\w+)\s*;)");

    // Map file → component name
    auto component_of = [&](const fs::path& p) -> std::string {
        auto rel = fs::relative(p, dir / "src");
        return rel.begin()->string();
    };

    if (!fs::exists(dir / "src")) return r;

    std::set<std::pair<std::string,std::string>> seen_data, seen_ctrl;

    for (const auto& entry : fs::recursive_directory_iterator(
            dir / "src", fs::directory_options::skip_permission_denied)) {
        if (!entry.is_regular_file()) continue;
        if (!std::regex_search(entry.path().string(), ext_re)) continue;
        if (is_excluded(entry.path(), exclude_patterns)) continue;

        std::string from_comp = component_of(entry.path());
        std::ifstream f(entry.path());
        std::string line;
        int lineno = 0;
        while (std::getline(f, line)) {
            lineno++;
            // Data coupling: #include of a sibling component
            std::smatch m;
            if (std::regex_search(line, m, include_re)) {
                std::string inc = m[1].str();
                // Strip to component name (first path component)
                auto slash = inc.find('/');
                std::string to_comp = (slash != std::string::npos) ? inc.substr(0, slash) : inc;
                if (to_comp != from_comp && to_comp != "cpfusa" &&
                    to_comp.find('.') == std::string::npos) {
                    auto key = std::make_pair(from_comp, to_comp);
                    if (seen_data.insert(key).second)
                        r.data_edges.push_back({from_comp, to_comp, inc});
                }
            }
            // Control coupling: namespace::function calls
            if (std::regex_search(line, m, call_re)) {
                std::string ns = m[1].str();
                if (ns != from_comp && !ns.empty() && ns != "std" && ns != "fs") {
                    std::string site = entry.path().filename().string() + ":" + std::to_string(lineno);
                    auto key = std::make_pair(from_comp, ns);
                    if (seen_ctrl.insert(key).second)
                        r.control_edges.push_back({from_comp, ns, site});
                }
            }
        }
    }

    r.data_count    = static_cast<int>(r.data_edges.size());
    r.control_count = static_cast<int>(r.control_edges.size());
    return r;
}

} // namespace

//fusa:req REQ-COUPLING001 REQ-COUPLING002 REQ-COUPLING003
CouplingReport analyse(const fs::path& dir) {
    return analyse_impl(dir, {});
}

//fusa:req REQ-CFG005
CouplingReport analyse(const fs::path& dir, const config::ProjectConfig& cfg) {
    return analyse_impl(dir, cfg.exclude_patterns);
}

void write_json(const fs::path& out, const CouplingReport& r) {
    json j;
    j["generatedAt"]  = r.generated_at;
    j["project"]      = r.project;
    j["dataCount"]    = r.data_count;
    j["controlCount"] = r.control_count;
    j["dataEdges"]    = json::array();
    j["controlEdges"] = json::array();
    for (auto& e : r.data_edges)
        j["dataEdges"].push_back({{"from", e.from_file}, {"to", e.to_file}, {"symbol", e.symbol}});
    for (auto& e : r.control_edges)
        j["controlEdges"].push_back({{"caller", e.caller_file}, {"callee", e.callee_file}, {"site", e.call_site}});
    std::ofstream f(out);
    f << j.dump(2);
}

void render_text(const CouplingReport& r) {
    std::cout << "Coupling Report — " << r.project << "\n";
    std::cout << "Data edges: " << r.data_count
              << "  Control edges: " << r.control_count << "\n";
    std::cout << std::string(60, '-') << "\n";
    for (auto& e : r.data_edges)
        std::cout << "[DATA]    " << e.from_file << " → " << e.to_file << " (via " << e.symbol << ")\n";
    for (auto& e : r.control_edges)
        std::cout << "[CONTROL] " << e.caller_file << " → " << e.callee_file << " @ " << e.call_site << "\n";
}

} // namespace cpfusa::coupling
