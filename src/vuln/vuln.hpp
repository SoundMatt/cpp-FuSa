#pragma once
#include <filesystem>
#include <string>
#include <vector>

namespace cpfusa::vuln {

//fusa:req REQ-VULN001
constexpr const char* VULN_FILE = "vuln.json";

struct Dependency {
    std::string name;
    std::string version;
    std::string source;
};

struct VulnFinding {
    std::string dep_name;
    std::string dep_version;
    std::string cve_id;
    std::string severity;
    std::string description;
    std::string reference;
};

struct VulnReport {
    std::string generated_at;
    std::string project;
    int scanned{0};
    std::vector<VulnFinding> findings;
};

[[nodiscard]] std::vector<Dependency> parse_deps(const std::filesystem::path& dir);
[[nodiscard]] VulnReport scan(const std::filesystem::path& dir);
void write_json(const std::filesystem::path& out, const VulnReport& r);
void render_text(const VulnReport& r);

} // namespace cpfusa::vuln
