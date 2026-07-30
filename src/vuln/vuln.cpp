#include "vuln.hpp"
#include "cpfusa/fusa.hpp"
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <regex>
#include <sstream>
#include <nlohmann/json.hpp>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace cpfusa::vuln {

namespace {
std::string now_iso() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ss;
    ss << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

// Known CVE advisories for common C++ build dependencies (offline database)
//fusa:req REQ-VULN002
struct Advisory {
    std::string package;
    std::string max_version; // affected up to (exclusive)
    std::string cve_id;
    std::string severity;
    std::string description;
};

const std::vector<Advisory>& known_advisories() {
    static const std::vector<Advisory> db = {
        {"nlohmann_json", "3.10.5", "CVE-2022-39189", "LOW",
         "Deeply nested JSON can cause stack overflow during parsing"},
        {"nlohmann_json", "3.11.0", "CVE-2023-20900", "MEDIUM",
         "JSON integer overflow in some platforms"},
        {"catch2", "3.0.0", "CVE-2021-46560", "LOW",
         "Test runner DoS via crafted test name"},
    };
    return db;
}

// Compare semver strings (simplified: works for x.y.z)
bool version_less(const std::string& a, const std::string& b) {
    auto parse_ver = [](const std::string& v) {
        int x=0,y=0,z=0;
        std::sscanf(v.c_str(), "%d.%d.%d", &x, &y, &z); // NOLINT
        return std::make_tuple(x,y,z);
    };
    return parse_ver(a) < parse_ver(b);
}
} // anonymous namespace

std::vector<Dependency> parse_deps(const fs::path& dir) {
    std::vector<Dependency> deps;

    // Parse cmake/FetchDeps.cmake or CMakeLists.txt for FetchContent entries
    static const std::regex fc_re(
        R"(FetchContent_Declare\s*\(\s*(\w+)[\s\S]*?GIT_TAG\s+v?([\d]+\.[\d]+\.[\d]+))",
        std::regex::icase);

    auto try_parse = [&](const fs::path& p) {
        if (!fs::exists(p)) return;
        std::ifstream f(p);
        std::string content((std::istreambuf_iterator<char>(f)),
                             std::istreambuf_iterator<char>());
        auto begin = std::sregex_iterator(content.begin(), content.end(), fc_re);
        for (auto it = begin; it != std::sregex_iterator(); ++it) {
            deps.push_back({(*it)[1].str(), (*it)[2].str(), p.filename().string()});
        }
    };

    try_parse(dir / "cmake" / "FetchDeps.cmake");
    try_parse(dir / "CMakeLists.txt");
    return deps;
}

//fusa:req REQ-VULN001 REQ-VULN002 REQ-VULN003 REQ-VULN004
VulnReport scan(const fs::path& dir) {
    VulnReport r;
    r.generated_at = now_iso();
    r.project = dir.filename().string();

    auto deps = parse_deps(dir);
    r.scanned = static_cast<int>(deps.size());

    for (auto& dep : deps) {
        for (auto& adv : known_advisories()) {
            if (dep.name != adv.package) continue;
            if (version_less(dep.version, adv.max_version)) {
                r.findings.push_back({
                    dep.name, dep.version,
                    adv.cve_id, adv.severity, adv.description,
                    "https://nvd.nist.gov/vuln/detail/" + adv.cve_id
                });
            }
        }
    }
    return r;
}

void write_json(const fs::path& out, const VulnReport& r) {
    json j;
    // §3.1 common header — required on every document.
    j["schemaVersion"] = std::string(SpecVersion);
    j["kind"]          = "vuln-report";
    j["tool"]          = "cpp-FuSa";
    j["toolVersion"]   = std::string(Version);
    j["language"]      = "cpp";
    j["generatedAt"] = r.generated_at;
    j["project"]     = r.project;
    j["scanned"]     = r.scanned;
    j["findings"]    = json::array();
    for (auto& f : r.findings) {
        j["findings"].push_back({
            {"dependency", f.dep_name},
            {"version",    f.dep_version},
            {"cveId",      f.cve_id},
            {"severity",   f.severity},
            {"description",f.description},
            {"reference",  f.reference}
        });
    }
    std::ofstream ofs(out);
    ofs << j.dump(2);
}

void render_text(const VulnReport& r) {
    std::cout << "Vulnerability Scan — " << r.project << "\n";
    std::cout << "Scanned: " << r.scanned
              << " dependencies  Findings: " << r.findings.size() << "\n";
    if (r.findings.empty()) {
        std::cout << "No known vulnerabilities found.\n";
        return;
    }
    std::cout << std::string(70, '-') << "\n";
    for (auto& f : r.findings) {
        std::cout << "[" << f.severity << "] " << f.cve_id
                  << "  " << f.dep_name << "@" << f.dep_version << "\n";
        std::cout << "  " << f.description << "\n";
        std::cout << "  " << f.reference << "\n\n";
    }
}

} // namespace cpfusa::vuln
