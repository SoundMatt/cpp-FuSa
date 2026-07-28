#include "sci.hpp"
#include "../quality/quality.hpp"
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <nlohmann/json.hpp>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace cpfusa::sci {

namespace {
std::string now_iso() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ss;
    ss << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

struct ArtifactDef { std::string category; std::string artifact; };
std::vector<ArtifactDef> lifecycle_items() {
    return {
        {"Requirements",       ".fusa-reqs.json"},
        {"Configuration",      ".fusa.json"},
        {"Hazard Analysis",    ".fusa-hara.json"},
        {"Test Evidence",      ".fusa-evidence.json"},
        {"Analysis",           "check-report.json"},
        {"Analysis",           "cyber-report.json"},
        {"Safety",             "fmea.json"},
        {"Safety",             "tara.json"},
        {"Safety",             "safety-case.json"},
        {"Qualification",      "qualify-report.json"},
        {"Release",            "sbom.json"},
        {"Release",            "provenance.json"},
        {"Release",            "artifact-manifest.json"},
        {"Audit",              "audit-pack.zip"},
        {"Gap Analysis",       "iso26262-gap-report.json"},
        {"Gap Analysis",       "iec61508-gap-report.json"},
        {"Gap Analysis",       "do178-gap-report.json"},
        {"Summary",            "sas.json"},
    };
}
} // anonymous namespace

//fusa:req REQ-SCI001 REQ-SCI002
SCI build(const fs::path& dir, const std::string& project, const std::string& version) {
    SCI s;
    s.project = project;
    s.version = version;
    s.generated_at = now_iso();

    for (auto& def : lifecycle_items()) {
        ConfigItem item;
        item.category = def.category;
        item.file     = def.artifact; // already project-relative (root-level artifact)
        item.version  = version;
        item.present  = fs::exists(dir / def.artifact);
        if (item.present) {
            std::ifstream f(dir / def.artifact, std::ios::binary);
            std::string bytes((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
            // §9.3: artifacts[].hash MUST be a real SHA-256 of the file's
            // current contents, and — because the field is *named* "hash"
            // (algorithm-varying convention, §2.7) — it MUST carry the
            // "sha256:" prefix, unlike a field literally named "sha256".
            item.hash = quality::sha256_prefixed(bytes);
        }
        s.artifacts.push_back(item);
    }
    return s;
}

//fusa:req REQ-SCI003
json to_json(const SCI& s, const std::string& project_root) {
    json j;
    j["schemaVersion"] = std::string(SpecVersion);
    j["kind"]          = "sci";
    j["tool"]          = "cpp-FuSa";
    j["toolVersion"]   = std::string(Version);
    j["language"]      = "cpp";
    j["generatedAt"]   = s.generated_at;
    if (!project_root.empty()) j["projectRoot"] = project_root;
    if (!s.project.empty()) j["project"] = s.project;
    if (!s.version.empty()) j["version"] = s.version;

    json aa = json::array();
    for (auto& item : s.artifacts) {
        json ij;
        ij["file"]     = item.file;
        ij["version"]  = item.version;
        if (item.present) ij["hash"] = item.hash;
        ij["category"] = item.category; // additive — tool-defined grouping
        ij["present"]  = item.present;  // additive — kept for back-compat consumers
        aa.push_back(ij);
    }
    j["artifacts"] = aa;
    return j;
}

void write_json(const fs::path& out, const SCI& s, const std::string& project_root) {
    std::ofstream f(out);
    f << to_json(s, project_root).dump(2);
}

} // namespace cpfusa::sci
