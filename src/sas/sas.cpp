#include "sas.hpp"
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <nlohmann/json.hpp>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace cpfusa::sas {

namespace {
std::string now_iso() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ss;
    ss << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

//fusa:req REQ-SAS002
std::vector<ChecklistItem> baseline_items() {
    return {
        {"Project configuration",          "11.1", ".fusa.json", false},
        {"Requirements registry",          "11.9", ".fusa-reqs.json", false},
        {"Test evidence",                  "11.14", ".fusa-evidence.json", false},
        {"Check report",                   "11.15", "check-report.json", false},
        {"Cybersecurity analysis",         "11.15", "cyber-report.json", false},
        {"FMEA",                           "11.15", "fmea.json", false},
        {"TARA",                           "11.15", "tara.json", false},
        {"Safety case",                    "11.15", "safety-case.json", false},
        {"Qualification report",           "12.2",  "qualify-report.json", false},
        {"SBOM",                           "11.16", "sbom.json", false},
        {"Provenance",                     "11.16", "provenance.json", false},
        {"Artifact manifest",              "11.16", "artifact-manifest.json", false},
        {"Audit pack",                     "11.16", "audit-pack.zip", false},
        {"Badge",                          "11.20", "fusa-badge.svg", false},
        {"ISO 26262 gap report",           "11.20", "iso26262-gap-report.json", false},
        {"IEC 61508 gap report",           "11.20", "iec61508-gap-report.json", false},
        {"DO-178C gap report",             "11.20", "do178-gap-report.json", false},
        {"Vulnerability report",           "11.15", "vuln.json", false},
        {"HARA",                           "11.9",  ".fusa-hara.json", false},
        {"Dispositions",                   "11.15", ".fusa-dispositions.json", false},
    };
}
} // anonymous namespace

//fusa:req REQ-SAS004
SAS build(const fs::path& dir, const std::string& project,
          const std::string& version, const std::string& dal) {
    SAS s;
    s.project = project;
    s.version = version;
    s.dal = dal;
    s.generated_at = now_iso();

    for (auto item : baseline_items()) {
        item.present = fs::exists(dir / item.artifact);
        s.checklist.push_back(item);
        s.total++;
        if (item.present) s.present++;
    }
    return s;
}

//fusa:req REQ-SAS005
json to_json(const SAS& s, const std::string& project_root) {
    json j;
    j["schemaVersion"] = std::string(SpecVersion);
    j["kind"]          = "sas";
    j["tool"]          = "cpp-FuSa";
    j["toolVersion"]   = std::string(Version);
    j["language"]      = "cpp";
    j["generatedAt"]   = s.generated_at;
    j["projectRoot"]   = project_root;
    if (!s.project.empty()) j["project"] = s.project;
    if (!s.version.empty()) j["version"] = s.version;
    if (!s.dal.empty())     j["dal"]     = s.dal;

    json ca = json::array();
    for (auto& item : s.checklist) {
        json cj;
        cj["item"]    = item.item;
        cj["clause"]  = item.clause;
        cj["present"] = item.present;
        if (item.present) cj["evidence"] = item.artifact;
        ca.push_back(cj);
    }
    j["checklist"] = ca;
    j["summary"]   = {{"total", s.total}, {"present", s.present}};
    if (s.attestation.present) j["attestation"] = quality::to_json(s.attestation);
    return j;
}

void write_json(const fs::path& out, const SAS& s, const std::string& project_root) {
    std::ofstream f(out);
    f << to_json(s, project_root).dump(2);
}

void write_markdown(const fs::path& out, const SAS& s) {
    std::ofstream f(out);
    f << "# Software Accomplishment Summary\n\n";
    f << "**Project:** " << s.project << "  \n";
    f << "**Version:** " << s.version << "  \n";
    f << "**DAL/ASIL/SIL:** " << s.dal << "  \n";
    f << "**Generated:** " << s.generated_at << "  \n\n";
    f << "## Checklist\n\n";
    f << "| Item | Clause | Status | Evidence |\n";
    f << "|------|--------|--------|----------|\n";
    for (auto& item : s.checklist) {
        f << "| " << item.item << " | " << item.clause << " | "
          << (item.present ? "present" : "absent") << " | `"
          << item.artifact << "` |\n";
    }
    f << "\n**Present: " << s.present << " / " << s.total << "**\n";
}

//fusa:req REQ-SAS006
std::vector<Finding> scan_quality(const SAS& s) {
    std::vector<quality::QualField> fields;
    for (auto& item : s.checklist)
        fields.push_back({"checklist[].item", item.item, SAS_JSON_FILE, 0});
    std::vector<Finding> out = quality::scan_stub001(fields, SAS_JSON_FILE);
    auto rule_b = quality::scan_stub002(fields, SAS_JSON_FILE);
    out.insert(out.end(), rule_b.begin(), rule_b.end());
    return out;
}

} // namespace cpfusa::sas
