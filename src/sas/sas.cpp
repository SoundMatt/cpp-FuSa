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
std::vector<EvidenceItem> baseline_items() {
    return {
        {"SAS-01", "Project configuration",          ".fusa.json"},
        {"SAS-02", "Requirements registry",          ".fusa-reqs.json"},
        {"SAS-03", "Test evidence",                  ".fusa-evidence.json"},
        {"SAS-04", "Check report",                   "check-report.json"},
        {"SAS-05", "Cybersecurity analysis",         "cyber-report.json"},
        {"SAS-06", "FMEA",                           "fmea.json"},
        {"SAS-07", "TARA",                           "tara.json"},
        {"SAS-08", "Safety case",                    "safety-case.json"},
        {"SAS-09", "Qualification report",           "qualify-report.json"},
        {"SAS-10", "SBOM",                           "sbom.json"},
        {"SAS-11", "Provenance",                     "provenance.json"},
        {"SAS-12", "Artifact manifest",              "artifact-manifest.json"},
        {"SAS-13", "Audit pack",                     "audit-pack.zip"},
        {"SAS-14", "Badge",                          "fusa-badge.svg"},
        {"SAS-15", "ISO 26262 gap report",           "iso26262-gap-report.json"},
        {"SAS-16", "IEC 61508 gap report",           "iec61508-gap-report.json"},
        {"SAS-17", "DO-178C gap report",             "do178-gap-report.json"},
        {"SAS-18", "Vulnerability report",           "vuln.json"},
        {"SAS-19", "HARA",                           ".fusa-hara.json"},
        {"SAS-20", "Dispositions",                   ".fusa-dispositions.json"},
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
        s.evidence.push_back(item);
        s.total++;
        if (item.present) s.complete++;
    }
    return s;
}

void write_json(const fs::path& out, const SAS& s) {
    json j;
    j["generatedAt"] = s.generated_at;
    j["project"]     = s.project;
    j["version"]     = s.version;
    j["dal"]         = s.dal;
    j["summary"]     = {{"total", s.total}, {"complete", s.complete}};
    j["evidence"]    = json::array();
    for (auto& item : s.evidence) {
        j["evidence"].push_back({
            {"id", item.id}, {"title", item.title},
            {"artifact", item.artifact}, {"present", item.present}
        });
    }
    std::ofstream f(out);
    f << j.dump(2);
}

void write_markdown(const fs::path& out, const SAS& s) {
    std::ofstream f(out);
    f << "# Software Accomplishment Summary\n\n";
    f << "**Project:** " << s.project << "  \n";
    f << "**Version:** " << s.version << "  \n";
    f << "**DAL/ASIL/SIL:** " << s.dal << "  \n";
    f << "**Generated:** " << s.generated_at << "  \n\n";
    f << "## Evidence Index\n\n";
    f << "| ID | Title | Artifact | Status |\n";
    f << "|----|-------|----------|--------|\n";
    for (auto& item : s.evidence) {
        f << "| " << item.id << " | " << item.title << " | `"
          << item.artifact << "` | " << (item.present ? "✅" : "❌") << " |\n";
    }
    f << "\n**Complete: " << s.complete << " / " << s.total << "**\n";
}

} // namespace cpfusa::sas
