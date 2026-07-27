//fusa:req REQ-UNECE-001 REQ-UNECE-002 REQ-UNECE-003 REQ-UNECE-004 REQ-UNECE-005
#include "unece.hpp"
#include "cpfusa/fusa.hpp"
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <nlohmann/json.hpp>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace cpfusa::unece {

namespace {

std::string status_str(Status s) {
    switch (s) {
        case Status::Satisfied: return "satisfied";
        case Status::Partial:   return "partial";
        default:                return "gap";
    }
}

std::string now_utc() {
    auto t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    struct tm tm_buf{};
#ifdef _WIN32
    gmtime_s(&tm_buf, &t);
#else
    gmtime_r(&t, &tm_buf);
#endif
    std::ostringstream ss;
    ss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

Status detect_status(const Threat& t, const fs::path& dir) {
    if (!t.automatable) return Status::Partial;
    if (t.evidence_file.empty()) return Status::Gap;
    return fs::exists(dir / t.evidence_file) ? Status::Partial : Status::Gap;
}

//fusa:req REQ-UNECE-002
std::vector<Threat> r155_threats() {
    // id, regulation, clause, iso21434_ref, title, automatable, status, evidence_file, notes
    return {
        {"TC-1", "R155", "Annex 5 §3.1", "ISO 21434 §9",
         "Vehicle communication channel threats (spoofing, replay, MITM)",
         true,  Status::Gap, "tara.json",
         "TARA covers communication threat scenarios"},
        {"TC-2", "R155", "Annex 5 §3.2", "ISO 21434 §10",
         "Update mechanism security (unauthorized update, rollback)",
         true,  Status::Gap, "provenance.json",
         "Provenance attests build integrity for update authorization"},
        {"TC-3", "R155", "Annex 5 §3.3", "ISO 21434 §9",
         "Unintended physical access (OBD, hardware attacks)",
         true,  Status::Gap, "tara.json",
         "TARA physical access threat scenarios"},
        {"TC-4", "R155", "Annex 5 §3.4", "ISO 21434 §10",
         "External connectivity and cloud threats (backend attacks)",
         true,  Status::Gap, "cyber-report.json",
         "Cyber analysis addresses external interface threats"},
        {"TC-5", "R155", "Annex 5 §3.5", "ISO 21434 §7",
         "Software and supply chain integrity (malicious code, third-party)",
         true,  Status::Gap, "sbom.json",
         "SBOM tracks third-party components for supply chain integrity"},
        {"TC-6", "R155", "Annex 5 §3.6", "ISO 21434 §9",
         "Data storage and privacy threats",
         true,  Status::Gap, "tara.json",
         "TARA data-at-rest threat scenarios"},
        {"TC-7", "R155", "Annex 5 §3.7", "ISO 21434 §10",
         "Cryptographic key management",
         false, Status::Gap, "",
         "Key lifecycle management — manual assessment required"},
        {"TC-8", "R155", "Annex 5 §3.8", "ISO 21434 §5",
         "Privacy protection for personal data",
         false, Status::Gap, "",
         "Privacy controls — manual assessment required"},
        {"TC-9", "R155", "Annex 5 §3.9", "ISO 21434 §13",
         "Cybersecurity incident detection and response",
         false, Status::Gap, "",
         "Incident detection — manual assessment required"},
    };
}

//fusa:req REQ-UNECE-003
std::vector<Threat> r156_threats() {
    return {
        {"SU-1", "R156", "§5.1", "ISO 21434 §10",
         "Software update authorization and authentication",
         true,  Status::Gap, "provenance.json",
         "Provenance attests update origin and integrity"},
        {"SU-2", "R156", "§5.2", "ISO 21434 §9",
         "Software update impact analysis",
         true,  Status::Gap, "tara.json",
         "TARA assesses update threat scenarios"},
        {"SU-3", "R156", "§5.3", "ISO 21434 §10",
         "Software update validation and testing",
         true,  Status::Gap, ".fusa-evidence.json",
         "Evidence bundle covers update validation tests"},
        {"SU-4", "R156", "§5.4", "ISO 21434 §10",
         "Rollback and recovery capability",
         false, Status::Gap, "",
         "Rollback mechanisms — manual assessment required"},
        {"SU-5", "R156", "§5.5", "ISO 21434 §7",
         "Update package supply chain integrity (SBOM)",
         true,  Status::Gap, "sbom.json",
         "SBOM covers update package dependencies"},
        {"SU-6", "R156", "§5.6", "ISO 21434 §13",
         "Update campaign monitoring and reporting",
         false, Status::Gap, "",
         "Campaign monitoring — manual assessment required"},
    };
}

Report build_report(const std::string& project,
                    const std::string& regulation,
                    std::vector<Threat> threats,
                    const fs::path& dir) {
    Report r;
    r.project    = project;
    r.regulation = "UNECE-" + regulation;
    r.generated_at = now_utc();

    for (auto thr : threats) {
        thr.status = detect_status(thr, dir);
        r.threats.push_back(thr);
        r.total++;
        switch (thr.status) {
            case Status::Satisfied: r.satisfied++; break;
            case Status::Partial:   r.partial++;   break;
            default:                r.gap++;        break;
        }
    }
    return r;
}

} // anonymous namespace

//fusa:req REQ-UNECE-006
Report assess_r155(const fs::path& dir, const std::string& project) {
    return build_report(project, "R155", r155_threats(), dir);
}

//fusa:req REQ-UNECE-007
Report assess_r156(const fs::path& dir, const std::string& project) {
    return build_report(project, "R156", r156_threats(), dir);
}

void write_json(const fs::path& out, const Report& r) {
    json j;
    j["schemaVersion"] = std::string(SpecVersion);
    j["kind"]          = "gap-report";
    j["tool"]          = "cpp-FuSa";
    j["toolVersion"]   = std::string(Version);
    j["language"]      = "cpp";
    j["generatedAt"]   = r.generated_at;
    j["project"]       = r.project;
    j["standard"]      = r.regulation.find("R155") != std::string::npos
                         ? "unece-r155" : "unece-r156";
    j["regulation"]    = r.regulation;
    j["summary"]       = {{"total",     r.total},
                          {"satisfied", r.satisfied},
                          {"partial",   r.partial},
                          {"gaps",      r.gap}};
    j["objectives"] = json::array();
    for (const auto& t : r.threats) {
        j["objectives"].push_back({
            {"id",          t.id},
            {"clause",      t.clause},
            {"iso21434Ref", t.iso21434_ref},
            {"title",       t.title},
            {"status",      status_str(t.status)},
            {"evidence",    t.evidence_file},
            {"notes",       t.notes}
        });
    }
    std::ofstream f(out);
    f << j.dump(2) << "\n";
}

void render_text(const Report& r) {
    std::cout << "UNECE " << r.regulation << " Gap Report — "
              << r.project << "\n";
    std::cout << std::string(70, '-') << "\n";
    for (const auto& t : r.threats) {
        const char* marker = (t.status == Status::Satisfied) ? "[OK]"
                           : (t.status == Status::Partial)   ? "[~~]"
                                                              : "[  ]";
        std::cout << marker << " " << t.id
                  << "  " << t.clause
                  << "  " << t.title << "\n";
    }
    std::cout << std::string(70, '-') << "\n";
    std::cout << "Total: "       << r.total
              << "  Satisfied: " << r.satisfied
              << "  Partial: "   << r.partial
              << "  Gap: "       << r.gap << "\n";
}

} // namespace cpfusa::unece
