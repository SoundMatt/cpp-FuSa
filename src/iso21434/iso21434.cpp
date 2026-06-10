//fusa:req REQ-ISO21434-001 REQ-ISO21434-002 REQ-ISO21434-003 REQ-ISO21434-004 REQ-ISO21434-005
#include "iso21434.hpp"
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

namespace cpfusa::iso21434 {

CAL parse_cal(const std::string& s) {
    if (s == "CAL-1" || s == "CAL1") return CAL::CAL1;
    if (s == "CAL-2" || s == "CAL2") return CAL::CAL2;
    if (s == "CAL-3" || s == "CAL3") return CAL::CAL3;
    return CAL::CAL4;
}
std::string cal_str(CAL c) {
    switch (c) {
        case CAL::CAL1: return "CAL-1";
        case CAL::CAL2: return "CAL-2";
        case CAL::CAL3: return "CAL-3";
        default:        return "CAL-4";
    }
}

namespace {

//fusa:req REQ-ISO21434-002
std::vector<Objective> baseline_objectives() {
    // id, clause, title, automatable, req_cal1..4, status, evidence_file, notes
    return {
        // Clause 5: Organizational cybersecurity management
        {"ISO21434-5.1",  "§5",  "Cybersecurity governance",
         false, true, true, true, true, Status::Gap, "",
         "Organizational cybersecurity policy — manual assessment required"},
        // Clause 6: Project-dependent cybersecurity management
        {"ISO21434-6.1",  "§6",  "Cybersecurity plan",
         true, true, true, true, true, Status::Gap, ".fusa.json",
         "Project cybersecurity planning"},
        {"ISO21434-6.2",  "§6",  "Cybersecurity responsibility assignment",
         false, false, true, true, true, Status::Gap, "",
         "Responsibility matrix — manual assessment required"},
        // Clause 7: Distributed cybersecurity activities
        {"ISO21434-7.1",  "§7",  "Supplier cybersecurity management",
         false, false, false, true, true, Status::Gap, "",
         "Supplier management — manual assessment required"},
        // Clause 8: Continual cybersecurity activities
        {"ISO21434-8.3",  "§8",  "Vulnerability monitoring and triage",
         true, true, true, true, true, Status::Gap, "vuln.json",
         "Vulnerability scan evidence"},
        // Clause 9: Concept
        {"ISO21434-9.1",  "§9",  "Item definition and threat analysis (asset ID)",
         true, true, true, true, true, Status::Gap, "tara.json",
         "TARA asset identification"},
        {"ISO21434-9.2",  "§9",  "Threat scenario identification",
         true, true, true, true, true, Status::Gap, "tara.json",
         "TARA threat scenarios"},
        {"ISO21434-9.3",  "§9",  "Impact rating",
         true, true, true, true, true, Status::Gap, "tara.json",
         "TARA impact rating"},
        {"ISO21434-9.4",  "§9",  "Attack feasibility rating",
         true, true, true, true, true, Status::Gap, "tara.json",
         "TARA attack feasibility"},
        {"ISO21434-9.5",  "§9",  "Risk value determination",
         true, true, true, true, true, Status::Gap, "tara.json",
         "TARA risk rating"},
        {"ISO21434-9.6",  "§9",  "Risk treatment decision",
         true, true, true, true, true, Status::Gap, "tara.json",
         "TARA risk treatment"},
        // Clause 10: Product development
        {"ISO21434-10.1", "§10", "Cybersecurity requirements specification",
         true, true, true, true, true, Status::Gap, ".fusa-reqs.json",
         "Requirements registry present"},
        {"ISO21434-10.3", "§10", "Cybersecurity design evidence",
         true, false, true, true, true, Status::Gap, "safety-case.json",
         "Safety/cybersecurity case evidence"},
        {"ISO21434-10.4", "§10", "Static cybersecurity analysis (SAST)",
         true, true, true, true, true, Status::Gap, "cyber-report.json",
         "Static analysis findings report"},
        // Clause 11: Cybersecurity validation
        {"ISO21434-11.1", "§11", "Cybersecurity validation report",
         false, false, true, true, true, Status::Gap, "",
         "Validation report — manual assessment required"},
        // Clause 12: Production
        {"ISO21434-12.1", "§12", "Production cybersecurity controls",
         false, false, false, true, true, Status::Gap, "",
         "Production security — manual assessment required"},
        // Clause 13: Operations and maintenance
        {"ISO21434-13.1", "§13", "Cybersecurity incident monitoring",
         false, false, true, true, true, Status::Gap, "",
         "Operational monitoring — manual assessment required"},
        // Clause 14: End of cybersecurity support
        {"ISO21434-14.1", "§14", "End-of-support plan",
         false, false, false, false, true, Status::Gap, "",
         "End-of-support — manual assessment required"},
        // Clause 15: Incident response
        {"ISO21434-15.1", "§15", "Incident response / PSIRT",
         false, true, true, true, true, Status::Gap, "",
         "PSIRT process — manual assessment required"},
        // Annex A: SBOM and provenance
        {"ISO21434-A.1",  "Annex A", "Software Bill of Materials (SBOM)",
         true, false, false, true, true, Status::Gap, "sbom.json",
         "SBOM evidence"},
        {"ISO21434-A.2",  "Annex A", "Build provenance attestation",
         true, false, false, true, true, Status::Gap, "provenance.json",
         "Provenance evidence"},
    };
}

bool is_required(const Objective& obj, CAL cal) {
    switch (cal) {
        case CAL::CAL1: return obj.required_cal1;
        case CAL::CAL2: return obj.required_cal2;
        case CAL::CAL3: return obj.required_cal3;
        default:        return obj.required_cal4;
    }
}

Status detect_status(const Objective& obj, const fs::path& dir) {
    if (!obj.automatable) return Status::Partial;  // manual — can't be gap or satisfied by tool
    if (obj.evidence_file.empty()) return Status::Gap;
    return fs::exists(dir / obj.evidence_file) ? Status::Partial : Status::Gap;
}

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

} // anonymous namespace

Report assess(const fs::path& dir, const std::string& project, CAL cal) {
    Report r;
    r.project      = project;
    r.cal          = cal_str(cal);
    r.generated_at = now_utc();

    for (auto obj : baseline_objectives()) {
        if (!is_required(obj, cal)) continue;
        obj.status = detect_status(obj, dir);
        r.objectives.push_back(obj);
        r.total++;
        switch (obj.status) {
            case Status::Satisfied: r.satisfied++; break;
            case Status::Partial:   r.partial++;   break;
            default:                r.gap++;        break;
        }
    }
    return r;
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
    j["standard"]      = "iso21434";
    j["cal"]           = r.cal;
    j["summary"]       = {{"total",     r.total},
                          {"satisfied", r.satisfied},
                          {"partial",   r.partial},
                          {"gaps",      r.gap}};
    j["objectives"] = json::array();
    for (const auto& o : r.objectives) {
        j["objectives"].push_back({
            {"id",      o.id},
            {"clause",  o.clause},
            {"title",   o.title},
            {"status",  status_str(o.status)},
            {"evidence", o.evidence_file},
            {"notes",   o.notes}
        });
    }
    std::ofstream f(out);
    f << j.dump(2) << "\n";
}

void render_text(const Report& r) {
    std::cout << "ISO 21434 Gap Report — " << r.project
              << " [" << r.cal << "]\n";
    std::cout << std::string(70, '-') << "\n";
    for (const auto& o : r.objectives) {
        const char* marker = (o.status == Status::Satisfied) ? "[OK]"
                           : (o.status == Status::Partial)   ? "[~~]"
                                                              : "[  ]";
        std::cout << marker << " " << o.id
                  << "  " << o.clause
                  << "  " << o.title << "\n";
    }
    std::cout << std::string(70, '-') << "\n";
    std::cout << "Total: "     << r.total
              << "  Satisfied: " << r.satisfied
              << "  Partial: " << r.partial
              << "  Gap: "     << r.gap << "\n";
}

} // namespace cpfusa::iso21434
