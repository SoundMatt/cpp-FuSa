#include "iec62443.hpp"
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

namespace cpfusa::iec62443 {

SL parse_sl(const std::string& s) {
    if (s == "SL-1" || s == "SL1" || s == "1") return SL::SL1;
    if (s == "SL-2" || s == "SL2" || s == "2") return SL::SL2;
    if (s == "SL-3" || s == "SL3" || s == "3") return SL::SL3;
    return SL::SL4;
}
std::string sl_str(SL sl) {
    switch (sl) {
        case SL::SL1: return "SL-1";
        case SL::SL2: return "SL-2";
        case SL::SL3: return "SL-3";
        default:      return "SL-4";
    }
}
std::string status_str(Status s) {
    switch (s) {
        case Status::Met:     return "satisfied";
        case Status::Partial: return "partial";
        default:              return "gap";
    }
}

namespace {

//fusa:req REQ-IEC62443-001 REQ-IEC62443-002
std::vector<Check> baseline_checks() {
    return {
        {"SR-1.1",  "Human user identification and authentication",
         "System shall identify and authenticate users", true, true, true, true},
        {"SR-1.2",  "Software process identification and authentication",
         "Software processes shall be identified and authenticated", false, true, true, true},
        {"SR-1.3",  "Account management",
         "System shall support account management lifecycle", true, true, true, true},
        {"SR-1.4",  "Identifier management",
         "System shall manage user and process identifiers", false, true, true, true},
        {"SR-1.5",  "Authenticator management",
         "System shall manage authenticators (credentials)", true, true, true, true},
        {"SR-2.1",  "Authorization enforcement",
         "System shall enforce authorisations on all requests", true, true, true, true},
        {"SR-2.2",  "Wireless use control",
         "System shall authorise and control wireless use", false, false, true, true},
        {"SR-2.3",  "Use control for portable devices",
         "System shall authorise portable device connections", false, true, true, true},
        {"SR-3.1",  "Communication integrity",
         "Communication channels shall provide integrity protection", false, true, true, true},
        {"SR-3.2",  "Malicious code protection",
         "System shall provide protection against malicious code", false, true, true, true},
        {"SR-3.3",  "Security functionality verification",
         "System shall support security function verification", false, false, true, true},
        {"SR-3.4",  "Software and information integrity",
         "System shall protect software and information integrity", false, true, true, true},
        {"SR-3.5",  "Input validation",
         "System shall validate input data for type, range, and format", true, true, true, true},
        {"SR-4.1",  "Information confidentiality",
         "System shall protect sensitive data confidentiality", false, false, true, true},
        {"SR-4.2",  "Use of cryptography",
         "System shall use approved cryptographic algorithms", false, true, true, true},
        {"SR-5.1",  "Network segmentation",
         "System shall support network and zone segmentation", false, false, true, true},
        {"SR-5.2",  "Zone boundary protection",
         "System shall protect zone boundaries", false, true, true, true},
        {"SR-6.1",  "Audit log accessibility",
         "System shall provide accessible audit logs", true, true, true, true},
        {"SR-6.2",  "Continuous monitoring",
         "System shall support continuous security monitoring", false, false, true, true},
        {"SR-7.1",  "Denial of service protection",
         "System shall protect against denial of service attacks", false, true, true, true},
        {"SR-7.2",  "Resource management",
         "System shall manage resources to prevent exhaustion", false, true, true, true},
        {"SR-7.3",  "Control system backup",
         "System shall provide backup and restore capability", true, true, true, true},
        {"SR-7.5",  "Emergency power",
         "System shall support emergency power operation", false, false, true, true},
        {"SR-7.6",  "Network and security configuration settings",
         "System shall provide exportable security configuration", true, true, true, true},
    };
}

Status detect_status(const Check& chk, const fs::path& dir) {
    // Evidence heuristics based on file presence
    if (chk.id.find("SR-6") != std::string::npos)
        return fs::exists(dir / "INCIDENT-RESPONSE.md") ? Status::Partial : Status::Gap;
    if (chk.id.find("SR-3.4") != std::string::npos || chk.id.find("SR-4") != std::string::npos)
        return fs::exists(dir / ".fusa-sign") || fs::exists(dir / "sbom.json") ? Status::Partial : Status::Gap;
    if (chk.id.find("SR-3.5") != std::string::npos)
        return fs::exists(dir / "cyber-report.json") ? Status::Partial : Status::Gap;
    if (chk.id.find("SR-7.3") != std::string::npos)
        return fs::exists(dir / ".fusa-reqs.json") ? Status::Partial : Status::Gap;
    return Status::Gap;
}

bool is_required(const Check& c, SL sl) {
    switch (sl) {
        case SL::SL1: return c.required_sl1;
        case SL::SL2: return c.required_sl2;
        case SL::SL3: return c.required_sl3;
        default:      return c.required_sl4;
    }
}

} // namespace

//fusa:req REQ-IEC62443-003
Report assess(const fs::path& dir, const std::string& project, SL sl) {
    Report r;
    r.project = project;
    r.sl      = sl_str(sl);

    auto now = std::chrono::system_clock::now();
    auto t   = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ts;
    ts << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ");
    r.generated_at = ts.str();

    for (auto chk : baseline_checks()) {
        if (!is_required(chk, sl)) continue;
        chk.status = detect_status(chk, dir);
        r.checks.push_back(chk);
        r.total++;
        switch (chk.status) {
            case Status::Met:     r.satisfied++;     break;
            case Status::Partial: r.partial++; break;
            default:              r.gap++;     break;
        }
    }
    return r;
}

void write_json(const fs::path& out, const Report& r) {
    json j;
    // §3.1 common header
    j["schemaVersion"] = std::string(cpfusa::SpecVersion);
    j["kind"]          = "gap-report";
    j["standard"]      = "iec62443";
    j["tool"]          = "cpp-FuSa";
    j["toolVersion"]   = std::string(cpfusa::Version);
    j["language"]      = "cpp";
    j["generatedAt"] = r.generated_at;
    j["project"]     = r.project;
    j["sl"]          = r.sl;
    j["summary"]     = {{"total", r.total}, {"satisfied", r.satisfied},
                         {"partial", r.partial}, {"gaps", r.gap}};
    j["objectives"] = json::array();
    for (auto& c : r.checks) {
        j["objectives"].push_back({
            {"id", c.id}, {"title", c.requirement},
            {"status", status_str(c.status)}
        });
    }
    std::ofstream f(out);
    f << j.dump(2);
}

void render_text(const Report& r) {
    std::cout << "IEC 62443 Compliance Report — " << r.project << " [" << r.sl << "]\n";
    std::cout << std::string(70, '-') << "\n";
    for (auto& c : r.checks) {
        const char* m = (c.status == Status::Met)     ? "[OK]"
                      : (c.status == Status::Partial) ? "[~~]" : "[  ]";
        std::cout << m << " " << c.id << "  " << c.requirement << "\n";
    }
    std::cout << std::string(70, '-') << "\n";
    std::cout << "Total: " << r.total << "  Satisfied: " << r.satisfied
              << "  Partial: " << r.partial << "  Gap: " << r.gap << "\n";
}

} // namespace cpfusa::iec62443
