#include "iso26262.hpp"
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <nlohmann/json.hpp>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace cpfusa::iso26262 {

ASIL parse_asil(const std::string& s) {
    if (s == "ASIL-A" || s == "A") return ASIL::A;
    if (s == "ASIL-B" || s == "B") return ASIL::B;
    if (s == "ASIL-C" || s == "C") return ASIL::C;
    return ASIL::D;
}
std::string asil_str(ASIL a) {
    switch (a) {
        case ASIL::A: return "ASIL-A";
        case ASIL::B: return "ASIL-B";
        case ASIL::C: return "ASIL-C";
        default:      return "ASIL-D";
    }
}

namespace {

// ISO 26262-6:2018 Part 6 (software) objectives — key clauses
//fusa:req REQ-ISO26262-002
std::vector<Objective> baseline_objectives() {
    // required_a/b/c/d encodes which ASILs mandate this objective
    return {
        {"6-5.1",  "Part 6", "§5.1",  "Software development planning",             true,  true,  true,  true,  Status::Gap, ""},
        {"6-5.2",  "Part 6", "§5.2",  "Software design criteria specification",    false, true,  true,  true,  Status::Gap, ""},
        {"6-6.1",  "Part 6", "§6.1",  "Software architectural design",             true,  true,  true,  true,  Status::Gap, ""},
        {"6-6.2",  "Part 6", "§6.2",  "Software unit design",                      true,  true,  true,  true,  Status::Gap, ""},
        {"6-6.3",  "Part 6", "§6.3",  "Software unit implementation",              true,  true,  true,  true,  Status::Gap, ""},
        {"6-7.1",  "Part 6", "§7.1",  "Software unit verification",                true,  true,  true,  true,  Status::Gap, ""},
        {"6-7.2",  "Part 6", "§7.2",  "Software unit testing",                     true,  true,  true,  true,  Status::Gap, ""},
        {"6-8.1",  "Part 6", "§8.1",  "Software integration and testing",          true,  true,  true,  true,  Status::Gap, ""},
        {"6-9.1",  "Part 6", "§9.1",  "Verification of software safety requirements", true, true, true, true, Status::Gap, ""},
        {"6-4.3",  "Part 6", "§4.3",  "MISRA C++ coding guidelines",              false, true,  true,  true,  Status::Gap, ""},
        {"6-4.4",  "Part 6", "§4.4",  "Static analysis",                           true,  true,  true,  true,  Status::Gap, ""},
        {"6-4.5",  "Part 6", "§4.5",  "Dynamic analysis / coverage measurement",  false, false, true,  true,  Status::Gap, ""},
        {"6-4.6",  "Part 6", "§4.6",  "Requirements traceability",                true,  true,  true,  true,  Status::Gap, ""},
        {"6-4.7",  "Part 6", "§4.7",  "Configuration management",                 true,  true,  true,  true,  Status::Gap, ""},
        {"6-4.8",  "Part 6", "§4.8",  "Change management",                        true,  true,  true,  true,  Status::Gap, ""},
        {"6-4.9",  "Part 6", "§4.9",  "Software tool qualification",              false, true,  true,  true,  Status::Gap, ""},
        {"8-6.1",  "Part 8", "§6.1",  "ASIL decomposition",                       false, true,  true,  true,  Status::Gap, ""},
        {"8-6.2",  "Part 8", "§6.2",  "Safety manual",                            true,  true,  true,  true,  Status::Gap, ""},
        {"9-1.1",  "Part 9", "§1.1",  "ASIL-B verification independence",         false, true,  false, false, Status::Gap, ""},
        {"9-2.1",  "Part 9", "§2.1",  "Safety case",                              true,  true,  true,  true,  Status::Gap, ""},
    };
}

bool is_required(const Objective& obj, ASIL asil) {
    switch (asil) {
        case ASIL::A: return obj.required_a;
        case ASIL::B: return obj.required_b;
        case ASIL::C: return obj.required_c;
        default:      return obj.required_d;
    }
}

// Evidence detection: check which artifacts exist to determine status
Status detect_status(const std::string& obj_id, const fs::path& dir) {
    // Map objective IDs to evidence files
    if (obj_id == "6-4.3") {
        // MISRA C++ — lint module
        return fs::exists(dir / ".fusa.json") ? Status::Partial : Status::Gap;
    }
    if (obj_id == "6-4.4") {
        return (fs::exists(dir / ".fusa.json") && fs::exists(dir / "cyber-report.json"))
               ? Status::Partial : (fs::exists(dir / ".fusa.json") ? Status::Partial : Status::Gap);
    }
    if (obj_id == "6-4.5") {
        return fs::exists(dir / "coverage-report.json") ? Status::Addressed : Status::Gap;
    }
    if (obj_id == "6-4.6") {
        return fs::exists(dir / ".fusa-reqs.json") ? Status::Addressed : Status::Gap;
    }
    if (obj_id == "6-4.7") {
        return (fs::exists(dir / ".fusa.json") && fs::exists(dir / "sbom.json"))
               ? Status::Partial : Status::Gap;
    }
    if (obj_id == "6-4.8") {
        return fs::exists(dir / "CHANGELOG.md") ? Status::Partial : Status::Gap;
    }
    if (obj_id == "6-7.1" || obj_id == "6-7.2") {
        return fs::exists(dir / ".fusa-evidence.json") ? Status::Partial : Status::Gap;
    }
    if (obj_id == "6-5.1") {
        return fs::exists(dir / ".fusa.json") ? Status::Partial : Status::Gap;
    }
    if (obj_id == "9-2.1") {
        return fs::exists(dir / "safety-case.json") ? Status::Partial : Status::Gap;
    }
    if (obj_id == "6-4.9") {
        return fs::exists(dir / "qualify-report.json") ? Status::Addressed : Status::Gap;
    }
    return Status::Gap;
}

std::string status_str(Status s) {
    switch (s) {
        case Status::Addressed: return "satisfied";
        case Status::Partial:   return "partial";
        default:                return "gap";
    }
}

} // anonymous namespace

Report assess(const fs::path& dir, const std::string& project, ASIL asil) {
    Report r;
    r.project = project;
    r.asil = asil_str(asil);

    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ts;
    ts << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ");
    r.generated_at = ts.str();

    for (auto obj : baseline_objectives()) {
        if (!is_required(obj, asil)) continue;
        obj.status = detect_status(obj.id, dir);
        r.objectives.push_back(obj);
        r.total++;
        switch (obj.status) {
            case Status::Addressed: r.addressed++; break;
            case Status::Partial:   r.partial++;   break;
            default:                r.gap++;        break;
        }
    }
    return r;
}

void write_json(const fs::path& out, const Report& r) {
    json j;
    j["generatedAt"] = r.generated_at;
    j["project"]     = r.project;
    j["asil"]        = r.asil;
    j["summary"]     = {{"total", r.total}, {"satisfied", r.addressed},
                         {"partial", r.partial}, {"gaps", r.gap}};
    j["objectives"] = json::array();
    for (auto& o : r.objectives) {
        j["objectives"].push_back({
            {"id", o.id}, {"part", o.part}, {"clause", o.clause},
            {"description", o.description},
            {"status", status_str(o.status)},
            {"evidence", o.evidence}
        });
    }
    std::ofstream f(out);
    f << j.dump(2);
}

void render_text(const Report& r) {
    std::cout << "ISO 26262 Gap Report — " << r.project
              << " [" << r.asil << "]\n";
    std::cout << std::string(70, '-') << "\n";
    for (auto& o : r.objectives) {
        const char* marker = (o.status == Status::Addressed) ? "[OK]"
                           : (o.status == Status::Partial)   ? "[~~]"
                                                              : "[  ]";
        std::cout << marker << " " << o.id
                  << "  " << o.clause << "  " << o.description << "\n";
    }
    std::cout << std::string(70, '-') << "\n";
    std::cout << "Total: " << r.total
              << "  Addressed: " << r.addressed
              << "  Partial: " << r.partial
              << "  Gap: " << r.gap << "\n";
}

} // namespace cpfusa::iso26262
