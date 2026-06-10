#include "iec61508.hpp"
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <nlohmann/json.hpp>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace cpfusa::iec61508 {

SIL parse_sil(const std::string& s) {
    if (s == "SIL-1" || s == "SIL1") return SIL::SIL1;
    if (s == "SIL-2" || s == "SIL2") return SIL::SIL2;
    if (s == "SIL-3" || s == "SIL3") return SIL::SIL3;
    return SIL::SIL4;
}
std::string sil_str(SIL s) {
    switch (s) {
        case SIL::SIL1: return "SIL-1";
        case SIL::SIL2: return "SIL-2";
        case SIL::SIL3: return "SIL-3";
        default:        return "SIL-4";
    }
}

namespace {

//fusa:req REQ-IEC61508-002
std::vector<Objective> baseline_objectives() {
    return {
        {"1-7.1",  "Part 1", "§7.1",  "Safety lifecycle",                          true,  true,  true,  true},
        {"1-7.2",  "Part 1", "§7.2",  "Hazard and risk analysis",                  true,  true,  true,  true},
        {"1-8.1",  "Part 1", "§8.1",  "Safety requirements specification",         true,  true,  true,  true},
        {"1-8.2",  "Part 1", "§8.2",  "Safety requirements allocation",            true,  true,  true,  true},
        {"3-7.1",  "Part 3", "§7.1",  "Software safety requirements specification", true, true,  true,  true},
        {"3-7.2",  "Part 3", "§7.2",  "Software architecture design",              true,  true,  true,  true},
        {"3-7.3",  "Part 3", "§7.3",  "Software design & development",             true,  true,  true,  true},
        {"3-7.4",  "Part 3", "§7.4",  "Software module testing",                   true,  true,  true,  true},
        {"3-7.5",  "Part 3", "§7.5",  "Software integration testing",              true,  true,  true,  true},
        {"3-7.6",  "Part 3", "§7.6",  "Software validation testing",               true,  true,  true,  true},
        {"3-7.7",  "Part 3", "§7.7",  "Software modification",                     true,  true,  true,  true},
        {"3-7.8",  "Part 3", "§7.8",  "Software verification",                     true,  true,  true,  true},
        {"3-7.9",  "Part 3", "§7.9",  "Functional safety assessment",              false, false, true,  true},
        {"3-B.1",  "Part 3", "Annex B","Language subset / coding standard",        false, true,  true,  true},
        {"3-B.2",  "Part 3", "Annex B","Static analysis",                          false, true,  true,  true},
        {"3-B.3",  "Part 3", "Annex B","Dynamic analysis / coverage",              false, false, true,  true},
        {"3-B.4",  "Part 3", "Annex B","Requirements traceability",                true,  true,  true,  true},
        {"3-B.5",  "Part 3", "Annex B","Tool qualification",                       false, false, true,  true},
        {"2-7.1",  "Part 2", "§7.1",  "Hardware safety requirements",              true,  true,  true,  true},
        {"2-8.1",  "Part 2", "§8.1",  "Safety case",                              true,  true,  true,  true},
    };
}

bool is_required(const Objective& obj, SIL sil) {
    switch (sil) {
        case SIL::SIL1: return obj.required_1;
        case SIL::SIL2: return obj.required_2;
        case SIL::SIL3: return obj.required_3;
        default:        return obj.required_4;
    }
}

Status detect_status(const std::string& id, const fs::path& dir) {
    if (id == "3-7.1") return fs::exists(dir / ".fusa-reqs.json") ? Status::Partial : Status::Gap;
    if (id == "3-7.3") return fs::exists(dir / ".fusa.json")      ? Status::Partial : Status::Gap;
    if (id == "3-7.4") return fs::exists(dir / ".fusa-evidence.json") ? Status::Partial : Status::Gap;
    if (id == "3-7.5") return fs::exists(dir / ".fusa-evidence.json") ? Status::Partial : Status::Gap;
    if (id == "3-B.1") return fs::exists(dir / ".fusa.json")      ? Status::Partial : Status::Gap;
    if (id == "3-B.2") return fs::exists(dir / "cyber-report.json")? Status::Partial : Status::Gap;
    if (id == "3-B.3") return fs::exists(dir / "coverage-report.json") ? Status::Addressed : Status::Gap;
    if (id == "3-B.4") return fs::exists(dir / ".fusa-reqs.json") ? Status::Addressed : Status::Gap;
    if (id == "3-B.5") return fs::exists(dir / "qualify-report.json") ? Status::Addressed : Status::Gap;
    if (id == "2-8.1") return fs::exists(dir / "safety-case.json") ? Status::Partial : Status::Gap;
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

Report assess(const fs::path& dir, const std::string& project, SIL sil) {
    Report r;
    r.project = project;
    r.sil = sil_str(sil);

    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ts;
    ts << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ");
    r.generated_at = ts.str();

    for (auto obj : baseline_objectives()) {
        if (!is_required(obj, sil)) continue;
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
    j["sil"]         = r.sil;
    j["summary"]     = {{"total", r.total}, {"satisfied", r.addressed},
                         {"partial", r.partial}, {"gaps", r.gap}};
    j["objectives"] = json::array();
    for (auto& o : r.objectives) {
        j["objectives"].push_back({
            {"id", o.id}, {"part", o.part}, {"clause", o.clause},
            {"description", o.description},
            {"status", status_str(o.status)}
        });
    }
    std::ofstream f(out);
    f << j.dump(2);
}

void render_text(const Report& r) {
    std::cout << "IEC 61508 Gap Report — " << r.project
              << " [" << r.sil << "]\n";
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

} // namespace cpfusa::iec61508
