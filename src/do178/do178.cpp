#include "do178.hpp"
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <nlohmann/json.hpp>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace cpfusa::do178 {

DAL parse_dal(const std::string& s) {
    if (s == "DAL-A" || s == "A") return DAL::A;
    if (s == "DAL-B" || s == "B") return DAL::B;
    if (s == "DAL-C" || s == "C") return DAL::C;
    return DAL::D;
}
std::string dal_str(DAL d) {
    switch (d) {
        case DAL::A: return "DAL-A";
        case DAL::B: return "DAL-B";
        case DAL::C: return "DAL-C";
        default:     return "DAL-D";
    }
}

namespace {

//fusa:req REQ-DO178-002
std::vector<Objective> baseline_objectives() {
    return {
        // Table A-1: Software Planning
        {"A-1.1", "A-1", "Software Development Plan",              true,  true,  true,  true},
        {"A-1.2", "A-1", "Software Verification Plan",             true,  true,  true,  true},
        {"A-1.3", "A-1", "Software Configuration Management Plan", true,  true,  true,  true},
        {"A-1.4", "A-1", "Software Quality Assurance Plan",        true,  true,  true,  true},
        // Table A-2: Software Development
        {"A-2.1", "A-2", "Software Requirements Standards",        true,  true,  true,  true},
        {"A-2.2", "A-2", "High-level requirements traceability",   true,  true,  true,  true},
        {"A-2.3", "A-2", "Low-level requirements traceability",    true,  true,  false, false},
        {"A-2.4", "A-2", "Source code traceability",               true,  true,  false, false},
        // Table A-3: Verification of Outputs
        {"A-3.1", "A-3", "Software requirements review",           true,  true,  true,  true},
        {"A-3.2", "A-3", "Software architecture review",           true,  true,  true,  true},
        {"A-3.3", "A-3", "Source code review",                     true,  true,  true,  true},
        {"A-3.4", "A-3", "Test case review",                       true,  true,  true,  true},
        // Table A-4: Testing
        {"A-4.1", "A-4", "Statement coverage (100%)",              true,  true,  true,  false},
        {"A-4.2", "A-4", "Decision coverage (100%)",               true,  true,  false, false},
        {"A-4.3", "A-4", "MC/DC coverage (100%)",                  true,  false, false, false},
        // Table A-5: Verification of Software Integration Output
        {"A-5.1", "A-5", "Software integration testing",           true,  true,  true,  true},
        {"A-5.2", "A-5", "Integration test procedures",            true,  true,  true,  false},
        {"A-5.3", "A-5", "Integration test results",               true,  true,  true,  false},
        {"A-5.4", "A-5", "Integration test coverage analysis",     true,  true,  false, false},
        {"A-5.5", "A-5", "Problem reports — integration phase",    true,  true,  true,  true},
        {"A-5.6", "A-5", "Software configuration index",           true,  true,  true,  true},
        // Table A-6: Verification of Testing outputs
        {"A-6.1", "A-6", "Test procedures reviewed",               true,  true,  true,  false},
        {"A-6.2", "A-6", "Test results reviewed",                  true,  true,  true,  false},
        {"A-6.3", "A-6", "Test coverage analysis reviewed",        true,  true,  false, false},
        {"A-6.4", "A-6", "Test problem reports reviewed",          true,  true,  true,  true},
        {"A-6.5", "A-6", "Test traceability to requirements",      true,  true,  true,  false},
        // Table A-10: Additional Considerations Testing
        {"A-10.1","A-10","Timing analysis and constraints",         true,  false, false, false},
        {"A-10.2","A-10","Memory and resource usage verification",  true,  true,  false, false},
        {"A-10.3","A-10","Equivalence class and boundary testing",  true,  true,  true,  false},
        {"A-10.4","A-10","Error guessing and fault injection",      true,  false, false, false},
        {"A-10.5","A-10","Partition and worst-case testing",        true,  true,  false, false},
        // Table A-11: Configuration Item Testing
        {"A-11.1","A-11","CI-level test procedures",               true,  true,  true,  true},
        {"A-11.2","A-11","CI-level test results",                  true,  true,  true,  true},
        {"A-11.3","A-11","CI-level test coverage analysis",        true,  true,  false, false},
        {"A-11.4","A-11","CI-level problem reports",               true,  true,  true,  true},
        {"A-11.5","A-11","CI software configuration index",        true,  true,  true,  true},
        {"A-11.6","A-11","CI test environment verification",       true,  true,  true,  false},
        {"A-11.7","A-11","CI regression test evidence",            true,  true,  false, false},
        // Table A-7: Configuration Management
        {"A-7.1", "A-7", "Software baseline established",          true,  true,  true,  true},
        {"A-7.2", "A-7", "Problem reporting and resolution",       true,  true,  true,  true},
        // Table A-8: Quality Assurance
        {"A-8.1", "A-8", "Software life cycle processes conform",  true,  true,  true,  true},
        {"A-8.2", "A-8", "Transition criteria satisfied",          true,  true,  true,  true},
        // Table A-9: Certification Liaison
        {"A-9.1", "A-9", "Comply with plans and standards",        true,  true,  true,  true},
        {"A-9.2", "A-9", "Software accomplishment summary",        true,  true,  true,  true},
    };
}

bool is_required(const Objective& obj, DAL dal) {
    switch (dal) {
        case DAL::A: return obj.required_a;
        case DAL::B: return obj.required_b;
        case DAL::C: return obj.required_c;
        default:     return obj.required_d;
    }
}

Status detect_status(const std::string& id, const fs::path& dir) {
    if (id.find("A-2.2") != std::string::npos || id.find("A-2.3") != std::string::npos ||
        id.find("A-2.4") != std::string::npos)
        return fs::exists(dir / ".fusa-reqs.json") ? Status::Partial : Status::Gap;
    if (id.find("A-4") != std::string::npos)
        return fs::exists(dir / "coverage-report.json") ? Status::Addressed : Status::Gap;
    if (id.find("A-7.2") != std::string::npos)
        return fs::exists(dir / ".fusa-problems.json") ? Status::Partial : Status::Gap;
    if (id.find("A-8") != std::string::npos)
        return fs::exists(dir / ".fusa-evidence.json") ? Status::Partial : Status::Gap;
    if (id.find("A-9.2") != std::string::npos)
        return fs::exists(dir / "sas.json") ? Status::Addressed : Status::Gap;
    return Status::Gap;
}

std::string status_str(Status s) {
    switch (s) {
        case Status::Addressed: return "addressed";
        case Status::Partial:   return "partial";
        default:                return "gap";
    }
}

} // anonymous namespace

Report assess(const fs::path& dir, const std::string& project, DAL dal) {
    Report r;
    r.project = project;
    r.dal = dal_str(dal);

    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ts;
    ts << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ");
    r.generated_at = ts.str();

    for (auto obj : baseline_objectives()) {
        if (!is_required(obj, dal)) continue;
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
    j["dal"]         = r.dal;
    j["summary"]     = {{"total", r.total}, {"satisfied", r.addressed},
                         {"partial", r.partial}, {"gaps", r.gap}};
    j["objectives"] = json::array();
    for (auto& o : r.objectives) {
        j["objectives"].push_back({
            {"id", o.id}, {"table", o.table},
            {"description", o.description},
            {"status", status_str(o.status)}
        });
    }
    std::ofstream f(out);
    f << j.dump(2);
}

void render_text(const Report& r) {
    std::cout << "DO-178C Gap Report — " << r.project << " [" << r.dal << "]\n";
    std::cout << std::string(70, '-') << "\n";
    for (auto& o : r.objectives) {
        const char* m = (o.status == Status::Addressed) ? "[OK]"
                      : (o.status == Status::Partial)   ? "[~~]" : "[  ]";
        std::cout << m << " " << o.id << " (Tbl " << o.table << ")  " << o.description << "\n";
    }
    std::cout << std::string(70, '-') << "\n";
    std::cout << "Total: " << r.total << "  Addressed: " << r.addressed
              << "  Partial: " << r.partial << "  Gap: " << r.gap << "\n";
}

} // namespace cpfusa::do178
