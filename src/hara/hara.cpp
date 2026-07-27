#include "hara.hpp"
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace cpfusa::hara {

// ISO 26262-3:2018 Table 4 ASIL determination
//fusa:req REQ-HARA002
std::string determine_asil(Severity s, Exposure e, Controllability c) {
    // S0 or E0 or C0 → QM
    if (s == Severity::S0 || e == Exposure::E0 || c == Controllability::C0)
        return "QM";

    int si = static_cast<int>(s);
    int ei = static_cast<int>(e);
    int ci = static_cast<int>(c);

    // Table 4 lookup: rows = S1..S3, cols = C1..C3, E1..E4 subrows
    // Encoded as (S,E,C) → ASIL
    // QM=0, A=1, B=2, C=3, D=4
    static const int table[3][4][3] = {
        // S1
        {{0,0,0}, {0,0,1}, {0,1,2}, {1,2,3}},
        // S2
        {{0,1,2}, {1,2,3}, {2,3,4}, {3,4,4}},
        // S3
        {{1,2,3}, {2,3,4}, {3,4,4}, {4,4,4}},
    };
    static const char* names[] = {"QM", "ASIL-A", "ASIL-B", "ASIL-C", "ASIL-D"};
    int idx = table[si-1][ei-1][ci-1];
    return names[idx];
}

Severity parse_severity(const std::string& s) {
    if (s == "S0") return Severity::S0;
    if (s == "S1") return Severity::S1;
    if (s == "S2") return Severity::S2;
    return Severity::S3;
}
Exposure parse_exposure(const std::string& s) {
    if (s == "E0") return Exposure::E0;
    if (s == "E1") return Exposure::E1;
    if (s == "E2") return Exposure::E2;
    if (s == "E3") return Exposure::E3;
    return Exposure::E4;
}
Controllability parse_controllability(const std::string& s) {
    if (s == "C0") return Controllability::C0;
    if (s == "C1") return Controllability::C1;
    if (s == "C2") return Controllability::C2;
    return Controllability::C3;
}

//fusa:req REQ-HARA001 REQ-HARA006
bool load(const fs::path& dir, HARA& out, std::string& err) {
    auto p = dir / HARA_FILE;
    std::ifstream f(p);
    if (!f) { err = "cannot open " + p.string(); return false; }
    try {
        auto j = json::parse(f);
        out.project  = j.value("project", "");
        out.standard = j.value("standard", "ISO 26262");
        out.created_at = j.value("createdAt", "");
        for (auto& s : j.value("situations", json::array())) {
            out.situations.push_back({s.value("id",""), s.value("description","")});
        }
        for (auto& h : j.value("hazards", json::array())) {
            Hazard hz;
            hz.id = h.value("id","");
            hz.description = h.value("description","");
            hz.situations = h.value("situations", std::vector<std::string>{});
            hz.safety_goals = h.value("safetyGoals", std::vector<std::string>{});
            if (h.contains("risk")) {
                hz.risk.severity        = h["risk"].value("severity","");
                hz.risk.exposure        = h["risk"].value("exposure","");
                hz.risk.controllability = h["risk"].value("controllability","");
                hz.risk.asil            = h["risk"].value("asil","QM");
            }
            out.hazards.push_back(hz);
        }
        for (auto& sg : j.value("safetyGoals", json::array())) {
            SafetyGoal g;
            g.id = sg.value("id","");
            g.description = sg.value("description","");
            g.hazard_ids = sg.value("hazardIds", std::vector<std::string>{});
            g.asil = sg.value("asil","QM");
            g.safe_state = sg.value("safeState","");
            out.safety_goals.push_back(g);
        }
    } catch (const std::exception& e) {
        err = std::string("parse error: ") + e.what();
        return false;
    }
    return true;
}

//fusa:req REQ-HARA007
bool save(const fs::path& path, const HARA& h, std::string& err) {
    json j;
    j["project"]   = h.project;
    j["standard"]  = h.standard;
    j["createdAt"] = h.created_at;
    j["situations"] = json::array();
    for (auto& s : h.situations)
        j["situations"].push_back({{"id", s.id}, {"description", s.description}});
    j["hazards"] = json::array();
    for (auto& hz : h.hazards) {
        json hj;
        hj["id"] = hz.id;
        hj["description"] = hz.description;
        hj["situations"] = hz.situations;
        hj["safetyGoals"] = hz.safety_goals;
        hj["risk"] = {
            {"severity", hz.risk.severity},
            {"exposure", hz.risk.exposure},
            {"controllability", hz.risk.controllability},
            {"asil", hz.risk.asil}
        };
        j["hazards"].push_back(hj);
    }
    j["safetyGoals"] = json::array();
    for (auto& sg : h.safety_goals) {
        j["safetyGoals"].push_back({
            {"id", sg.id},
            {"description", sg.description},
            {"hazardIds", sg.hazard_ids},
            {"asil", sg.asil},
            {"safeState", sg.safe_state}
        });
    }
    std::ofstream f(path);
    if (!f) { err = "cannot write " + path.string(); return false; }
    f << j.dump(2);
    return true;
}

//fusa:req REQ-HARA008
bool init(const fs::path& dir, const std::string& project, const std::string& standard, std::string& err) {
    auto p = dir / HARA_FILE;
    if (fs::exists(p)) {
        err = std::string(HARA_FILE) + " already exists — delete it first to reinitialise";
        return false;
    }
    HARA h;
    h.project  = project;
    h.standard = standard;
    h.created_at = "2026-06-09T00:00:00Z"; // populated at write time
    h.situations.push_back({"OS-001", "Normal operation"});
    h.hazards.push_back({
        "H-001",
        "Example hazard — replace with project-specific hazard",
        {"OS-001"},
        {"S2", "E3", "C2", determine_asil(Severity::S2, Exposure::E3, Controllability::C2)},
        {"SG-001"}
    });
    h.safety_goals.push_back({
        "SG-001",
        "Example safety goal — replace with project-specific goal",
        {"H-001"},
        determine_asil(Severity::S2, Exposure::E3, Controllability::C2),
        "safe state description"
    });
    return save(p, h, err);
}

void render_text(const HARA& h) {
    std::cout << "HARA — " << h.project << " (" << h.standard << ")\n";
    std::cout << std::string(70, '-') << "\n\n";

    std::cout << "Operational Situations (" << h.situations.size() << ")\n";
    for (auto& s : h.situations)
        std::cout << "  " << s.id << "  " << s.description << "\n";

    std::cout << "\nHazards (" << h.hazards.size() << ")\n";
    for (auto& hz : h.hazards) {
        std::cout << "  " << hz.id << "  " << hz.description << "\n";
        std::cout << "    Risk: S=" << hz.risk.severity
                  << " E=" << hz.risk.exposure
                  << " C=" << hz.risk.controllability
                  << " → " << hz.risk.asil << "\n";
    }

    std::cout << "\nSafety Goals (" << h.safety_goals.size() << ")\n";
    for (auto& sg : h.safety_goals) {
        std::cout << "  " << sg.id << " [" << sg.asil << "]  " << sg.description << "\n";
        std::cout << "    Safe state: " << sg.safe_state << "\n";
    }
}

} // namespace cpfusa::hara
