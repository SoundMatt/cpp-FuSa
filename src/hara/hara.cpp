#include "hara.hpp"
#include <algorithm>
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
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
        // §1.2.5 canonical key: "operationalSituations". Accept the legacy
        // "situations" key too so an existing file is not silently emptied.
        auto situations_json = j.contains("operationalSituations")
                                    ? j["operationalSituations"]
                                    : j.value("situations", json::array());
        for (auto& s : situations_json) {
            out.situations.push_back({s.value("id",""), s.value("description","")});
        }
        for (auto& h : j.value("hazards", json::array())) {
            Hazard hz;
            hz.id = h.value("id","");
            hz.description = h.value("description","");
            hz.source = h.value("source","");
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
            // §1.2.5 canonical key is "hazards" (refs back into hazards[]);
            // accept the legacy "hazardIds" key too.
            g.hazards = sg.contains("hazards")
                            ? sg.value("hazards", std::vector<std::string>{})
                            : sg.value("hazardIds", std::vector<std::string>{});
            g.asil = sg.value("asil","QM");
            g.safe_state = sg.value("safeState","");
            g.fssr_refs = sg.value("fssrRefs", std::vector<std::string>{});
            out.safety_goals.push_back(g);
        }
        out.attestation = quality::parse(j);
    } catch (const std::exception& e) {
        err = std::string("parse error: ") + e.what();
        return false;
    }
    return true;
}

//fusa:req REQ-HARA012
json content_json(const HARA& h) {
    json j;
    j["project"]   = h.project;
    j["standard"]  = h.standard;
    j["createdAt"] = h.created_at;
    j["operationalSituations"] = json::array();
    for (auto& s : h.situations)
        j["operationalSituations"].push_back({{"id", s.id}, {"description", s.description}});
    j["hazards"] = json::array();
    for (auto& hz : h.hazards) {
        json hj;
        hj["id"] = hz.id;
        hj["description"] = hz.description;
        if (!hz.source.empty()) hj["source"] = hz.source;
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
            {"hazards", sg.hazards},
            {"asil", sg.asil},
            {"safeState", sg.safe_state},
            {"fssrRefs", sg.fssr_refs}
        });
    }
    return j;
}

//fusa:req REQ-HARA007
bool save(const fs::path& path, const HARA& h, std::string& err) {
    json j = content_json(h);
    if (h.attestation.present) j["attestation"] = quality::to_json(h.attestation);
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
    // §1.6 rule 1 / §9.2 `--init`: scaffold EMPTY collections, never a dummy
    // row — a project author fills these in with item-specific analysis.
    HARA h;
    h.project  = project;
    h.standard = standard;
    h.created_at = "2026-06-09T00:00:00Z"; // populated at write time
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
        std::cout << "    FSSR refs: ";
        for (size_t i = 0; i < sg.fssr_refs.size(); ++i) {
            if (i) std::cout << ", ";
            std::cout << sg.fssr_refs[i];
        }
        if (sg.fssr_refs.empty()) std::cout << "(none — MUST have >=1, §1.2.5)";
        std::cout << "\n";
    }
}

//fusa:req REQ-HARA009
Completeness compute_completeness(const HARA& h, const std::vector<std::string>& requirement_ids) {
    Completeness c;
    std::vector<std::string> situation_ids, hazard_ids, goal_ids;
    for (auto& s : h.situations) situation_ids.push_back(s.id);
    for (auto& hz : h.hazards) hazard_ids.push_back(hz.id);
    for (auto& sg : h.safety_goals) goal_ids.push_back(sg.id);

    auto contains = [](const std::vector<std::string>& v, const std::string& id) {
        return std::find(v.begin(), v.end(), id) != v.end();
    };

    c.total_hazards = static_cast<int>(h.hazards.size());
    for (auto& hz : h.hazards) {
        if (!hz.risk.asil.empty()) ++c.hazards_with_asil;
        if (!hz.safety_goals.empty()) ++c.hazards_with_safety_goal;
        for (auto& sid : hz.situations)
            if (!contains(situation_ids, sid)) ++c.dangling_references;
        for (auto& gid : hz.safety_goals)
            if (!contains(goal_ids, gid)) ++c.dangling_references;
    }

    c.total_safety_goals = static_cast<int>(h.safety_goals.size());
    for (auto& sg : h.safety_goals) {
        if (!sg.fssr_refs.empty()) ++c.safety_goals_with_fssr_refs;
        for (auto& hid : sg.hazards)
            if (!contains(hazard_ids, hid)) ++c.dangling_references;
        // fssrRefs MUST resolve into .fusa-reqs.json (§1.2.5) — a dangling
        // requirement id here is counted the same as a structural dangling ref.
        for (auto& rid : sg.fssr_refs)
            if (!contains(requirement_ids, rid)) ++c.dangling_references;
    }
    return c;
}

//fusa:req REQ-HARA010
std::vector<Finding> scan_quality(const HARA& h) {
    std::vector<quality::QualField> fields;
    for (auto& hz : h.hazards)
        fields.push_back({"hazards[].description", hz.description, HARA_FILE, 0});
    for (auto& sg : h.safety_goals)
        fields.push_back({"safetyGoals[].description", sg.description, HARA_FILE, 0});

    std::vector<Finding> out = quality::scan_stub001(fields, HARA_FILE);
    auto rule_b = quality::scan_stub002(fields, HARA_FILE);
    out.insert(out.end(), rule_b.begin(), rule_b.end());
    return out;
}

//fusa:req REQ-HARA011
json to_report_json(const HARA& h, const config::ProjectConfig& cfg,
                    const std::vector<std::string>& requirement_ids) {
    // Reentrant gmtime — std::gmtime uses a shared static buffer (CWE-676 /
    // CodeQL cpp/potentially-dangerous-function); gmtime_r/gmtime_s do not.
    std::time_t t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    struct tm tm_buf{};
#ifdef _WIN32
    gmtime_s(&tm_buf, &t);
#else
    gmtime_r(&t, &tm_buf);
#endif
    std::ostringstream ts;
    ts << std::put_time(&tm_buf, "%FT%TZ");

    json j;
    j["schemaVersion"] = std::string(SpecVersion);
    j["kind"]          = "hara-report";
    j["tool"]          = "cpp-FuSa";
    j["toolVersion"]   = std::string(Version);
    j["language"]      = "cpp";
    j["generatedAt"]   = ts.str();
    j["projectRoot"]   = cfg.project_root;
    if (!cfg.project.empty())  j["project"]  = cfg.project;
    if (!cfg.standard.empty()) j["standard"] = cfg.standard;

    json situations = json::array();
    for (auto& s : h.situations)
        situations.push_back({{"id", s.id}, {"description", s.description}});

    json hazards = json::array();
    for (auto& hz : h.hazards) {
        json hj;
        hj["id"] = hz.id;
        hj["description"] = hz.description;
        if (!hz.source.empty()) hj["source"] = hz.source;
        hj["situations"] = hz.situations;
        hj["safetyGoals"] = hz.safety_goals;
        hj["risk"] = {
            {"severity", hz.risk.severity}, {"exposure", hz.risk.exposure},
            {"controllability", hz.risk.controllability}, {"asil", hz.risk.asil}
        };
        hazards.push_back(hj);
    }

    json goals = json::array();
    for (auto& sg : h.safety_goals) {
        goals.push_back({
            {"id", sg.id}, {"description", sg.description}, {"hazards", sg.hazards},
            {"asil", sg.asil}, {"safeState", sg.safe_state}, {"fssrRefs", sg.fssr_refs}
        });
    }

    j["operationalSituations"] = situations;
    j["hazards"]               = hazards;
    j["safetyGoals"]           = goals;

    auto c = compute_completeness(h, requirement_ids);
    j["completeness"] = {
        {"totalHazards", c.total_hazards},
        {"hazardsWithAsil", c.hazards_with_asil},
        {"hazardsWithSafetyGoal", c.hazards_with_safety_goal},
        {"safetyGoalsWithFssrRefs", c.safety_goals_with_fssr_refs},
        {"danglingReferences", c.dangling_references}
    };
    if (h.attestation.present) j["attestation"] = quality::to_json(h.attestation);
    return j;
}

} // namespace cpfusa::hara
