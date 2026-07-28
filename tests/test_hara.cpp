//fusa:test REQ-HARA001
//fusa:test REQ-HARA002
//fusa:test REQ-HARA003
//fusa:test REQ-HARA006
//fusa:test REQ-HARA007
//fusa:test REQ-HARA008
//fusa:test REQ-HARA009
//fusa:test REQ-HARA010
//fusa:test REQ-HARA011
//fusa:test REQ-HARA012
#include <catch2/catch_all.hpp>
#include "hara/hara.hpp"
#include "testutil/testutil.hpp"
#include <fstream>

using namespace cpfusa;
using namespace cpfusa::testutil;

// ─── determine_asil ──────────────────────────────────────────────────────────

TEST_CASE("hara: S3 E4 C3 = ASIL-D", "[hara][hara001]") {
    REQUIRE(hara::determine_asil(hara::Severity::S3, hara::Exposure::E4, hara::Controllability::C3) == "ASIL-D");
}

TEST_CASE("hara: S0 any = QM", "[hara][hara001]") {
    REQUIRE(hara::determine_asil(hara::Severity::S0, hara::Exposure::E4, hara::Controllability::C3) == "QM");
}

TEST_CASE("hara: S1 E1 C1 = QM", "[hara][hara001]") {
    REQUIRE(hara::determine_asil(hara::Severity::S1, hara::Exposure::E1, hara::Controllability::C1) == "QM");
}

TEST_CASE("hara: parse_severity S2", "[hara][hara001]") {
    REQUIRE(hara::parse_severity("S2") == hara::Severity::S2);
}

TEST_CASE("hara: parse_exposure E3", "[hara][hara001]") {
    REQUIRE(hara::parse_exposure("E3") == hara::Exposure::E3);
}

TEST_CASE("hara: parse_controllability C2", "[hara][hara001]") {
    REQUIRE(hara::parse_controllability("C2") == hara::Controllability::C2);
}

// ─── init / load / save ───────────────────────────────────────────────────────

TEST_CASE("hara: init creates HARA file", "[hara][hara002]") {
    TempDir tmp;
    std::string err;
    REQUIRE(hara::init(tmp.path(), "test-proj", "ISO 26262", err));
    REQUIRE(std::filesystem::exists(tmp.path() / hara::HARA_FILE));
}

TEST_CASE("hara: load after init succeeds", "[hara][hara002]") {
    TempDir tmp;
    std::string err;
    REQUIRE(hara::init(tmp.path(), "proj", "ISO 26262", err));
    hara::HARA h;
    REQUIRE(hara::load(tmp.path(), h, err));
    REQUIRE(h.project == "proj");
}

TEST_CASE("hara: load returns false when file missing", "[hara][hara002]") {
    TempDir tmp;
    hara::HARA h;
    std::string err;
    REQUIRE_FALSE(hara::load(tmp.path(), h, err));
    REQUIRE_FALSE(err.empty());
}

TEST_CASE("hara: save and load roundtrip preserves hazard count", "[hara][hara003]") {
    TempDir tmp;
    hara::HARA h;
    h.project  = "roundtrip-proj";
    h.standard = "ISO 26262";
    hara::Hazard hz;
    hz.id = "H-001";
    hz.description = "Test hazard";
    h.hazards.push_back(hz);
    std::string err;
    REQUIRE(hara::save(tmp.path() / hara::HARA_FILE, h, err));
    hara::HARA loaded;
    REQUIRE(hara::load(tmp.path(), loaded, err));
    REQUIRE(loaded.hazards.size() == 1);
    REQUIRE(loaded.hazards[0].id == "H-001");
}

TEST_CASE("hara: save fails on bad path", "[hara][hara002]") {
    hara::HARA h;
    std::string err;
    REQUIRE_FALSE(hara::save("/no/such/dir/hara.json", h, err));
}

// ─── §1.2.5 fssrRefs / hazards[] safetyGoals reference rename ────────────────

TEST_CASE("hara: save/load round-trips fssrRefs (MUST, >=1 entry)", "[hara][hara009]") {
    TempDir tmp;
    hara::HARA h;
    h.project = "p"; h.standard = "ISO 26262";
    hara::SafetyGoal sg;
    sg.id = "SG-001"; sg.description = "goal"; sg.fssr_refs = {"REQ-X001"};
    h.safety_goals.push_back(sg);
    std::string err;
    REQUIRE(hara::save(tmp.path() / hara::HARA_FILE, h, err));
    hara::HARA loaded;
    REQUIRE(hara::load(tmp.path(), loaded, err));
    REQUIRE(loaded.safety_goals.size() == 1);
    REQUIRE(loaded.safety_goals[0].fssr_refs == std::vector<std::string>{"REQ-X001"});
}

TEST_CASE("hara: safetyGoals[].hazards uses the spec key (not hazardIds)", "[hara][hara009]") {
    TempDir tmp;
    hara::HARA h;
    hara::SafetyGoal sg;
    sg.id = "SG-001"; sg.hazards = {"H-001"};
    h.safety_goals.push_back(sg);
    std::string err;
    REQUIRE(hara::save(tmp.path() / hara::HARA_FILE, h, err));
    std::ifstream f(tmp.path() / hara::HARA_FILE);
    nlohmann::json j; f >> j;
    REQUIRE(j["safetyGoals"][0].contains("hazards"));
    REQUIRE_FALSE(j["safetyGoals"][0].contains("hazardIds"));
}

TEST_CASE("hara: init scaffolds EMPTY collections, never a placeholder row", "[hara][hara009]") {
    TempDir tmp;
    std::string err;
    REQUIRE(hara::init(tmp.path(), "proj", "ISO 26262", err));
    hara::HARA h;
    REQUIRE(hara::load(tmp.path(), h, err));
    REQUIRE(h.hazards.empty());
    REQUIRE(h.safety_goals.empty());
    REQUIRE(h.situations.empty());
}

// ─── completeness ─────────────────────────────────────────────────────────────

TEST_CASE("hara: compute_completeness counts fssrRefs and dangling references",
          "[hara][hara009]") {
    hara::HARA h;
    hara::Hazard hz;
    hz.id = "H-001"; hz.risk.asil = "ASIL-B"; hz.safety_goals = {"SG-001"};
    h.hazards.push_back(hz);
    hara::SafetyGoal sg;
    sg.id = "SG-001"; sg.hazards = {"H-001"}; sg.fssr_refs = {"REQ-KNOWN", "REQ-DANGLING"};
    h.safety_goals.push_back(sg);

    auto c = hara::compute_completeness(h, {"REQ-KNOWN"});
    REQUIRE(c.total_hazards == 1);
    REQUIRE(c.hazards_with_asil == 1);
    REQUIRE(c.hazards_with_safety_goal == 1);
    REQUIRE(c.total_safety_goals == 1);
    REQUIRE(c.safety_goals_with_fssr_refs == 1);
    REQUIRE(c.dangling_references == 1); // REQ-DANGLING not in the known set
}

TEST_CASE("hara: compute_completeness reports zero dangling refs for a consistent file",
          "[hara][hara009]") {
    hara::HARA h;
    h.situations.push_back({"OS-001", "desc"});
    hara::Hazard hz;
    hz.id = "H-001"; hz.situations = {"OS-001"}; hz.safety_goals = {"SG-001"};
    h.hazards.push_back(hz);
    hara::SafetyGoal sg;
    sg.id = "SG-001"; sg.hazards = {"H-001"}; sg.fssr_refs = {"REQ-KNOWN"};
    h.safety_goals.push_back(sg);
    auto c = hara::compute_completeness(h, {"REQ-KNOWN"});
    REQUIRE(c.dangling_references == 0);
}

// ─── §1.6.1 quality scan wiring ───────────────────────────────────────────────

TEST_CASE("hara: scan_quality flags placeholder hazard/goal descriptions", "[hara][hara010]") {
    hara::HARA h;
    hara::Hazard hz; hz.id = "H-001"; hz.description = "[describe hazard]";
    h.hazards.push_back(hz);
    hara::SafetyGoal sg; sg.id = "SG-001"; sg.description = "TBD";
    h.safety_goals.push_back(sg);
    auto findings = hara::scan_quality(h);
    int stub001 = 0;
    for (auto& f : findings) if (f.rule_id == "FUSA-STUB001") ++stub001;
    REQUIRE(stub001 == 2);
}

TEST_CASE("hara: scan_quality is clean for genuine, item-specific descriptions",
          "[hara][hara010]") {
    hara::HARA h;
    hara::Hazard hz; hz.id = "H-001";
    hz.description = "check silently swallows a rule error, so a real defect is reported as clean";
    h.hazards.push_back(hz);
    auto findings = hara::scan_quality(h);
    for (auto& f : findings) REQUIRE(f.rule_id != "FUSA-STUB001");
}

// ─── hara-report (§9.2) JSON document ─────────────────────────────────────────

TEST_CASE("hara: to_report_json emits the spec 3.1 header and completeness block",
          "[hara][hara011]") {
    hara::HARA h;
    h.project = "P"; h.standard = "ISO 26262";
    config::ProjectConfig cfg;
    auto j = hara::to_report_json(h, cfg, {});
    REQUIRE(j["kind"] == "hara-report");
    REQUIRE(j.contains("schemaVersion"));
    REQUIRE(j.contains("completeness"));
    REQUIRE(j.contains("operationalSituations"));
}

// ─── §1.6.2 content_json (attestation hashing target) ────────────────────────

TEST_CASE("hara: content_json excludes attestation but includes hazards", "[hara][hara012]") {
    hara::HARA h;
    h.project = "P";
    hara::Hazard hz; hz.id = "H-001"; hz.description = "d";
    h.hazards.push_back(hz);
    h.attestation.present = true;
    h.attestation.status = "reviewed";
    auto j = hara::content_json(h);
    REQUIRE_FALSE(j.contains("attestation"));
    REQUIRE(j["hazards"].size() == 1);
}

TEST_CASE("hara: content_json is stable across repeated calls (for hash comparison)",
          "[hara][hara012]") {
    hara::HARA h;
    h.project = "P"; h.standard = "ISO 26262";
    auto j1 = hara::content_json(h);
    auto j2 = hara::content_json(h);
    REQUIRE(j1 == j2);
}
