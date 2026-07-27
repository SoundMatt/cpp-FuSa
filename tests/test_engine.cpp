//fusa:test REQ-FUSA001
//fusa:test REQ-FUSA002
//fusa:test REQ-FUSA003
//fusa:test REQ-FUSA004
//fusa:test REQ-FUSA005
//fusa:test REQ-ENG001
//fusa:test REQ-ENG002
//fusa:test REQ-ENG003
//fusa:test REQ-ENG004
//fusa:test REQ-COUP003
//fusa:test REQ-HARA005
//fusa:test REQ-ISO26262002
//fusa:test REQ-ISO26262003
//fusa:test REQ-HARA002
//fusa:test REQ-HARA003
//fusa:test REQ-HARA004
//fusa:test REQ-VERIFY006
#include <catch2/catch_all.hpp>
#include "engine/engine.hpp"
#include "engine/rules.hpp"
#include "testutil/testutil.hpp"

using namespace cpfusa;
using namespace cpfusa::testutil;

// ─── FUSA001 — config file presence ───────────────────────────────────────────

TEST_CASE("engine: FUSA001 fires when .fusa.json is absent", "[engine][fusa001]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto rule = engine::make_fusa001();
    REQUIRE(has_finding(rule.check(tmp.path(), cfg), "FUSA001"));
}

TEST_CASE("engine: FUSA001 passes when .fusa.json exists", "[engine][fusa001]") {
    TempDir tmp;
    tmp.write(".fusa.json", R"({"project":"test","version":"1.0.0"})");
    config::ProjectConfig cfg;
    REQUIRE(engine::make_fusa001().check(tmp.path(), cfg).empty());
}

TEST_CASE("engine: FUSA001 finding is project-relative path", "[engine][fusa001]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto findings = engine::make_fusa001().check(tmp.path(), cfg);
    REQUIRE_FALSE(findings.empty());
    // must not be an absolute path
    REQUIRE(findings[0].file.find(':') == std::string::npos);
    REQUIRE(findings[0].file.find("\\\\") == std::string::npos);
}

TEST_CASE("engine: FUSA001 finding has config category", "[engine][fusa001]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto findings = engine::make_fusa001().check(tmp.path(), cfg);
    REQUIRE_FALSE(findings.empty());
    REQUIRE(findings[0].category == "config");
}

// ─── FUSA002 — annotation presence ────────────────────────────────────────────

TEST_CASE("engine: FUSA002 fires when no annotations in source", "[engine][fusa002]") {
    TempDir tmp;
    tmp.write("src/main.cpp", "int main() { return 0; }\n");
    config::ProjectConfig cfg;
    REQUIRE(has_finding(engine::make_fusa002().check(tmp.path(), cfg), "FUSA002"));
}

TEST_CASE("engine: FUSA002 passes when fusa:req annotation present", "[engine][fusa002]") {
    TempDir tmp;
    tmp.write("src/main.cpp", "// fusa:req REQ-001\nint main() { return 0; }\n");
    config::ProjectConfig cfg;
    REQUIRE(engine::make_fusa002().check(tmp.path(), cfg).empty());
}

TEST_CASE("engine: FUSA002 finding has requirement category", "[engine][fusa002]") {
    TempDir tmp;
    tmp.write("src/main.cpp", "int main() { return 0; }\n");
    config::ProjectConfig cfg;
    auto findings = engine::make_fusa002().check(tmp.path(), cfg);
    REQUIRE_FALSE(findings.empty());
    REQUIRE(findings[0].category == "requirement");
}

// ─── FUSA003 — version field ───────────────────────────────────────────────────

TEST_CASE("engine: FUSA003 fires when version is empty", "[engine][fusa003]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    cfg.version = "";
    REQUIRE(has_finding(engine::make_fusa003().check(tmp.path(), cfg), "FUSA003"));
}

TEST_CASE("engine: FUSA003 passes when version is set", "[engine][fusa003]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    cfg.version = "1.0.0";
    REQUIRE(engine::make_fusa003().check(tmp.path(), cfg).empty());
}

// ─── FUSA004 — evidence file ───────────────────────────────────────────────────

TEST_CASE("engine: FUSA004 fires when evidence file absent", "[engine][fusa004]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    REQUIRE(has_finding(engine::make_fusa004().check(tmp.path(), cfg), "FUSA004"));
}

TEST_CASE("engine: FUSA004 passes when .fusa-evidence.json exists", "[engine][fusa004]") {
    TempDir tmp;
    tmp.write(".fusa-evidence.json", R"({"summary":{"total":5,"passed":5}})");
    config::ProjectConfig cfg;
    REQUIRE(engine::make_fusa004().check(tmp.path(), cfg).empty());
}

// ─── FUSA005 — standard field ─────────────────────────────────────────────────

TEST_CASE("engine: FUSA005 fires when CHANGELOG.md is absent", "[engine][fusa005]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    REQUIRE(has_finding(engine::make_fusa005().check(tmp.path(), cfg), "FUSA005"));
}

TEST_CASE("engine: FUSA005 passes when CHANGELOG.md exists with content", "[engine][fusa005]") {
    TempDir tmp;
    tmp.write("CHANGELOG.md", "## [1.0.0] — 2026-01-01\n\n### Added\n- Initial release\n");
    config::ProjectConfig cfg;
    REQUIRE(engine::make_fusa005().check(tmp.path(), cfg).empty());
}

// ─── default engine ────────────────────────────────────────────────────────────

TEST_CASE("engine: default engine has thirteen built-in rules", "[engine]") {
    auto eng = engine::make_default_engine();
    REQUIRE(eng.rules().size() == 13);
}

TEST_CASE("engine: default engine fires FUSA001 and FUSA004 on empty dir", "[engine]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    cfg.version = "1.0.0";
    cfg.standard = "iso26262";
    auto findings = engine::make_default_engine().run(tmp.path(), cfg);
    REQUIRE(has_finding(findings, "FUSA001"));
    REQUIRE(has_finding(findings, "FUSA004"));
}

TEST_CASE("engine: all findings have non-empty ruleId", "[engine]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto findings = engine::make_default_engine().run(tmp.path(), cfg);
    for (const auto& f : findings)
        REQUIRE_FALSE(f.rule_id.empty());
}

TEST_CASE("engine: all findings have a severity set", "[engine]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto findings = engine::make_default_engine().run(tmp.path(), cfg);
    REQUIRE_FALSE(findings.empty());
    for (const auto& f : findings) {
        bool valid = f.severity == Severity::ERROR
                  || f.severity == Severity::WARNING
                  || f.severity == Severity::INFO;
        REQUIRE(valid);
    }
}

TEST_CASE("engine: all findings have non-empty remediation", "[engine]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto findings = engine::make_default_engine().run(tmp.path(), cfg);
    REQUIRE_FALSE(findings.empty());
    for (const auto& f : findings)
        REQUIRE_FALSE(f.remediation.empty());
}

// ─── COUP003 — coupling evidence ──────────────────────────────────────────────

TEST_CASE("engine: COUP003 fires on DO-178C project without coupling-report.json", "[engine][coup003]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    cfg.standard = "DO-178C";
    auto findings = engine::make_coup003().check(tmp.path(), cfg);
    REQUIRE(has_finding(findings, "COUP003"));
}

TEST_CASE("engine: COUP003 passes when coupling-report.json exists", "[engine][coup003]") {
    TempDir tmp;
    tmp.write("coupling-report.json", R"({"kind":"coupling-report"})");
    config::ProjectConfig cfg;
    cfg.standard = "DO-178C";
    REQUIRE(engine::make_coup003().check(tmp.path(), cfg).empty());
}

TEST_CASE("engine: COUP003 does not fire for non-DO178C projects", "[engine][coup003]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    cfg.standard = "ISO26262";
    REQUIRE(engine::make_coup003().check(tmp.path(), cfg).empty());
}

// ─── HARA005 — ASIL mismatch ──────────────────────────────────────────────────

TEST_CASE("engine: HARA005 fires when hara has ASIL-D and project is ASIL-A", "[engine][hara005]") {
    TempDir tmp;
    tmp.write(".fusa-hara.json", R"({
        "hazards": [
            {"id": "H-001", "risk": {"asil": "ASIL-D"}}
        ]
    })");
    config::ProjectConfig cfg;
    cfg.asil = "ASIL-A";
    auto findings = engine::make_hara005().check(tmp.path(), cfg);
    REQUIRE(has_finding(findings, "HARA005"));
}

TEST_CASE("engine: HARA005 passes when hara ASIL matches project ASIL", "[engine][hara005]") {
    TempDir tmp;
    tmp.write(".fusa-hara.json", R"({
        "hazards": [
            {"id": "H-001", "risk": {"asil": "ASIL-B"}}
        ]
    })");
    config::ProjectConfig cfg;
    cfg.asil = "ASIL-D";
    REQUIRE(engine::make_hara005().check(tmp.path(), cfg).empty());
}

TEST_CASE("engine: HARA005 skips when no asil in config", "[engine][hara005]") {
    TempDir tmp;
    tmp.write(".fusa-hara.json", R"({"hazards": []})");
    config::ProjectConfig cfg;
    cfg.asil = "";
    REQUIRE(engine::make_hara005().check(tmp.path(), cfg).empty());
}

// ─── ISO26262002 — ASIL on requirements ───────────────────────────────────────

TEST_CASE("engine: ISO26262002 fires when req has no asil field in ISO26262 project", "[engine][iso26262002]") {
    TempDir tmp;
    tmp.write(".fusa-reqs.json", R"({"requirements":[{"id":"REQ-001","title":"T"}]})");
    config::ProjectConfig cfg;
    cfg.standard = "ISO26262";
    auto findings = engine::make_iso26262002().check(tmp.path(), cfg);
    REQUIRE(has_finding(findings, "ISO26262002"));
}

TEST_CASE("engine: ISO26262002 passes when all reqs have asil field", "[engine][iso26262002]") {
    TempDir tmp;
    tmp.write(".fusa-reqs.json", R"({"requirements":[{"id":"REQ-001","title":"T","asil":"ASIL-B"}]})");
    config::ProjectConfig cfg;
    cfg.standard = "ISO26262";
    REQUIRE(engine::make_iso26262002().check(tmp.path(), cfg).empty());
}

TEST_CASE("engine: ISO26262002 does not fire for non-ISO26262 standard", "[engine][iso26262002]") {
    TempDir tmp;
    tmp.write(".fusa-reqs.json", R"({"requirements":[{"id":"REQ-001","title":"T"}]})");
    config::ProjectConfig cfg;
    cfg.standard = "IEC61508";
    REQUIRE(engine::make_iso26262002().check(tmp.path(), cfg).empty());
}

// ─── ISO26262003 — tool qualification failures ────────────────────────────────

TEST_CASE("engine: ISO26262003 fires when qualify-report has failures", "[engine][iso26262003]") {
    TempDir tmp;
    tmp.write("qualify-report.json", R"({"passed":5,"failed":1,"total":6})");
    config::ProjectConfig cfg;
    auto findings = engine::make_iso26262003().check(tmp.path(), cfg);
    REQUIRE(has_finding(findings, "ISO26262003"));
}

TEST_CASE("engine: ISO26262003 passes when qualify-report has zero failures", "[engine][iso26262003]") {
    TempDir tmp;
    tmp.write("qualify-report.json", R"({"passed":8,"failed":0,"total":8})");
    config::ProjectConfig cfg;
    REQUIRE(engine::make_iso26262003().check(tmp.path(), cfg).empty());
}

TEST_CASE("engine: ISO26262003 does not fire when qualify-report.json absent", "[engine][iso26262003]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    REQUIRE(engine::make_iso26262003().check(tmp.path(), cfg).empty());
}

// ─── HARA002 — hazard missing S/E/C ──────────────────────────────────────────

TEST_CASE("engine: HARA002 fires when hazard has no risk severity", "[engine][hara002]") {
    TempDir tmp;
    tmp.write(".fusa-hara.json",
        R"({"hazards":[{"id":"H-001","risk":{"exposure":"E3","controllability":"C2"}}],"safetyGoals":[]})");
    config::ProjectConfig cfg;
    auto findings = engine::make_hara002().check(tmp.path(), cfg);
    REQUIRE(has_finding(findings, "HARA002"));
}

TEST_CASE("engine: HARA002 passes when hazard has all S/E/C fields", "[engine][hara002]") {
    TempDir tmp;
    tmp.write(".fusa-hara.json",
        R"({"hazards":[{"id":"H-001","risk":{"severity":"S2","exposure":"E3","controllability":"C2","asil":"ASIL-B"}}],"safetyGoals":[]})");
    config::ProjectConfig cfg;
    REQUIRE(engine::make_hara002().check(tmp.path(), cfg).empty());
}

// ─── HARA003 — hazard not linked to a safety goal ────────────────────────────

TEST_CASE("engine: HARA003 fires when hazard has empty safetyGoals", "[engine][hara003]") {
    TempDir tmp;
    tmp.write(".fusa-hara.json",
        R"({"hazards":[{"id":"H-001","safetyGoals":[],"risk":{"severity":"S2","exposure":"E3","controllability":"C2"}}],"safetyGoals":[]})");
    config::ProjectConfig cfg;
    auto findings = engine::make_hara003().check(tmp.path(), cfg);
    REQUIRE(has_finding(findings, "HARA003"));
}

TEST_CASE("engine: HARA003 passes when hazard references a safety goal", "[engine][hara003]") {
    TempDir tmp;
    tmp.write(".fusa-hara.json",
        R"({"hazards":[{"id":"H-001","safetyGoals":["SG-001"],"risk":{"severity":"S2","exposure":"E3","controllability":"C2"}}],"safetyGoals":[{"id":"SG-001","asil":"ASIL-B"}]})");
    config::ProjectConfig cfg;
    REQUIRE(engine::make_hara003().check(tmp.path(), cfg).empty());
}

// ─── HARA004 — safety goal missing ASIL ─────────────────────────────────────

TEST_CASE("engine: HARA004 fires when safety goal has no asil field", "[engine][hara004]") {
    TempDir tmp;
    tmp.write(".fusa-hara.json",
        R"({"hazards":[],"safetyGoals":[{"id":"SG-001","description":"No loss of control"}]})");
    config::ProjectConfig cfg;
    auto findings = engine::make_hara004().check(tmp.path(), cfg);
    REQUIRE(has_finding(findings, "HARA004"));
}

TEST_CASE("engine: HARA004 passes when safety goal has asil assigned", "[engine][hara004]") {
    TempDir tmp;
    tmp.write(".fusa-hara.json",
        R"({"hazards":[],"safetyGoals":[{"id":"SG-001","asil":"ASIL-C","description":"No loss of control"}]})");
    config::ProjectConfig cfg;
    REQUIRE(engine::make_hara004().check(tmp.path(), cfg).empty());
}

// ─── VERIFY002 — test evidence reports failures ───────────────────────────────

TEST_CASE("engine: VERIFY002 fires when evidence has failed tests", "[engine][verify002]") {
    TempDir tmp;
    tmp.write(".fusa-evidence.json",
        R"({"summary":{"total":10,"passed":8,"failed":2},"results":[]})");
    config::ProjectConfig cfg;
    auto findings = engine::make_verify002().check(tmp.path(), cfg);
    REQUIRE(has_finding(findings, "VERIFY002"));
}

TEST_CASE("engine: VERIFY002 passes when all tests passed", "[engine][verify002]") {
    TempDir tmp;
    tmp.write(".fusa-evidence.json",
        R"({"summary":{"total":10,"passed":10,"failed":0},"results":[]})");
    config::ProjectConfig cfg;
    REQUIRE(engine::make_verify002().check(tmp.path(), cfg).empty());
}

// ─── run_ids ──────────────────────────────────────────────────────────────────

TEST_CASE("engine: run_ids runs only rules with matching id", "[engine][eng003]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto eng = engine::make_default_engine();
    // Request only FUSA001 — should fire because .fusa.json is absent.
    auto findings = eng.run_ids(tmp.path(), cfg, {"FUSA001"});
    REQUIRE(has_finding(findings, "FUSA001"));
    // FUSA004 was NOT requested, so it must not appear.
    REQUIRE_FALSE(has_finding(findings, "FUSA004"));
}

TEST_CASE("engine: run_ids with empty id list returns no findings", "[engine][eng003]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto eng = engine::make_default_engine();
    auto findings = eng.run_ids(tmp.path(), cfg, {});
    REQUIRE(findings.empty());
}

TEST_CASE("engine: run_ids with unknown id returns no findings", "[engine][eng003]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto eng = engine::make_default_engine();
    auto findings = eng.run_ids(tmp.path(), cfg, {"NONEXISTENT999"});
    REQUIRE(findings.empty());
}

TEST_CASE("engine: run_ids can run multiple rules by id", "[engine][eng003]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    cfg.version = "1.0.0";
    auto eng = engine::make_default_engine();
    // Request FUSA001 and FUSA004 — both should fire.
    auto findings = eng.run_ids(tmp.path(), cfg, {"FUSA001", "FUSA004"});
    REQUIRE(has_finding(findings, "FUSA001"));
    REQUIRE(has_finding(findings, "FUSA004"));
}

// ─── rules() accessor ────────────────────────────────────────────────────────

TEST_CASE("engine: rules() returns non-empty vector for default engine", "[engine]") {
    auto eng = engine::make_default_engine();
    REQUIRE_FALSE(eng.rules().empty());
}

TEST_CASE("engine: each rule has a non-empty id", "[engine]") {
    auto eng = engine::make_default_engine();
    for (const auto& rule : eng.rules())
        REQUIRE_FALSE(rule.info.id.empty());
}
