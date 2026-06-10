//fusa:test REQ-FUSA001 REQ-FUSA002 REQ-FUSA003 REQ-FUSA004 REQ-FUSA005 REQ-ENG001 REQ-ENG002 REQ-ENG003 REQ-ENG004
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

TEST_CASE("engine: default engine has five built-in rules", "[engine]") {
    auto eng = engine::make_default_engine();
    REQUIRE(eng.rules().size() == 5);
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
