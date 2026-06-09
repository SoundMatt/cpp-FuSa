#include <catch2/catch_all.hpp>
#include "engine/engine.hpp"
#include "engine/rules.hpp"
#include "testutil/testutil.hpp"
#include <fstream>

using namespace cpfusa;
using namespace cpfusa::testutil;

TEST_CASE("engine: FUSA001 fires when .fusa.json is absent", "[engine][fusa001]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto rule = engine::make_fusa001();
    auto findings = rule.check(tmp.path(), cfg);
    REQUIRE(has_finding(findings, "FUSA001"));
}

TEST_CASE("engine: FUSA001 passes when .fusa.json exists", "[engine][fusa001]") {
    TempDir tmp;
    tmp.write(".fusa.json", R"({"project":"test","version":"1.0.0"})");
    config::ProjectConfig cfg;
    auto rule = engine::make_fusa001();
    auto findings = rule.check(tmp.path(), cfg);
    REQUIRE(findings.empty());
}

TEST_CASE("engine: FUSA002 fires when no annotations in source", "[engine][fusa002]") {
    TempDir tmp;
    tmp.write("src/main.cpp", "int main() { return 0; }\n");
    config::ProjectConfig cfg;
    auto rule = engine::make_fusa002();
    auto findings = rule.check(tmp.path(), cfg);
    REQUIRE(has_finding(findings, "FUSA002"));
}

TEST_CASE("engine: FUSA002 passes when fusa:req annotation present", "[engine][fusa002]") {
    TempDir tmp;
    tmp.write("src/main.cpp", "// fusa:req REQ-001\nint main() { return 0; }\n");
    config::ProjectConfig cfg;
    auto rule = engine::make_fusa002();
    auto findings = rule.check(tmp.path(), cfg);
    REQUIRE(findings.empty());
}

TEST_CASE("engine: FUSA003 fires when version is empty", "[engine][fusa003]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    cfg.version = "";
    auto rule = engine::make_fusa003();
    auto findings = rule.check(tmp.path(), cfg);
    REQUIRE(has_finding(findings, "FUSA003"));
}

TEST_CASE("engine: FUSA004 fires when evidence file absent", "[engine][fusa004]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto rule = engine::make_fusa004();
    auto findings = rule.check(tmp.path(), cfg);
    REQUIRE(has_finding(findings, "FUSA004"));
}

TEST_CASE("engine: default engine runs all five built-in rules", "[engine]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    cfg.version = "1.0.0";
    auto eng = engine::make_default_engine();
    REQUIRE(eng.rules().size() == 5);
    auto findings = eng.run(tmp.path(), cfg);
    // At minimum FUSA001 and FUSA004 should fire on an empty temp dir.
    REQUIRE(has_finding(findings, "FUSA001"));
    REQUIRE(has_finding(findings, "FUSA004"));
}
