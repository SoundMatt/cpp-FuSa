//fusa:test REQ-SAFETYCASE001
//fusa:test REQ-SAFETYCASE002
//fusa:test REQ-SAFETYCASE003
//fusa:test REQ-SAFETYCASE004
//fusa:test REQ-SAFETYCASE005
#include <catch2/catch_all.hpp>
#include "safety_case/safety_case.hpp"
#include "testutil/testutil.hpp"
#include <nlohmann/json.hpp>
#include <fstream>

using namespace cpfusa;
using namespace cpfusa::testutil;
using json = nlohmann::json;

// ─── generate ─────────────────────────────────────────────────────────────────

TEST_CASE("safety_case: generate returns a SafetyCase", "[safety_case][safetycase001]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    cfg.project = "TestProject";
    auto r = safety_case::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
}

TEST_CASE("safety_case: generate SafetyCase has GSN nodes", "[safety_case][safetycase001]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto r = safety_case::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    REQUIRE_FALSE(value_of(r).nodes.empty());
}

TEST_CASE("safety_case: generate SafetyCase has edges", "[safety_case][safetycase001]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto r = safety_case::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    REQUIRE_FALSE(value_of(r).edges.empty());
}

TEST_CASE("safety_case: generate sets project", "[safety_case][safetycase001]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    cfg.project = "MyProject";
    auto r = safety_case::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    REQUIRE(value_of(r).project == "MyProject");
}

TEST_CASE("safety_case: generate sets generated_at", "[safety_case][safetycase001]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto r = safety_case::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    REQUIRE_FALSE(value_of(r).generated_at.empty());
}

TEST_CASE("safety_case: generate every node has a non-empty id", "[safety_case][safetycase001]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto r = safety_case::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    for (auto& n : value_of(r).nodes) {
        REQUIRE_FALSE(n.id.empty());
        REQUIRE_FALSE(n.type.empty());
    }
}

TEST_CASE("safety_case: generate with evidence artifacts lists them", "[safety_case][safetycase001]") {
    TempDir tmp;
    // Write a known evidence file
    std::ofstream(tmp.path() / "qualify-report.json") << R"({"passed":8,"total":8})";
    config::ProjectConfig cfg;
    auto r = safety_case::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    bool found = false;
    for (auto& ev : value_of(r).evidence)
        if (ev.find("qualify-report") != std::string::npos) found = true;
    REQUIRE(found);
}

// ─── write ────────────────────────────────────────────────────────────────────

TEST_CASE("safety_case: write creates safety-case.json", "[safety_case][safetycase002]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto r = safety_case::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    auto w = safety_case::write(tmp.path(), value_of(r));
    REQUIRE(is_ok(w));
    REQUIRE(std::filesystem::exists(tmp.path() / safety_case::SafetyCaseJson));
}

TEST_CASE("safety_case: write creates safety-case.mermaid", "[safety_case][safetycase002]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto r = safety_case::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    safety_case::write(tmp.path(), value_of(r));
    REQUIRE(std::filesystem::exists(tmp.path() / safety_case::SafetyCaseMermaid));
}

TEST_CASE("safety_case: write creates safety-case.md", "[safety_case][safetycase002]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto r = safety_case::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    safety_case::write(tmp.path(), value_of(r));
    REQUIRE(std::filesystem::exists(tmp.path() / safety_case::SafetyCaseMd));
}

TEST_CASE("safety_case: safety-case.json is valid JSON with nodes", "[safety_case][safetycase002]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto r = safety_case::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    safety_case::write(tmp.path(), value_of(r));
    std::ifstream f(tmp.path() / safety_case::SafetyCaseJson);
    json j;
    REQUIRE_NOTHROW(f >> j);
    REQUIRE(j.contains("nodes"));
}

TEST_CASE("safety_case: safety-case.mermaid contains graph directive", "[safety_case][safetycase002]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto r = safety_case::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    safety_case::write(tmp.path(), value_of(r));
    std::ifstream f(tmp.path() / safety_case::SafetyCaseMermaid);
    std::string content((std::istreambuf_iterator<char>(f)), {});
    REQUIRE(content.find("graph") != std::string::npos);
}
