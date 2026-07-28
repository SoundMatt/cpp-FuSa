//fusa:test REQ-SAFETYCASE001
//fusa:test REQ-SAFETYCASE002
//fusa:test REQ-SAFETYCASE003
//fusa:test REQ-SAFETYCASE004
//fusa:test REQ-SAFETYCASE005
//fusa:test REQ-SAFETYCASE006
//fusa:test REQ-SAFETYCASE007
//fusa:test REQ-SAFETYCASE008
#include <catch2/catch_all.hpp>
#include "safety_case/safety_case.hpp"
#include "testutil/testutil.hpp"
#include <nlohmann/json.hpp>
#include <fstream>
#include <set>

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

// ─── §9.2 GSN node/edge type conformance ─────────────────────────────────────

TEST_CASE("safety_case: every node type is one of the six lowercase GSN types",
          "[safety_case][safetycase006]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto r = safety_case::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    static const std::set<std::string> valid = {
        "goal", "strategy", "solution", "context", "assumption", "justification"
    };
    for (auto& n : value_of(r).nodes) REQUIRE(valid.count(n.type) == 1);
}

TEST_CASE("safety_case: every edge type is supportedBy or inContextOf",
          "[safety_case][safetycase006]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto r = safety_case::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    for (auto& e : value_of(r).edges)
        REQUIRE((e.type == "supportedBy" || e.type == "inContextOf"));
}

TEST_CASE("safety_case: solution nodes name a real evidence filename",
          "[safety_case][safetycase006]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto r = safety_case::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    for (auto& n : value_of(r).nodes)
        if (n.type == "solution") REQUIRE_FALSE(n.evidence.empty());
}

// ─── completeness ─────────────────────────────────────────────────────────────

TEST_CASE("safety_case: compute_completeness counts goals and undeveloped ones",
          "[safety_case][safetycase007]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto r = safety_case::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    auto c = safety_case::compute_completeness(value_of(r));
    REQUIRE(c.total_goals > 0);
    REQUIRE(c.undeveloped <= c.total_goals);
}

// ─── §1.6.1 quality scan wiring ───────────────────────────────────────────────

TEST_CASE("safety_case: scan_quality flags a placeholder goal", "[safety_case][safetycase008]") {
    safety_case::SafetyCase sc;
    safety_case::GSNNode n;
    n.id = "G1"; n.type = "goal"; n.text = "[describe the top-level safety goal]";
    sc.nodes.push_back(n);
    auto findings = safety_case::scan_quality(sc);
    bool found = false;
    for (auto& f : findings) if (f.rule_id == "FUSA-STUB001") found = true;
    REQUIRE(found);
}

TEST_CASE("safety_case: to_json emits the spec 3.1 header and spec 9.2 shape",
          "[safety_case][safetycase006]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    cfg.project = "P"; cfg.project_root = tmp.path().string();
    auto r = safety_case::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    auto j = safety_case::to_json(value_of(r), cfg);
    REQUIRE(j["kind"] == "safety-case");
    REQUIRE(j.contains("schemaVersion"));
    REQUIRE(j.contains("completeness"));
}
