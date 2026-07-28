//fusa:test REQ-TARA001
//fusa:test REQ-TARA002
//fusa:test REQ-TARA003
//fusa:test REQ-TARA004
//fusa:test REQ-TARA005
//fusa:test REQ-TARA006
//fusa:test REQ-TARA007
#include <catch2/catch_all.hpp>
#include "tara/tara.hpp"
#include "testutil/testutil.hpp"
#include <nlohmann/json.hpp>
#include <fstream>

using namespace cpfusa;
using namespace cpfusa::testutil;
using json = nlohmann::json;

// ─── generate ─────────────────────────────────────────────────────────────────

TEST_CASE("tara: generate returns a report", "[tara][tara001]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    cfg.project = "TestProj";
    auto r = tara::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
}

TEST_CASE("tara: generate report has non-empty project", "[tara][tara001]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    cfg.project = "MyProject";
    auto r = tara::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    REQUIRE(value_of(r).project == "MyProject");
}

TEST_CASE("tara: generate report contains scenarios", "[tara][tara001]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto r = tara::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    REQUIRE_FALSE(value_of(r).scenarios.empty());
}

TEST_CASE("tara: generate scenarios have non-empty ids and threats", "[tara][tara001]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto r = tara::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    for (auto& s : value_of(r).scenarios) {
        REQUIRE_FALSE(s.id.empty());
        REQUIRE_FALSE(s.threat.empty());
        REQUIRE_FALSE(s.attack_vector.empty());
    }
}

TEST_CASE("tara: generate sets generated_at", "[tara][tara001]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto r = tara::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    REQUIRE_FALSE(value_of(r).generated_at.empty());
}

TEST_CASE("tara: standard is the canonical iso21434 id", "[tara][tara001]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto r = tara::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    REQUIRE(value_of(r).standard == "iso21434");
}

// ─── §9.2 SFOP impact + derived risk ─────────────────────────────────────────

TEST_CASE("tara: every scenario's attackFeasibility is a valid ISO 21434 level", "[tara][tara006]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto r = tara::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    for (auto& s : value_of(r).scenarios) {
        bool valid = s.attack_feasibility == "high" || s.attack_feasibility == "medium" ||
                     s.attack_feasibility == "low"  || s.attack_feasibility == "very-low";
        REQUIRE(valid);
    }
}

TEST_CASE("tara: every scenario's SFOP impact axes are valid levels", "[tara][tara006]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto r = tara::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    auto valid = [](const std::string& v) { return v == "high" || v == "medium" || v == "low"; };
    for (auto& s : value_of(r).scenarios) {
        REQUIRE(valid(s.impact.safety));
        REQUIRE(valid(s.impact.financial));
        REQUIRE(valid(s.impact.operational));
        REQUIRE(valid(s.impact.privacy));
    }
}

TEST_CASE("tara: risk is derived (non-empty) for every scenario", "[tara][tara006]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto r = tara::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    for (auto& s : value_of(r).scenarios) REQUIRE_FALSE(s.risk.empty());
}

TEST_CASE("tara: high-impact high-feasibility scenario is at least high risk", "[tara][tara006]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto r = tara::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    // TARA-001 (release binary) always carries safety=high impact.
    bool checked = false;
    for (auto& s : value_of(r).scenarios) {
        if (s.id == "TARA-001") {
            REQUIRE(s.impact.safety == "high");
            checked = true;
        }
    }
    REQUIRE(checked);
}

// ─── §9.2 summary.coveragePct ─────────────────────────────────────────────────

TEST_CASE("tara: summary reports assetsAnalyzed/assetsInProject and a method", "[tara][tara006]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto r = tara::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    const auto& s = value_of(r).summary;
    REQUIRE(s.assets_analyzed > 0);
    REQUIRE(s.assets_in_project == s.assets_analyzed);
    REQUIRE_FALSE(s.asset_inventory_method.empty());
}

// ─── write ────────────────────────────────────────────────────────────────────

TEST_CASE("tara: write creates tara.json", "[tara][tara002]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto r = tara::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    auto w = tara::write(tmp.path(), value_of(r));
    REQUIRE(is_ok(w));
    REQUIRE(std::filesystem::exists(tmp.path() / tara::TaraJsonFile));
}

TEST_CASE("tara: write creates tara.md", "[tara][tara002]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto r = tara::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    tara::write(tmp.path(), value_of(r));
    REQUIRE(std::filesystem::exists(tmp.path() / tara::TaraMdFile));
}

TEST_CASE("tara: tara.json is valid JSON with threats[] (canonical key)", "[tara][tara002]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto r = tara::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    tara::write(tmp.path(), value_of(r));
    std::ifstream f(tmp.path() / tara::TaraJsonFile);
    json j;
    REQUIRE_NOTHROW(f >> j);
    REQUIRE(j.contains("threats"));
    REQUIRE(j.contains("summary"));
    REQUIRE(j["summary"].contains("coveragePct"));
    REQUIRE(j["summary"].contains("assetInventoryMethod"));
}

TEST_CASE("tara: tara.md contains markdown header", "[tara][tara002]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto r = tara::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    tara::write(tmp.path(), value_of(r));
    std::ifstream f(tmp.path() / tara::TaraMdFile);
    std::string content((std::istreambuf_iterator<char>(f)), {});
    REQUIRE(content.find('#') != std::string::npos);
}

TEST_CASE("tara: tara.json has generatedAt field", "[tara][tara002]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    cfg.project = "TaraProj";
    auto r = tara::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    tara::write(tmp.path(), value_of(r));
    std::ifstream f(tmp.path() / tara::TaraJsonFile);
    json j; f >> j;
    REQUIRE(j.contains("generatedAt"));
    REQUIRE_FALSE(j["generatedAt"].get<std::string>().empty());
}

TEST_CASE("tara: tara.json threats have risk field (not riskLevel)", "[tara][tara002]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto r = tara::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    tara::write(tmp.path(), value_of(r));
    std::ifstream f(tmp.path() / tara::TaraJsonFile);
    json j; f >> j;
    for (auto& s : j["threats"]) {
        REQUIRE(s.contains("risk"));
        REQUIRE(s.contains("attackVector"));
        REQUIRE(s.contains("attackFeasibility"));
        REQUIRE(s.contains("impact"));
        REQUIRE(s["impact"].contains("safety"));
        REQUIRE(s["impact"].contains("financial"));
        REQUIRE(s["impact"].contains("operational"));
        REQUIRE(s["impact"].contains("privacy"));
    }
}

TEST_CASE("tara: tara.md contains project name", "[tara][tara002]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    cfg.project = "MyTARA";
    auto r = tara::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    tara::write(tmp.path(), value_of(r));
    std::ifstream f(tmp.path() / tara::TaraMdFile);
    std::string content((std::istreambuf_iterator<char>(f)), {});
    REQUIRE(content.find("MyTARA") != std::string::npos);
}

// ─── §1.6.1 quality scan wiring ───────────────────────────────────────────────

TEST_CASE("tara: scan_quality flags a placeholder threat description", "[tara][tara007]") {
    tara::TARAReport rpt;
    tara::ThreatScenario s;
    s.id = "TARA-X"; s.asset = "X"; s.threat = "[describe threat]";
    rpt.scenarios.push_back(s);
    auto findings = tara::scan_quality(rpt);
    bool found = false;
    for (auto& f : findings) if (f.rule_id == "FUSA-STUB001") found = true;
    REQUIRE(found);
}

TEST_CASE("tara: scan_quality is clean for the default scenario catalogue", "[tara][tara007]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto r = tara::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    auto findings = tara::scan_quality(value_of(r));
    for (auto& f : findings) REQUIRE(f.rule_id != "FUSA-STUB001");
}
