//fusa:test REQ-FMEA001
//fusa:test REQ-FMEA002
//fusa:test REQ-FMEA003
//fusa:test REQ-FMEA004
//fusa:test REQ-FMEA005
//fusa:test REQ-FMEA006
//fusa:test REQ-FMEA007
//fusa:test REQ-FMEA008
//fusa:test REQ-FMEA009
#include <catch2/catch_all.hpp>
#include "fmea/fmea.hpp"
#include "testutil/testutil.hpp"
#include <nlohmann/json.hpp>
#include <fstream>

using namespace cpfusa;
using namespace cpfusa::testutil;
using json = nlohmann::json;

// ─── generate ─────────────────────────────────────────────────────────────────

TEST_CASE("fmea: generate returns a report", "[fmea][fmea001]") {
    TempDir tmp;
    tmp.write("src/engine.cpp", "class Engine { public:\n  void start() {}\n  void stop() {}\n};\n");
    config::ProjectConfig cfg;
    auto r = fmea::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
}

TEST_CASE("fmea: generate report has non-empty project", "[fmea][fmea001]") {
    TempDir tmp;
    tmp.write("src/x.cpp", "class Foo {};\n");
    config::ProjectConfig cfg;
    cfg.project = "MyFMEA";
    auto r = fmea::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    REQUIRE(value_of(r).project == "MyFMEA");
}

TEST_CASE("fmea: generate finds class declarations in source", "[fmea][fmea001]") {
    TempDir tmp;
    tmp.write("src/safety.cpp",
        "class SafetyMonitor {\npublic:\n  void check();\n  void reset();\n};\n");
    config::ProjectConfig cfg;
    auto r = fmea::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    bool found = false;
    for (auto& e : value_of(r).entries)
        if (e.component.find("SafetyMonitor") != std::string::npos) found = true;
    REQUIRE(found);
}

TEST_CASE("fmea: generate sets generated_at", "[fmea][fmea001]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto r = fmea::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    REQUIRE_FALSE(value_of(r).generated_at.empty());
}

TEST_CASE("fmea: every entry has non-zero rpn", "[fmea][fmea001]") {
    TempDir tmp;
    tmp.write("src/x.cpp", "class Widget { public:\n  void draw();\n};\n");
    config::ProjectConfig cfg;
    auto r = fmea::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    for (auto& e : value_of(r).entries)
        REQUIRE(e.rpn > 0);
}

TEST_CASE("fmea: generate empty dir produces empty entries", "[fmea][fmea001]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto r = fmea::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    REQUIRE(value_of(r).entries.empty());
}

TEST_CASE("fmea: multiple classes in source all generate entries", "[fmea][fmea001]") {
    TempDir tmp;
    tmp.write("src/multi.cpp",
        "class Alpha { public:\n  void run();\n};\n"
        "class Beta  { public:\n  void run();\n};\n");
    config::ProjectConfig cfg;
    auto r = fmea::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    int alpha = 0, beta = 0;
    for (auto& e : value_of(r).entries) {
        if (e.component.find("Alpha") != std::string::npos) ++alpha;
        if (e.component.find("Beta")  != std::string::npos) ++beta;
    }
    REQUIRE(alpha > 0);
    REQUIRE(beta  > 0);
}

// ─── §1.6.1 rule B: qualitative fields must vary with item identity ──────────

TEST_CASE("fmea: failureMode embeds the real component name (not one fixed string)", "[fmea][fmea009]") {
    TempDir tmp;
    tmp.write("src/multi.cpp",
        "class Alpha { public:\n  void run();\n};\n"
        "class Beta  { public:\n  void run();\n};\n");
    config::ProjectConfig cfg;
    auto r = fmea::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    bool alpha_named = false, beta_named = false;
    for (auto& e : value_of(r).entries) {
        if (e.failure_mode.find("Alpha") != std::string::npos) alpha_named = true;
        if (e.failure_mode.find("Beta")  != std::string::npos) beta_named  = true;
    }
    REQUIRE(alpha_named);
    REQUIRE(beta_named);
}

// ─── §9.2 summary.coveragePct ─────────────────────────────────────────────────

TEST_CASE("fmea: summary.coveragePct is 100 when every detected declaration got an entry",
          "[fmea][fmea009]") {
    TempDir tmp;
    tmp.write("src/x.cpp", "class Widget { public:\n  void draw();\n};\n");
    config::ProjectConfig cfg;
    auto r = fmea::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    REQUIRE(value_of(r).summary.coverage_pct == Catch::Approx(100.0));
    REQUIRE_FALSE(value_of(r).summary.component_inventory_method.empty());
}

TEST_CASE("fmea: summary counts componentsAnalyzed and componentsInProject consistently",
          "[fmea][fmea009]") {
    TempDir tmp;
    tmp.write("src/x.cpp", "class Widget { public:\n  void draw();\n};\n");
    config::ProjectConfig cfg;
    auto r = fmea::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    const auto& s = value_of(r).summary;
    REQUIRE(s.components_analyzed <= s.components_in_project);
    REQUIRE(s.components_analyzed > 0);
}

// ─── write ────────────────────────────────────────────────────────────────────

TEST_CASE("fmea: write creates fmea.json", "[fmea][fmea002]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto r = fmea::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    auto w = fmea::write(tmp.path(), value_of(r));
    REQUIRE(is_ok(w));
    REQUIRE(std::filesystem::exists(tmp.path() / fmea::FmeaJsonFile));
}

TEST_CASE("fmea: write creates fmea.csv", "[fmea][fmea002]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto r = fmea::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    fmea::write(tmp.path(), value_of(r));
    REQUIRE(std::filesystem::exists(tmp.path() / fmea::FmeaCsvFile));
}

TEST_CASE("fmea: fmea.json is valid JSON with entries key", "[fmea][fmea002]") {
    TempDir tmp;
    tmp.write("src/x.cpp", "class Foo {};\n");
    config::ProjectConfig cfg;
    auto r = fmea::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    fmea::write(tmp.path(), value_of(r));
    std::ifstream f(tmp.path() / fmea::FmeaJsonFile);
    json j;
    REQUIRE_NOTHROW(f >> j);
    REQUIRE(j.contains("entries"));
    REQUIRE(j.contains("ratingScale"));
    REQUIRE(j.contains("summary"));
    REQUIRE(j["summary"].contains("coveragePct"));
    REQUIRE(j["summary"].contains("componentsInProject"));
    REQUIRE(j["summary"].contains("componentInventoryMethod"));
}

TEST_CASE("fmea: fmea.csv has header row", "[fmea][fmea002]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto r = fmea::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    fmea::write(tmp.path(), value_of(r));
    std::ifstream f(tmp.path() / fmea::FmeaCsvFile);
    std::string header;
    std::getline(f, header);
    REQUIRE_FALSE(header.empty());
    REQUIRE(header.find(',') != std::string::npos);
}

TEST_CASE("fmea: JSON entries have item field (spec 9.2 identity)", "[fmea][fmea002]") {
    TempDir tmp;
    tmp.write("src/x.cpp", "class Actuator { public:\n  void move();\n};\n");
    config::ProjectConfig cfg;
    auto r = fmea::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    fmea::write(tmp.path(), value_of(r));
    std::ifstream f(tmp.path() / fmea::FmeaJsonFile);
    json j; f >> j;
    for (auto& e : j["entries"]) {
        REQUIRE(e.contains("item"));
        REQUIRE(e.contains("file"));
        REQUIRE(e.contains("failureMode"));
        REQUIRE(e.contains("effect"));
        REQUIRE(e.contains("detection"));
    }
}

TEST_CASE("fmea: JSON entries have rpn field", "[fmea][fmea002]") {
    TempDir tmp;
    tmp.write("src/x.cpp", "class Sensor { public:\n  int read();\n};\n");
    config::ProjectConfig cfg;
    auto r = fmea::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    fmea::write(tmp.path(), value_of(r));
    std::ifstream f(tmp.path() / fmea::FmeaJsonFile);
    json j; f >> j;
    for (auto& e : j["entries"])
        REQUIRE(e.contains("rpn"));
}

// ─── fmea --cyber enrichment ─────────────────────────────────────────────────

TEST_CASE("fmea: cyber enrichment appends CYBER rule IDs to matching entries' mitigations",
          "[fmea][fmea007]") {
    TempDir tmp;
    tmp.write("src/widget.cpp", "class Widget { public:\n  void draw();\n};\n");
    tmp.write("cyber-report.json",
        R"({"findings":[{"ruleId":"CYBER001","file":"src/widget.cpp","message":"test"}],"totalFindings":1})");
    config::ProjectConfig cfg;
    auto r = fmea::generate(tmp.path(), cfg, true);
    REQUIRE(is_ok(r));
    bool enriched = false;
    for (const auto& e : value_of(r).entries)
        for (const auto& m : e.mitigations)
            if (m.find("CYBER001") != std::string::npos) enriched = true;
    REQUIRE(enriched);
}

TEST_CASE("fmea: cyber enrichment is a no-op when cyber-report.json absent", "[fmea][fmea007]") {
    TempDir tmp;
    tmp.write("src/widget.cpp", "class Widget { public:\n  void draw();\n};\n");
    config::ProjectConfig cfg;
    auto r = fmea::generate(tmp.path(), cfg, true);
    REQUIRE(is_ok(r));
    for (const auto& e : value_of(r).entries)
        for (const auto& m : e.mitigations)
            REQUIRE(m.find("CYBER") == std::string::npos);
}

// ─── §1.6.1 quality scan wiring ───────────────────────────────────────────────

TEST_CASE("fmea: scan_quality flags a placeholder failureMode", "[fmea][fmea009]") {
    fmea::FMEAReport rpt;
    fmea::FmeaEntry e;
    e.id = "FMEA-1"; e.item = "Foo"; e.file = "src/foo.cpp";
    e.failure_mode = "[describe failure mode]";
    e.effect = "Some real effect derived from Foo's signature";
    rpt.entries.push_back(e);
    auto findings = fmea::scan_quality(rpt);
    bool found = false;
    for (auto& f : findings) if (f.rule_id == "FUSA-STUB001") found = true;
    REQUIRE(found);
}

TEST_CASE("fmea: scan_quality is clean for genuinely varied content", "[fmea][fmea009]") {
    TempDir tmp;
    tmp.write("src/x.cpp", "class Widget { public:\n  void draw();\n};\n");
    config::ProjectConfig cfg;
    auto r = fmea::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    auto findings = fmea::scan_quality(value_of(r));
    for (auto& f : findings) REQUIRE(f.rule_id != "FUSA-STUB001");
}
