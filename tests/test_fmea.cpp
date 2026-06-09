//fusa:test REQ-FMEA001 REQ-FMEA002 REQ-FMEA003 REQ-FMEA004 REQ-FMEA005 REQ-FMEA006
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
