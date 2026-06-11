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

TEST_CASE("fmea: JSON entries have component field", "[fmea][fmea002]") {
    TempDir tmp;
    tmp.write("src/x.cpp", "class Actuator { public:\n  void move();\n};\n");
    config::ProjectConfig cfg;
    auto r = fmea::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    fmea::write(tmp.path(), value_of(r));
    std::ifstream f(tmp.path() / fmea::FmeaJsonFile);
    json j; f >> j;
    for (auto& e : j["entries"])
        REQUIRE(e.contains("component"));
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
