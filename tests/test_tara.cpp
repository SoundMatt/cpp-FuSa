//fusa:test REQ-TARA001 REQ-TARA002 REQ-TARA003 REQ-TARA004 REQ-TARA005
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

TEST_CASE("tara: generate scenarios have non-empty ids", "[tara][tara001]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto r = tara::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    for (auto& s : value_of(r).scenarios) {
        REQUIRE_FALSE(s.id.empty());
        REQUIRE_FALSE(s.threat.empty());
    }
}

TEST_CASE("tara: generate sets generated_at", "[tara][tara001]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto r = tara::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    REQUIRE_FALSE(value_of(r).generated_at.empty());
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

TEST_CASE("tara: tara.json is valid JSON", "[tara][tara002]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto r = tara::generate(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    tara::write(tmp.path(), value_of(r));
    std::ifstream f(tmp.path() / tara::TaraJsonFile);
    json j;
    REQUIRE_NOTHROW(f >> j);
    REQUIRE(j.contains("scenarios"));
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
