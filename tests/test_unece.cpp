//fusa:test REQ-UNECE-001 REQ-UNECE-002 REQ-UNECE-003 REQ-UNECE-004 REQ-UNECE-005
#include <catch2/catch_all.hpp>
#include "unece/unece.hpp"
#include "testutil/testutil.hpp"
#include <nlohmann/json.hpp>
#include <fstream>

using namespace cpfusa;
using namespace cpfusa::testutil;
using json = nlohmann::json;

// ─── assess_r155() ───────────────────────────────────────────────────────────

TEST_CASE("unece: assess_r155 returns non-empty report", "[unece][unece001]") {
    TempDir tmp;
    auto r = unece::assess_r155(tmp.path(), "TestProj");
    REQUIRE_FALSE(r.threats.empty());
    REQUIRE(r.total > 0);
    REQUIRE(r.project == "TestProj");
    REQUIRE(r.regulation == "UNECE-R155");
}

TEST_CASE("unece: assess_r155 total equals satisfied+partial+gap", "[unece][unece001]") {
    TempDir tmp;
    auto r = unece::assess_r155(tmp.path(), "p");
    REQUIRE(r.total == r.satisfied + r.partial + r.gap);
}

TEST_CASE("unece: assess_r155 tara.json improves threat coverage", "[unece][unece002]") {
    TempDir tmp;
    auto r1 = unece::assess_r155(tmp.path(), "p");
    tmp.write("tara.json", "{\"scenarios\":[]}");
    auto r2 = unece::assess_r155(tmp.path(), "p");
    REQUIRE(r2.partial >= r1.partial);
}

TEST_CASE("unece: assess_r155 sbom.json covers supply chain threat", "[unece][unece002]") {
    TempDir tmp;
    auto r1 = unece::assess_r155(tmp.path(), "p");
    tmp.write("sbom.json", "{\"components\":[]}");
    auto r2 = unece::assess_r155(tmp.path(), "p");
    REQUIRE(r2.gap <= r1.gap);
}

TEST_CASE("unece: assess_r155 generated_at is non-empty", "[unece][unece001]") {
    TempDir tmp;
    auto r = unece::assess_r155(tmp.path(), "p");
    REQUIRE_FALSE(r.generated_at.empty());
}

// ─── assess_r156() ───────────────────────────────────────────────────────────

TEST_CASE("unece: assess_r156 returns non-empty report", "[unece][unece003]") {
    TempDir tmp;
    auto r = unece::assess_r156(tmp.path(), "TestProj");
    REQUIRE_FALSE(r.threats.empty());
    REQUIRE(r.total > 0);
    REQUIRE(r.regulation == "UNECE-R156");
}

TEST_CASE("unece: assess_r156 total equals satisfied+partial+gap", "[unece][unece003]") {
    TempDir tmp;
    auto r = unece::assess_r156(tmp.path(), "p");
    REQUIRE(r.total == r.satisfied + r.partial + r.gap);
}

TEST_CASE("unece: assess_r156 provenance.json covers update authorization", "[unece][unece003]") {
    TempDir tmp;
    auto r1 = unece::assess_r156(tmp.path(), "p");
    tmp.write("provenance.json", "{\"builder\":\"ci\"}");
    auto r2 = unece::assess_r156(tmp.path(), "p");
    REQUIRE(r2.gap <= r1.gap);
}

// ─── write_json() ────────────────────────────────────────────────────────────

TEST_CASE("unece: write_json R155 creates valid JSON", "[unece][unece004]") {
    TempDir tmp;
    auto r = unece::assess_r155(tmp.path(), "p");
    auto out = tmp.path() / "unece-r155-gap-report.json";
    REQUIRE_NOTHROW(unece::write_json(out, r));
    std::ifstream f(out);
    REQUIRE_NOTHROW(json::parse(f));
}

TEST_CASE("unece: write_json R155 has spec v1.10 envelope", "[unece][unece004]") {
    TempDir tmp;
    auto r = unece::assess_r155(tmp.path(), "p");
    auto out = tmp.path() / "unece-r155-gap-report.json";
    unece::write_json(out, r);
    std::ifstream f(out);
    auto j = json::parse(f);
    REQUIRE(j["schemaVersion"] == "1.10");
    REQUIRE(j["kind"]          == "gap-report");
    REQUIRE(j["tool"]          == "cpp-FuSa");
    REQUIRE(j["standard"]      == "unece-r155");
}

TEST_CASE("unece: write_json R156 standard field is unece-r156", "[unece][unece004]") {
    TempDir tmp;
    auto r = unece::assess_r156(tmp.path(), "p");
    auto out = tmp.path() / "unece-r156-gap-report.json";
    unece::write_json(out, r);
    std::ifstream f(out);
    auto j = json::parse(f);
    REQUIRE(j["standard"] == "unece-r156");
}

TEST_CASE("unece: write_json summary uses satisfied and gaps keys (spec 9.3)", "[unece][unece004]") {
    TempDir tmp;
    auto r = unece::assess_r155(tmp.path(), "p");
    auto out = tmp.path() / "unece-r155-gap-report.json";
    unece::write_json(out, r);
    std::ifstream f(out);
    auto j = json::parse(f);
    REQUIRE(j["summary"].contains("total"));
    REQUIRE(j["summary"].contains("satisfied"));
    REQUIRE(j["summary"].contains("partial"));
    REQUIRE(j["summary"].contains("gaps"));
    REQUIRE_FALSE(j["summary"].contains("addressed"));
}

TEST_CASE("unece: write_json objectives have id, clause, title, status", "[unece][unece004]") {
    TempDir tmp;
    auto r = unece::assess_r155(tmp.path(), "p");
    auto out = tmp.path() / "unece-r155-gap-report.json";
    unece::write_json(out, r);
    std::ifstream f(out);
    auto j = json::parse(f);
    REQUIRE_FALSE(j["objectives"].empty());
    const auto& obj = j["objectives"][0];
    REQUIRE(obj.contains("id"));
    REQUIRE(obj.contains("clause"));
    REQUIRE(obj.contains("title"));
    REQUIRE(obj.contains("status"));
}

TEST_CASE("unece: objective status values are spec-conformant", "[unece][unece004]") {
    TempDir tmp;
    auto r = unece::assess_r155(tmp.path(), "p");
    auto out = tmp.path() / "unece-r155-gap-report.json";
    unece::write_json(out, r);
    std::ifstream f(out);
    auto j = json::parse(f);
    for (const auto& obj : j["objectives"]) {
        const std::string s = obj["status"];
        bool ok = (s == "satisfied" || s == "partial" || s == "gap");
        REQUIRE(ok);
    }
}

TEST_CASE("unece: R155 summary invariant satisfied+partial+gaps==total", "[unece][unece004]") {
    TempDir tmp;
    auto r = unece::assess_r155(tmp.path(), "p");
    auto out = tmp.path() / "out.json";
    unece::write_json(out, r);
    std::ifstream f(out);
    auto j = json::parse(f);
    int total     = j["summary"]["total"];
    int satisfied = j["summary"]["satisfied"];
    int partial   = j["summary"]["partial"];
    int gaps      = j["summary"]["gaps"];
    REQUIRE(total == satisfied + partial + gaps);
}
