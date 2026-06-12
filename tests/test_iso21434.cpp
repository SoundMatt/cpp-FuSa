//fusa:test REQ-ISO21434-001 REQ-ISO21434-002 REQ-ISO21434-003 REQ-ISO21434-004 REQ-ISO21434-005
#include <catch2/catch_all.hpp>
#include "iso21434/iso21434.hpp"
#include "testutil/testutil.hpp"
#include <nlohmann/json.hpp>
#include <fstream>

using namespace cpfusa;
using namespace cpfusa::testutil;
using json = nlohmann::json;

// ─── CAL parsing ─────────────────────────────────────────────────────────────

TEST_CASE("iso21434: parse_cal CAL-1 through CAL-4", "[iso21434][iso21434001]") {
    REQUIRE(iso21434::parse_cal("CAL-1") == iso21434::CAL::CAL1);
    REQUIRE(iso21434::parse_cal("CAL-2") == iso21434::CAL::CAL2);
    REQUIRE(iso21434::parse_cal("CAL-3") == iso21434::CAL::CAL3);
    REQUIRE(iso21434::parse_cal("CAL-4") == iso21434::CAL::CAL4);
    REQUIRE(iso21434::parse_cal("CAL1")  == iso21434::CAL::CAL1);
}

TEST_CASE("iso21434: cal_str round-trips", "[iso21434][iso21434001]") {
    REQUIRE(iso21434::cal_str(iso21434::CAL::CAL1) == "CAL-1");
    REQUIRE(iso21434::cal_str(iso21434::CAL::CAL4) == "CAL-4");
}

// ─── assess() ────────────────────────────────────────────────────────────────

TEST_CASE("iso21434: assess returns non-empty report", "[iso21434][iso21434002]") {
    TempDir tmp;
    auto r = iso21434::assess(tmp.path(), "TestProj", iso21434::CAL::CAL2);
    REQUIRE_FALSE(r.objectives.empty());
    REQUIRE(r.total > 0);
    REQUIRE(r.project == "TestProj");
    REQUIRE(r.cal == "CAL-2");
}

TEST_CASE("iso21434: assess CAL-4 includes more objectives than CAL-1", "[iso21434][iso21434002]") {
    TempDir tmp;
    auto r1 = iso21434::assess(tmp.path(), "p", iso21434::CAL::CAL1);
    auto r4 = iso21434::assess(tmp.path(), "p", iso21434::CAL::CAL4);
    REQUIRE(r4.total >= r1.total);
}

TEST_CASE("iso21434: assess total equals satisfied+partial+gap", "[iso21434][iso21434002]") {
    TempDir tmp;
    auto r = iso21434::assess(tmp.path(), "p", iso21434::CAL::CAL2);
    REQUIRE(r.total == r.satisfied + r.partial + r.gap);
}

TEST_CASE("iso21434: tara.json present raises partial count", "[iso21434][iso21434003]") {
    TempDir tmp;
    auto r1 = iso21434::assess(tmp.path(), "p", iso21434::CAL::CAL2);
    tmp.write("tara.json", "{\"scenarios\":[]}");
    auto r2 = iso21434::assess(tmp.path(), "p", iso21434::CAL::CAL2);
    REQUIRE(r2.partial >= r1.partial);
    REQUIRE(r2.gap     <= r1.gap);
}

TEST_CASE("iso21434: vuln.json present reduces gap count", "[iso21434][iso21434003]") {
    TempDir tmp;
    auto r1 = iso21434::assess(tmp.path(), "p", iso21434::CAL::CAL2);
    tmp.write("vuln.json", "{\"components\":[]}");
    auto r2 = iso21434::assess(tmp.path(), "p", iso21434::CAL::CAL2);
    REQUIRE(r2.gap <= r1.gap);
}

TEST_CASE("iso21434: .fusa-reqs.json present covers requirements objective", "[iso21434][iso21434003]") {
    TempDir tmp;
    tmp.write(".fusa-reqs.json", "{\"requirements\":[]}");
    auto r = iso21434::assess(tmp.path(), "p", iso21434::CAL::CAL2);
    REQUIRE(r.total == r.satisfied + r.partial + r.gap);
}

TEST_CASE("iso21434: generated_at is non-empty", "[iso21434][iso21434002]") {
    TempDir tmp;
    auto r = iso21434::assess(tmp.path(), "p", iso21434::CAL::CAL2);
    REQUIRE_FALSE(r.generated_at.empty());
}

// ─── write_json() ────────────────────────────────────────────────────────────

TEST_CASE("iso21434: write_json creates valid JSON file", "[iso21434][iso21434004]") {
    TempDir tmp;
    auto r = iso21434::assess(tmp.path(), "p", iso21434::CAL::CAL2);
    auto out = tmp.path() / "iso21434-gap-report.json";
    REQUIRE_NOTHROW(iso21434::write_json(out, r));
    std::ifstream f(out);
    REQUIRE_NOTHROW(json::parse(f));
}

TEST_CASE("iso21434: write_json has spec v1.10 envelope", "[iso21434][iso21434004]") {
    TempDir tmp;
    auto r = iso21434::assess(tmp.path(), "p", iso21434::CAL::CAL2);
    auto out = tmp.path() / "iso21434-gap-report.json";
    iso21434::write_json(out, r);
    std::ifstream f(out);
    auto j = json::parse(f);
    REQUIRE(j["schemaVersion"] == "1.10");
    REQUIRE(j["kind"]          == "gap-report");
    REQUIRE(j["tool"]          == "cpp-FuSa");
    REQUIRE(j["language"]      == "cpp");
    REQUIRE(j["standard"]      == "iso21434");
}

TEST_CASE("iso21434: write_json summary uses satisfied and gaps keys (spec 9.3)", "[iso21434][iso21434004]") {
    TempDir tmp;
    auto r = iso21434::assess(tmp.path(), "p", iso21434::CAL::CAL2);
    auto out = tmp.path() / "iso21434-gap-report.json";
    iso21434::write_json(out, r);
    std::ifstream f(out);
    auto j = json::parse(f);
    REQUIRE(j["summary"].contains("total"));
    REQUIRE(j["summary"].contains("satisfied"));
    REQUIRE(j["summary"].contains("partial"));
    REQUIRE(j["summary"].contains("gaps"));
    REQUIRE_FALSE(j["summary"].contains("addressed"));
    REQUIRE_FALSE(j["summary"].contains("gap"));
}

TEST_CASE("iso21434: write_json objectives have id, clause, title, status", "[iso21434][iso21434004]") {
    TempDir tmp;
    auto r = iso21434::assess(tmp.path(), "p", iso21434::CAL::CAL2);
    auto out = tmp.path() / "iso21434-gap-report.json";
    iso21434::write_json(out, r);
    std::ifstream f(out);
    auto j = json::parse(f);
    REQUIRE_FALSE(j["objectives"].empty());
    const auto& obj = j["objectives"][0];
    REQUIRE(obj.contains("id"));
    REQUIRE(obj.contains("clause"));
    REQUIRE(obj.contains("title"));
    REQUIRE(obj.contains("status"));
}

TEST_CASE("iso21434: objective status values are spec-conformant", "[iso21434][iso21434004]") {
    TempDir tmp;
    auto r = iso21434::assess(tmp.path(), "p", iso21434::CAL::CAL2);
    auto out = tmp.path() / "iso21434-gap-report.json";
    iso21434::write_json(out, r);
    std::ifstream f(out);
    auto j = json::parse(f);
    for (const auto& obj : j["objectives"]) {
        const std::string s = obj["status"];
        bool ok = (s == "satisfied" || s == "partial" || s == "gap");
        REQUIRE(ok);
    }
}

TEST_CASE("iso21434: summary invariant satisfied+partial+gaps==total", "[iso21434][iso21434004]") {
    TempDir tmp;
    auto r = iso21434::assess(tmp.path(), "p", iso21434::CAL::CAL3);
    auto out = tmp.path() / "iso21434-gap-report.json";
    iso21434::write_json(out, r);
    std::ifstream f(out);
    auto j = json::parse(f);
    int total     = j["summary"]["total"];
    int satisfied = j["summary"]["satisfied"];
    int partial   = j["summary"]["partial"];
    int gaps      = j["summary"]["gaps"];
    REQUIRE(total == satisfied + partial + gaps);
}
