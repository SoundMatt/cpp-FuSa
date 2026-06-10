//fusa:test REQ-ISO26262-001 REQ-ISO26262-002 REQ-ISO26262-003
#include <catch2/catch_all.hpp>
#include "iso26262/iso26262.hpp"
#include "testutil/testutil.hpp"
#include <nlohmann/json.hpp>
#include <fstream>

using namespace cpfusa;
using namespace cpfusa::testutil;
using json = nlohmann::json;

// ─── parse_asil / asil_str ───────────────────────────────────────────────────

TEST_CASE("iso26262: parse_asil A", "[iso26262][iso26262001]") {
    REQUIRE(iso26262::parse_asil("A") == iso26262::ASIL::A);
    REQUIRE(iso26262::parse_asil("ASIL-A") == iso26262::ASIL::A);
}

TEST_CASE("iso26262: asil_str roundtrip", "[iso26262][iso26262001]") {
    REQUIRE(iso26262::asil_str(iso26262::parse_asil("B")) == "ASIL-B");
    REQUIRE(iso26262::asil_str(iso26262::parse_asil("D")) == "ASIL-D");
}

// ─── assess ───────────────────────────────────────────────────────────────────

TEST_CASE("iso26262: assess returns non-empty report", "[iso26262][iso26262002]") {
    TempDir tmp;
    auto r = iso26262::assess(tmp.path(), "proj", iso26262::ASIL::A);
    REQUIRE(r.total > 0);
}

TEST_CASE("iso26262: assess sets project and asil", "[iso26262][iso26262002]") {
    TempDir tmp;
    auto r = iso26262::assess(tmp.path(), "my-proj", iso26262::ASIL::B);
    REQUIRE(r.project == "my-proj");
    REQUIRE(r.asil == "ASIL-B");
}

TEST_CASE("iso26262: assess counts are consistent", "[iso26262][iso26262002]") {
    TempDir tmp;
    auto r = iso26262::assess(tmp.path(), "p", iso26262::ASIL::A);
    REQUIRE(r.addressed + r.partial + r.gap == r.total);
}

TEST_CASE("iso26262: ASIL-D has >= objectives than ASIL-A", "[iso26262][iso26262002]") {
    TempDir tmp;
    auto ra = iso26262::assess(tmp.path(), "p", iso26262::ASIL::A);
    auto rd = iso26262::assess(tmp.path(), "p", iso26262::ASIL::D);
    REQUIRE(rd.total >= ra.total);
}

TEST_CASE("iso26262: objectives have non-empty ids", "[iso26262][iso26262002]") {
    TempDir tmp;
    auto r = iso26262::assess(tmp.path(), "p", iso26262::ASIL::B);
    for (auto& o : r.objectives)
        REQUIRE_FALSE(o.id.empty());
}

TEST_CASE("iso26262: generated_at is non-empty", "[iso26262][iso26262001]") {
    TempDir tmp;
    auto r = iso26262::assess(tmp.path(), "p", iso26262::ASIL::A);
    REQUIRE_FALSE(r.generated_at.empty());
}

// ─── write_json ───────────────────────────────────────────────────────────────

TEST_CASE("iso26262: write_json creates valid JSON", "[iso26262][iso26262003]") {
    TempDir tmp;
    auto r = iso26262::assess(tmp.path(), "p", iso26262::ASIL::B);
    auto out = tmp.path() / iso26262::ISO26262_REPORT_FILE;
    REQUIRE_NOTHROW(iso26262::write_json(out, r));
    std::ifstream f(out);
    json j;
    REQUIRE_NOTHROW(f >> j);
    REQUIRE(j.contains("objectives"));
    REQUIRE(j.contains("summary"));
}

TEST_CASE("iso26262: JSON summary total matches report", "[iso26262][iso26262003]") {
    TempDir tmp;
    auto r = iso26262::assess(tmp.path(), "p", iso26262::ASIL::A);
    iso26262::write_json(tmp.path() / iso26262::ISO26262_REPORT_FILE, r);
    std::ifstream f(tmp.path() / iso26262::ISO26262_REPORT_FILE);
    json j; f >> j;
    REQUIRE(j["summary"]["total"].get<int>() == r.total);
}

TEST_CASE("iso26262: JSON objectives have id field", "[iso26262][iso26262003]") {
    TempDir tmp;
    auto r = iso26262::assess(tmp.path(), "p", iso26262::ASIL::C);
    iso26262::write_json(tmp.path() / iso26262::ISO26262_REPORT_FILE, r);
    std::ifstream f(tmp.path() / iso26262::ISO26262_REPORT_FILE);
    json j; f >> j;
    for (auto& o : j["objectives"])
        REQUIRE(o.contains("id"));
}

TEST_CASE("iso26262: JSON summary uses satisfied and gaps keys (spec 9.3)", "[iso26262][iso26262003]") {
    TempDir tmp;
    auto r = iso26262::assess(tmp.path(), "p", iso26262::ASIL::B);
    iso26262::write_json(tmp.path() / iso26262::ISO26262_REPORT_FILE, r);
    std::ifstream f(tmp.path() / iso26262::ISO26262_REPORT_FILE);
    json j; f >> j;
    REQUIRE(j["summary"].contains("satisfied"));
    REQUIRE(j["summary"].contains("gaps"));
    REQUIRE_FALSE(j["summary"].contains("addressed"));
    REQUIRE_FALSE(j["summary"].contains("gap"));
}
