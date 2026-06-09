//fusa:test REQ-IEC61508-001 REQ-IEC61508-002 REQ-IEC61508-003
#include <catch2/catch_all.hpp>
#include "iec61508/iec61508.hpp"
#include "testutil/testutil.hpp"
#include <nlohmann/json.hpp>
#include <fstream>

using namespace cpfusa;
using namespace cpfusa::testutil;
using json = nlohmann::json;

// ─── parse_sil / sil_str ─────────────────────────────────────────────────────

TEST_CASE("iec61508: parse_sil SIL1", "[iec61508][iec61508001]") {
    REQUIRE(iec61508::parse_sil("SIL1")  == iec61508::SIL::SIL1);
    REQUIRE(iec61508::parse_sil("SIL-1") == iec61508::SIL::SIL1);
}

TEST_CASE("iec61508: sil_str roundtrip", "[iec61508][iec61508001]") {
    REQUIRE(iec61508::sil_str(iec61508::parse_sil("SIL3"))  == "SIL-3");
    REQUIRE(iec61508::sil_str(iec61508::parse_sil("SIL-4")) == "SIL-4");
}

// ─── assess ───────────────────────────────────────────────────────────────────

TEST_CASE("iec61508: assess returns non-empty report", "[iec61508][iec61508002]") {
    TempDir tmp;
    auto r = iec61508::assess(tmp.path(), "proj", iec61508::SIL::SIL1);
    REQUIRE(r.total > 0);
}

TEST_CASE("iec61508: assess sets project and sil", "[iec61508][iec61508002]") {
    TempDir tmp;
    auto r = iec61508::assess(tmp.path(), "my-proj", iec61508::SIL::SIL2);
    REQUIRE(r.project == "my-proj");
    REQUIRE(r.sil == "SIL-2");
}

TEST_CASE("iec61508: assess counts are consistent", "[iec61508][iec61508002]") {
    TempDir tmp;
    auto r = iec61508::assess(tmp.path(), "p", iec61508::SIL::SIL1);
    REQUIRE(r.addressed + r.partial + r.gap == r.total);
}

TEST_CASE("iec61508: higher SIL has >= objectives than lower", "[iec61508][iec61508002]") {
    TempDir tmp;
    auto r1 = iec61508::assess(tmp.path(), "p", iec61508::SIL::SIL1);
    auto r4 = iec61508::assess(tmp.path(), "p", iec61508::SIL::SIL4);
    REQUIRE(r4.total >= r1.total);
}

TEST_CASE("iec61508: objectives have non-empty ids", "[iec61508][iec61508002]") {
    TempDir tmp;
    auto r = iec61508::assess(tmp.path(), "p", iec61508::SIL::SIL2);
    for (auto& o : r.objectives)
        REQUIRE_FALSE(o.id.empty());
}

TEST_CASE("iec61508: generated_at is non-empty", "[iec61508][iec61508001]") {
    TempDir tmp;
    auto r = iec61508::assess(tmp.path(), "p", iec61508::SIL::SIL1);
    REQUIRE_FALSE(r.generated_at.empty());
}

// ─── write_json ───────────────────────────────────────────────────────────────

TEST_CASE("iec61508: write_json creates valid JSON", "[iec61508][iec61508003]") {
    TempDir tmp;
    auto r = iec61508::assess(tmp.path(), "p", iec61508::SIL::SIL2);
    auto out = tmp.path() / iec61508::IEC61508_REPORT_FILE;
    REQUIRE_NOTHROW(iec61508::write_json(out, r));
    std::ifstream f(out);
    json j;
    REQUIRE_NOTHROW(f >> j);
    REQUIRE(j.contains("objectives"));
    REQUIRE(j.contains("summary"));
}

TEST_CASE("iec61508: JSON summary total matches report", "[iec61508][iec61508003]") {
    TempDir tmp;
    auto r = iec61508::assess(tmp.path(), "p", iec61508::SIL::SIL1);
    iec61508::write_json(tmp.path() / iec61508::IEC61508_REPORT_FILE, r);
    std::ifstream f(tmp.path() / iec61508::IEC61508_REPORT_FILE);
    json j; f >> j;
    REQUIRE(j["summary"]["total"].get<int>() == r.total);
}
