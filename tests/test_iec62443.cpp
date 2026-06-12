//fusa:test REQ-IEC62443-001 REQ-IEC62443-002 REQ-IEC62443-003
#include <catch2/catch_all.hpp>
#include "iec62443/iec62443.hpp"
#include "testutil/testutil.hpp"
#include <nlohmann/json.hpp>
#include <fstream>

using namespace cpfusa;
using namespace cpfusa::testutil;
using json = nlohmann::json;

// ─── parse_sl / sl_str ───────────────────────────────────────────────────────

TEST_CASE("iec62443: parse_sl SL1", "[iec62443][iec62443001]") {
    REQUIRE(iec62443::parse_sl("SL1") == iec62443::SL::SL1);
    REQUIRE(iec62443::parse_sl("1")   == iec62443::SL::SL1);
}

TEST_CASE("iec62443: sl_str roundtrip", "[iec62443][iec62443001]") {
    REQUIRE(iec62443::sl_str(iec62443::parse_sl("SL2")) == "SL-2");
    REQUIRE(iec62443::sl_str(iec62443::parse_sl("4"))   == "SL-4");
}

TEST_CASE("iec62443: status_str met", "[iec62443][iec62443001]") {
    REQUIRE(iec62443::status_str(iec62443::Status::Met) == "satisfied");
}

TEST_CASE("iec62443: status_str gap", "[iec62443][iec62443001]") {
    REQUIRE(iec62443::status_str(iec62443::Status::Gap) == "gap");
}

// ─── assess ───────────────────────────────────────────────────────────────────

TEST_CASE("iec62443: assess returns non-empty report for SL1", "[iec62443][iec62443002]") {
    TempDir tmp;
    auto r = iec62443::assess(tmp.path(), "proj", iec62443::SL::SL1);
    REQUIRE(r.total > 0);
}

TEST_CASE("iec62443: assess sets project and sl", "[iec62443][iec62443002]") {
    TempDir tmp;
    auto r = iec62443::assess(tmp.path(), "my-proj", iec62443::SL::SL2);
    REQUIRE(r.project == "my-proj");
    REQUIRE(r.sl == "SL-2");
}

TEST_CASE("iec62443: assess counts are consistent", "[iec62443][iec62443002]") {
    TempDir tmp;
    auto r = iec62443::assess(tmp.path(), "p", iec62443::SL::SL1);
    REQUIRE(r.satisfied + r.partial + r.gap == r.total);
}

TEST_CASE("iec62443: higher SL has >= checks than lower", "[iec62443][iec62443002]") {
    TempDir tmp;
    auto r1 = iec62443::assess(tmp.path(), "p", iec62443::SL::SL1);
    auto r4 = iec62443::assess(tmp.path(), "p", iec62443::SL::SL4);
    REQUIRE(r4.total >= r1.total);
}

TEST_CASE("iec62443: checks have non-empty ids", "[iec62443][iec62443002]") {
    TempDir tmp;
    auto r = iec62443::assess(tmp.path(), "p", iec62443::SL::SL2);
    for (auto& c : r.checks)
        REQUIRE_FALSE(c.id.empty());
}

TEST_CASE("iec62443: generated_at is non-empty", "[iec62443][iec62443001]") {
    TempDir tmp;
    auto r = iec62443::assess(tmp.path(), "p", iec62443::SL::SL1);
    REQUIRE_FALSE(r.generated_at.empty());
}

// ─── write_json ───────────────────────────────────────────────────────────────

TEST_CASE("iec62443: write_json creates valid JSON", "[iec62443][iec62443003]") {
    TempDir tmp;
    auto r = iec62443::assess(tmp.path(), "p", iec62443::SL::SL2);
    auto out = tmp.path() / iec62443::IEC62443_REPORT_FILE;
    REQUIRE_NOTHROW(iec62443::write_json(out, r));
    std::ifstream f(out);
    json j;
    REQUIRE_NOTHROW(f >> j);
    REQUIRE(j.contains("objectives"));
    REQUIRE(j.contains("summary"));
}

TEST_CASE("iec62443: JSON summary total matches report", "[iec62443][iec62443003]") {
    TempDir tmp;
    auto r = iec62443::assess(tmp.path(), "p", iec62443::SL::SL1);
    iec62443::write_json(tmp.path() / iec62443::IEC62443_REPORT_FILE, r);
    std::ifstream f(tmp.path() / iec62443::IEC62443_REPORT_FILE);
    json j; f >> j;
    REQUIRE(j["summary"]["total"].get<int>() == r.total);
}

TEST_CASE("iec62443: JSON objectives have id field", "[iec62443][iec62443003]") {
    TempDir tmp;
    auto r = iec62443::assess(tmp.path(), "p", iec62443::SL::SL2);
    iec62443::write_json(tmp.path() / iec62443::IEC62443_REPORT_FILE, r);
    std::ifstream f(tmp.path() / iec62443::IEC62443_REPORT_FILE);
    json j; f >> j;
    for (auto& c : j["objectives"])
        REQUIRE(c.contains("id"));
}

TEST_CASE("iec62443: JSON summary has spec 9.3 keys satisfied and gaps", "[iec62443][iec62443003]") {
    TempDir tmp;
    auto r = iec62443::assess(tmp.path(), "p", iec62443::SL::SL1);
    iec62443::write_json(tmp.path() / iec62443::IEC62443_REPORT_FILE, r);
    std::ifstream f(tmp.path() / iec62443::IEC62443_REPORT_FILE);
    json j; f >> j;
    REQUIRE(j["summary"].contains("satisfied"));
    REQUIRE(j["summary"].contains("gaps"));
    REQUIRE_FALSE(j["summary"].contains("met"));
    REQUIRE_FALSE(j["summary"].contains("gap"));
}

TEST_CASE("iec62443: objective status values are spec-conformant", "[iec62443][iec62443003]") {
    TempDir tmp;
    auto r = iec62443::assess(tmp.path(), "p", iec62443::SL::SL1);
    iec62443::write_json(tmp.path() / iec62443::IEC62443_REPORT_FILE, r);
    std::ifstream f(tmp.path() / iec62443::IEC62443_REPORT_FILE);
    json j; f >> j;
    for (auto& c : j["objectives"]) {
        auto s = c["status"].get<std::string>();
        REQUIRE((s == "satisfied" || s == "partial" || s == "gap"));
    }
}
