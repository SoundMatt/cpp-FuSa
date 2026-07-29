//fusa:test REQ-IEC61508-001
//fusa:test REQ-IEC61508-002
//fusa:test REQ-IEC61508-003
#include <catch2/catch_all.hpp>
#include "iec61508/iec61508.hpp"
#include "testutil/testutil.hpp"
#include <nlohmann/json.hpp>
#include <fstream>

using namespace cpfusa;
using namespace cpfusa::testutil;
using json = nlohmann::json;

namespace {
const iec61508::Objective* find_obj(const iec61508::Report& r, const std::string& id) {
    for (auto& o : r.objectives) if (o.id == id) return &o;
    return nullptr;
}
} // namespace

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

TEST_CASE("iec61508: JSON summary uses satisfied and gaps keys (spec 9.3)", "[iec61508][iec61508003]") {
    TempDir tmp;
    auto r = iec61508::assess(tmp.path(), "p", iec61508::SIL::SIL2);
    iec61508::write_json(tmp.path() / iec61508::IEC61508_REPORT_FILE, r);
    std::ifstream f(tmp.path() / iec61508::IEC61508_REPORT_FILE);
    json j; f >> j;
    REQUIRE(j["summary"].contains("satisfied"));
    REQUIRE(j["summary"].contains("gaps"));
    REQUIRE_FALSE(j["summary"].contains("addressed"));
    REQUIRE_FALSE(j["summary"].contains("gap"));
}

// ─── detect_status: previously-unhandled objectives (issue #57) ───────────────
//
// Prior to the fix, every one of these objective ids fell through
// detect_status()'s final `return Status::Gap;` unconditionally, regardless of
// what evidence existed on disk.

TEST_CASE("iec61508: 1-7.1 safety lifecycle clears with project config", "[iec61508][iec61508002]") {
    TempDir tmp;
    tmp.write(".fusa.json", "{}");
    auto r = iec61508::assess(tmp.path(), "p", iec61508::SIL::SIL2);
    auto* o = find_obj(r, "1-7.1");
    REQUIRE(o != nullptr);
    REQUIRE(o->status != iec61508::Status::Gap);
}

TEST_CASE("iec61508: 1-7.1 is gap with no config", "[iec61508][iec61508002]") {
    TempDir tmp;
    auto r = iec61508::assess(tmp.path(), "p", iec61508::SIL::SIL2);
    auto* o = find_obj(r, "1-7.1");
    REQUIRE(o != nullptr);
    REQUIRE(o->status == iec61508::Status::Gap);
}

TEST_CASE("iec61508: 1-8.1 safety requirements spec clears with reqs registry", "[iec61508][iec61508002]") {
    TempDir tmp;
    tmp.write(".fusa-reqs.json", "{}");
    auto r = iec61508::assess(tmp.path(), "p", iec61508::SIL::SIL2);
    auto* o = find_obj(r, "1-8.1");
    REQUIRE(o != nullptr);
    REQUIRE(o->status != iec61508::Status::Gap);
}

TEST_CASE("iec61508: 1-8.2 requirements allocation is Addressed with HARA and reqs",
          "[iec61508][iec61508002]") {
    TempDir tmp;
    tmp.write(".fusa-hara.json", "{}");
    tmp.write(".fusa-reqs.json", "{}");
    auto r = iec61508::assess(tmp.path(), "p", iec61508::SIL::SIL2);
    auto* o = find_obj(r, "1-8.2");
    REQUIRE(o != nullptr);
    REQUIRE(o->status == iec61508::Status::Addressed);
}

TEST_CASE("iec61508: 1-8.2 is partial with only reqs and no HARA", "[iec61508][iec61508002]") {
    TempDir tmp;
    tmp.write(".fusa-reqs.json", "{}");
    auto r = iec61508::assess(tmp.path(), "p", iec61508::SIL::SIL2);
    auto* o = find_obj(r, "1-8.2");
    REQUIRE(o != nullptr);
    REQUIRE(o->status == iec61508::Status::Partial);
}

TEST_CASE("iec61508: 3-7.2 software architecture design clears with sas.md", "[iec61508][iec61508002]") {
    TempDir tmp;
    tmp.write("sas.md", "# SAS\n");
    auto r = iec61508::assess(tmp.path(), "p", iec61508::SIL::SIL2);
    auto* o = find_obj(r, "3-7.2");
    REQUIRE(o != nullptr);
    REQUIRE(o->status != iec61508::Status::Gap);
}

TEST_CASE("iec61508: 3-7.6 software validation testing clears with test evidence",
          "[iec61508][iec61508002]") {
    TempDir tmp;
    tmp.write(".fusa-evidence.json", "{}");
    auto r = iec61508::assess(tmp.path(), "p", iec61508::SIL::SIL2);
    auto* o = find_obj(r, "3-7.6");
    REQUIRE(o != nullptr);
    REQUIRE(o->status != iec61508::Status::Gap);
}

TEST_CASE("iec61508: 3-7.7 software modification clears with CHANGELOG.md", "[iec61508][iec61508002]") {
    TempDir tmp;
    tmp.write("CHANGELOG.md", "# Changelog\n");
    auto r = iec61508::assess(tmp.path(), "p", iec61508::SIL::SIL2);
    auto* o = find_obj(r, "3-7.7");
    REQUIRE(o != nullptr);
    REQUIRE(o->status != iec61508::Status::Gap);
}

TEST_CASE("iec61508: 3-7.8 software verification clears with check-report.json",
          "[iec61508][iec61508002]") {
    TempDir tmp;
    tmp.write("check-report.json", "{}");
    auto r = iec61508::assess(tmp.path(), "p", iec61508::SIL::SIL2);
    auto* o = find_obj(r, "3-7.8");
    REQUIRE(o != nullptr);
    REQUIRE(o->status == iec61508::Status::Addressed);
}

TEST_CASE("iec61508: 2-7.1 hardware safety requirements clears with reqs registry",
          "[iec61508][iec61508002]") {
    TempDir tmp;
    tmp.write(".fusa-reqs.json", "{}");
    auto r = iec61508::assess(tmp.path(), "p", iec61508::SIL::SIL2);
    auto* o = find_obj(r, "2-7.1");
    REQUIRE(o != nullptr);
    REQUIRE(o->status != iec61508::Status::Gap);
}
