//fusa:test REQ-ISO26262-001
//fusa:test REQ-ISO26262-002
//fusa:test REQ-ISO26262-003
#include <catch2/catch_all.hpp>
#include "iso26262/iso26262.hpp"
#include "testutil/testutil.hpp"
#include <nlohmann/json.hpp>
#include <fstream>

using namespace cpfusa;
using namespace cpfusa::testutil;
using json = nlohmann::json;

namespace {
const iso26262::Objective* find_obj(const iso26262::Report& r, const std::string& id) {
    for (auto& o : r.objectives) if (o.id == id) return &o;
    return nullptr;
}
} // namespace

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

// ─── detect_status: previously-unhandled objectives (issue #57) ───────────────
//
// Prior to the fix, every one of these objective ids fell through
// detect_status()'s final `return Status::Gap;` unconditionally, regardless of
// what evidence existed on disk. Each case below plants the real artifact the
// objective asks for and asserts the gap actually clears.

TEST_CASE("iso26262: 6-5.2 design criteria clears with SQAP.md", "[iso26262][iso26262002]") {
    TempDir tmp;
    tmp.write("SQAP.md", "# Software Quality Assurance Plan\n");
    auto r = iso26262::assess(tmp.path(), "p", iso26262::ASIL::B);
    auto* o = find_obj(r, "6-5.2");
    REQUIRE(o != nullptr);
    REQUIRE(o->status != iso26262::Status::Gap);
}

TEST_CASE("iso26262: 6-5.2 is gap with no evidence", "[iso26262][iso26262002]") {
    TempDir tmp;
    auto r = iso26262::assess(tmp.path(), "p", iso26262::ASIL::B);
    auto* o = find_obj(r, "6-5.2");
    REQUIRE(o != nullptr);
    REQUIRE(o->status == iso26262::Status::Gap);
}

TEST_CASE("iso26262: 6-6.1 architectural design clears with sas.md", "[iso26262][iso26262002]") {
    TempDir tmp;
    tmp.write("sas.md", "# Software Accomplishment Summary\n");
    auto r = iso26262::assess(tmp.path(), "p", iso26262::ASIL::B);
    auto* o = find_obj(r, "6-6.1");
    REQUIRE(o != nullptr);
    REQUIRE(o->status != iso26262::Status::Gap);
}

TEST_CASE("iso26262: 6-6.1 architectural design clears with sas.json", "[iso26262][iso26262002]") {
    TempDir tmp;
    tmp.write("sas.json", "{}");
    auto r = iso26262::assess(tmp.path(), "p", iso26262::ASIL::B);
    auto* o = find_obj(r, "6-6.1");
    REQUIRE(o != nullptr);
    REQUIRE(o->status != iso26262::Status::Gap);
}

TEST_CASE("iso26262: 6-6.2 unit design clears with boundary diagram", "[iso26262][iso26262002]") {
    TempDir tmp;
    tmp.write("boundary.mermaid", "graph TD\n");
    auto r = iso26262::assess(tmp.path(), "p", iso26262::ASIL::B);
    auto* o = find_obj(r, "6-6.2");
    REQUIRE(o != nullptr);
    REQUIRE(o->status != iso26262::Status::Gap);
}

TEST_CASE("iso26262: 6-6.3 unit implementation clears with check-report.json", "[iso26262][iso26262002]") {
    TempDir tmp;
    tmp.write("check-report.json", "{}");
    auto r = iso26262::assess(tmp.path(), "p", iso26262::ASIL::B);
    auto* o = find_obj(r, "6-6.3");
    REQUIRE(o != nullptr);
    REQUIRE(o->status != iso26262::Status::Gap);
}

TEST_CASE("iso26262: 6-8.1 integration testing clears with test evidence", "[iso26262][iso26262002]") {
    TempDir tmp;
    tmp.write(".fusa-evidence.json", "{}");
    auto r = iso26262::assess(tmp.path(), "p", iso26262::ASIL::B);
    auto* o = find_obj(r, "6-8.1");
    REQUIRE(o != nullptr);
    REQUIRE(o->status != iso26262::Status::Gap);
}

TEST_CASE("iso26262: 6-9.1 verification of safety reqs is Addressed with reqs and evidence",
          "[iso26262][iso26262002]") {
    TempDir tmp;
    tmp.write(".fusa-reqs.json", "{}");
    tmp.write(".fusa-evidence.json", "{}");
    auto r = iso26262::assess(tmp.path(), "p", iso26262::ASIL::B);
    auto* o = find_obj(r, "6-9.1");
    REQUIRE(o != nullptr);
    REQUIRE(o->status == iso26262::Status::Addressed);
}

TEST_CASE("iso26262: 6-9.1 is partial with only one of reqs/evidence", "[iso26262][iso26262002]") {
    TempDir tmp;
    tmp.write(".fusa-reqs.json", "{}");
    auto r = iso26262::assess(tmp.path(), "p", iso26262::ASIL::B);
    auto* o = find_obj(r, "6-9.1");
    REQUIRE(o != nullptr);
    REQUIRE(o->status == iso26262::Status::Partial);
}

TEST_CASE("iso26262: 8-6.1 ASIL decomposition clears with HARA", "[iso26262][iso26262002]") {
    TempDir tmp;
    tmp.write(".fusa-hara.json", "{}");
    auto r = iso26262::assess(tmp.path(), "p", iso26262::ASIL::B);
    auto* o = find_obj(r, "8-6.1");
    REQUIRE(o != nullptr);
    REQUIRE(o->status != iso26262::Status::Gap);
}

TEST_CASE("iso26262: 8-6.2 safety manual clears with SAFETY_MANUAL.md", "[iso26262][iso26262002]") {
    TempDir tmp;
    tmp.write("SAFETY_MANUAL.md", "# Safety Manual\n");
    auto r = iso26262::assess(tmp.path(), "p", iso26262::ASIL::B);
    auto* o = find_obj(r, "8-6.2");
    REQUIRE(o != nullptr);
    REQUIRE(o->status != iso26262::Status::Gap);
}

TEST_CASE("iso26262: 8-6.2 is gap with no safety manual", "[iso26262][iso26262002]") {
    TempDir tmp;
    auto r = iso26262::assess(tmp.path(), "p", iso26262::ASIL::B);
    auto* o = find_obj(r, "8-6.2");
    REQUIRE(o != nullptr);
    REQUIRE(o->status == iso26262::Status::Gap);
}

TEST_CASE("iso26262: 9-1.1 verification independence is Addressed with a reviewed attestation",
          "[iso26262][iso26262002]") {
    TempDir tmp;
    tmp.write("safety-case.json", R"({
        "attestation": {
            "status": "reviewed",
            "implementationAuthor": "alice",
            "independentReviewer": "bob",
            "reviewedAt": "2026-01-01T00:00:00Z",
            "contentHash": "sha256:abc"
        }
    })");
    auto r = iso26262::assess(tmp.path(), "p", iso26262::ASIL::B);
    auto* o = find_obj(r, "9-1.1");
    REQUIRE(o != nullptr);
    REQUIRE(o->status == iso26262::Status::Addressed);
}

TEST_CASE("iso26262: 9-1.1 is not Addressed without an independent reviewer",
          "[iso26262][iso26262002]") {
    TempDir tmp;
    tmp.write("safety-case.json", "{}");
    auto r = iso26262::assess(tmp.path(), "p", iso26262::ASIL::B);
    auto* o = find_obj(r, "9-1.1");
    REQUIRE(o != nullptr);
    REQUIRE(o->status != iso26262::Status::Addressed);
}
