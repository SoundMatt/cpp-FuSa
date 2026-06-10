//fusa:test REQ-DO178-001 REQ-DO178-002 REQ-DO178-003
#include <catch2/catch_all.hpp>
#include "do178/do178.hpp"
#include "testutil/testutil.hpp"
#include <nlohmann/json.hpp>
#include <fstream>

using namespace cpfusa;
using namespace cpfusa::testutil;
using json = nlohmann::json;

// ─── parse_dal / dal_str ──────────────────────────────────────────────────────

TEST_CASE("do178: parse_dal A", "[do178][do178001]") {
    REQUIRE(do178::parse_dal("A") == do178::DAL::A);
    REQUIRE(do178::parse_dal("DAL-A") == do178::DAL::A);
}

TEST_CASE("do178: dal_str roundtrip", "[do178][do178001]") {
    REQUIRE(do178::dal_str(do178::parse_dal("B")) == "DAL-B");
    REQUIRE(do178::dal_str(do178::parse_dal("D")) == "DAL-D");
}

// ─── assess ───────────────────────────────────────────────────────────────────

TEST_CASE("do178: assess returns non-empty report", "[do178][do178002]") {
    TempDir tmp;
    auto r = do178::assess(tmp.path(), "test-proj", do178::DAL::A);
    REQUIRE(r.total > 0);
}

TEST_CASE("do178: assess has at least 38 objectives", "[do178][do178002]") {
    TempDir tmp;
    auto r = do178::assess(tmp.path(), "test-proj", do178::DAL::A);
    REQUIRE(r.total >= 38);
}

TEST_CASE("do178: assess sets project name", "[do178][do178002]") {
    TempDir tmp;
    auto r = do178::assess(tmp.path(), "my-proj", do178::DAL::B);
    REQUIRE(r.project == "my-proj");
}

TEST_CASE("do178: assess sets DAL string", "[do178][do178002]") {
    TempDir tmp;
    auto r = do178::assess(tmp.path(), "p", do178::DAL::C);
    REQUIRE(r.dal == "DAL-C");
}

TEST_CASE("do178: assess counts are consistent", "[do178][do178002]") {
    TempDir tmp;
    auto r = do178::assess(tmp.path(), "p", do178::DAL::A);
    REQUIRE(r.addressed + r.partial + r.gap == r.total);
}

TEST_CASE("do178: DAL-D requires fewer objectives than DAL-A", "[do178][do178002]") {
    TempDir tmp;
    auto ra = do178::assess(tmp.path(), "p", do178::DAL::A);
    auto rd = do178::assess(tmp.path(), "p", do178::DAL::D);
    REQUIRE(ra.total >= rd.total);
}

TEST_CASE("do178: objectives have non-empty ids", "[do178][do178002]") {
    TempDir tmp;
    auto r = do178::assess(tmp.path(), "p", do178::DAL::A);
    for (auto& o : r.objectives)
        REQUIRE_FALSE(o.id.empty());
}

TEST_CASE("do178: objectives have non-empty descriptions", "[do178][do178002]") {
    TempDir tmp;
    auto r = do178::assess(tmp.path(), "p", do178::DAL::A);
    for (auto& o : r.objectives)
        REQUIRE_FALSE(o.description.empty());
}

// ─── write_json ───────────────────────────────────────────────────────────────

TEST_CASE("do178: write_json creates valid JSON", "[do178][do178003]") {
    TempDir tmp;
    auto r = do178::assess(tmp.path(), "p", do178::DAL::B);
    auto out = tmp.path() / do178::DO178_REPORT_FILE;
    REQUIRE_NOTHROW(do178::write_json(out, r));
    std::ifstream f(out);
    json j;
    REQUIRE_NOTHROW(f >> j);
    REQUIRE(j.contains("objectives"));
    REQUIRE(j.contains("summary"));
}

TEST_CASE("do178: JSON summary totals match report", "[do178][do178003]") {
    TempDir tmp;
    auto r = do178::assess(tmp.path(), "p", do178::DAL::A);
    do178::write_json(tmp.path() / do178::DO178_REPORT_FILE, r);
    std::ifstream f(tmp.path() / do178::DO178_REPORT_FILE);
    json j; f >> j;
    REQUIRE(j["summary"]["total"].get<int>() == r.total);
}

TEST_CASE("do178: JSON objectives array matches report size", "[do178][do178003]") {
    TempDir tmp;
    auto r = do178::assess(tmp.path(), "p", do178::DAL::A);
    do178::write_json(tmp.path() / do178::DO178_REPORT_FILE, r);
    std::ifstream f(tmp.path() / do178::DO178_REPORT_FILE);
    json j; f >> j;
    REQUIRE(j["objectives"].size() == r.objectives.size());
}

TEST_CASE("do178: JSON summary uses satisfied and gaps keys (§9.3)", "[do178][do178003]") {
    TempDir tmp;
    auto r = do178::assess(tmp.path(), "p", do178::DAL::C);
    do178::write_json(tmp.path() / do178::DO178_REPORT_FILE, r);
    std::ifstream f(tmp.path() / do178::DO178_REPORT_FILE);
    json j; f >> j;
    REQUIRE(j["summary"].contains("satisfied"));
    REQUIRE(j["summary"].contains("gaps"));
    REQUIRE_FALSE(j["summary"].contains("addressed"));
    REQUIRE_FALSE(j["summary"].contains("gap"));
}
