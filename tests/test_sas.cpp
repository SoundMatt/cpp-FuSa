//fusa:test REQ-SAS001 REQ-SAS002 REQ-SAS003
#include <catch2/catch_all.hpp>
#include "sas/sas.hpp"
#include "testutil/testutil.hpp"
#include <nlohmann/json.hpp>
#include <fstream>

using namespace cpfusa;
using namespace cpfusa::testutil;
using json = nlohmann::json;

// ─── build ────────────────────────────────────────────────────────────────────

TEST_CASE("sas: build returns non-empty SAS", "[sas][sas001]") {
    TempDir tmp;
    auto s = sas::build(tmp.path(), "proj", "1.0", "DAL-B");
    REQUIRE(s.total > 0);
}

TEST_CASE("sas: build sets project and version", "[sas][sas001]") {
    TempDir tmp;
    auto s = sas::build(tmp.path(), "my-proj", "2.0", "DAL-C");
    REQUIRE(s.project == "my-proj");
    REQUIRE(s.version == "2.0");
}

TEST_CASE("sas: build sets dal", "[sas][sas001]") {
    TempDir tmp;
    auto s = sas::build(tmp.path(), "p", "1.0", "DAL-A");
    REQUIRE(s.dal == "DAL-A");
}

TEST_CASE("sas: build complete <= total", "[sas][sas001]") {
    TempDir tmp;
    auto s = sas::build(tmp.path(), "p", "1.0", "DAL-B");
    REQUIRE(s.complete <= s.total);
}

TEST_CASE("sas: build generated_at is non-empty", "[sas][sas001]") {
    TempDir tmp;
    auto s = sas::build(tmp.path(), "p", "1.0", "DAL-C");
    REQUIRE_FALSE(s.generated_at.empty());
}

TEST_CASE("sas: evidence items have non-empty ids", "[sas][sas002]") {
    TempDir tmp;
    auto s = sas::build(tmp.path(), "p", "1.0", "DAL-B");
    for (auto& e : s.evidence)
        REQUIRE_FALSE(e.id.empty());
}

// ─── write_json ───────────────────────────────────────────────────────────────

TEST_CASE("sas: write_json creates valid JSON", "[sas][sas003]") {
    TempDir tmp;
    auto s = sas::build(tmp.path(), "p", "1.0", "DAL-B");
    auto out = tmp.path() / sas::SAS_JSON_FILE;
    REQUIRE_NOTHROW(sas::write_json(out, s));
    std::ifstream f(out);
    json j;
    REQUIRE_NOTHROW(f >> j);
    REQUIRE(j.contains("evidence"));
    REQUIRE(j.contains("summary"));
}

TEST_CASE("sas: JSON summary total matches", "[sas][sas003]") {
    TempDir tmp;
    auto s = sas::build(tmp.path(), "p", "1.0", "DAL-A");
    sas::write_json(tmp.path() / sas::SAS_JSON_FILE, s);
    std::ifstream f(tmp.path() / sas::SAS_JSON_FILE);
    json j; f >> j;
    REQUIRE(j["summary"]["total"].get<int>() == s.total);
}

// ─── write_markdown ───────────────────────────────────────────────────────────

TEST_CASE("sas: write_markdown creates a file", "[sas][sas003]") {
    TempDir tmp;
    auto s = sas::build(tmp.path(), "p", "1.0", "DAL-C");
    auto out = tmp.path() / sas::SAS_MD_FILE;
    REQUIRE_NOTHROW(sas::write_markdown(out, s));
    REQUIRE(std::filesystem::exists(out));
    REQUIRE(std::filesystem::file_size(out) > 0);
}
