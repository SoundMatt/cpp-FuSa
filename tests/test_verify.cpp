//fusa:test REQ-VERIFY001 REQ-VERIFY002 REQ-VERIFY003 REQ-VERIFY004 REQ-VERIFY005
#include <catch2/catch_all.hpp>
#include "verify/verify.hpp"
#include "testutil/testutil.hpp"
#include <nlohmann/json.hpp>
#include <fstream>

using namespace cpfusa;
using namespace cpfusa::testutil;
using json = nlohmann::json;

// ─── write_evidence ───────────────────────────────────────────────────────────

TEST_CASE("verify: write_evidence creates .fusa-evidence.json", "[verify][verify002]") {
    TempDir tmp;
    verify::EvidenceBundle b;
    b.generated_at = "2026-01-01T00:00:00Z";
    b.cpp_version  = "C++17";
    b.summary.total = b.summary.passed = 5;
    REQUIRE(is_ok(verify::write_evidence(tmp.path(), b)));
    REQUIRE(std::filesystem::exists(tmp.path() / ".fusa-evidence.json"));
}

TEST_CASE("verify: write_evidence produces valid JSON", "[verify][verify002]") {
    TempDir tmp;
    verify::EvidenceBundle b;
    b.generated_at = "2026-01-01T00:00:00Z";
    b.cpp_version  = "C++17";
    b.summary.total = 10; b.summary.passed = 9; b.summary.failed = 1;
    verify::write_evidence(tmp.path(), b);
    std::ifstream f(tmp.path() / ".fusa-evidence.json");
    json j; REQUIRE_NOTHROW(f >> j);
    REQUIRE(j.contains("summary"));
}

TEST_CASE("verify: write_evidence JSON has correct summary counts", "[verify][verify002]") {
    TempDir tmp;
    verify::EvidenceBundle b;
    b.generated_at = "2026-01-01T00:00:00Z"; b.cpp_version = "C++17";
    b.summary.total = 42; b.summary.passed = 40; b.summary.failed = 2;
    verify::write_evidence(tmp.path(), b);
    std::ifstream f(tmp.path() / ".fusa-evidence.json");
    json j; f >> j;
    REQUIRE(j["summary"]["total"].get<int>()  == 42);
    REQUIRE(j["summary"]["passed"].get<int>() == 40);
    REQUIRE(j["summary"]["failed"].get<int>() == 2);
}

TEST_CASE("verify: write_evidence JSON has generatedAt field", "[verify][verify002]") {
    TempDir tmp;
    verify::EvidenceBundle b;
    b.generated_at = "2026-06-09T12:00:00Z"; b.cpp_version = "C++17";
    verify::write_evidence(tmp.path(), b);
    std::ifstream f(tmp.path() / ".fusa-evidence.json");
    json j; f >> j;
    REQUIRE(j["generatedAt"].get<std::string>() == "2026-06-09T12:00:00Z");
}

TEST_CASE("verify: write_evidence JSON has results array", "[verify][verify002]") {
    TempDir tmp;
    verify::EvidenceBundle b;
    b.generated_at = "2026-01-01T00:00:00Z"; b.cpp_version = "C++17";
    b.results.push_back({"test_foo", "tests/t.cpp", "passed", 0.01});
    b.results.push_back({"test_bar", "tests/t.cpp", "failed", 0.02});
    b.summary.total = 2; b.summary.passed = 1; b.summary.failed = 1;
    verify::write_evidence(tmp.path(), b);
    std::ifstream f(tmp.path() / ".fusa-evidence.json");
    json j; f >> j;
    REQUIRE(j["results"].is_array());
    REQUIRE(j["results"].size() == 2);
}

TEST_CASE("verify: write_evidence JSON result entries have name and status", "[verify][verify003]") {
    TempDir tmp;
    verify::EvidenceBundle b;
    b.generated_at = "2026-01-01T00:00:00Z"; b.cpp_version = "C++17";
    b.results.push_back({"my_test", "tests/t.cpp", "passed", 0.5});
    b.summary.total = b.summary.passed = 1;
    verify::write_evidence(tmp.path(), b);
    std::ifstream f(tmp.path() / ".fusa-evidence.json");
    json j; f >> j;
    REQUIRE(j["results"][0].contains("name"));
    REQUIRE(j["results"][0]["status"] == "passed");
}

TEST_CASE("verify: write_evidence JSON has cppVersion field", "[verify][verify004]") {
    TempDir tmp;
    verify::EvidenceBundle b;
    b.generated_at = "2026-01-01T00:00:00Z"; b.cpp_version = "C++17";
    verify::write_evidence(tmp.path(), b);
    std::ifstream f(tmp.path() / ".fusa-evidence.json");
    json j; f >> j;
    REQUIRE(j.contains("cppVersion"));
    REQUIRE(j["cppVersion"] == "C++17");
}

TEST_CASE("verify: write_evidence overwrite is idempotent", "[verify][verify005]") {
    TempDir tmp;
    verify::EvidenceBundle b;
    b.generated_at = "2026-01-01T00:00:00Z"; b.cpp_version = "C++17";
    b.summary.total = b.summary.passed = 3;
    REQUIRE(is_ok(verify::write_evidence(tmp.path(), b)));
    b.summary.total = b.summary.passed = 7;
    REQUIRE(is_ok(verify::write_evidence(tmp.path(), b)));
    std::ifstream f(tmp.path() / ".fusa-evidence.json");
    json j; f >> j;
    REQUIRE(j["summary"]["total"].get<int>() == 7);
}

// ─── run_ctest (integration) ──────────────────────────────────────────────────

TEST_CASE("verify: run_ctest returns error or empty bundle on missing build", "[verify][verify001]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto r = verify::run_ctest(tmp.path(), cfg);
    if (is_ok(r)) REQUIRE(value_of(r).summary.total == 0);
    else          REQUIRE_FALSE(error_of(r).empty());
}
