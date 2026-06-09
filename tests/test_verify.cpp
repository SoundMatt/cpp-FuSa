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
    verify::EvidenceBundle bundle;
    bundle.generated_at  = "2026-01-01T00:00:00Z";
    bundle.project_root  = tmp.path().string();
    bundle.cpp_version   = "C++17";
    bundle.summary.total   = 5;
    bundle.summary.passed  = 5;
    auto r = verify::write_evidence(tmp.path(), bundle);
    REQUIRE(is_ok(r));
    REQUIRE(std::filesystem::exists(tmp.path() / ".fusa-evidence.json"));
}

TEST_CASE("verify: write_evidence produces valid JSON", "[verify][verify002]") {
    TempDir tmp;
    verify::EvidenceBundle bundle;
    bundle.generated_at = "2026-01-01T00:00:00Z";
    bundle.cpp_version  = "C++17";
    bundle.summary.total  = 10;
    bundle.summary.passed = 9;
    bundle.summary.failed = 1;
    verify::write_evidence(tmp.path(), bundle);
    std::ifstream f(tmp.path() / ".fusa-evidence.json");
    json j;
    REQUIRE_NOTHROW(f >> j);
    REQUIRE(j.contains("summary"));
}

TEST_CASE("verify: write_evidence JSON has correct summary counts", "[verify][verify002]") {
    TempDir tmp;
    verify::EvidenceBundle bundle;
    bundle.generated_at    = "2026-01-01T00:00:00Z";
    bundle.cpp_version     = "C++17";
    bundle.summary.total   = 42;
    bundle.summary.passed  = 40;
    bundle.summary.failed  = 2;
    bundle.summary.skipped = 0;
    verify::write_evidence(tmp.path(), bundle);
    std::ifstream f(tmp.path() / ".fusa-evidence.json");
    json j;
    f >> j;
    REQUIRE(j["summary"]["total"].get<int>()  == 42);
    REQUIRE(j["summary"]["passed"].get<int>() == 40);
    REQUIRE(j["summary"]["failed"].get<int>() == 2);
}

TEST_CASE("verify: write_evidence JSON has generatedAt field", "[verify][verify002]") {
    TempDir tmp;
    verify::EvidenceBundle bundle;
    bundle.generated_at = "2026-06-09T12:00:00Z";
    bundle.cpp_version  = "C++17";
    verify::write_evidence(tmp.path(), bundle);
    std::ifstream f(tmp.path() / ".fusa-evidence.json");
    json j;
    f >> j;
    REQUIRE(j.contains("generatedAt"));
    REQUIRE(j["generatedAt"].get<std::string>() == "2026-06-09T12:00:00Z");
}

TEST_CASE("verify: write_evidence JSON has results array", "[verify][verify002]") {
    TempDir tmp;
    verify::EvidenceBundle bundle;
    bundle.generated_at = "2026-01-01T00:00:00Z";
    bundle.cpp_version  = "C++17";
    bundle.results.push_back({"test_foo", "tests/test.cpp", "passed", 0.01});
    bundle.results.push_back({"test_bar", "tests/test.cpp", "failed", 0.02});
    bundle.summary.total = 2; bundle.summary.passed = 1; bundle.summary.failed = 1;
    verify::write_evidence(tmp.path(), bundle);
    std::ifstream f(tmp.path() / ".fusa-evidence.json");
    json j;
    f >> j;
    REQUIRE(j["results"].is_array());
    REQUIRE(j["results"].size() == 2);
}

// ─── run_ctest (integration — only runs if ctest is available) ────────────────

TEST_CASE("verify: run_ctest returns an error if no build dir found", "[verify][verify001]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    // Empty dir has no CTestTestfile.cmake — expect error or empty bundle
    auto r = verify::run_ctest(tmp.path(), cfg);
    // Either an error (no build dir) or a bundle with 0 tests is acceptable
    if (is_ok(r)) {
        REQUIRE(value_of(r).summary.total == 0);
    } else {
        REQUIRE_FALSE(error_of(r).empty());
    }
}
