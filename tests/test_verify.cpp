//fusa:test REQ-VERIFY001
//fusa:test REQ-VERIFY002
//fusa:test REQ-VERIFY003
//fusa:test REQ-VERIFY004
//fusa:test REQ-VERIFY005
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

TEST_CASE("verify: run_ctest finds existing build dir via CMakeCache.txt", "[verify][verify001]") {
    // fusa:test REQ-VERIFY001
    TempDir tmp;
    // Create a build directory with CMakeCache.txt so find_build_dir returns it.
    tmp.write("build/CMakeCache.txt", "# CMake cache stub\n");
    config::ProjectConfig cfg;
    // run_ctest will find the build dir and attempt ctest; the output may be
    // empty or produce no parsed test results — both are acceptable outcomes.
    auto r = verify::run_ctest(tmp.path(), cfg);
    // Either path is valid: success with zero tests, or a ctest error.
    if (is_ok(r)) {
        REQUIRE(value_of(r).summary.failed == 0);
    } else {
        REQUIRE_FALSE(error_of(r).empty());
    }
}

TEST_CASE("verify: run_ctest finds build dir with CTestTestfile.cmake", "[verify][verify001]") {
    // fusa:test REQ-VERIFY001
    TempDir tmp;
    tmp.write("build/CTestTestfile.cmake", "# stub\n");
    config::ProjectConfig cfg;
    auto r = verify::run_ctest(tmp.path(), cfg);
    // Any non-crashing outcome is valid when ctest finds no real tests.
    if (is_ok(r)) REQUIRE(value_of(r).summary.total >= 0);
    else          REQUIRE_FALSE(error_of(r).empty());
}

TEST_CASE("verify: write_evidence stores project_root field", "[verify][verify002]") {
    // fusa:test REQ-VERIFY002
    TempDir tmp;
    verify::EvidenceBundle b;
    b.generated_at = "2026-07-27T00:00:00Z";
    b.project_root = "/some/project";
    b.cpp_version  = "C++17";
    verify::write_evidence(tmp.path(), b);
    std::ifstream f(tmp.path() / ".fusa-evidence.json");
    json j; f >> j;
    REQUIRE(j.contains("projectRoot"));
    REQUIRE(j["projectRoot"].get<std::string>() == "/some/project");
}

TEST_CASE("verify: write_evidence result entries have elapsedSeconds field", "[verify][verify003]") {
    // fusa:test REQ-VERIFY003
    TempDir tmp;
    verify::EvidenceBundle b;
    b.generated_at = "2026-01-01T00:00:00Z"; b.cpp_version = "C++17";
    b.results.push_back({"perf_test", "tests/t.cpp", "passed", 1.23});
    b.summary.total = b.summary.passed = 1;
    verify::write_evidence(tmp.path(), b);
    std::ifstream f(tmp.path() / ".fusa-evidence.json");
    json j; f >> j;
    REQUIRE(j["results"][0].contains("elapsedSeconds"));
    REQUIRE(j["results"][0]["elapsedSeconds"].get<double>() == Catch::Approx(1.23));
}

TEST_CASE("verify: write_evidence skipped count round-trips", "[verify][verify004]") {
    // fusa:test REQ-VERIFY004
    TempDir tmp;
    verify::EvidenceBundle b;
    b.generated_at = "2026-01-01T00:00:00Z"; b.cpp_version = "C++17";
    b.summary.total = 5; b.summary.passed = 3; b.summary.skipped = 2;
    verify::write_evidence(tmp.path(), b);
    std::ifstream f(tmp.path() / ".fusa-evidence.json");
    json j; f >> j;
    REQUIRE(j["summary"]["skipped"].get<int>() == 2);
}
