//fusa:test REQ-COV001 REQ-COV002 REQ-COV003
#include <catch2/catch_all.hpp>
#include "coverage/coverage.hpp"
#include "testutil/testutil.hpp"
#include <nlohmann/json.hpp>
#include <fstream>

using namespace cpfusa;
using namespace cpfusa::testutil;
using json = nlohmann::json;

static const char* LCOV_SAMPLE =
    "SF:src/engine/engine.cpp\n"
    "LF:100\n"
    "LH:85\n"
    "BRF:40\n"
    "BRH:30\n"
    "end_of_record\n"
    "SF:src/config/config.cpp\n"
    "LF:50\n"
    "LH:50\n"
    "BRF:20\n"
    "BRH:20\n"
    "end_of_record\n";

// ─── parse_dal / dal_str ──────────────────────────────────────────────────────

TEST_CASE("coverage: parse_dal A returns DAL::A", "[coverage][cov001]") {
    REQUIRE(coverage::parse_dal("A") == coverage::DAL::A);
    REQUIRE(coverage::parse_dal("DAL-A") == coverage::DAL::A);
}

TEST_CASE("coverage: dal_str roundtrip", "[coverage][cov001]") {
    REQUIRE(coverage::dal_str(coverage::parse_dal("B")) == "DAL-B");
    REQUIRE(coverage::dal_str(coverage::parse_dal("D")) == "DAL-D");
}

// ─── build_from_lcov ─────────────────────────────────────────────────────────

TEST_CASE("coverage: build_from_lcov parses two files", "[coverage][cov002]") {
    TempDir tmp;
    tmp.write(coverage::COVERAGE_FILE, LCOV_SAMPLE);
    auto r = coverage::build_from_lcov(tmp.path() / coverage::COVERAGE_FILE, coverage::DAL::C);
    REQUIRE(r.files.size() == 2);
}

TEST_CASE("coverage: build_from_lcov aggregates totals correctly", "[coverage][cov002]") {
    TempDir tmp;
    tmp.write(coverage::COVERAGE_FILE, LCOV_SAMPLE);
    auto r = coverage::build_from_lcov(tmp.path() / coverage::COVERAGE_FILE, coverage::DAL::D);
    REQUIRE(r.total_lines == 150);
    REQUIRE(r.hit_lines == 135);
}

TEST_CASE("coverage: build_from_lcov computes line_pct", "[coverage][cov002]") {
    TempDir tmp;
    tmp.write(coverage::COVERAGE_FILE, LCOV_SAMPLE);
    auto r = coverage::build_from_lcov(tmp.path() / coverage::COVERAGE_FILE, coverage::DAL::D);
    REQUIRE(r.line_pct == Catch::Approx(90.0).epsilon(0.01));
}

TEST_CASE("coverage: DAL-D with 90% line passes meets_dal", "[coverage][cov002]") {
    TempDir tmp;
    tmp.write(coverage::COVERAGE_FILE, LCOV_SAMPLE);
    auto r = coverage::build_from_lcov(tmp.path() / coverage::COVERAGE_FILE, coverage::DAL::D);
    REQUIRE(r.meets_dal);
}

TEST_CASE("coverage: DAL-A with 90% line fails meets_dal", "[coverage][cov002]") {
    TempDir tmp;
    tmp.write(coverage::COVERAGE_FILE, LCOV_SAMPLE);
    auto r = coverage::build_from_lcov(tmp.path() / coverage::COVERAGE_FILE, coverage::DAL::A);
    REQUIRE_FALSE(r.meets_dal);
}

TEST_CASE("coverage: missing file throws", "[coverage][cov002]") {
    TempDir tmp;
    REQUIRE_THROWS(coverage::build_from_lcov(tmp.path() / "no_such.info", coverage::DAL::D));
}

TEST_CASE("coverage: generated_at is non-empty", "[coverage][cov001]") {
    TempDir tmp;
    tmp.write(coverage::COVERAGE_FILE, LCOV_SAMPLE);
    auto r = coverage::build_from_lcov(tmp.path() / coverage::COVERAGE_FILE, coverage::DAL::D);
    REQUIRE_FALSE(r.generated_at.empty());
}

// ─── write_json ───────────────────────────────────────────────────────────────

TEST_CASE("coverage: write_json creates valid JSON", "[coverage][cov003]") {
    TempDir tmp;
    tmp.write(coverage::COVERAGE_FILE, LCOV_SAMPLE);
    auto r = coverage::build_from_lcov(tmp.path() / coverage::COVERAGE_FILE, coverage::DAL::C);
    auto out = tmp.path() / coverage::COVERAGE_REPORT_FILE;
    REQUIRE_NOTHROW(coverage::write_json(out, r));
    std::ifstream f(out);
    json j;
    REQUIRE_NOTHROW(f >> j);
    REQUIRE(j.contains("linePct"));
    REQUIRE(j.contains("files"));
}

TEST_CASE("coverage: JSON has correct dal field", "[coverage][cov003]") {
    TempDir tmp;
    tmp.write(coverage::COVERAGE_FILE, LCOV_SAMPLE);
    auto r = coverage::build_from_lcov(tmp.path() / coverage::COVERAGE_FILE, coverage::DAL::C);
    coverage::write_json(tmp.path() / coverage::COVERAGE_REPORT_FILE, r);
    std::ifstream f(tmp.path() / coverage::COVERAGE_REPORT_FILE);
    json j; f >> j;
    REQUIRE(j["dal"].get<std::string>() == "DAL-C");
}
