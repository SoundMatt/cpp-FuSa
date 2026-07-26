//fusa:test REQ-COV001 REQ-COV002 REQ-COV003 REQ-COV004 REQ-COV005
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

// ─── MC/DC coverage (REQ-COV004, REQ-COV005) ──────────────────────────────────

static const char* MCDC_JSON_COVERED =
    R"({"mcdc_records":[{"function_name":"compute","conditions":[{"covered_true_count":3,"covered_false_count":2},{"covered_true_count":1,"covered_false_count":4}]}]})";

static const char* MCDC_JSON_PARTIAL =
    R"({"mcdc_records":[{"function_name":"risky","conditions":[{"covered_true_count":1,"covered_false_count":0}]}]})";

static const char* MCDC_JSON_EMPTY =
    R"({"mcdc_records":[]})";

TEST_CASE("coverage: MCDCCondition is_covered when both sides > 0", "[coverage][cov004]") {
    //fusa:test REQ-COV004
    coverage::MCDCCondition c;
    c.covered_true_count  = 1;
    c.covered_false_count = 2;
    REQUIRE(c.is_covered());
}

TEST_CASE("coverage: MCDCCondition not covered when false side is 0", "[coverage][cov004]") {
    //fusa:test REQ-COV004
    coverage::MCDCCondition c;
    c.covered_true_count  = 1;
    c.covered_false_count = 0;
    REQUIRE_FALSE(c.is_covered());
}

TEST_CASE("coverage: apply_mcdc parses covered conditions", "[coverage][cov004]") {
    //fusa:test REQ-COV004
    TempDir tmp;
    tmp.write(coverage::COVERAGE_FILE, LCOV_SAMPLE);
    tmp.write("mcdc.json", MCDC_JSON_COVERED);
    auto r = coverage::build_from_lcov(tmp.path() / coverage::COVERAGE_FILE, coverage::DAL::A);
    coverage::apply_mcdc(r, tmp.path() / "mcdc.json", 100.0);
    REQUIRE(r.mcdc_enabled);
    REQUIRE(r.mcdc_conditions_total == 2);
    REQUIRE(r.mcdc_conditions_covered == 2);
    REQUIRE(r.mcdc_pct == Catch::Approx(100.0).epsilon(0.01));
    REQUIRE(r.meets_mcdc);
}

TEST_CASE("coverage: apply_mcdc fails when condition not covered on both sides", "[coverage][cov004]") {
    //fusa:test REQ-COV004
    TempDir tmp;
    tmp.write(coverage::COVERAGE_FILE, LCOV_SAMPLE);
    tmp.write("mcdc.json", MCDC_JSON_PARTIAL);
    auto r = coverage::build_from_lcov(tmp.path() / coverage::COVERAGE_FILE, coverage::DAL::A);
    coverage::apply_mcdc(r, tmp.path() / "mcdc.json", 100.0);
    REQUIRE(r.mcdc_enabled);
    REQUIRE(r.mcdc_conditions_total == 1);
    REQUIRE(r.mcdc_conditions_covered == 0);
    REQUIRE_FALSE(r.meets_mcdc);
}

TEST_CASE("coverage: apply_mcdc empty records yields 0% and meets_mcdc false at 100 threshold", "[coverage][cov004]") {
    //fusa:test REQ-COV004
    TempDir tmp;
    tmp.write(coverage::COVERAGE_FILE, LCOV_SAMPLE);
    tmp.write("mcdc.json", MCDC_JSON_EMPTY);
    auto r = coverage::build_from_lcov(tmp.path() / coverage::COVERAGE_FILE, coverage::DAL::A);
    coverage::apply_mcdc(r, tmp.path() / "mcdc.json", 100.0);
    REQUIRE(r.mcdc_conditions_total == 0);
    REQUIRE(r.mcdc_pct == Catch::Approx(0.0).epsilon(0.01));
    // 0/0 → 0%, threshold 100 → does not meet
    REQUIRE_FALSE(r.meets_mcdc);
}

TEST_CASE("coverage: write_json includes mcdc block when enabled", "[coverage][cov005]") {
    //fusa:test REQ-COV005
    TempDir tmp;
    tmp.write(coverage::COVERAGE_FILE, LCOV_SAMPLE);
    tmp.write("mcdc.json", MCDC_JSON_COVERED);
    auto r = coverage::build_from_lcov(tmp.path() / coverage::COVERAGE_FILE, coverage::DAL::A);
    coverage::apply_mcdc(r, tmp.path() / "mcdc.json", 100.0);
    auto json_out = tmp.path() / coverage::COVERAGE_REPORT_FILE;
    REQUIRE_NOTHROW(coverage::write_json(json_out, r));
    std::ifstream f(json_out);
    json j; f >> j;
    REQUIRE(j.contains("mcdc"));
    REQUIRE(j["mcdc"]["enabled"] == true);
    REQUIRE(j["mcdc"]["conditionsTotal"] == 2);
    REQUIRE(j["mcdc"]["conditionsCovered"] == 2);
    REQUIRE(j["mcdc"]["meetsMcdc"] == true);
}

TEST_CASE("coverage: write_json mcdc records have per-condition coverage", "[coverage][cov005]") {
    //fusa:test REQ-COV005
    TempDir tmp;
    tmp.write(coverage::COVERAGE_FILE, LCOV_SAMPLE);
    tmp.write("mcdc.json", MCDC_JSON_COVERED);
    auto r = coverage::build_from_lcov(tmp.path() / coverage::COVERAGE_FILE, coverage::DAL::A);
    coverage::apply_mcdc(r, tmp.path() / "mcdc.json", 100.0);
    auto json_out = tmp.path() / coverage::COVERAGE_REPORT_FILE;
    coverage::write_json(json_out, r);
    std::ifstream f(json_out);
    json j; f >> j;
    REQUIRE(j["mcdc"]["records"].is_array());
    REQUIRE(j["mcdc"]["records"].size() == 1);
    REQUIRE(j["mcdc"]["records"][0]["functionName"] == "compute");
    REQUIRE(j["mcdc"]["records"][0]["conditionsTotal"] == 2);
    REQUIRE(j["mcdc"]["records"][0]["fullyCovered"] == true);
}

TEST_CASE("coverage: apply_mcdc throws when file missing", "[coverage][cov004]") {
    //fusa:test REQ-COV004
    TempDir tmp;
    tmp.write(coverage::COVERAGE_FILE, LCOV_SAMPLE);
    auto r = coverage::build_from_lcov(tmp.path() / coverage::COVERAGE_FILE, coverage::DAL::D);
    REQUIRE_THROWS(coverage::apply_mcdc(r, tmp.path() / "nonexistent.json", 100.0));
}

TEST_CASE("coverage: MCDCRecord fully_covered when all conditions covered", "[coverage][cov004]") {
    //fusa:test REQ-COV004
    coverage::MCDCRecord rec;
    coverage::MCDCCondition c1; c1.covered_true_count = 1; c1.covered_false_count = 1;
    coverage::MCDCCondition c2; c2.covered_true_count = 2; c2.covered_false_count = 3;
    rec.conditions = {c1, c2};
    REQUIRE(rec.fully_covered());
    REQUIRE(rec.covered_conditions() == 2);
}

TEST_CASE("coverage: MCDCRecord not fully_covered when one condition missing", "[coverage][cov004]") {
    //fusa:test REQ-COV004
    coverage::MCDCRecord rec;
    coverage::MCDCCondition c1; c1.covered_true_count = 1; c1.covered_false_count = 1;
    coverage::MCDCCondition c2; c2.covered_true_count = 1; c2.covered_false_count = 0; // not covered
    rec.conditions = {c1, c2};
    REQUIRE_FALSE(rec.fully_covered());
    REQUIRE(rec.covered_conditions() == 1);
}
