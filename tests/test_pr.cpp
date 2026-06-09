//fusa:test REQ-PR001 REQ-PR002 REQ-PR003
#include <catch2/catch_all.hpp>
#include "pr/pr.hpp"
#include "testutil/testutil.hpp"
#include <nlohmann/json.hpp>
#include <fstream>

using namespace cpfusa;
using namespace cpfusa::testutil;
using json = nlohmann::json;

// ─── status_str / severity_str ────────────────────────────────────────────────

TEST_CASE("pr: status_str Open", "[pr][pr001]") {
    REQUIRE(pr::status_str(pr::PRStatus::Open) == "open");
}

TEST_CASE("pr: status_str Closed", "[pr][pr001]") {
    REQUIRE(pr::status_str(pr::PRStatus::Closed) == "closed");
}

TEST_CASE("pr: severity_str Critical", "[pr][pr001]") {
    REQUIRE(pr::severity_str(pr::PRSeverity::Critical) == "critical");
}

TEST_CASE("pr: parse_status roundtrip", "[pr][pr001]") {
    REQUIRE(pr::parse_status("open") == pr::PRStatus::Open);
    REQUIRE(pr::parse_status("closed") == pr::PRStatus::Closed);
}

TEST_CASE("pr: parse_severity roundtrip", "[pr][pr001]") {
    REQUIRE(pr::parse_severity("major") == pr::PRSeverity::Major);
    REQUIRE(pr::parse_severity("minor") == pr::PRSeverity::Minor);
}

// ─── load ─────────────────────────────────────────────────────────────────────

TEST_CASE("pr: load returns empty log when file missing", "[pr][pr002]") {
    TempDir tmp;
    auto log = pr::load(tmp.path());
    REQUIRE(log.reports.empty());
}

TEST_CASE("pr: load after save roundtrip preserves entries", "[pr][pr002]") {
    TempDir tmp;
    pr::PRLog log;
    pr::ProblemReport report;
    report.id = "PR-001";
    report.title = "Test problem";
    report.severity = pr::PRSeverity::Major;
    report.status = pr::PRStatus::Open;
    log = pr::add(log, report);
    std::string err;
    REQUIRE(pr::save(tmp.path() / pr::PR_FILE, log, err));
    auto loaded = pr::load(tmp.path());
    REQUIRE(loaded.reports.size() == 1);
    REQUIRE(loaded.reports[0].id == "PR-001");
}

// ─── save ─────────────────────────────────────────────────────────────────────

TEST_CASE("pr: save creates valid JSON", "[pr][pr002]") {
    TempDir tmp;
    pr::PRLog log;
    std::string err;
    REQUIRE(pr::save(tmp.path() / pr::PR_FILE, log, err));
    std::ifstream f(tmp.path() / pr::PR_FILE);
    json j;
    REQUIRE_NOTHROW(f >> j);
    REQUIRE(j.contains("reports"));
}

TEST_CASE("pr: save fails on invalid path", "[pr][pr002]") {
    pr::PRLog log;
    std::string err;
    REQUIRE_FALSE(pr::save("/no/such/dir/pr.json", log, err));
    REQUIRE_FALSE(err.empty());
}

// ─── add ─────────────────────────────────────────────────────────────────────

TEST_CASE("pr: add increases report count", "[pr][pr003]") {
    pr::PRLog log;
    pr::ProblemReport r1, r2;
    r1.id = "PR-001"; r2.id = "PR-002";
    log = pr::add(log, r1);
    log = pr::add(log, r2);
    REQUIRE(log.reports.size() == 2);
}
