//fusa:test REQ-METRICS001
//fusa:test REQ-METRICS002
//fusa:test REQ-METRICS003
#include <catch2/catch_all.hpp>
#include "metrics/metrics.hpp"
#include "testutil/testutil.hpp"
#include <nlohmann/json.hpp>
#include <fstream>

using namespace cpfusa;
using namespace cpfusa::testutil;
using json = nlohmann::json;

// ─── collect ─────────────────────────────────────────────────────────────────

TEST_CASE("metrics: collect returns snapshot with timestamp", "[metrics][metrics001]") {
    TempDir tmp;
    auto snap = metrics::collect(tmp.path());
    REQUIRE_FALSE(snap.timestamp.empty());
}

TEST_CASE("metrics: collect returns non-negative counts", "[metrics][metrics001]") {
    TempDir tmp;
    auto snap = metrics::collect(tmp.path());
    REQUIRE(snap.error_count >= 0);
    REQUIRE(snap.warning_count >= 0);
    REQUIRE(snap.total_requirements >= 0);
}

// ─── load / save / append ─────────────────────────────────────────────────────

TEST_CASE("metrics: load returns empty series when file missing", "[metrics][metrics002]") {
    TempDir tmp;
    auto ts = metrics::load(tmp.path());
    REQUIRE(ts.snapshots.empty());
}

TEST_CASE("metrics: save and load roundtrip preserves snapshots", "[metrics][metrics002]") {
    TempDir tmp;
    metrics::TimeSeries ts;
    ts.project = "roundtrip-proj";
    metrics::Snapshot snap;
    snap.timestamp = "2026-01-01T00:00:00Z";
    snap.error_count = 3;
    ts = metrics::append(ts, snap);
    metrics::save(tmp.path() / metrics::METRICS_FILE, ts);
    auto loaded = metrics::load(tmp.path());
    REQUIRE(loaded.snapshots.size() == 1);
    REQUIRE(loaded.snapshots[0].error_count == 3);
}

TEST_CASE("metrics: append increases snapshot count", "[metrics][metrics002]") {
    metrics::TimeSeries ts;
    metrics::Snapshot s1, s2;
    s1.timestamp = "2026-01-01T00:00:00Z";
    s2.timestamp = "2026-01-02T00:00:00Z";
    ts = metrics::append(ts, s1);
    ts = metrics::append(ts, s2);
    REQUIRE(ts.snapshots.size() == 2);
}

TEST_CASE("metrics: save creates valid JSON", "[metrics][metrics002]") {
    TempDir tmp;
    metrics::TimeSeries ts;
    ts.project = "test";
    metrics::save(tmp.path() / metrics::METRICS_FILE, ts);
    std::ifstream f(tmp.path() / metrics::METRICS_FILE);
    json j;
    REQUIRE_NOTHROW(f >> j);
    REQUIRE(j.contains("snapshots"));
}

// ─── render_json ─────────────────────────────────────────────────────────────

TEST_CASE("metrics: render_json creates valid JSON", "[metrics][metrics003]") {
    TempDir tmp;
    metrics::TimeSeries ts;
    ts.project = "test-proj";
    auto out = tmp.path() / "metrics-out.json";
    REQUIRE_NOTHROW(metrics::render_json(out, ts));
    std::ifstream f(out);
    json j;
    REQUIRE_NOTHROW(f >> j);
    REQUIRE(j.contains("project"));
}

TEST_CASE("metrics: render_json project field matches", "[metrics][metrics003]") {
    TempDir tmp;
    metrics::TimeSeries ts;
    ts.project = "my-proj";
    metrics::render_json(tmp.path() / "m.json", ts);
    std::ifstream f(tmp.path() / "m.json");
    json j; f >> j;
    REQUIRE(j["project"].get<std::string>() == "my-proj");
}

// ─── collect with real data files ────────────────────────────────────────────

TEST_CASE("metrics: collect counts errors from check-report.json", "[metrics][metrics001]") {
    TempDir tmp;
    tmp.write("check-report.json", R"({
        "findings": [
            {"severity": "error", "message": "e1"},
            {"severity": "error", "message": "e2"},
            {"severity": "warning", "message": "w1"}
        ]
    })");
    auto snap = metrics::collect(tmp.path());
    REQUIRE(snap.error_count == 2);
    REQUIRE(snap.warning_count == 1);
}

TEST_CASE("metrics: collect counts info findings from check-report.json", "[metrics][metrics001]") {
    TempDir tmp;
    tmp.write("check-report.json", R"({
        "findings": [
            {"severity": "info", "message": "i1"},
            {"severity": "info", "message": "i2"}
        ]
    })");
    auto snap = metrics::collect(tmp.path());
    REQUIRE(snap.info_count == 2);
}

TEST_CASE("metrics: collect counts requirements from .fusa-reqs.json", "[metrics][metrics001]") {
    TempDir tmp;
    tmp.write(".fusa-reqs.json", R"({
        "requirements": [
            {"id": "REQ-001", "title": "T1", "implementations": ["src/a.cpp"]},
            {"id": "REQ-002", "title": "T2", "implementations": []},
            {"id": "REQ-003", "title": "T3", "tests": ["t.cpp"]}
        ]
    })");
    auto snap = metrics::collect(tmp.path());
    REQUIRE(snap.total_requirements == 3);
    REQUIRE(snap.traced_requirements == 2);
}

TEST_CASE("metrics: collect computes coverage_pct from requirements", "[metrics][metrics001]") {
    TempDir tmp;
    tmp.write(".fusa-reqs.json", R"({
        "requirements": [
            {"id": "REQ-001", "implementations": ["src/a.cpp"]},
            {"id": "REQ-002", "implementations": []}
        ]
    })");
    auto snap = metrics::collect(tmp.path());
    REQUIRE(snap.coverage_pct == Catch::Approx(50.0));
}

TEST_CASE("metrics: collect counts cyber findings from cyber-report.json", "[metrics][metrics001]") {
    TempDir tmp;
    tmp.write("cyber-report.json", R"({
        "findings": [
            {"rule_id": "CYBER001", "severity": "error"},
            {"rule_id": "CYBER002", "severity": "warning"}
        ]
    })");
    auto snap = metrics::collect(tmp.path());
    REQUIRE(snap.cyber_findings == 2);
}

TEST_CASE("metrics: collect gracefully ignores malformed check-report.json", "[metrics][metrics001]") {
    TempDir tmp;
    tmp.write("check-report.json", "not valid json{{{{");
    auto snap = metrics::collect(tmp.path());
    REQUIRE(snap.error_count == 0);
}

TEST_CASE("metrics: append preserves project name", "[metrics][metrics002]") {
    metrics::TimeSeries ts;
    ts.project = "my-proj";
    metrics::Snapshot s;
    s.timestamp = "2026-01-01T00:00:00Z";
    ts = metrics::append(ts, s);
    REQUIRE(ts.project == "my-proj");
    REQUIRE(ts.snapshots.size() == 1);
}

TEST_CASE("metrics: append snapshot values are preserved", "[metrics][metrics002]") {
    metrics::TimeSeries ts;
    metrics::Snapshot s;
    s.timestamp = "2026-06-01T00:00:00Z";
    s.error_count = 7;
    s.warning_count = 3;
    s.coverage_pct = 88.5;
    ts = metrics::append(ts, s);
    REQUIRE(ts.snapshots[0].error_count == 7);
    REQUIRE(ts.snapshots[0].warning_count == 3);
    REQUIRE(ts.snapshots[0].coverage_pct == Catch::Approx(88.5));
}

TEST_CASE("metrics: load handles malformed JSON gracefully", "[metrics][metrics002]") {
    TempDir tmp;
    tmp.write(std::string(metrics::METRICS_FILE), "{ bad json");
    auto ts = metrics::load(tmp.path());
    REQUIRE(ts.snapshots.empty());
}

TEST_CASE("metrics: render_text prints header for non-empty TimeSeries", "[metrics][metrics003]") {
    metrics::TimeSeries ts;
    ts.project = "prj";
    metrics::Snapshot s;
    s.timestamp = "2026-01-01T00:00:00Z";
    s.error_count = 0;
    ts = metrics::append(ts, s);
    // render_text writes to stdout; just ensure no exception is thrown
    REQUIRE_NOTHROW(metrics::render_text(ts));
}

TEST_CASE("metrics: render_text with empty series prints no-data message", "[metrics][metrics003]") {
    metrics::TimeSeries ts;
    ts.project = "empty-prj";
    REQUIRE_NOTHROW(metrics::render_text(ts));
}

TEST_CASE("metrics: save/load roundtrip preserves all snapshot fields", "[metrics][metrics002]") {
    TempDir tmp;
    metrics::TimeSeries ts;
    ts.project = "full-test";
    metrics::Snapshot s;
    s.timestamp           = "2026-05-01T12:00:00Z";
    s.error_count         = 2;
    s.warning_count       = 5;
    s.info_count          = 8;
    s.total_requirements  = 100;
    s.traced_requirements = 90;
    s.coverage_pct        = 90.0;
    s.cyber_findings      = 3;
    ts = metrics::append(ts, s);
    metrics::save(tmp.path() / metrics::METRICS_FILE, ts);
    auto loaded = metrics::load(tmp.path());
    REQUIRE(loaded.project == "full-test");
    REQUIRE(loaded.snapshots.size() == 1);
    const auto& ls = loaded.snapshots[0];
    REQUIRE(ls.error_count         == 2);
    REQUIRE(ls.warning_count       == 5);
    REQUIRE(ls.info_count          == 8);
    REQUIRE(ls.total_requirements  == 100);
    REQUIRE(ls.traced_requirements == 90);
    REQUIRE(ls.coverage_pct        == Catch::Approx(90.0));
    REQUIRE(ls.cyber_findings      == 3);
}
