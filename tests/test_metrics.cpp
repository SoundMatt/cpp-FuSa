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
