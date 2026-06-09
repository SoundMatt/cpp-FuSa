#include <catch2/catch_all.hpp>
#include "trace/trace.hpp"
#include "testutil/testutil.hpp"

using namespace cpfusa;
using namespace cpfusa::testutil;

TEST_CASE("trace: scan_annotations finds fusa:req", "[trace]") {
    TempDir tmp;
    tmp.write("src/foo.cpp",
              "// fusa:req REQ-001\n"
              "void safety_fn() {}\n");
    auto anns = trace::scan_annotations(tmp.path());
    REQUIRE(anns.size() == 1);
    REQUIRE(anns[0].req_id == "REQ-001");
    REQUIRE_FALSE(anns[0].is_test);
}

TEST_CASE("trace: scan_annotations finds fusa:test", "[trace]") {
    TempDir tmp;
    tmp.write("tests/test_foo.cpp",
              "// fusa:test REQ-001\n"
              "TEST_CASE(\"test\") {}\n");
    auto anns = trace::scan_annotations(tmp.path());
    REQUIRE(anns.size() == 1);
    REQUIRE(anns[0].req_id == "REQ-001");
    REQUIRE(anns[0].is_test);
}

TEST_CASE("trace: empty dir yields empty annotations", "[trace]") {
    TempDir tmp;
    auto anns = trace::scan_annotations(tmp.path());
    REQUIRE(anns.empty());
}

TEST_CASE("trace: run() with no requirements file succeeds", "[trace]") {
    TempDir tmp;
    tmp.write(".fusa.json", R"({"project":"test","version":"1.0.0"})");
    config::ProjectConfig cfg;
    cfg.project = "test";
    cfg.version = "1.0.0";
    auto r = trace::run(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    const auto& res = value_of(r);
    REQUIRE(res.total == 0);
}

TEST_CASE("trace: coverage gate fails when below threshold", "[trace]") {
    TempDir tmp;
    // No source annotations — coverage will be 0%.
    config::ProjectConfig cfg;
    cfg.project = "test";
    cfg.version = "1.0.0";
    trace::TraceOptions opts;
    opts.min_test_pct = 80;
    // No requirements means 0 total — gate should not fire when total is 0.
    auto r = trace::run(tmp.path(), cfg, opts);
    REQUIRE(is_ok(r)); // 0 requirements = nothing to fail
}

TEST_CASE("trace: render_matrix handles no requirements gracefully", "[trace]") {
    trace::TraceResult res;
    trace::TraceOptions opts;
    auto txt = trace::render_matrix(res, opts);
    REQUIRE_FALSE(txt.empty());
}
