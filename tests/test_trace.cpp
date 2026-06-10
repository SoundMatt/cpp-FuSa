//fusa:test REQ-TRACE001 REQ-TRACE002 REQ-TRACE003 REQ-TRACE004 REQ-TRACE005 REQ-TRACE006 REQ-TRACE007
#include <catch2/catch_all.hpp>
#include "trace/trace.hpp"
#include "testutil/testutil.hpp"

using namespace cpfusa;
using namespace cpfusa::testutil;

// ─── scan_annotations ────────────────────────────────────────────────────────

TEST_CASE("trace: scan_annotations finds fusa:req", "[trace][trace001]") {
    TempDir tmp;
    tmp.write("src/foo.cpp",
              "// fusa:req REQ-001\n"
              "void safety_fn() {}\n");
    auto anns = trace::scan_annotations(tmp.path());
    REQUIRE(anns.size() == 1);
    REQUIRE(anns[0].req_id == "REQ-001");
    REQUIRE_FALSE(anns[0].is_test);
}

TEST_CASE("trace: scan_annotations finds fusa:test", "[trace][trace001]") {
    TempDir tmp;
    tmp.write("tests/test_foo.cpp",
              "// fusa:test REQ-001\n"
              "TEST_CASE(\"test\") {}\n");
    auto anns = trace::scan_annotations(tmp.path());
    REQUIRE(anns.size() == 1);
    REQUIRE(anns[0].req_id == "REQ-001");
    REQUIRE(anns[0].is_test);
}

TEST_CASE("trace: scan_annotations finds multiple reqs in one file", "[trace][trace001]") {
    TempDir tmp;
    tmp.write("src/foo.cpp",
              "// fusa:req REQ-001\n"
              "void fn1() {}\n"
              "// fusa:req REQ-002\n"
              "void fn2() {}\n");
    auto anns = trace::scan_annotations(tmp.path());
    REQUIRE(anns.size() == 2);
}

TEST_CASE("trace: scan_annotations empty dir yields empty list", "[trace][trace001]") {
    TempDir tmp;
    REQUIRE(trace::scan_annotations(tmp.path()).empty());
}

TEST_CASE("trace: scan_annotations finds annotations in both src and tests", "[trace][trace002]") {
    TempDir tmp;
    tmp.write("src/a.cpp",  "// fusa:req REQ-001\nvoid a() {}\n");
    tmp.write("tests/t.cpp","// fusa:test REQ-001\nTEST_CASE(\"t\"){}\n");
    auto anns = trace::scan_annotations(tmp.path());
    bool found_req = false, found_test = false;
    for (const auto& a : anns) {
        if (!a.is_test) found_req  = true;
        else            found_test = true;
    }
    REQUIRE(found_req);
    REQUIRE(found_test);
}

// ─── load_requirements ────────────────────────────────────────────────────────

TEST_CASE("trace: load_requirements returns empty when file absent", "[trace][trace003]") {
    TempDir tmp;
    auto r = trace::load_requirements(tmp.path());
    REQUIRE(is_ok(r));
    REQUIRE(value_of(r).empty());
}

TEST_CASE("trace: load_requirements parses flat JSON array", "[trace][trace003]") {
    TempDir tmp;
    // load_requirements expects a flat JSON array (not wrapped in {"requirements":[...]})
    tmp.write(".fusa-reqs.json", R"([
      {"id":"REQ-001","title":"Config must exist","severity":"safety"},
      {"id":"REQ-002","title":"Version must be set","severity":"safety"}
    ])");
    auto r = trace::load_requirements(tmp.path());
    REQUIRE(is_ok(r));
    REQUIRE(value_of(r).size() == 2);
    REQUIRE(value_of(r)[0].id == "REQ-001");
    REQUIRE(value_of(r)[1].id == "REQ-002");
}

TEST_CASE("trace: load_requirements reads title field", "[trace][trace003]") {
    TempDir tmp;
    tmp.write(".fusa-reqs.json", R"([{"id":"REQ-001","title":"Safety config","severity":"safety"}])");
    auto reqs = value_of(trace::load_requirements(tmp.path()));
    REQUIRE(reqs[0].title == "Safety config");
}

// ─── run ─────────────────────────────────────────────────────────────────────

TEST_CASE("trace: run with no requirements file succeeds", "[trace][trace004]") {
    TempDir tmp;
    config::ProjectConfig cfg; cfg.project = "test"; cfg.version = "1.0.0";
    auto r = trace::run(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    REQUIRE(value_of(r).total == 0);
}

TEST_CASE("trace: run counts annotation coverage", "[trace][trace004]") {
    TempDir tmp;
    tmp.write(".fusa-reqs.json", R"([{"id":"REQ-001","title":"T","severity":"safety"}])");
    tmp.write("src/a.cpp", "//fusa:req REQ-001\nvoid f(){}\n");
    config::ProjectConfig cfg; cfg.project = "p"; cfg.version = "1.0.0";
    auto r = trace::run(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    REQUIRE(value_of(r).total == 1);
}

TEST_CASE("trace: coverage gate does not fail when total is 0", "[trace][trace005]") {
    TempDir tmp;
    config::ProjectConfig cfg; cfg.project = "test"; cfg.version = "1.0.0";
    trace::TraceOptions opts; opts.min_test_pct = 80;
    REQUIRE(is_ok(trace::run(tmp.path(), cfg, opts)));
}

// ─── render_matrix ────────────────────────────────────────────────────────────

TEST_CASE("trace: render_matrix handles no requirements gracefully", "[trace][trace006]") {
    trace::TraceResult res; trace::TraceOptions opts;
    REQUIRE_FALSE(trace::render_matrix(res, opts).empty());
}

TEST_CASE("trace: render_matrix contains req IDs when present", "[trace][trace006]") {
    TempDir tmp;
    tmp.write(".fusa-reqs.json", R"([{"id":"REQ-001","title":"T","severity":"safety"}])");
    config::ProjectConfig cfg; cfg.project = "p"; cfg.version = "1.0.0";
    auto res = value_of(trace::run(tmp.path(), cfg));
    auto txt = trace::render_matrix(res, {});
    REQUIRE(txt.find("REQ-001") != std::string::npos);
}

// ─── render_req ──────────────────────────────────────────────────────────────

TEST_CASE("trace: render_req includes req ID in output", "[trace][trace007]") {
    trace::Requirement req;
    req.id    = "REQ-042";
    req.title = "Something important";
    auto anns = trace::scan_annotations(TempDir{}.path());
    REQUIRE(trace::render_req(req, anns).find("REQ-042") != std::string::npos);
}
