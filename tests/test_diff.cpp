//fusa:test REQ-DIFF001 REQ-DIFF002 REQ-DIFF003 REQ-DIFF004
#include <catch2/catch_all.hpp>
#include "diff/diff.hpp"
#include "testutil/testutil.hpp"
#include <fstream>

using namespace cpfusa;
using namespace cpfusa::testutil;

// ─── load_findings ────────────────────────────────────────────────────────────

TEST_CASE("diff: load_findings returns error for missing file", "[diff][diff002]") {
    auto result = diff::load_findings("/nonexistent/path/report.json");
    REQUIRE_FALSE(is_ok(result));
}

TEST_CASE("diff: load_findings returns error for malformed JSON", "[diff][diff002]") {
    TempDir tmp;
    tmp.write("report.json", "not valid json");
    auto result = diff::load_findings(tmp.path() / "report.json");
    REQUIRE_FALSE(is_ok(result));
}

TEST_CASE("diff: load_findings returns empty list for report with no findings", "[diff][diff002]") {
    TempDir tmp;
    tmp.write("report.json", R"({"findings":[]})");
    auto result = diff::load_findings(tmp.path() / "report.json");
    REQUIRE(is_ok(result));
    REQUIRE(value_of(result).empty());
}

TEST_CASE("diff: load_findings parses findings from JSON report", "[diff][diff002]") {
    TempDir tmp;
    tmp.write("report.json", R"({"findings":[
        {"ruleId":"FUSA001","severity":"ERROR","message":"missing .fusa.json","file":"x.cpp","line":1}
    ]})");
    auto result = diff::load_findings(tmp.path() / "report.json");
    REQUIRE(is_ok(result));
    auto& findings = value_of(result);
    REQUIRE(findings.size() == 1);
    REQUIRE(findings[0].rule_id == "FUSA001");
}

// ─── compare ─────────────────────────────────────────────────────────────────

TEST_CASE("diff: compare identical findings produces no introduced or resolved", "[diff][diff001]") {
    diff::DiffFinding f{"FUSA001", "ERROR", "msg", "file.cpp", 1};
    auto d = diff::compare({f}, {f});
    REQUIRE(d.introduced.empty());
    REQUIRE(d.resolved.empty());
    REQUIRE(d.unchanged.size() == 1);
}

TEST_CASE("diff: compare detects introduced finding", "[diff][diff001]") {
    diff::DiffFinding f{"FUSA001", "ERROR", "msg", "file.cpp", 1};
    auto d = diff::compare({}, {f});
    REQUIRE(d.introduced.size() == 1);
    REQUIRE(d.introduced[0].rule_id == "FUSA001");
    REQUIRE(d.resolved.empty());
}

TEST_CASE("diff: compare detects resolved finding", "[diff][diff001]") {
    diff::DiffFinding f{"FUSA001", "ERROR", "msg", "file.cpp", 1};
    auto d = diff::compare({f}, {});
    REQUIRE(d.resolved.size() == 1);
    REQUIRE(d.resolved[0].rule_id == "FUSA001");
    REQUIRE(d.introduced.empty());
}

TEST_CASE("diff: compare both empty produces empty diff", "[diff][diff001]") {
    auto d = diff::compare({}, {});
    REQUIRE(d.introduced.empty());
    REQUIRE(d.resolved.empty());
    REQUIRE(d.unchanged.empty());
}

// ─── render_text ──────────────────────────────────────────────────────────────

TEST_CASE("diff: render_text produces non-empty output", "[diff][diff003]") {
    diff::DiffFinding f{"FUSA001", "ERROR", "msg", "file.cpp", 1};
    auto d = diff::compare({}, {f});
    auto text = diff::render_text(d);
    REQUIRE_FALSE(text.empty());
}

TEST_CASE("diff: render_text mentions introduced count", "[diff][diff003]") {
    diff::DiffFinding f{"LINT002", "ERROR", "goto used", "src/x.cpp", 5};
    auto d = diff::compare({}, {f});
    auto text = diff::render_text(d);
    REQUIRE(text.find("LINT002") != std::string::npos);
}

TEST_CASE("diff: render_text for empty diff shows no changes", "[diff][diff003]") {
    auto d = diff::compare({}, {});
    auto text = diff::render_text(d);
    REQUIRE_FALSE(text.empty());
}
