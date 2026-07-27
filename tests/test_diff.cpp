//fusa:test REQ-DIFF001
//fusa:test REQ-DIFF002
//fusa:test REQ-DIFF003
//fusa:test REQ-DIFF004
#include <catch2/catch_all.hpp>
#include "diff/diff.hpp"
#include "testutil/testutil.hpp"
#include <fstream>
#include <nlohmann/json.hpp>

using namespace cpfusa;
using namespace cpfusa::testutil;
using json = nlohmann::json;

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

// ─── load_findings — location-object format ───────────────────────────────────

TEST_CASE("diff: load_findings parses nested location object format", "[diff][diff002]") {
    TempDir tmp;
    tmp.write("report.json", R"({
        "findings": [
            {
                "ruleId": "LINT001",
                "severity": "WARNING",
                "message": "raw new",
                "location": {"file": "src/foo.cpp", "line": 10}
            }
        ]
    })");
    auto result = diff::load_findings(tmp.path() / "report.json");
    REQUIRE(is_ok(result));
    const auto& findings = value_of(result);
    REQUIRE(findings.size() == 1);
    REQUIRE(findings[0].rule_id == "LINT001");
    REQUIRE(findings[0].file == "src/foo.cpp");
    REQUIRE(findings[0].line == 10);
}

TEST_CASE("diff: load_findings also accepts snake_case rule_id key", "[diff][diff002]") {
    TempDir tmp;
    tmp.write("report.json", R"({
        "findings": [
            {"rule_id": "FUSA002", "severity": "ERROR", "message": "m", "file": "x.cpp", "line": 5}
        ]
    })");
    auto result = diff::load_findings(tmp.path() / "report.json");
    REQUIRE(is_ok(result));
    REQUIRE(value_of(result)[0].rule_id == "FUSA002");
}

TEST_CASE("diff: load_findings returns empty vector when no findings key", "[diff][diff002]") {
    TempDir tmp;
    tmp.write("report.json", R"({"kind":"check-report","summary":{"total":0}})");
    auto result = diff::load_findings(tmp.path() / "report.json");
    REQUIRE(is_ok(result));
    REQUIRE(value_of(result).empty());
}

// ─── render_json ─────────────────────────────────────────────────────────────

TEST_CASE("diff: render_json produces valid JSON", "[diff][diff003]") {
    diff::DiffFinding f{"LINT001", "WARNING", "msg", "src/foo.cpp", 3};
    auto d = diff::compare({}, {f});
    auto text = diff::render_json(d);
    REQUIRE_NOTHROW(json::parse(text));
}

TEST_CASE("diff: render_json has introduced, resolved, unchanged keys", "[diff][diff003]") {
    diff::DiffFinding f{"LINT001", "WARNING", "msg", "src/foo.cpp", 3};
    auto d = diff::compare({}, {f});
    auto j = json::parse(diff::render_json(d));
    REQUIRE(j.contains("introduced"));
    REQUIRE(j.contains("resolved"));
    REQUIRE(j.contains("unchanged"));
}

TEST_CASE("diff: render_json introduced entry has expected fields", "[diff][diff004]") {
    diff::DiffFinding f{"ANAL003", "ERROR", "global write", "src/g.cpp", 7};
    auto d = diff::compare({}, {f});
    auto j = json::parse(diff::render_json(d));
    REQUIRE(j["introduced"].size() == 1);
    const auto& entry = j["introduced"][0];
    REQUIRE(entry["ruleId"] == "ANAL003");
    REQUIRE(entry["file"]   == "src/g.cpp");
    REQUIRE(entry["line"]   == 7);
}

TEST_CASE("diff: compare key uniqueness: same rule/file/line is unchanged", "[diff][diff001]") {
    diff::DiffFinding f1{"FUSA001", "ERROR", "no config", ".", 0};
    diff::DiffFinding f2{"FUSA001", "ERROR", "no config updated", ".", 0};
    // Same key → unchanged (only key matters, not message)
    auto d = diff::compare({f1}, {f2});
    REQUIRE(d.unchanged.size() == 1);
    REQUIRE(d.introduced.empty());
    REQUIRE(d.resolved.empty());
}
