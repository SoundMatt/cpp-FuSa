//fusa:test REQ-RPT001
//fusa:test REQ-RPT002
//fusa:test REQ-RPT003
//fusa:test REQ-RPT004
//fusa:test REQ-RPT005
//fusa:test REQ-RPT006
//fusa:test REQ-RPT007
//fusa:test REQ-RPT008
#include <catch2/catch_all.hpp>
#include "report/report.hpp"
#include "testutil/testutil.hpp"
#include <nlohmann/json.hpp>
#include <fstream>
#include <filesystem>

using namespace cpfusa;
using namespace cpfusa::testutil;
using json = nlohmann::json;

namespace {
config::ProjectConfig make_cfg() {
    config::ProjectConfig cfg;
    cfg.project      = "TestProject";
    cfg.version      = "1.0.0";
    cfg.standard     = "iso26262";
    cfg.asil         = "ASIL-B";
    cfg.project_root = "/tmp/test";
    return cfg;
}
Finding make_finding() {
    Finding f;
    f.rule_id     = "LINT001";
    f.severity    = Severity::WARNING;
    f.message     = "raw new detected";
    f.file        = "src/foo.cpp";
    f.line        = 42;
    f.column      = 7;
    f.remediation = "Use std::make_unique instead";
    f.category    = "lint";
    f.standard_id = "MISRA-C++:2023";
    f.clause      = "A18-5-2";
    return f;
}
} // namespace

// ─── render_text ──────────────────────────────────────────────────────────────

TEST_CASE("report: render_text with no findings", "[report][rpt001]") {
    REQUIRE(report::render_text({}, make_cfg()).find("No findings") != std::string::npos);
}

TEST_CASE("report: render_text contains finding ruleId and message", "[report][rpt001]") {
    auto txt = report::render_text({make_finding()}, make_cfg());
    REQUIRE(txt.find("LINT001") != std::string::npos);
    REQUIRE(txt.find("raw new detected") != std::string::npos);
    REQUIRE(txt.find("ERROR") == std::string::npos); // it's a WARNING
}

TEST_CASE("report: render_text uses remediation label not fix", "[report][rpt001]") {
    auto txt = report::render_text({make_finding()}, make_cfg());
    REQUIRE(txt.find("remediation:") != std::string::npos);
    REQUIRE(txt.find("fix:") == std::string::npos);
}

TEST_CASE("report: render_text summary counts are correct", "[report][rpt001]") {
    Finding e; e.rule_id = "E"; e.severity = Severity::ERROR;   e.message = "e";
    Finding w; w.rule_id = "W"; w.severity = Severity::WARNING; w.message = "w";
    Finding i; i.rule_id = "I"; i.severity = Severity::INFO;    i.message = "i";
    auto txt = report::render_text({e, w, i}, make_cfg());
    REQUIRE(txt.find("1 error(s)") != std::string::npos);
    REQUIRE(txt.find("1 warning(s)") != std::string::npos);
    REQUIRE(txt.find("1 info(s)") != std::string::npos);
}

// ─── render_json — spec v1.10.12 envelope and finding schema ──────────────────

TEST_CASE("render_json: schemaVersion is 1.10.12", "[report][rpt002]") {
    auto j = json::parse(report::render_json({}, make_cfg()));
    REQUIRE(j["schemaVersion"] == std::string(SpecVersion));
}

TEST_CASE("render_json: kind is check-report", "[report][rpt002]") {
    auto j = json::parse(report::render_json({}, make_cfg()));
    REQUIRE(j["kind"] == "check-report");
}

TEST_CASE("render_json: tool is cpp-FuSa", "[report][rpt002]") {
    auto j = json::parse(report::render_json({}, make_cfg()));
    REQUIRE(j["tool"] == "cpp-FuSa");
}

TEST_CASE("render_json: language is cpp", "[report][rpt002]") {
    auto j = json::parse(report::render_json({}, make_cfg()));
    REQUIRE(j["language"] == "cpp");
}

TEST_CASE("render_json: envelope has projectRoot and project", "[report][rpt002]") {
    auto j = json::parse(report::render_json({}, make_cfg()));
    REQUIRE(j.contains("projectRoot"));
    REQUIRE(j["project"] == "TestProject");
}

TEST_CASE("render_json: envelope has asil key for ASIL integrity", "[report][rpt002]") {
    auto j = json::parse(report::render_json({}, make_cfg()));
    REQUIRE(j.contains("asil"));
    REQUIRE(j["asil"] == "ASIL-B");
}

TEST_CASE("render_json: finding uses camelCase ruleId", "[report][rpt003]") {
    auto j = json::parse(report::render_json({make_finding()}, make_cfg()));
    REQUIRE(j["findings"][0].contains("ruleId"));
    REQUIRE_FALSE(j["findings"][0].contains("rule_id"));
    REQUIRE(j["findings"][0]["ruleId"] == "LINT001");
}

TEST_CASE("render_json: finding location is nested object", "[report][rpt003]") {
    auto j = json::parse(report::render_json({make_finding()}, make_cfg()));
    auto& loc = j["findings"][0]["location"];
    REQUIRE(loc.is_object());
    REQUIRE(loc["file"] == "src/foo.cpp");
    REQUIRE(loc["line"] == 42);
    REQUIRE(loc["column"] == 7);
}

TEST_CASE("render_json: finding has remediation not fix", "[report][rpt003]") {
    auto j = json::parse(report::render_json({make_finding()}, make_cfg()));
    REQUIRE(j["findings"][0].contains("remediation"));
    REQUIRE_FALSE(j["findings"][0].contains("fix"));
}

TEST_CASE("render_json: finding has category, standard, clause", "[report][rpt003]") {
    auto j = json::parse(report::render_json({make_finding()}, make_cfg()));
    auto& f = j["findings"][0];
    REQUIRE(f["category"] == "lint");
    REQUIRE(f["standard"] == "MISRA-C++:2023");
    REQUIRE(f["clause"]   == "A18-5-2");
}

TEST_CASE("render_json: summary has total count", "[report][rpt004]") {
    auto j = json::parse(report::render_json({make_finding(), make_finding()}, make_cfg()));
    REQUIRE(j["summary"]["total"] == 2);
}

TEST_CASE("render_json: summary counts errors, warnings, infos", "[report][rpt004]") {
    Finding e; e.rule_id = "E"; e.severity = Severity::ERROR;   e.message = "e";
    auto j = json::parse(report::render_json({e}, make_cfg()));
    REQUIRE(j["summary"]["errors"]   == 1);
    REQUIRE(j["summary"]["warnings"] == 0);
    REQUIRE(j["summary"]["infos"]    == 0);
}

// ─── render_html ─────────────────────────────────────────────────────────────

TEST_CASE("report: render_html contains project name", "[report][rpt001]") {
    REQUIRE(report::render_html({}, make_cfg()).find("TestProject") != std::string::npos);
}

TEST_CASE("report: render_html uses remediation class not fix", "[report][rpt001]") {
    auto html = report::render_html({make_finding()}, make_cfg());
    REQUIRE(html.find("remediation") != std::string::npos);
    REQUIRE(html.find("class=\"fix\"") == std::string::npos);
}

// ─── render_sarif ─────────────────────────────────────────────────────────────

TEST_CASE("report: render_sarif has runs array", "[report][rpt005]") {
    REQUIRE(report::render_sarif({}, make_cfg()).find("\"runs\"") != std::string::npos);
}

TEST_CASE("report: render_sarif tool name is cpp-FuSa", "[report][rpt005]") {
    auto sarif = json::parse(report::render_sarif({}, make_cfg()));
    REQUIRE(sarif["runs"][0]["tool"]["driver"]["name"] == "cpp-FuSa");
}

TEST_CASE("report: render_sarif finding uses camelCase ruleId", "[report][rpt005]") {
    auto sarif = json::parse(report::render_sarif({make_finding()}, make_cfg()));
    REQUIRE(sarif["runs"][0]["results"][0].contains("ruleId"));
}

TEST_CASE("report: render_sarif has physicalLocation on results", "[report][rpt005]") {
    auto sarif = json::parse(report::render_sarif({make_finding()}, make_cfg()));
    auto& locs = sarif["runs"][0]["results"][0]["locations"];
    REQUIRE(locs.is_array());
    REQUIRE(locs[0].contains("physicalLocation"));
}

// ─── endLine / endColumn (§4 MAY) ────────────────────────────────────────────

TEST_CASE("render_json: finding with end_line emits endLine in location", "[report][rpt006]") {
    Finding f = make_finding();
    f.end_line   = 44;
    f.end_column = 12;
    auto j = json::parse(report::render_json({f}, make_cfg()));
    auto& loc = j["findings"][0]["location"];
    REQUIRE(loc["endLine"]   == 44);
    REQUIRE(loc["endColumn"] == 12);
}

TEST_CASE("render_json: finding without end_line omits endLine", "[report][rpt006]") {
    auto j = json::parse(report::render_json({make_finding()}, make_cfg()));
    auto& loc = j["findings"][0]["location"];
    REQUIRE_FALSE(loc.contains("endLine"));
    REQUIRE_FALSE(loc.contains("endColumn"));
}

TEST_CASE("render_sarif: finding with end_line emits region endLine", "[report][rpt006]") {
    Finding f = make_finding();
    f.end_line   = 44;
    f.end_column = 12;
    auto sarif = json::parse(report::render_sarif({f}, make_cfg()));
    auto& region = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"];
    REQUIRE(region["endLine"]   == 44);
    REQUIRE(region["endColumn"] == 12);
}

// ─── exit_code ────────────────────────────────────────────────────────────────

TEST_CASE("report: exit_code returns 0 when no errors", "[report]") {
    Finding warn{"W001", Severity::WARNING, "warn", "", 0, ""};
    REQUIRE(report::exit_code({warn}, false) == 0);
}

TEST_CASE("report: exit_code returns 1 on error", "[report]") {
    Finding err{"E001", Severity::ERROR, "err", "", 0, ""};
    REQUIRE(report::exit_code({err}, false) == 1);
}

TEST_CASE("report: strict mode returns 1 on warning", "[report]") {
    Finding warn{"W001", Severity::WARNING, "warn", "", 0, ""};
    REQUIRE(report::exit_code({warn}, true) == 1);
}

TEST_CASE("report: exit_code returns 0 with no findings", "[report]") {
    REQUIRE(report::exit_code({}, false) == 0);
    REQUIRE(report::exit_code({}, true)  == 0);
}

// ─── SIL / DAL integrity level keys (§1.2.1 / §3.2) ─────────────────────────

TEST_CASE("render_json: SIL integrity level emits sil key", "[report][rpt002]") {
    config::ProjectConfig cfg = make_cfg();
    cfg.asil = "SIL-2";
    auto j = json::parse(report::render_json({}, cfg));
    REQUIRE(j.contains("sil"));
    REQUIRE(j["sil"] == "SIL-2");
    REQUIRE_FALSE(j.contains("asil"));
}

TEST_CASE("render_json: DAL integrity level emits dal key", "[report][rpt002]") {
    config::ProjectConfig cfg = make_cfg();
    cfg.asil = "DAL-A";
    auto j = json::parse(report::render_json({}, cfg));
    REQUIRE(j.contains("dal"));
    REQUIRE(j["dal"] == "DAL-A");
    REQUIRE_FALSE(j.contains("asil"));
}

TEST_CASE("render_json: empty asil omits integrity key", "[report][rpt002]") {
    config::ProjectConfig cfg = make_cfg();
    cfg.asil = "";
    auto j = json::parse(report::render_json({}, cfg));
    REQUIRE_FALSE(j.contains("asil"));
    REQUIRE_FALSE(j.contains("sil"));
    REQUIRE_FALSE(j.contains("dal"));
}

TEST_CASE("render_json: empty standard omits standard key", "[report][rpt002]") {
    config::ProjectConfig cfg = make_cfg();
    cfg.standard = "";
    auto j = json::parse(report::render_json({}, cfg));
    REQUIRE_FALSE(j.contains("standard"));
}

// ─── write_report ────────────────────────────────────────────────────────────

TEST_CASE("report: write_report to file creates file", "[report][rpt001]") {
    TempDir tmp;
    report::ReportOptions opts;
    opts.format = report::Format::JSON;
    opts.output = (tmp.path() / "out.json").string();
    auto r = report::write_report({make_finding()}, make_cfg(), opts);
    REQUIRE(is_ok(r));
    REQUIRE(std::filesystem::exists(tmp.path() / "out.json"));
}

TEST_CASE("report: write_report JSON file is valid JSON", "[report][rpt001]") {
    TempDir tmp;
    report::ReportOptions opts;
    opts.format = report::Format::JSON;
    opts.output = (tmp.path() / "report.json").string();
    (void)report::write_report({make_finding()}, make_cfg(), opts);
    std::ifstream f(opts.output);
    json j;
    REQUIRE_NOTHROW(f >> j);
    REQUIRE(j.contains("findings"));
}

TEST_CASE("report: write_report HTML format creates html content", "[report][rpt001]") {
    TempDir tmp;
    report::ReportOptions opts;
    opts.format = report::Format::HTML;
    opts.output = (tmp.path() / "report.html").string();
    auto r = report::write_report({make_finding()}, make_cfg(), opts);
    REQUIRE(is_ok(r));
    std::ifstream f(opts.output);
    std::string content((std::istreambuf_iterator<char>(f)), {});
    REQUIRE(content.find("DOCTYPE html") != std::string::npos);
}

TEST_CASE("report: write_report SARIF format creates valid output", "[report][rpt001]") {
    TempDir tmp;
    report::ReportOptions opts;
    opts.format = report::Format::SARIF;
    opts.output = (tmp.path() / "report.sarif").string();
    auto r = report::write_report({make_finding()}, make_cfg(), opts);
    REQUIRE(is_ok(r));
    std::ifstream f(opts.output);
    json j;
    REQUIRE_NOTHROW(f >> j);
    REQUIRE(j.contains("runs"));
}

TEST_CASE("report: write_report TEXT format creates text output", "[report][rpt001]") {
    TempDir tmp;
    report::ReportOptions opts;
    opts.format = report::Format::TEXT;
    opts.output = (tmp.path() / "report.txt").string();
    auto r = report::write_report({make_finding()}, make_cfg(), opts);
    REQUIRE(is_ok(r));
    std::ifstream f(opts.output);
    std::string content((std::istreambuf_iterator<char>(f)), {});
    REQUIRE(content.find("LINT001") != std::string::npos);
}

TEST_CASE("report: write_report returns error for unwritable path", "[report][rpt001]") {
    report::ReportOptions opts;
    opts.format = report::Format::JSON;
    opts.output = "/nonexistent_dir_xyz/report.json";
    auto r = report::write_report({}, make_cfg(), opts);
    REQUIRE_FALSE(is_ok(r));
}

// ─── render_html with findings ────────────────────────────────────────────────

TEST_CASE("report: render_html with finding shows rule id", "[report][rpt001]") {
    auto html = report::render_html({make_finding()}, make_cfg());
    REQUIRE(html.find("LINT001") != std::string::npos);
}

TEST_CASE("report: render_html with empty finding has green check", "[report][rpt001]") {
    auto html = report::render_html({}, make_cfg());
    REQUIRE(html.find("No findings") != std::string::npos);
}

TEST_CASE("report: render_html finding includes file and line", "[report][rpt001]") {
    auto html = report::render_html({make_finding()}, make_cfg());
    REQUIRE(html.find("src/foo.cpp") != std::string::npos);
    REQUIRE(html.find("42") != std::string::npos);
}
