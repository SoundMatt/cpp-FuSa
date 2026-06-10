//fusa:test REQ-RPT001 REQ-RPT002 REQ-RPT003 REQ-RPT004 REQ-RPT005
#include <catch2/catch_all.hpp>
#include "report/report.hpp"

using namespace cpfusa;

namespace {
config::ProjectConfig make_cfg() {
    config::ProjectConfig cfg;
    cfg.project  = "TestProject";
    cfg.version  = "1.0.0";
    cfg.standard = "iso26262";
    cfg.asil     = "B";
    return cfg;
}
} // namespace

TEST_CASE("report: render_text with no findings", "[report]") {
    auto txt = report::render_text({}, make_cfg());
    REQUIRE(txt.find("No findings") != std::string::npos);
}

TEST_CASE("report: render_text contains finding details", "[report]") {
    Finding f{"FUSA001", Severity::ERROR, "Config missing", "path/to/file", 10, "cpfusa init"};
    auto txt = report::render_text({f}, make_cfg());
    REQUIRE(txt.find("FUSA001") != std::string::npos);
    REQUIRE(txt.find("Config missing") != std::string::npos);
    REQUIRE(txt.find("ERROR") != std::string::npos);
}

TEST_CASE("report: render_json produces valid JSON with findings array", "[report]") {
    Finding f{"LINT001", Severity::WARNING, "raw new", "src/a.cpp", 5, ""};
    auto j = report::render_json({f}, make_cfg());
    REQUIRE(j.find("\"findings\"") != std::string::npos);
    REQUIRE(j.find("LINT001") != std::string::npos);
}

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

TEST_CASE("report: render_html contains project name", "[report]") {
    auto html = report::render_html({}, make_cfg());
    REQUIRE(html.find("TestProject") != std::string::npos);
}

TEST_CASE("report: render_sarif contains runs array", "[report]") {
    auto sarif = report::render_sarif({}, make_cfg());
    REQUIRE(sarif.find("\"runs\"") != std::string::npos);
    REQUIRE(sarif.find("cpp-FuSa") != std::string::npos);
}
