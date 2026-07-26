//fusa:test REQ-CLI001
//fusa:test REQ-CLI002
//fusa:test REQ-CLI003
//fusa:test REQ-CLI004
//fusa:test REQ-CLI005
//fusa:test REQ-CLI006
//fusa:test REQ-CLI007
//fusa:test REQ-CLI008
//fusa:test REQ-CLI009
//fusa:test REQ-CLI010
#include <catch2/catch_all.hpp>
#include "report/report.hpp"
#include "engine/engine.hpp"
#include "engine/rules.hpp"
#include "lint/lint.hpp"
#include "cyber/cyber.hpp"
#include "trace/trace.hpp"
#include "qualify/qualify.hpp"
#include "testutil/testutil.hpp"

using namespace cpfusa;
using namespace cpfusa::testutil;

// ─── REQ-CLI003/CLI004: exit code semantics ───────────────────────────────────

TEST_CASE("cli: exit_code is 0 with no findings", "[cli][cli003]") {
    REQUIRE(report::exit_code({}, false) == 0);
}

TEST_CASE("cli: exit_code is 0 with only WARNING findings in non-strict mode", "[cli][cli003]") {
    Finding w{"W001", Severity::WARNING, "warn", "", 0, ""};
    REQUIRE(report::exit_code({w}, false) == 0);
}

TEST_CASE("cli: exit_code is 1 when any ERROR finding present", "[cli][cli004]") {
    Finding e{"E001", Severity::ERROR, "err", "", 0, ""};
    REQUIRE(report::exit_code({e}, false) == 1);
}

TEST_CASE("cli: exit_code is 1 for mixed ERROR and WARNING findings", "[cli][cli004]") {
    Finding e{"E001", Severity::ERROR, "err", "", 0, ""};
    Finding w{"W001", Severity::WARNING, "warn", "", 0, ""};
    REQUIRE(report::exit_code({e, w}, false) == 1);
}

// ─── REQ-CLI005: strict mode ─────────────────────────────────────────────────

TEST_CASE("cli: strict mode returns 1 on WARNING", "[cli][cli005]") {
    Finding w{"W001", Severity::WARNING, "warn", "", 0, ""};
    REQUIRE(report::exit_code({w}, true) == 1);
}

TEST_CASE("cli: strict mode returns 0 on only INFO findings", "[cli][cli005]") {
    Finding i{"I001", Severity::INFO, "info", "", 0, ""};
    REQUIRE(report::exit_code({i}, true) == 0);
}

// ─── REQ-CLI007: lint subcommand available (LINT rules exist) ─────────────────

TEST_CASE("cli: lint check_raw_new_delete is available", "[cli][cli007]") {
    TempDir tmp;
    tmp.write("src/ok.cpp", "int main() { return 0; }\n");
    auto findings = lint::check_raw_new_delete(tmp.path());
    REQUIRE(findings.empty());
}

// ─── REQ-CLI009: cyber subcommand available (cyber run exists) ───────────────

TEST_CASE("cli: cyber::run is available and returns a report", "[cli][cli009]") {
    TempDir tmp;
    tmp.write("src/main.cpp", "int main() { return 0; }\n");
    config::ProjectConfig cfg;
    auto r = cyber::run(tmp.path(), cfg);
    REQUIRE(r.findings.empty());
}

// ─── REQ-CLI008: trace subcommand available (trace::run exists) ──────────────

TEST_CASE("cli: trace::run is available and succeeds on empty project", "[cli][cli008]") {
    TempDir tmp;
    tmp.write(".fusa.json", R"({"project":"test","version":"1.0.0"})");
    config::ProjectConfig cfg;
    cfg.project = "test";
    cfg.version = "1.0.0";
    auto r = trace::run(tmp.path(), cfg);
    REQUIRE(is_ok(r));
}

// ─── REQ-CLI006: qualify subcommand available ─────────────────────────────────

TEST_CASE("cli: qualify::run is available and passes built-in cases", "[cli][cli006]") {
    auto cases = qualify::builtin_cases();
    REQUIRE_FALSE(cases.empty());
    auto r = qualify::run(cases);
    REQUIRE(is_ok(r));
    REQUIRE(value_of(r).failed == 0);
}
