//fusa:test REQ-MISRA001
//fusa:test REQ-MISRA002
//fusa:test REQ-MISRA003
#include <catch2/catch_all.hpp>
#include "misra/misra.hpp"
#include "testutil/testutil.hpp"
#include <nlohmann/json.hpp>
#include <fstream>

using namespace cpfusa;
using namespace cpfusa::testutil;
using json = nlohmann::json;

// ─── mapping_table ───────────────────────────────────────────────────────────

TEST_CASE("misra: mapping_table is non-empty", "[misra][misra001]") {
    auto rules = misra::mapping_table();
    REQUIRE_FALSE(rules.empty());
}

TEST_CASE("misra: every rule has a non-empty id", "[misra][misra001]") {
    for (auto& r : misra::mapping_table())
        REQUIRE_FALSE(r.id.empty());
}

TEST_CASE("misra: every rule has a non-empty description", "[misra][misra001]") {
    for (auto& r : misra::mapping_table())
        REQUIRE_FALSE(r.description.empty());
}

TEST_CASE("misra: every rule has a non-empty category", "[misra][misra001]") {
    for (auto& r : misra::mapping_table())
        REQUIRE_FALSE(r.category.empty());
}

TEST_CASE("misra: mapped rules have a lint_rule set", "[misra][misra002]") {
    for (auto& r : misra::mapping_table()) {
        if (r.status == misra::Status::Mapped)
            REQUIRE_FALSE(r.lint_rule.empty());
    }
}

TEST_CASE("misra: N/A rules have empty lint_rule", "[misra][misra002]") {
    for (auto& r : misra::mapping_table()) {
        if (r.status == misra::Status::NA)
            REQUIRE(r.lint_rule.empty());
    }
}

TEST_CASE("misra: mapping contains LINT001 mapping for A18-5-2", "[misra][misra002]") {
    bool found = false;
    for (auto& r : misra::mapping_table())
        if (r.id == "A18-5-2" && r.lint_rule == "LINT001") found = true;
    REQUIRE(found);
}

TEST_CASE("misra: mapping contains LINT002 mapping for A6-6-1", "[misra][misra002]") {
    bool found = false;
    for (auto& r : misra::mapping_table())
        if (r.id == "A6-6-1" && r.lint_rule == "LINT002") found = true;
    REQUIRE(found);
}

TEST_CASE("misra: mapping contains LINT003 mapping for A5-2-4", "[misra][misra002]") {
    bool found = false;
    for (auto& r : misra::mapping_table())
        if (r.id == "A5-2-4" && r.lint_rule == "LINT003") found = true;
    REQUIRE(found);
}

TEST_CASE("misra: table has at least one N/A rule", "[misra][misra001]") {
    bool has_na = false;
    for (auto& r : misra::mapping_table())
        if (r.status == misra::Status::NA) has_na = true;
    REQUIRE(has_na);
}

// ─── build_report ────────────────────────────────────────────────────────────

TEST_CASE("misra: build_report returns all rules when gaps_only=false", "[misra][misra003]") {
    auto r = misra::build_report(false);
    REQUIRE(r.total > 0);
    REQUIRE(r.total == static_cast<int>(misra::mapping_table().size()));
}

TEST_CASE("misra: build_report returns only manual rules when gaps_only=true", "[misra][misra003]") {
    auto r = misra::build_report(true);
    for (auto& rule : r.rules)
        REQUIRE(rule.status == misra::Status::Manual);
}

TEST_CASE("misra: build_report totals are consistent", "[misra][misra003]") {
    auto r = misra::build_report(false);
    REQUIRE(r.mapped + r.na_count + r.manual == r.total);
}

TEST_CASE("misra: build_report has non-empty generated_at", "[misra][misra003]") {
    auto r = misra::build_report(false);
    REQUIRE_FALSE(r.generated_at.empty());
}

// ─── write_json ───────────────────────────────────────────────────────────────

TEST_CASE("misra: write_json creates valid JSON", "[misra][misra003]") {
    TempDir tmp;
    auto r = misra::build_report(false);
    auto path = (tmp.path() / misra::MISRA_REPORT_FILE).string();
    REQUIRE_NOTHROW(misra::write_json(path, r));
    std::ifstream f(path);
    json j;
    REQUIRE_NOTHROW(f >> j);
    REQUIRE(j.contains("rules"));
    REQUIRE(j.contains("summary"));
}

TEST_CASE("misra: JSON report summary totals match report", "[misra][misra003]") {
    TempDir tmp;
    auto r = misra::build_report(false);
    misra::write_json((tmp.path() / misra::MISRA_REPORT_FILE).string(), r);
    std::ifstream f(tmp.path() / misra::MISRA_REPORT_FILE);
    json j; f >> j;
    REQUIRE(j["summary"]["total"].get<int>() == r.total);
    REQUIRE(j["summary"]["mapped"].get<int>() == r.mapped);
}

TEST_CASE("misra: JSON report rules array is non-empty", "[misra][misra003]") {
    TempDir tmp;
    auto r = misra::build_report(false);
    misra::write_json((tmp.path() / misra::MISRA_REPORT_FILE).string(), r);
    std::ifstream f(tmp.path() / misra::MISRA_REPORT_FILE);
    json j; f >> j;
    REQUIRE(j["rules"].size() > 0);
}

TEST_CASE("misra: JSON rule entries have id field", "[misra][misra003]") {
    TempDir tmp;
    auto r = misra::build_report(false);
    misra::write_json((tmp.path() / misra::MISRA_REPORT_FILE).string(), r);
    std::ifstream f(tmp.path() / misra::MISRA_REPORT_FILE);
    json j; f >> j;
    for (auto& rule : j["rules"])
        REQUIRE(rule.contains("id"));
}
