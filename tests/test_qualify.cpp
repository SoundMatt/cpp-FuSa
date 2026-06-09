//fusa:test REQ-QUALIFY001 REQ-QUALIFY002 REQ-QUALIFY003 REQ-QUALIFY004
#include <catch2/catch_all.hpp>
#include "qualify/qualify.hpp"
#include "testutil/testutil.hpp"
#include <nlohmann/json.hpp>
#include <fstream>

using namespace cpfusa;
using namespace cpfusa::testutil;
using json = nlohmann::json;

// ─── builtin_cases ────────────────────────────────────────────────────────────

TEST_CASE("qualify: builtin_cases returns non-empty list", "[qualify][qualify001]") {
    auto cases = qualify::builtin_cases();
    REQUIRE_FALSE(cases.empty());
}

TEST_CASE("qualify: every builtin case has a name and rule_id", "[qualify][qualify001]") {
    for (auto& c : qualify::builtin_cases()) {
        REQUIRE_FALSE(c.name.empty());
        REQUIRE_FALSE(c.rule_id.empty());
        REQUIRE_FALSE(c.description.empty());
    }
}

TEST_CASE("qualify: builtin_cases include positive and negative cases for FUSA001", "[qualify][qualify001]") {
    bool found_pos = false, found_neg = false;
    for (auto& c : qualify::builtin_cases()) {
        if (c.rule_id == "FUSA001" && c.expect_finding)  found_pos = true;
        if (c.rule_id == "FUSA001" && !c.expect_finding) found_neg = true;
    }
    REQUIRE(found_pos);
    REQUIRE(found_neg);
}

// ─── run ──────────────────────────────────────────────────────────────────────

TEST_CASE("qualify: run passes all built-in cases", "[qualify][qualify003]") {
    auto cases = qualify::builtin_cases();
    auto result = qualify::run(cases);
    REQUIRE(is_ok(result));
    auto& r = value_of(result);
    REQUIRE(r.total > 0);
    REQUIRE(r.failed == 0);
    REQUIRE(r.passed == r.total);
}

TEST_CASE("qualify: run report has SHA-256 hash", "[qualify][qualify002]") {
    auto cases = qualify::builtin_cases();
    auto result = qualify::run(cases);
    REQUIRE(is_ok(result));
    auto& r = value_of(result);
    REQUIRE(r.hash.size() == 64); // SHA-256 hex is 64 chars
}

TEST_CASE("qualify: run report hash is not all-zeros", "[qualify][qualify002]") {
    auto cases = qualify::builtin_cases();
    auto result = qualify::run(cases);
    REQUIRE(is_ok(result));
    auto& r = value_of(result);
    REQUIRE(r.hash != std::string(64, '0'));
}

TEST_CASE("qualify: run sets generated_at timestamp", "[qualify][qualify002]") {
    auto cases = qualify::builtin_cases();
    auto result = qualify::run(cases);
    REQUIRE(is_ok(result));
    REQUIRE_FALSE(value_of(result).generated_at.empty());
}

TEST_CASE("qualify: run sets module field", "[qualify][qualify002]") {
    auto cases = qualify::builtin_cases();
    auto result = qualify::run(cases);
    REQUIRE(is_ok(result));
    REQUIRE_FALSE(value_of(result).module.empty());
}

TEST_CASE("qualify: run empty cases produces zero totals", "[qualify]") {
    auto result = qualify::run({});
    REQUIRE(is_ok(result));
    auto& r = value_of(result);
    REQUIRE(r.total == 0);
    REQUIRE(r.passed == 0);
    REQUIRE(r.failed == 0);
}

// ─── save / load round-trip ────────────────────────────────────────────────────

TEST_CASE("qualify: save writes valid JSON", "[qualify][qualify002]") {
    TempDir tmp;
    auto cases = qualify::builtin_cases();
    auto result = qualify::run(cases);
    REQUIRE(is_ok(result));
    auto path = tmp.path() / "qualify-report.json";
    auto save_r = qualify::save(path, value_of(result));
    REQUIRE(is_ok(save_r));
    std::ifstream f(path);
    REQUIRE(f.good());
    json j;
    f >> j;
    REQUIRE(j.contains("total"));
    REQUIRE(j.contains("passed"));
    REQUIRE(j.contains("hash"));
}

TEST_CASE("qualify: saved hash matches computed hash", "[qualify][qualify002]") {
    TempDir tmp;
    auto cases = qualify::builtin_cases();
    auto rr    = qualify::run(cases);
    REQUIRE(is_ok(rr));
    auto& report = value_of(rr);
    auto path = tmp.path() / "qualify-report.json";
    qualify::save(path, report);
    std::ifstream f(path);
    json j;
    f >> j;
    REQUIRE(j["hash"].get<std::string>() == report.hash);
}
