//fusa:test REQ-QUALIFY001
//fusa:test REQ-QUALIFY002
//fusa:test REQ-QUALIFY003
//fusa:test REQ-QUALIFY004
//fusa:test REQ-QUALIFY005
//fusa:test REQ-QUALIFY006
//fusa:test REQ-QUALIFY007
//fusa:test REQ-QUALIFY008
//fusa:test REQ-QUALIFY009
//fusa:test REQ-QUALIFY010
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

// ─── Tool Qualification Display (REQ-QUALIFY005..REQ-QUALIFY007) ──────────────

TEST_CASE("qualify: qualification_method field serialised to JSON", "[qualify][qualify005]") {
    //fusa:test REQ-QUALIFY005
    TempDir tmp;
    auto cases = qualify::builtin_cases();
    auto rr = qualify::run(cases);
    REQUIRE(is_ok(rr));
    auto report = value_of(rr);
    report.qualification_method = "independent";
    auto path = tmp.path() / "qualify-report.json";
    REQUIRE(is_ok(qualify::save(path, report)));
    std::ifstream f(path);
    json j; f >> j;
    REQUIRE(j.contains("qualificationMethod"));
    REQUIRE(j["qualificationMethod"] == "independent");
}

TEST_CASE("qualify: qualification_record_uri serialised to JSON", "[qualify][qualify006]") {
    //fusa:test REQ-QUALIFY006
    TempDir tmp;
    auto cases = qualify::builtin_cases();
    auto rr = qualify::run(cases);
    REQUIRE(is_ok(rr));
    auto report = value_of(rr);
    report.qualification_record_uri = "https://example.com/dossier/v1";
    auto path = tmp.path() / "qualify-report.json";
    REQUIRE(is_ok(qualify::save(path, report)));
    std::ifstream f(path);
    json j; f >> j;
    REQUIRE(j.contains("qualificationRecordUri"));
    REQUIRE(j["qualificationRecordUri"] == "https://example.com/dossier/v1");
}

TEST_CASE("qualify: qualifier_identity serialised to JSON", "[qualify][qualify007]") {
    //fusa:test REQ-QUALIFY007
    TempDir tmp;
    auto cases = qualify::builtin_cases();
    auto rr = qualify::run(cases);
    REQUIRE(is_ok(rr));
    auto report = value_of(rr);
    report.qualifier_identity = "Safety Corp Ltd";
    auto path = tmp.path() / "qualify-report.json";
    REQUIRE(is_ok(qualify::save(path, report)));
    std::ifstream f(path);
    json j; f >> j;
    REQUIRE(j.contains("qualifierIdentity"));
    REQUIRE(j["qualifierIdentity"] == "Safety Corp Ltd");
}

TEST_CASE("qualify: independently-qualified badge emitted when method=independent", "[qualify][qualify005]") {
    //fusa:test REQ-QUALIFY005
    TempDir tmp;
    auto cases = qualify::builtin_cases();
    auto rr = qualify::run(cases);
    REQUIRE(is_ok(rr));
    auto report = value_of(rr);
    report.qualification_method = "independent";
    auto path = tmp.path() / "qualify-report.json";
    REQUIRE(is_ok(qualify::save(path, report)));
    std::ifstream f(path);
    json j; f >> j;
    REQUIRE(j.contains("badge"));
    REQUIRE(j["badge"] == "independently-qualified");
}

TEST_CASE("qualify: self-qualified badge emitted when method=self", "[qualify][qualify005]") {
    //fusa:test REQ-QUALIFY005
    TempDir tmp;
    auto cases = qualify::builtin_cases();
    auto rr = qualify::run(cases);
    REQUIRE(is_ok(rr));
    auto report = value_of(rr);
    report.qualification_method = "self";
    auto path = tmp.path() / "qualify-report.json";
    REQUIRE(is_ok(qualify::save(path, report)));
    std::ifstream f(path);
    json j; f >> j;
    REQUIRE(j["badge"] == "self-qualified");
}

// ─── V&V Independence (REQ-QUALIFY008..REQ-QUALIFY010) ───────────────────────

TEST_CASE("qualify: independence_status is independent when reviewer differs from author", "[qualify][qualify008]") {
    //fusa:test REQ-QUALIFY008
    qualify::QualifyReport r;
    r.implementation_author  = "Alice";
    r.independent_reviewer   = "Bob";
    REQUIRE(r.independence_status() == "independent");
}

TEST_CASE("qualify: independence_status is self when reviewer equals author", "[qualify][qualify008]") {
    //fusa:test REQ-QUALIFY008
    qualify::QualifyReport r;
    r.implementation_author = "Alice";
    r.independent_reviewer  = "Alice";
    REQUIRE(r.independence_status() == "self");
}

TEST_CASE("qualify: independence_status is unqualified when fields are empty", "[qualify][qualify008]") {
    //fusa:test REQ-QUALIFY008
    qualify::QualifyReport r;
    REQUIRE(r.independence_status() == "unqualified");
}

TEST_CASE("qualify: independence fields serialised to JSON", "[qualify][qualify009]") {
    //fusa:test REQ-QUALIFY009
    TempDir tmp;
    auto cases = qualify::builtin_cases();
    auto rr = qualify::run(cases);
    REQUIRE(is_ok(rr));
    auto report = value_of(rr);
    report.implementation_author       = "Alice";
    report.independent_reviewer        = "Bob";
    report.independent_test_executor   = "Charlie";
    report.achievable_asil             = "ASIL-B";
    auto path = tmp.path() / "qualify-report.json";
    REQUIRE(is_ok(qualify::save(path, report)));
    std::ifstream f(path);
    json j; f >> j;
    REQUIRE(j["implementationAuthor"]    == "Alice");
    REQUIRE(j["independentReviewer"]     == "Bob");
    REQUIRE(j["independentTestExecutor"] == "Charlie");
    REQUIRE(j["achievableAsil"]          == "ASIL-B");
}

TEST_CASE("qualify: independently-qualified badge from reviewer != author", "[qualify][qualify010]") {
    //fusa:test REQ-QUALIFY010
    TempDir tmp;
    auto cases = qualify::builtin_cases();
    auto rr = qualify::run(cases);
    REQUIRE(is_ok(rr));
    auto report = value_of(rr);
    report.implementation_author = "Alice";
    report.independent_reviewer  = "Bob";
    auto path = tmp.path() / "qualify-report.json";
    REQUIRE(is_ok(qualify::save(path, report)));
    std::ifstream f(path);
    json j; f >> j;
    REQUIRE(j.contains("badge"));
    REQUIRE(j["badge"] == "independently-qualified");
    REQUIRE(j["independenceStatus"] == "independent");
}
