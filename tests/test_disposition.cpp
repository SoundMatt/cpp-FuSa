//fusa:test REQ-DISP001
//fusa:test REQ-DISP002
//fusa:test REQ-DISP003
#include <catch2/catch_all.hpp>
#include "disposition/disposition.hpp"
#include "testutil/testutil.hpp"
#include <nlohmann/json.hpp>
#include <fstream>

using namespace cpfusa;
using namespace cpfusa::testutil;
using json = nlohmann::json;

// ─── action_str / parse_action ────────────────────────────────────────────────

TEST_CASE("disposition: action_str accept", "[disposition][disp001]") {
    REQUIRE(disposition::action_str(disposition::Action::Accept) == "accept");
}

TEST_CASE("disposition: action_str fix", "[disposition][disp001]") {
    REQUIRE(disposition::action_str(disposition::Action::Fix) == "fix");
}

TEST_CASE("disposition: parse_action roundtrip", "[disposition][disp001]") {
    REQUIRE(disposition::parse_action("fix") == disposition::Action::Fix);
    REQUIRE(disposition::parse_action("accept") == disposition::Action::Accept);
}

// ─── load ─────────────────────────────────────────────────────────────────────

TEST_CASE("disposition: load returns empty log when file missing", "[disposition][disp002]") {
    TempDir tmp;
    auto log = disposition::load(tmp.path());
    REQUIRE(log.entries.empty());
}

TEST_CASE("disposition: load parses saved entries", "[disposition][disp002]") {
    TempDir tmp;
    disposition::Log log;
    disposition::Entry e{"LINT001", "intentional use", "alice", "2026-01-01",
                         disposition::Action::Accept, ""};
    log = disposition::add(log, e);
    std::string err;
    REQUIRE(disposition::save(tmp.path() / disposition::DISPOSITIONS_FILE, log, err));
    auto loaded = disposition::load(tmp.path());
    REQUIRE(loaded.entries.size() == 1);
    REQUIRE(loaded.entries[0].rule_id == "LINT001");
}

// ─── save ─────────────────────────────────────────────────────────────────────

TEST_CASE("disposition: save writes valid JSON", "[disposition][disp002]") {
    TempDir tmp;
    disposition::Log log;
    std::string err;
    REQUIRE(disposition::save(tmp.path() / disposition::DISPOSITIONS_FILE, log, err));
    std::ifstream f(tmp.path() / disposition::DISPOSITIONS_FILE);
    json j;
    REQUIRE_NOTHROW(f >> j);
    REQUIRE(j.contains("entries"));
}

TEST_CASE("disposition: save fails on invalid path", "[disposition][disp002]") {
    TempDir tmp;
    disposition::Log log;
    std::string err;
    auto result = disposition::save(tmp.path() / "nosuchdir" / "f.json", log, err);
    REQUIRE_FALSE(result);
    REQUIRE_FALSE(err.empty());
}

// ─── add / find_by_rule ───────────────────────────────────────────────────────

TEST_CASE("disposition: add inserts new entry", "[disposition][disp003]") {
    disposition::Log log;
    disposition::Entry e{"LINT002", "rationale", "bob", "2026-01-02",
                         disposition::Action::Fix, ""};
    log = disposition::add(log, e);
    REQUIRE(log.entries.size() == 1);
}

TEST_CASE("disposition: add updates existing rule_id", "[disposition][disp003]") {
    disposition::Log log;
    disposition::Entry e1{"LINT001", "old", "alice", "2026-01-01", disposition::Action::Accept, ""};
    disposition::Entry e2{"LINT001", "new", "bob",   "2026-01-02", disposition::Action::Fix,    ""};
    log = disposition::add(log, e1);
    log = disposition::add(log, e2);
    REQUIRE(log.entries.size() == 1);
    REQUIRE(log.entries[0].rationale == "new");
}

TEST_CASE("disposition: find_by_rule returns entry when present", "[disposition][disp003]") {
    disposition::Log log;
    disposition::Entry e{"LINT003", "r", "x", "2026-01-01", disposition::Action::Accept, ""};
    log = disposition::add(log, e);
    disposition::Entry out;
    REQUIRE(disposition::find_by_rule(log, "LINT003", out));
    REQUIRE(out.rule_id == "LINT003");
}

TEST_CASE("disposition: find_by_rule returns false when absent", "[disposition][disp003]") {
    disposition::Log log;
    disposition::Entry out;
    REQUIRE_FALSE(disposition::find_by_rule(log, "LINT999", out));
}
