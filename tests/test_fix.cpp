//fusa:test REQ-FIX001
//fusa:test REQ-FIX002
//fusa:test REQ-FIX003
#include <catch2/catch_all.hpp>
#include "fix/fix.hpp"

using namespace cpfusa;

// ─── catalog ──────────────────────────────────────────────────────────────────

TEST_CASE("fix: catalog is non-empty", "[fix][fix001]") {
    auto entries = fix::catalog();
    REQUIRE_FALSE(entries.empty());
}

TEST_CASE("fix: every catalog entry has a rule_id", "[fix][fix001]") {
    for (auto& e : fix::catalog())
        REQUIRE_FALSE(e.rule_id.empty());
}

TEST_CASE("fix: every catalog entry has a title", "[fix][fix001]") {
    for (auto& e : fix::catalog())
        REQUIRE_FALSE(e.title.empty());
}

TEST_CASE("fix: every catalog entry has a description", "[fix][fix001]") {
    for (auto& e : fix::catalog())
        REQUIRE_FALSE(e.description.empty());
}

TEST_CASE("fix: catalog contains LINT001 entry", "[fix][fix001]") {
    bool found = false;
    for (auto& e : fix::catalog())
        if (e.rule_id == "LINT001") found = true;
    REQUIRE(found);
}

TEST_CASE("fix: catalog contains LINT002 entry", "[fix][fix001]") {
    bool found = false;
    for (auto& e : fix::catalog())
        if (e.rule_id == "LINT002") found = true;
    REQUIRE(found);
}

TEST_CASE("fix: LINT001 entry has before and after examples", "[fix][fix002]") {
    for (auto& e : fix::catalog()) {
        if (e.rule_id == "LINT001") {
            REQUIRE_FALSE(e.before.empty());
            REQUIRE_FALSE(e.after.empty());
        }
    }
}

TEST_CASE("fix: LINT001 entry has non-empty standard_ref", "[fix][fix002]") {
    for (auto& e : fix::catalog()) {
        if (e.rule_id == "LINT001")
            REQUIRE_FALSE(e.standard_ref.empty());
    }
}

// ─── show ──────────────────────────────────────────────────────────────────────

TEST_CASE("fix: show outputs guidance for known rule", "[fix][fix002]") {
    // show() writes to stdout; verify it does not throw.
    REQUIRE_NOTHROW(fix::show("LINT001"));
}

TEST_CASE("fix: show outputs not-found message for unknown rule", "[fix][fix002]") {
    REQUIRE_NOTHROW(fix::show("UNKNOWN999"));
}

TEST_CASE("fix: show handles empty rule_id gracefully", "[fix][fix002]") {
    REQUIRE_NOTHROW(fix::show(""));
}

TEST_CASE("fix: show works for all catalog entries", "[fix][fix002]") {
    for (auto& e : fix::catalog()) {
        REQUIRE_NOTHROW(fix::show(e.rule_id));
    }
}

// ─── list_all ─────────────────────────────────────────────────────────────────

TEST_CASE("fix: list_all does not throw", "[fix][fix001]") {
    REQUIRE_NOTHROW(fix::list_all());
}

TEST_CASE("fix: catalog has FUSA001 entry", "[fix][fix001]") {
    bool found = false;
    for (auto& e : fix::catalog())
        if (e.rule_id == "FUSA001") found = true;
    REQUIRE(found);
}

TEST_CASE("fix: catalog has FUSA004 entry", "[fix][fix001]") {
    bool found = false;
    for (auto& e : fix::catalog())
        if (e.rule_id == "FUSA004") found = true;
    REQUIRE(found);
}

TEST_CASE("fix: every catalog entry has non-empty before and after", "[fix][fix002]") {
    for (auto& e : fix::catalog()) {
        REQUIRE_FALSE(e.before.empty());
        REQUIRE_FALSE(e.after.empty());
    }
}
