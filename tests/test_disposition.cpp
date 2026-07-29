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

// ─── status_str / parse_status ────────────────────────────────────────────────

TEST_CASE("disposition: status_str accepted", "[disposition][disp001]") {
    REQUIRE(disposition::status_str(disposition::Status::Accepted) == "accepted");
}

TEST_CASE("disposition: status_str deferred", "[disposition][disp001]") {
    REQUIRE(disposition::status_str(disposition::Status::Deferred) == "deferred");
}

TEST_CASE("disposition: status_str rejected", "[disposition][disp001]") {
    REQUIRE(disposition::status_str(disposition::Status::Rejected) == "rejected");
}

TEST_CASE("disposition: parse_status roundtrip", "[disposition][disp001]") {
    REQUIRE(disposition::parse_status("accepted") == disposition::Status::Accepted);
    REQUIRE(disposition::parse_status("deferred") == disposition::Status::Deferred);
    REQUIRE(disposition::parse_status("rejected") == disposition::Status::Rejected);
}

TEST_CASE("disposition: parse_status defaults unrecognised value to accepted",
          "[disposition][disp001]") {
    REQUIRE(disposition::parse_status("bogus") == disposition::Status::Accepted);
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
    disposition::Entry e;
    e.rule_id = "LINT001";
    e.note    = "intentional use";
    e.by      = "alice";
    e.at      = "2026-01-01T00:00:00Z";
    e.status  = disposition::Status::Accepted;
    log = disposition::add(log, e);
    std::string err;
    REQUIRE(disposition::save(tmp.path() / disposition::DISPOSITIONS_FILE, log, err));
    auto loaded = disposition::load(tmp.path());
    REQUIRE(loaded.entries.size() == 1);
    REQUIRE(loaded.entries[0].rule_id == "LINT001");
    REQUIRE(loaded.entries[0].status == disposition::Status::Accepted);
}

// §1.2.3 MUST: the canonical top-level key is "dispositions", and per-entry
// keys are fingerprint/ruleId/file/line/status/note/by/at — not the legacy
// entries/action/date/rationale/reviewer shape this tool used to emit.
TEST_CASE("disposition: save writes the canonical §1.2.3 dispositions/status/fingerprint "
          "shape, not the legacy entries/action shape",
          "[disposition][disp002]") {
    TempDir tmp;
    disposition::Log log;
    disposition::Entry e;
    e.fingerprint = "sha256:abc123";
    e.rule_id     = "LINT001";
    e.file        = "src/foo.cpp";
    e.line        = 42;
    e.status      = disposition::Status::Deferred;
    e.note        = "tracked in JIRA-123";
    e.by          = "matt@jellybaby.com";
    e.at          = "2026-06-10T12:00:00Z";
    log = disposition::add(log, e);
    std::string err;
    REQUIRE(disposition::save(tmp.path() / disposition::DISPOSITIONS_FILE, log, err));

    std::ifstream f(tmp.path() / disposition::DISPOSITIONS_FILE);
    json j;
    REQUIRE_NOTHROW(f >> j);
    REQUIRE(j.contains("dispositions"));
    REQUIRE_FALSE(j.contains("entries"));
    auto& ej = j["dispositions"][0];
    REQUIRE(ej["fingerprint"] == "sha256:abc123");
    REQUIRE(ej["ruleId"]      == "LINT001");
    REQUIRE(ej["file"]        == "src/foo.cpp");
    REQUIRE(ej["line"]        == 42);
    REQUIRE(ej["status"]      == "deferred");
    REQUIRE(ej["note"]        == "tracked in JIRA-123");
    REQUIRE(ej["by"]          == "matt@jellybaby.com");
    REQUIRE(ej["at"]          == "2026-06-10T12:00:00Z");
    REQUIRE_FALSE(ej.contains("action"));
    REQUIRE_FALSE(ej.contains("rationale"));
    REQUIRE_FALSE(ej.contains("reviewer"));
    REQUIRE_FALSE(ej.contains("date"));
}

// Migration: a legacy on-disk file (entries/action/date/rationale/reviewer)
// must still be readable, not silently dropped.
TEST_CASE("disposition: load migrates the legacy entries/action shape",
          "[disposition][disp002]") {
    TempDir tmp;
    tmp.write(std::string(disposition::DISPOSITIONS_FILE), R"({
      "entries": [
        {
          "ruleId": "LINT001",
          "action": "accept",
          "date": "2026-06-09",
          "rationale": "Test files use new for test fixtures",
          "reference": "test-only",
          "reviewer": "Matt Jones"
        }
      ]
    })");
    auto log = disposition::load(tmp.path());
    REQUIRE(log.entries.size() == 1);
    REQUIRE(log.entries[0].rule_id  == "LINT001");
    REQUIRE(log.entries[0].status   == disposition::Status::Accepted);
    REQUIRE(log.entries[0].note     == "Test files use new for test fixtures");
    REQUIRE(log.entries[0].by       == "Matt Jones");
    REQUIRE(log.entries[0].at       == "2026-06-09");
    REQUIRE(log.entries[0].reference == "test-only");
}

TEST_CASE("disposition: load migrates a legacy action:fix entry to status deferred",
          "[disposition][disp002]") {
    TempDir tmp;
    tmp.write(std::string(disposition::DISPOSITIONS_FILE), R"({
      "entries": [
        { "ruleId": "LINT002", "action": "fix", "reviewer": "x", "date": "2026-01-01",
          "rationale": "r", "reference": "" }
      ]
    })");
    auto log = disposition::load(tmp.path());
    REQUIRE(log.entries.size() == 1);
    REQUIRE(log.entries[0].status == disposition::Status::Deferred);
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
    REQUIRE(j.contains("dispositions"));
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
    disposition::Entry e;
    e.rule_id = "LINT002"; e.note = "rationale"; e.by = "bob";
    e.at = "2026-01-02T00:00:00Z"; e.status = disposition::Status::Deferred;
    log = disposition::add(log, e);
    REQUIRE(log.entries.size() == 1);
}

TEST_CASE("disposition: add updates existing rule_id", "[disposition][disp003]") {
    disposition::Log log;
    disposition::Entry e1;
    e1.rule_id = "LINT001"; e1.note = "old"; e1.by = "alice";
    e1.at = "2026-01-01T00:00:00Z"; e1.status = disposition::Status::Accepted;
    disposition::Entry e2;
    e2.rule_id = "LINT001"; e2.note = "new"; e2.by = "bob";
    e2.at = "2026-01-02T00:00:00Z"; e2.status = disposition::Status::Deferred;
    log = disposition::add(log, e1);
    log = disposition::add(log, e2);
    REQUIRE(log.entries.size() == 1);
    REQUIRE(log.entries[0].note == "new");
}

TEST_CASE("disposition: find_by_rule returns entry when present", "[disposition][disp003]") {
    disposition::Log log;
    disposition::Entry e;
    e.rule_id = "LINT003"; e.note = "r"; e.by = "x";
    e.at = "2026-01-01T00:00:00Z"; e.status = disposition::Status::Accepted;
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
