//fusa:test REQ-QUAL001
//fusa:test REQ-QUAL002
//fusa:test REQ-QUAL003
//fusa:test REQ-QUAL004
//fusa:test REQ-QUAL005
//fusa:test REQ-QUAL006
//fusa:test REQ-QUAL007
#include <catch2/catch_all.hpp>
#include "quality/quality.hpp"
#include <nlohmann/json.hpp>

using namespace cpfusa;
using json = nlohmann::json;

// ─── hashing ──────────────────────────────────────────────────────────────────

TEST_CASE("quality: sha256_hex is 64 lowercase hex chars", "[quality][qual001]") {
    auto h = quality::sha256_hex("hello");
    REQUIRE(h.size() == 64);
    REQUIRE(h == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
}

TEST_CASE("quality: sha256_prefixed carries sha256: prefix", "[quality][qual001]") {
    auto h = quality::sha256_prefixed("hello");
    REQUIRE(h.rfind("sha256:", 0) == 0);
    REQUIRE(h == "sha256:" + quality::sha256_hex("hello"));
}

// ─── canonicalisation ─────────────────────────────────────────────────────────

TEST_CASE("quality: canonical_bytes is independent of key insertion order", "[quality][qual002]") {
    json a, b;
    a["z"] = 1; a["a"] = 2;
    b["a"] = 2; b["z"] = 1;
    REQUIRE(quality::canonical_bytes(a) == quality::canonical_bytes(b));
}

TEST_CASE("quality: canonical_bytes has no insignificant whitespace", "[quality][qual002]") {
    json j; j["a"] = 1;
    auto bytes = quality::canonical_bytes(j);
    REQUIRE(bytes == R"({"a":1})");
}

TEST_CASE("quality: content_hash is stable across key order", "[quality][qual002]") {
    json a, b;
    a["x"] = "one"; a["y"] = 2;
    b["y"] = 2; b["x"] = "one";
    REQUIRE(quality::content_hash(a) == quality::content_hash(b));
    REQUIRE(quality::content_hash(a).rfind("sha256:", 0) == 0);
}

TEST_CASE("quality: content_hash changes when content changes", "[quality][qual002]") {
    json a, b;
    a["x"] = "one";
    b["x"] = "two";
    REQUIRE(quality::content_hash(a) != quality::content_hash(b));
}

// ─── fingerprint ──────────────────────────────────────────────────────────────

TEST_CASE("quality: fingerprint is deterministic", "[quality][qual003]") {
    auto f1 = quality::fingerprint("FUSA-STUB001", "src/foo.cpp", "bad thing");
    auto f2 = quality::fingerprint("FUSA-STUB001", "src/foo.cpp", "bad thing");
    REQUIRE(f1 == f2);
    REQUIRE(f1.rfind("sha256:", 0) == 0);
}

TEST_CASE("quality: fingerprint collapses digit runs", "[quality][qual003]") {
    auto f1 = quality::fingerprint("R1", "f", "line 42 failed");
    auto f2 = quality::fingerprint("R1", "f", "line 99999 failed");
    REQUIRE(f1 == f2);
}

TEST_CASE("quality: fingerprint differs on rule id", "[quality][qual003]") {
    auto f1 = quality::fingerprint("R1", "f", "msg");
    auto f2 = quality::fingerprint("R2", "f", "msg");
    REQUIRE(f1 != f2);
}

// ─── attestation ──────────────────────────────────────────────────────────────

TEST_CASE("quality: parse defaults to heuristic when absent", "[quality][qual004]") {
    json doc; doc["foo"] = "bar";
    auto a = quality::parse(doc);
    REQUIRE_FALSE(a.present);
    REQUIRE(a.status == "heuristic");
}

TEST_CASE("quality: parse reads a reviewed attestation", "[quality][qual004]") {
    json doc;
    doc["attestation"] = {
        {"status", "reviewed"},
        {"implementationAuthor", "auto"},
        {"independentReviewer", "Jane Doe <jane@example.com>"},
        {"reviewedAt", "2026-07-28T00:00:00Z"},
        {"contentHash", "sha256:abc"}
    };
    auto a = quality::parse(doc);
    REQUIRE(a.present);
    REQUIRE(a.status == "reviewed");
    REQUIRE(a.independent_reviewer == "Jane Doe <jane@example.com>");
}

TEST_CASE("quality: parse downgrades unrecognised status to heuristic", "[quality][qual004]") {
    json doc; doc["attestation"] = {{"status", "bogus"}};
    auto a = quality::parse(doc);
    REQUIRE(a.status == "heuristic");
}

TEST_CASE("quality: is_valid_reviewed true for genuine independent review", "[quality][qual005]") {
    json content; content["x"] = "y";
    quality::Attestation a;
    a.present = true;
    a.status = "reviewed";
    a.implementation_author = "auto";
    a.independent_reviewer = "Jane Doe <jane@example.com>";
    a.content_hash = quality::content_hash(content);
    REQUIRE(quality::is_valid_reviewed(a, content));
}

TEST_CASE("quality: is_valid_reviewed false when reviewer equals author (self-attestation)", "[quality][qual005]") {
    json content; content["x"] = "y";
    quality::Attestation a;
    a.present = true;
    a.status = "reviewed";
    a.implementation_author = "Jane Doe <jane@example.com>";
    a.independent_reviewer = "Jane Doe <jane@example.com>";
    a.content_hash = quality::content_hash(content);
    REQUIRE_FALSE(quality::is_valid_reviewed(a, content));
}

TEST_CASE("quality: is_valid_reviewed false when content_hash is stale", "[quality][qual005]") {
    json content; content["x"] = "y";
    quality::Attestation a;
    a.present = true;
    a.status = "reviewed";
    a.implementation_author = "auto";
    a.independent_reviewer = "Jane Doe <jane@example.com>";
    a.content_hash = "sha256:not-the-real-hash";
    REQUIRE_FALSE(quality::is_valid_reviewed(a, content));
}

TEST_CASE("quality: is_valid_reviewed false for heuristic status", "[quality][qual005]") {
    json content; content["x"] = "y";
    quality::Attestation a;
    a.present = true;
    a.status = "heuristic";
    REQUIRE_FALSE(quality::is_valid_reviewed(a, content));
}

// ─── Rule A / FUSA-STUB001 ────────────────────────────────────────────────────

TEST_CASE("quality: scan_stub001 flags bracketed placeholder text", "[quality][qual006]") {
    std::vector<quality::QualField> fields = {
        {"description", "[describe asset]", "fmea.json", 0},
    };
    auto findings = quality::scan_stub001(fields, "fmea.json");
    REQUIRE(findings.size() == 1);
    REQUIRE(findings[0].rule_id == quality::kStub001RuleId);
    REQUIRE(findings[0].severity == Severity::ERROR);
    REQUIRE(findings[0].category == "safety");
    REQUIRE_FALSE(findings[0].fingerprint.empty());
}

TEST_CASE("quality: scan_stub001 flags 'replace with' case-insensitively", "[quality][qual006]") {
    std::vector<quality::QualField> fields = {
        {"description", "Example hazard — REPLACE WITH project-specific hazard", "", 0},
    };
    auto findings = quality::scan_stub001(fields, "hara.json");
    REQUIRE(findings.size() == 1);
}

TEST_CASE("quality: scan_stub001 flags TBD and lorem ipsum", "[quality][qual006]") {
    std::vector<quality::QualField> fields = {
        {"a", "TBD", "", 0},
        {"b", "lorem ipsum dolor", "", 0},
        {"c", "please fill in details", "", 0},
    };
    auto findings = quality::scan_stub001(fields, "x.json");
    REQUIRE(findings.size() == 3);
}

TEST_CASE("quality: scan_stub001 does not flag genuine content", "[quality][qual006]") {
    std::vector<quality::QualField> fields = {
        {"description", "Adapter registry returns a null pointer when PATH lookup fails", "", 0},
    };
    auto findings = quality::scan_stub001(fields, "x.json");
    REQUIRE(findings.empty());
}

// ─── Rule B / FUSA-STUB002 ────────────────────────────────────────────────────

TEST_CASE("quality: scan_stub002 does not fire below 10 entries", "[quality][qual007]") {
    std::vector<quality::QualField> fields;
    for (int i = 0; i < 9; ++i) fields.push_back({"failureMode", "Incorrect return value", "", 0});
    auto findings = quality::scan_stub002(fields, "fmea.json");
    REQUIRE(findings.empty());
}

TEST_CASE("quality: scan_stub002 fires when one value covers >=10 entries", "[quality][qual007]") {
    std::vector<quality::QualField> fields;
    for (int i = 0; i < 12; ++i) fields.push_back({"failureMode", "Incorrect return value", "", 0});
    auto findings = quality::scan_stub002(fields, "fmea.json");
    REQUIRE(findings.size() == 1);
    REQUIRE(findings[0].rule_id == quality::kStub002RuleId);
    REQUIRE(findings[0].severity == Severity::WARNING);
}

TEST_CASE("quality: scan_stub002 does not fire when values vary sufficiently", "[quality][qual007]") {
    std::vector<quality::QualField> fields;
    for (int i = 0; i < 12; ++i)
        fields.push_back({"failureMode", "Failure mode #" + std::to_string(i), "", 0});
    auto findings = quality::scan_stub002(fields, "fmea.json");
    REQUIRE(findings.empty());
}
