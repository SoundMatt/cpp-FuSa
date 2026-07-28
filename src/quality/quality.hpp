#pragma once
// quality implements the x-FuSa spec §1.6 "evidence artifact content-quality
// baseline" shared by every evidence artifact with free-text qualitative
// content: fmea.json, .fusa-hara.json, tara.json, safety-case.json, sas.json.
//
// It provides three things every one of those artifact modules needs:
//   1. §1.6.1 Rule A / FUSA-STUB001 — placeholder-text deny-list scan
//      (always ERROR, disposition-suppressible only).
//   2. §1.6.1 Rule B / FUSA-STUB002 — distinct-value-ratio scan
//      (WARNING by default, attestation-suppressible, --strict-gating).
//   3. §1.6.2 Attestation — the DCO-style independent-review mechanism that
//      resolves Rule B's false-positive risk, plus the §4.2 fingerprint and
//      RFC 8785-subset canonicalization both rules and attestation hashing
//      depend on.
#include "cpfusa/fusa.hpp"
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

namespace cpfusa::quality {

// §1.6.1 canonical rule ids.
constexpr const char* kStub001RuleId = "FUSA-STUB001";
constexpr const char* kStub002RuleId = "FUSA-STUB002";

// ---- hashing & canonicalisation (§2.7, §4.2, §6, §1.6.2) -------------------

// sha256_hex returns the lowercase hex SHA-256 digest of data — the bare-hex
// form §2.7 mandates for a field *named for its algorithm* (e.g. sci's old
// "sha256" field). Prefer sha256_prefixed for any field literally named
// "hash", whose algorithm varies by convention.
//
//fusa:req REQ-QUAL001
[[nodiscard]] std::string sha256_hex(const std::string& data);

// sha256_prefixed returns "sha256:" + sha256_hex(data) — the §2.7 convention
// for a field named "hash" (SBOM components[].hash, fingerprint, qualify.hash,
// sci artifacts[].hash, attestation.contentHash).
//
//fusa:req REQ-QUAL001
[[nodiscard]] std::string sha256_prefixed(const std::string& data);

// canonical_bytes serialises j per a practical subset of RFC 8785 (JCS): UTF-8,
// object keys sorted lexicographically at every level, no insignificant
// whitespace, numbers via nlohmann's own shortest round-trip formatting. Used
// for §6 qualify.hash and §1.6.2 attestation.contentHash — any self-integrity
// "hash" field in the spec that must be reproducible independent of key/array
// ordering.
//
//fusa:req REQ-QUAL002
[[nodiscard]] std::string canonical_bytes(const nlohmann::json& j);

// content_hash = "sha256:" + lowercase_hex(SHA-256(canonical_bytes(content))).
//
//fusa:req REQ-QUAL002
[[nodiscard]] std::string content_hash(const nlohmann::json& content);

// fingerprint computes the §4.2 canonical fingerprint:
//   sha256:" + lowercase_hex(SHA-256(ruleId + "\x1f" + file + "\x1f" + normalizedMessage))
// normalizedMessage collapses ASCII digit runs to "#" and whitespace runs to
// a single space, then trims.
//
//fusa:req REQ-QUAL003
[[nodiscard]] std::string fingerprint(const std::string& rule_id,
                                      const std::string& file,
                                      const std::string& message);

// ---- §1.6.2 attestation -----------------------------------------------------

struct Attestation {
    // "heuristic" | "reviewed". Absent input MUST be treated as "heuristic"
    // (fail-safe) — see parse().
    std::string status{"heuristic"};
    std::string implementation_author;
    std::string independent_reviewer;
    std::string reviewed_at;     // RFC 3339
    std::string content_hash;    // "sha256:..."
    bool present{false};         // true only when the source doc actually carried one
};

// parse reads doc["attestation"] when present; a missing/malformed object
// yields the fail-safe default (status "heuristic", present=false).
//
//fusa:req REQ-QUAL004
[[nodiscard]] Attestation parse(const nlohmann::json& doc);

// to_json serialises a present attestation per §1.6.2's shape. Only call when
// a.present (or when about to persist a freshly-authored one).
//
//fusa:req REQ-QUAL004
[[nodiscard]] nlohmann::json to_json(const Attestation& a);

// is_valid_reviewed reports whether `a` is a non-stale, genuinely-independent
// "reviewed" attestation over `content` (§1.6.2): status=="reviewed",
// independent_reviewer non-empty and distinct from implementation_author, and
// content_hash == content_hash(content) (a stale hash — i.e. the artifact
// changed since review — falls back to false, same as "heuristic").
//
//fusa:req REQ-QUAL005
[[nodiscard]] bool is_valid_reviewed(const Attestation& a, const nlohmann::json& content);

// ---- §1.6.1 detection heuristics -------------------------------------------

// QualField is one qualitative (free-text) field instance to scan — e.g. one
// FMEA entry's failureMode, or one HARA hazard's description.
struct QualField {
    std::string field;   // e.g. "failureMode", "description", "text"
    std::string value;
    std::string file;    // location.file for the resulting Finding
    int line{0};
};

// scan_stub001 (Rule A) flags any qualitative value containing bracketed
// instructional text or a deny-listed substring ("replace with", "example
// hazard", "tbd", "lorem ipsum", "fill in" — case-insensitive) as an ERROR
// Finding, category "safety", ruleId FUSA-STUB001. Always runs regardless of
// entry count. Never attestation-suppressible (§1.6.1).
//
//fusa:req REQ-QUAL006
[[nodiscard]] std::vector<Finding> scan_stub001(const std::vector<QualField>& fields,
                                                const std::string& artifact_file);

// scan_stub002 (Rule B) groups fields by name and, for any group with >=10
// entries, computes distinct(value)/count; a ratio < 0.1 emits one WARNING
// Finding (category "safety", ruleId FUSA-STUB002) naming the field and ratio.
// Caller applies attestation suppression (is_valid_reviewed) separately —
// this function always reports the raw heuristic result.
//
//fusa:req REQ-QUAL007
[[nodiscard]] std::vector<Finding> scan_stub002(const std::vector<QualField>& fields,
                                                const std::string& artifact_file);

} // namespace cpfusa::quality
