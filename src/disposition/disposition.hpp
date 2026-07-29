#pragma once
#include <filesystem>
#include <string>
#include <vector>

namespace cpfusa::disposition {

//fusa:req REQ-DISP001
constexpr const char* DISPOSITIONS_FILE = ".fusa-dispositions.json";

// §1.2.3: status is a closed enum — accepted (waiver granted) | deferred
// (waiver granted for now, tracked to fix later) | rejected (a proposed
// waiver was denied — the finding remains actionable).
enum class Status { Accepted, Deferred, Rejected };
std::string status_str(Status s);
Status      parse_status(const std::string& s);

// §1.2.3 canonical shape: { fingerprint, ruleId, file, line, status, note,
// by, at }. `reference` is a tool-defined additive field (not in the spec
// schema) kept for ticket/issue traceability.
struct Entry {
    std::string fingerprint;  // SHOULD. §4.2 fingerprint — primary match key
    std::string rule_id;      // MAY. fallback match key
    std::string file;         // MAY. fallback match key (project-relative)
    int         line{0};      // MAY. fallback match key
    Status      status{Status::Accepted};
    std::string note;         // SHOULD
    std::string by;           // SHOULD
    std::string at;           // SHOULD. RFC 3339
    std::string reference;    // tool-defined additive field (ticket/issue link)
};

struct Log {
    std::vector<Entry> entries;
};

// load reads .fusa-dispositions.json. Accepts the canonical
// {"dispositions": [...]} shape (§1.2.3); also accepts the legacy
// {"entries": [...]} shape this tool wrote before adopting §1.2.3 (migration
// — never written, only read, per the §1.2 "un-prefixed name is canonical"
// migration convention).
[[nodiscard]] Log  load(const std::filesystem::path& dir);
// save always writes the canonical {"dispositions": [...]} shape.
[[nodiscard]] bool save(const std::filesystem::path& path, const Log& log, std::string& err);
Log add(Log log, const Entry& e);
void render_entries(const Log& log);
bool find_by_rule(const Log& log, const std::string& rule_id, Entry& out);

} // namespace cpfusa::disposition
