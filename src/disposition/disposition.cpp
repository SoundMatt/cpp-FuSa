#include "disposition.hpp"
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <nlohmann/json.hpp>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace cpfusa::disposition {

std::string status_str(Status s) {
    switch (s) {
        case Status::Deferred: return "deferred";
        case Status::Rejected: return "rejected";
        case Status::Accepted:
        default:               return "accepted";
    }
}

Status parse_status(const std::string& s) {
    if (s == "deferred") return Status::Deferred;
    if (s == "rejected") return Status::Rejected;
    return Status::Accepted;
}

namespace {

// Legacy pre-§1.2.3 shape this tool used to read/write: top-level "entries"
// with action/date/rationale/reviewer/reference keys instead of the
// canonical dispositions/status/fingerprint/note/by/at keys (§1.2's
// migration convention: the canonical shape is preferred and is all this
// tool ever writes now, but an already-on-disk legacy file is still read
// rather than silently discarded).
Entry parse_legacy_entry(const json& e) {
    Entry out;
    out.rule_id   = e.value("ruleId", "");
    out.note      = e.value("rationale", "");
    out.by        = e.value("reviewer", "");
    out.at        = e.value("date", "");
    out.status    = e.value("action", "accept") == "fix" ? Status::Deferred : Status::Accepted;
    out.reference = e.value("reference", "");
    return out;
}

Entry parse_canonical_entry(const json& e) {
    Entry out;
    out.fingerprint = e.value("fingerprint", "");
    out.rule_id     = e.value("ruleId", "");
    out.file        = e.value("file", "");
    out.line        = e.value("line", 0);
    out.status      = parse_status(e.value("status", "accepted"));
    out.note        = e.value("note", "");
    out.by          = e.value("by", "");
    out.at          = e.value("at", "");
    out.reference   = e.value("reference", "");
    return out;
}

} // namespace

//fusa:req REQ-DISP002
Log load(const fs::path& dir) {
    Log log;
    auto p = dir / DISPOSITIONS_FILE;
    if (!fs::exists(p)) return log;
    std::ifstream f(p);
    if (!f) return log;
    try {
        auto j = json::parse(f);
        if (j.contains("dispositions")) {
            for (auto& e : j["dispositions"])
                log.entries.push_back(parse_canonical_entry(e));
        } else if (j.contains("entries")) {
            for (auto& e : j["entries"])
                log.entries.push_back(parse_legacy_entry(e));
        }
    } catch (...) {}
    return log;
}

//fusa:req REQ-DISP002
bool save(const fs::path& path, const Log& log, std::string& err) {
    json j;
    json da = json::array();
    for (auto& e : log.entries) {
        json ej;
        // §1.2.3: fingerprint/ruleId/file/line are all match keys (SHOULD/
        // MAY) — omit whichever weren't set rather than emit empty/zero
        // placeholders that would look like real match data.
        if (!e.fingerprint.empty()) ej["fingerprint"] = e.fingerprint;
        if (!e.rule_id.empty())     ej["ruleId"]      = e.rule_id;
        if (!e.file.empty())        ej["file"]        = e.file;
        if (e.line > 0)             ej["line"]        = e.line;
        ej["status"] = status_str(e.status); // MUST
        if (!e.note.empty())        ej["note"]        = e.note;
        if (!e.by.empty())          ej["by"]          = e.by;
        if (!e.at.empty())          ej["at"]          = e.at;
        if (!e.reference.empty())   ej["reference"]   = e.reference;
        da.push_back(ej);
    }
    j["dispositions"] = da;
    std::ofstream f(path);
    if (!f) { err = "cannot write " + path.string(); return false; }
    f << j.dump(2);
    return true;
}

//fusa:req REQ-DISP003
Log add(Log log, const Entry& e) {
    // Update if rule_id already exists
    for (auto& existing : log.entries) {
        if (existing.rule_id == e.rule_id) { existing = e; return log; }
    }
    log.entries.push_back(e);
    return log;
}

void render_entries(const Log& log) {
    if (log.entries.empty()) {
        std::cout << "No dispositions recorded.\n";
        return;
    }
    std::cout << std::string(70, '-') << "\n";
    for (auto& e : log.entries) {
        std::cout << "Rule:      " << e.rule_id << "\n";
        std::cout << "Status:    " << status_str(e.status) << "\n";
        std::cout << "By:        " << e.by << "\n";
        std::cout << "At:        " << e.at << "\n";
        std::cout << "Note:      " << e.note << "\n";
        if (!e.reference.empty())
            std::cout << "Reference: " << e.reference << "\n";
        std::cout << "\n";
    }
}

//fusa:req REQ-DISP003
bool find_by_rule(const Log& log, const std::string& rule_id, Entry& out) {
    for (auto& e : log.entries) {
        if (e.rule_id == rule_id) { out = e; return true; }
    }
    return false;
}

} // namespace cpfusa::disposition
