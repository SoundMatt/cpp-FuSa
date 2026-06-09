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

std::string action_str(Action a) { return a == Action::Accept ? "accept" : "fix"; }
Action parse_action(const std::string& s) { return s == "fix" ? Action::Fix : Action::Accept; }

//fusa:req REQ-DISP002
Log load(const fs::path& dir) {
    Log log;
    auto p = dir / DISPOSITIONS_FILE;
    if (!fs::exists(p)) return log;
    std::ifstream f(p);
    if (!f) return log;
    try {
        auto j = json::parse(f);
        for (auto& e : j.value("entries", json::array())) {
            log.entries.push_back({
                e.value("ruleId",    ""),
                e.value("rationale", ""),
                e.value("reviewer",  ""),
                e.value("date",      ""),
                parse_action(e.value("action", "accept")),
                e.value("reference", "")
            });
        }
    } catch (...) {}
    return log;
}

bool save(const fs::path& path, const Log& log, std::string& err) {
    json j;
    j["entries"] = json::array();
    for (auto& e : log.entries) {
        j["entries"].push_back({
            {"ruleId",    e.rule_id},
            {"rationale", e.rationale},
            {"reviewer",  e.reviewer},
            {"date",      e.date},
            {"action",    action_str(e.action)},
            {"reference", e.reference}
        });
    }
    std::ofstream f(path);
    if (!f) { err = "cannot write " + path.string(); return false; }
    f << j.dump(2);
    return true;
}

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
        std::cout << "Action:    " << action_str(e.action) << "\n";
        std::cout << "Reviewer:  " << e.reviewer << "\n";
        std::cout << "Date:      " << e.date << "\n";
        std::cout << "Rationale: " << e.rationale << "\n";
        if (!e.reference.empty())
            std::cout << "Reference: " << e.reference << "\n";
        std::cout << "\n";
    }
}

bool find_by_rule(const Log& log, const std::string& rule_id, Entry& out) {
    for (auto& e : log.entries) {
        if (e.rule_id == rule_id) { out = e; return true; }
    }
    return false;
}

} // namespace cpfusa::disposition
