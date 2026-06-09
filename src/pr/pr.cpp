#include "pr.hpp"
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <nlohmann/json.hpp>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace cpfusa::pr {

std::string status_str(PRStatus s) {
    switch (s) {
        case PRStatus::Open:       return "open";
        case PRStatus::InProgress: return "in-progress";
        default:                   return "closed";
    }
}
std::string severity_str(PRSeverity s) {
    switch (s) {
        case PRSeverity::Critical: return "critical";
        case PRSeverity::Major:    return "major";
        default:                   return "minor";
    }
}
PRStatus parse_status(const std::string& s) {
    if (s == "in-progress") return PRStatus::InProgress;
    if (s == "closed")      return PRStatus::Closed;
    return PRStatus::Open;
}
PRSeverity parse_severity(const std::string& s) {
    if (s == "critical") return PRSeverity::Critical;
    if (s == "major")    return PRSeverity::Major;
    return PRSeverity::Minor;
}

//fusa:req REQ-PR002
PRLog load(const fs::path& dir) {
    PRLog log;
    auto p = dir / PR_FILE;
    if (!fs::exists(p)) return log;
    std::ifstream f(p);
    if (!f) return log;
    try {
        auto j = json::parse(f);
        log.project = j.value("project", "");
        for (auto& r : j.value("reports", json::array())) {
            ProblemReport pr;
            pr.id          = r.value("id", "");
            pr.title       = r.value("title", "");
            pr.description = r.value("description", "");
            pr.created_at  = r.value("createdAt", "");
            pr.closed_at   = r.value("closedAt", "");
            pr.severity    = parse_severity(r.value("severity", "minor"));
            pr.status      = parse_status(r.value("status", "open"));
            pr.assignee    = r.value("assignee", "");
            pr.resolution  = r.value("resolution", "");
            log.reports.push_back(pr);
        }
    } catch (...) {}
    return log;
}

bool save(const fs::path& path, const PRLog& log, std::string& err) {
    json j;
    j["project"] = log.project;
    j["reports"] = json::array();
    for (auto& r : log.reports) {
        j["reports"].push_back({
            {"id",          r.id},
            {"title",       r.title},
            {"description", r.description},
            {"createdAt",   r.created_at},
            {"closedAt",    r.closed_at},
            {"severity",    severity_str(r.severity)},
            {"status",      status_str(r.status)},
            {"assignee",    r.assignee},
            {"resolution",  r.resolution}
        });
    }
    std::ofstream f(path);
    if (!f) { err = "cannot write " + path.string(); return false; }
    f << j.dump(2);
    return true;
}

PRLog add(PRLog log, const ProblemReport& pr) {
    log.reports.push_back(pr);
    return log;
}

void render(const PRLog& log, const std::string& filter) {
    std::cout << "Problem Reports — " << log.project << "\n";
    std::cout << std::string(70, '-') << "\n";
    int shown = 0;
    for (auto& r : log.reports) {
        if (!filter.empty() && status_str(r.status) != filter) continue;
        std::cout << "[" << r.id << "] " << r.title
                  << "  [" << severity_str(r.severity) << "/" << status_str(r.status) << "]\n";
        if (!r.description.empty())
            std::cout << "  " << r.description << "\n";
        std::cout << "  Created: " << r.created_at;
        if (!r.assignee.empty()) std::cout << "  Assignee: " << r.assignee;
        std::cout << "\n\n";
        shown++;
    }
    if (shown == 0) std::cout << "No problem reports found.\n";
}

} // namespace cpfusa::pr
