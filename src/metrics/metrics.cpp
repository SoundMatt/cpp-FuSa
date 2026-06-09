#include "metrics.hpp"
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <nlohmann/json.hpp>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace cpfusa::metrics {

namespace {
std::string now_iso() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ss;
    ss << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}
} // namespace

TimeSeries load(const fs::path& dir) {
    TimeSeries ts;
    auto p = dir / METRICS_FILE;
    if (!fs::exists(p)) return ts;
    std::ifstream f(p);
    if (!f) return ts;
    try {
        auto j = json::parse(f);
        ts.project = j.value("project", "");
        for (auto& s : j.value("snapshots", json::array())) {
            Snapshot snap;
            snap.timestamp           = s.value("timestamp", "");
            snap.error_count         = s.value("errorCount", 0);
            snap.warning_count       = s.value("warningCount", 0);
            snap.info_count          = s.value("infoCount", 0);
            snap.total_requirements  = s.value("totalRequirements", 0);
            snap.traced_requirements = s.value("tracedRequirements", 0);
            snap.coverage_pct        = s.value("coveragePct", 0.0);
            snap.cyber_findings      = s.value("cyberFindings", 0);
            ts.snapshots.push_back(snap);
        }
    } catch (...) {}
    return ts;
}

//fusa:req REQ-METRICS002
Snapshot collect(const fs::path& dir) {
    Snapshot snap;
    snap.timestamp = now_iso();

    // Count findings from check-report.json if present
    auto check_rep = dir / "check-report.json";
    if (fs::exists(check_rep)) {
        try {
            std::ifstream f(check_rep);
            auto j = json::parse(f);
            for (auto& finding : j.value("findings", json::array())) {
                std::string sev = finding.value("severity", "");
                if (sev == "error")   snap.error_count++;
                else if (sev == "warning") snap.warning_count++;
                else                  snap.info_count++;
            }
        } catch (...) {}
    }

    // Count requirements from .fusa-reqs.json
    auto reqs_file = dir / ".fusa-reqs.json";
    if (fs::exists(reqs_file)) {
        try {
            std::ifstream f(reqs_file);
            auto j = json::parse(f);
            auto reqs = j.value("requirements", json::array());
            snap.total_requirements = static_cast<int>(reqs.size());
            for (auto& r : reqs) {
                if (!r.value("implementations", json::array()).empty() ||
                    !r.value("tests", json::array()).empty())
                    snap.traced_requirements++;
            }
            snap.coverage_pct = snap.total_requirements > 0
                ? 100.0 * snap.traced_requirements / snap.total_requirements : 0.0;
        } catch (...) {}
    }

    // Count cyber findings
    auto cyber_rep = dir / "cyber-report.json";
    if (fs::exists(cyber_rep)) {
        try {
            std::ifstream f(cyber_rep);
            auto j = json::parse(f);
            snap.cyber_findings = static_cast<int>(
                j.value("findings", json::array()).size());
        } catch (...) {}
    }

    return snap;
}

TimeSeries append(TimeSeries ts, const Snapshot& snap) {
    ts.snapshots.push_back(snap);
    return ts;
}

void save(const fs::path& path, const TimeSeries& ts) {
    json j;
    j["project"]   = ts.project;
    j["snapshots"] = json::array();
    for (auto& s : ts.snapshots) {
        j["snapshots"].push_back({
            {"timestamp",           s.timestamp},
            {"errorCount",          s.error_count},
            {"warningCount",        s.warning_count},
            {"infoCount",           s.info_count},
            {"totalRequirements",   s.total_requirements},
            {"tracedRequirements",  s.traced_requirements},
            {"coveragePct",         s.coverage_pct},
            {"cyberFindings",       s.cyber_findings}
        });
    }
    std::ofstream f(path);
    f << j.dump(2);
}

void render_text(const TimeSeries& ts) {
    std::cout << "Safety Metrics — " << ts.project << "\n";
    std::cout << std::string(80, '-') << "\n";
    if (ts.snapshots.empty()) {
        std::cout << "No metrics snapshots recorded yet. Run: cpfusa metrics record\n";
        return;
    }
    std::cout << std::left
              << std::setw(22) << "Timestamp"
              << std::setw(8)  << "Errors"
              << std::setw(10) << "Warnings"
              << std::setw(8)  << "Infos"
              << std::setw(8)  << "Reqs"
              << std::setw(8)  << "Traced"
              << std::setw(10) << "Cov%"
              << std::setw(8)  << "Cyber"
              << "\n";
    std::cout << std::string(80, '-') << "\n";
    for (auto& s : ts.snapshots) {
        std::cout << std::left
                  << std::setw(22) << s.timestamp
                  << std::setw(8)  << s.error_count
                  << std::setw(10) << s.warning_count
                  << std::setw(8)  << s.info_count
                  << std::setw(8)  << s.total_requirements
                  << std::setw(8)  << s.traced_requirements
                  << std::setw(10) << std::fixed << std::setprecision(1) << s.coverage_pct
                  << std::setw(8)  << s.cyber_findings
                  << "\n";
    }
}

void render_json(const fs::path& out, const TimeSeries& ts) {
    save(out, ts);
}

} // namespace cpfusa::metrics
