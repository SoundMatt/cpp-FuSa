#include "report.hpp"
#include <nlohmann/json.hpp>
#include <fstream>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <algorithm>

namespace cpfusa::report {

using json = nlohmann::json;

namespace {

std::string now_iso8601() {
    auto t = std::time(nullptr);
    std::ostringstream ss;
    ss << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

std::string severity_label(Severity s) {
    switch (s) {
        case Severity::ERROR:   return "ERROR";
        case Severity::WARNING: return "WARNING";
        case Severity::INFO:    return "INFO";
    }
    return "UNKNOWN";
}

} // namespace

//fusa:req REQ-RPT001 REQ-RPT002 REQ-RPT003 REQ-RPT004 REQ-RPT005
std::string render_text(const std::vector<Finding>& findings,
                        const config::ProjectConfig& cfg) {
    std::ostringstream out;
    out << "cpfusa compliance report — " << cfg.project
        << " v" << cfg.version << " [" << cfg.standard << "/" << cfg.asil << "]\n"
        << "Generated: " << now_iso8601() << "\n"
        << std::string(70, '-') << "\n\n";

    if (findings.empty()) {
        out << "No findings. All checks passed.\n";
        return out.str();
    }

    int errors = 0, warnings = 0, infos = 0;
    for (const auto& f : findings) {
        std::string loc = f.file.empty() ? "" : f.file;
        if (f.line > 0) loc += ":" + std::to_string(f.line);
        out << "[" << severity_label(f.severity) << "] "
            << f.rule_id << ": " << f.message << "\n";
        if (!loc.empty()) out << "  at " << loc << "\n";
        if (!f.fix.empty()) out << "  fix: " << f.fix << "\n";
        out << "\n";
        switch (f.severity) {
            case Severity::ERROR:   ++errors;   break;
            case Severity::WARNING: ++warnings; break;
            case Severity::INFO:    ++infos;    break;
        }
    }

    out << std::string(70, '-') << "\n"
        << "Summary: " << errors << " error(s), "
        << warnings << " warning(s), " << infos << " info(s)\n";
    return out.str();
}

std::string render_json(const std::vector<Finding>& findings,
                        const config::ProjectConfig& cfg) {
    json j;
    j["project"]   = cfg.project;
    j["version"]   = cfg.version;
    j["standard"]  = cfg.standard;
    j["asil"]      = cfg.asil;
    j["generated"] = now_iso8601();
    j["findings"]  = json::array();
    for (const auto& f : findings) {
        json item;
        item["rule_id"]  = f.rule_id;
        item["severity"] = severity_label(f.severity);
        item["message"]  = f.message;
        if (!f.file.empty()) item["file"] = f.file;
        if (f.line > 0)      item["line"] = f.line;
        if (!f.fix.empty())  item["fix"]  = f.fix;
        j["findings"].push_back(item);
    }
    int errors = 0, warnings = 0;
    for (const auto& f : findings) {
        if (f.severity == Severity::ERROR)   ++errors;
        if (f.severity == Severity::WARNING) ++warnings;
    }
    j["summary"] = {{"errors", errors}, {"warnings", warnings},
                    {"infos", static_cast<int>(findings.size()) - errors - warnings}};
    return j.dump(2);
}

std::string render_html(const std::vector<Finding>& findings,
                        const config::ProjectConfig& cfg) {
    std::ostringstream out;
    out << R"(<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">)"
        << "<title>cpfusa — " << cfg.project << "</title>"
        << R"(<style>
body{font-family:monospace;max-width:900px;margin:2em auto;background:#fafafa}
h1{color:#1a1a2e}
.finding{border-left:4px solid #ccc;padding:.5em 1em;margin:.5em 0}
.ERROR{border-color:#e74c3c;background:#fdf0f0}
.WARNING{border-color:#f39c12;background:#fefbf0}
.INFO{border-color:#3498db;background:#f0f8ff}
.rule{font-weight:bold;color:#2c3e50}
.fix{color:#27ae60;font-style:italic}
</style></head><body>
<h1>cpfusa Compliance Report</h1>
<p><b>Project:</b> )" << cfg.project
        << " v" << cfg.version << " &nbsp;|&nbsp; "
        << "<b>Standard:</b> " << cfg.standard << "/" << cfg.asil
        << " &nbsp;|&nbsp; <b>Generated:</b> " << now_iso8601() << "</p>\n";

    if (findings.empty()) {
        out << "<p style=\"color:green\">&#10003; No findings. All checks passed.</p>\n";
    } else {
        for (const auto& f : findings) {
            std::string sev = severity_label(f.severity);
            out << "<div class=\"finding " << sev << "\">"
                << "<span class=\"rule\">[" << sev << "] " << f.rule_id << "</span>: "
                << f.message;
            if (!f.file.empty()) {
                out << "<br><small>at " << f.file;
                if (f.line > 0) out << ":" << f.line;
                out << "</small>";
            }
            if (!f.fix.empty())
                out << "<br><span class=\"fix\">fix: " << f.fix << "</span>";
            out << "</div>\n";
        }
    }
    out << "</body></html>\n";
    return out.str();
}

std::string render_sarif(const std::vector<Finding>& findings,
                         const config::ProjectConfig& cfg) {
    json sarif;
    sarif["version"] = "2.1.0";
    sarif["$schema"] = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";

    json run;
    run["tool"]["driver"]["name"]            = "cpfusa";
    run["tool"]["driver"]["version"]         = std::string(Version);
    run["tool"]["driver"]["informationUri"]  = "https://github.com/SoundMatt/cpp-FuSa";

    json results = json::array();
    for (const auto& f : findings) {
        json r;
        r["ruleId"]  = f.rule_id;
        r["level"]   = (f.severity == Severity::ERROR) ? "error"
                     : (f.severity == Severity::WARNING) ? "warning" : "note";
        r["message"]["text"] = f.message;
        // GitHub Code Scanning requires at least one location on every result.
        {
            std::string uri = f.file.empty() ? "." : f.file;
            r["locations"] = json::array({
                {{"physicalLocation",
                  {{"artifactLocation", {{"uri", uri}}},
                   {"region", {{"startLine", f.line > 0 ? f.line : 1}}}}}}
            });
        }
        results.push_back(r);
    }
    run["results"] = results;
    sarif["runs"]  = json::array({run});
    return sarif.dump(2);
}

Result<std::monostate> write_report(const std::vector<Finding>& findings,
                                    const config::ProjectConfig& cfg,
                                    const ReportOptions& opts) {
    std::string content;
    switch (opts.format) {
        case Format::TEXT:  content = render_text(findings, cfg);  break;
        case Format::JSON:  content = render_json(findings, cfg);  break;
        case Format::HTML:  content = render_html(findings, cfg);  break;
        case Format::SARIF: content = render_sarif(findings, cfg); break;
    }

    if (opts.output.empty()) {
        std::cout << content;
        return std::monostate{};
    }
    std::ofstream f(opts.output);
    if (!f) return std::string("failed to open ") + opts.output;
    f << content;
    return std::monostate{};
}

int exit_code(const std::vector<Finding>& findings, bool strict) {
    for (const auto& f : findings) {
        if (f.severity == Severity::ERROR) return 1;
        if (strict && f.severity == Severity::WARNING) return 1;
    }
    return 0;
}

} // namespace cpfusa::report
