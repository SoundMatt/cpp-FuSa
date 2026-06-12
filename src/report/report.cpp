#include "report.hpp"
#include "cpfusa/fusa.hpp"
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

// §3.1 common header — on every document.
json make_header(std::string_view kind) {
    json h;
    h["schemaVersion"] = std::string(SpecVersion);
    h["kind"]          = std::string(kind);
    h["tool"]          = "cpp-FuSa";
    h["toolVersion"]   = std::string(Version);
    h["language"]      = "cpp";
    h["generatedAt"]   = now_iso8601();
    return h;
}

// §3.2 report envelope (report documents add these fields to the §3.1 header).
void add_report_envelope(json& j, const config::ProjectConfig& cfg) {
    j["projectRoot"] = cfg.project_root;
    if (!cfg.project.empty())  j["project"]  = cfg.project;
    if (!cfg.standard.empty()) j["standard"]  = cfg.standard;
    if (!cfg.asil.empty()) {
        // emit only the relevant integrity key (§1.2.1 / §3.2)
        const auto& a = cfg.asil;
        if (a.rfind("SIL", 0) == 0)      j["sil"] = a;
        else if (a.rfind("DAL", 0) == 0) j["dal"] = a;
        else                              j["asil"] = a;
    }
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
        if (!loc.empty())         out << "  at " << loc << "\n";
        if (!f.remediation.empty()) out << "  remediation: " << f.remediation << "\n";
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

// §4 check-report JSON — spec v1.8 canonical shape.
std::string render_json(const std::vector<Finding>& findings,
                        const config::ProjectConfig& cfg) {
    json j = make_header("check-report");
    add_report_envelope(j, cfg);

    json farr = json::array();
    int errors = 0, warnings = 0, infos = 0;
    for (const auto& f : findings) {
        json item;
        item["ruleId"]   = f.rule_id;                 // §4: camelCase key
        item["severity"] = severity_label(f.severity);
        item["message"]  = f.message;
        // §4: location MUST be an object, not flat file/line
        json loc;
        loc["file"] = f.file;                          // project-relative (§4)
        if (f.line > 0)       loc["line"]      = f.line;
        if (f.column > 0)     loc["column"]    = f.column;
        if (f.end_line > 0)   loc["endLine"]   = f.end_line;   // §4 MAY
        if (f.end_column > 0) loc["endColumn"] = f.end_column; // §4 MAY
        item["location"] = loc;
        if (!f.category.empty())     item["category"]    = f.category;
        if (!f.standard_id.empty())  item["standard"]    = f.standard_id;
        if (!f.clause.empty())       item["clause"]      = f.clause;
        if (!f.remediation.empty())  item["remediation"] = f.remediation; // §4: NOT "fix"
        if (!f.fingerprint.empty())  item["fingerprint"] = f.fingerprint;
        farr.push_back(item);
        switch (f.severity) {
            case Severity::ERROR:   ++errors;   break;
            case Severity::WARNING: ++warnings; break;
            case Severity::INFO:    ++infos;    break;
        }
    }
    j["findings"] = farr;
    j["summary"]  = {{"total", static_cast<int>(findings.size())},
                     {"errors", errors}, {"warnings", warnings}, {"infos", infos}};
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
.remediation{color:#27ae60;font-style:italic}
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
            if (!f.remediation.empty())
                out << "<br><span class=\"remediation\">remediation: " << f.remediation << "</span>";
            out << "</div>\n";
        }
    }
    out << "</body></html>\n";
    return out.str();
}

// §2.9 / §4: SARIF 2.1.0 with physicalLocation on every result.
std::string render_sarif(const std::vector<Finding>& findings,
                         const config::ProjectConfig& cfg) {
    json sarif;
    sarif["version"] = "2.1.0";
    sarif["$schema"] = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";

    json run;
    // §2.9: tool.driver.name = canonical human name from §1.1 registry
    run["tool"]["driver"]["name"]           = "cpp-FuSa";
    run["tool"]["driver"]["version"]        = std::string(Version);
    run["tool"]["driver"]["informationUri"] = "https://github.com/SoundMatt/cpp-FuSa";

    // Collect unique rules for tool.driver.rules[]
    json rules_arr = json::array();
    std::vector<std::string> seen_rules;
    for (const auto& f : findings) {
        if (std::find(seen_rules.begin(), seen_rules.end(), f.rule_id) == seen_rules.end()) {
            json r;
            r["id"] = f.rule_id;
            if (!f.category.empty() || !f.standard_id.empty()) {
                json props;
                if (!f.category.empty())    props["category"] = f.category;
                if (!f.standard_id.empty()) props["standard"] = f.standard_id;
                if (!f.clause.empty())      props["clause"]   = f.clause;
                r["properties"] = props;
            }
            rules_arr.push_back(r);
            seen_rules.push_back(f.rule_id);
        }
    }
    run["tool"]["driver"]["rules"] = rules_arr;

    json results = json::array();
    for (const auto& f : findings) {
        json r;
        r["ruleId"] = f.rule_id;  // §2.9: same id in every format
        r["level"]  = (f.severity == Severity::ERROR)   ? "error"
                    : (f.severity == Severity::WARNING)  ? "warning" : "note";
        r["message"]["text"] = f.message;
        // §4: physicalLocation MUST be on every result (GitHub Code Scanning)
        std::string uri = f.file.empty() ? "." : f.file; // already project-relative
        r["locations"] = json::array({
            {{"physicalLocation",
              {{"artifactLocation", {{"uri", uri}}},
               {"region", [&]() {
                   json reg{{"startLine", f.line > 0 ? f.line : 1}};
                   if (f.column > 0)     reg["startColumn"] = f.column;
                   if (f.end_line > 0)   reg["endLine"]     = f.end_line;
                   if (f.end_column > 0) reg["endColumn"]   = f.end_column;
                   return reg;
               }()}}}}
        });
        if (!cfg.project.empty()) {
            json props;
            if (!f.category.empty())    props["category"] = f.category;
            if (!f.standard_id.empty()) props["standard"] = f.standard_id;
            r["properties"] = props;
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
        // §2.2: when --output is absent, write to stdout
        std::cout << content;
        return std::monostate{};
    }
    // §2.2 MUST: when --output is given, write to file and MUST NOT also write to stdout
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
