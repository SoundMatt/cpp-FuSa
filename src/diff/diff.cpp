#include "diff.hpp"
#include <nlohmann/json.hpp>
#include <fstream>
#include <sstream>

using json = nlohmann::json;

namespace cpfusa::diff {

namespace {

std::string key_of(const DiffFinding& f) {
    return f.rule_id + ":" + f.file + ":" + std::to_string(f.line);
}

} // namespace

//fusa:req REQ-DIFF002
Result<std::vector<DiffFinding>> load_findings(const std::filesystem::path& report_path) {
    if (!std::filesystem::exists(report_path)) {
        return std::string("diff: report not found: ") + report_path.string();
    }
    std::ifstream f(report_path);
    if (!f) return std::string("diff: cannot open ") + report_path.string();
    try {
        json j = json::parse(f);
        std::vector<DiffFinding> findings;
        if (!j.contains("findings")) return findings;
        for (const auto& fi : j["findings"]) {
            DiffFinding df;
            df.rule_id  = fi.value("ruleId",   fi.value("rule_id", ""));
            df.severity = fi.value("severity", "");
            df.message  = fi.value("message",  "");
            // Support both nested location and flat file/line
            if (fi.contains("location")) {
                df.file = fi["location"].value("file", "");
                df.line = fi["location"].value("line", 0);
            } else {
                df.file = fi.value("file", "");
                df.line = fi.value("line", 0);
            }
            findings.push_back(df);
        }
        return findings;
    } catch (const json::exception& e) {
        return std::string("diff: parse error: ") + e.what();
    }
}

//fusa:req REQ-DIFF001
Diff compare(const std::vector<DiffFinding>& baseline,
             const std::vector<DiffFinding>& current) {
    std::unordered_map<std::string, DiffFinding> base_set, cur_set;
    for (const auto& f : baseline) base_set[key_of(f)] = f;
    for (const auto& f : current)  cur_set[key_of(f)]  = f;

    Diff d;
    for (const auto& [k, f] : cur_set) {
        if (base_set.count(k)) d.unchanged.push_back(f);
        else                   d.introduced.push_back(f);
    }
    for (const auto& [k, f] : base_set) {
        if (!cur_set.count(k)) d.resolved.push_back(f);
    }
    return d;
}

//fusa:req REQ-DIFF003
std::string render_text(const Diff& d) {
    std::ostringstream ss;
    ss << "cpfusa diff\n" << std::string(60, '-') << "\n\n";
    ss << "Introduced (" << d.introduced.size() << "):\n";
    for (const auto& f : d.introduced)
        ss << "  [+] " << f.rule_id << " — " << f.file << ":" << f.line
           << " — " << f.message << "\n";
    ss << "\nResolved (" << d.resolved.size() << "):\n";
    for (const auto& f : d.resolved)
        ss << "  [-] " << f.rule_id << " — " << f.file << ":" << f.line
           << " — " << f.message << "\n";
    ss << "\nUnchanged (" << d.unchanged.size() << "):\n";
    for (const auto& f : d.unchanged)
        ss << "  [=] " << f.rule_id << " — " << f.file << ":" << f.line
           << " — " << f.message << "\n";
    return ss.str();
}

std::string render_json(const Diff& d) {
    auto to_arr = [](const std::vector<DiffFinding>& v) {
        json a = json::array();
        for (const auto& f : v)
            a.push_back({{"ruleId",f.rule_id},{"severity",f.severity},
                         {"message",f.message},{"file",f.file},{"line",f.line}});
        return a;
    };
    json j;
    j["introduced"] = to_arr(d.introduced);
    j["resolved"]   = to_arr(d.resolved);
    j["unchanged"]  = to_arr(d.unchanged);
    return j.dump(2);
}

} // namespace cpfusa::diff
