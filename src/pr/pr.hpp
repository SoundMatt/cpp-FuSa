#pragma once
#include <filesystem>
#include <string>
#include <vector>

namespace cpfusa::pr {

//fusa:req REQ-PR001
constexpr const char* PR_FILE = ".fusa-problems.json";

enum class PRStatus  { Open, InProgress, Closed };
enum class PRSeverity{ Critical, Major, Minor };
std::string status_str(PRStatus s);
std::string severity_str(PRSeverity s);
PRStatus   parse_status(const std::string& s);
PRSeverity parse_severity(const std::string& s);

struct ProblemReport {
    std::string id;
    std::string title;
    std::string description;
    std::string created_at;
    std::string closed_at;
    PRSeverity  severity{PRSeverity::Minor};
    PRStatus    status{PRStatus::Open};
    std::string assignee;
    std::string resolution;
};

struct PRLog {
    std::string project;
    std::vector<ProblemReport> reports;
};

[[nodiscard]] PRLog  load(const std::filesystem::path& dir);
[[nodiscard]] bool   save(const std::filesystem::path& path, const PRLog& log, std::string& err);
PRLog add(PRLog log, const ProblemReport& pr);
void  render(const PRLog& log, const std::string& filter);

} // namespace cpfusa::pr
