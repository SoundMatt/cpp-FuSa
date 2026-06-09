#include "rules.hpp"
#include <filesystem>
#include <fstream>
#include <regex>
#include <string>

namespace fs = std::filesystem;

namespace cpfusa::engine {

namespace {

// Returns true if any file in the directory tree matches the predicate.
bool any_file(const fs::path& dir,
              const std::function<bool(const fs::path&)>& pred) {
    if (!fs::exists(dir)) return false;
    for (const auto& entry : fs::recursive_directory_iterator(
             dir, fs::directory_options::skip_permission_denied)) {
        if (entry.is_regular_file() && pred(entry.path())) return true;
    }
    return false;
}

// Searches all .cpp/.hpp/.h/.cxx/.cc files for a regex pattern.
bool source_contains(const fs::path& dir, const std::regex& pat) {
    static const std::regex cpp_ext(R"(\.(cpp|hpp|h|cxx|cc|hxx|c\+\+)$)");
    return any_file(dir, [&](const fs::path& p) {
        if (!std::regex_search(p.string(), cpp_ext)) return false;
        std::ifstream f(p);
        std::string line;
        while (std::getline(f, line)) {
            if (std::regex_search(line, pat)) return true;
        }
        return false;
    });
}

} // anonymous namespace

// FUSA001 – Project configuration file (.fusa.json) must exist.
Rule make_fusa001() {
    return Rule{
        RuleInfo{"FUSA001", "Project configuration",
                 "A .fusa.json configuration file must exist at the project root.",
                 Severity::ERROR},
        [](const fs::path& dir, const config::ProjectConfig&) -> std::vector<Finding> {
            if (fs::exists(dir / ".fusa.json")) return {};
            return {Finding{"FUSA001", Severity::ERROR,
                            ".fusa.json not found — run 'cpfusa init'",
                            (dir / ".fusa.json").string(), 0,
                            "cpfusa init"}};
        }};
}

// FUSA002 – At least one //fusa:req annotation must exist in source.
Rule make_fusa002() {
    return Rule{
        RuleInfo{"FUSA002", "Requirements annotations",
                 "Source must contain at least one //fusa:req annotation.",
                 Severity::WARNING},
        [](const fs::path& dir, const config::ProjectConfig&) -> std::vector<Finding> {
            static const std::regex req_pat(R"(//\s*fusa:req\s+\S)");
            if (source_contains(dir, req_pat)) return {};
            return {Finding{"FUSA002", Severity::WARNING,
                            "No //fusa:req annotations found — traceability cannot be established",
                            "", 0,
                            "Add //fusa:req REQ-XXX comments above safety-critical functions"}};
        }};
}

// FUSA003 – The project version field must be set (not empty / not "0.0.0").
Rule make_fusa003() {
    return Rule{
        RuleInfo{"FUSA003", "Safety version declared",
                 "project.version must be set in .fusa.json.",
                 Severity::WARNING},
        [](const fs::path&, const config::ProjectConfig& cfg) -> std::vector<Finding> {
            if (!cfg.version.empty() && cfg.version != "0.0.0") return {};
            return {Finding{"FUSA003", Severity::WARNING,
                            "Safety version is not declared in .fusa.json",
                            ".fusa.json", 0,
                            "Set the \"version\" field in .fusa.json"}};
        }};
}

// FUSA004 – Test evidence file must exist.
Rule make_fusa004() {
    return Rule{
        RuleInfo{"FUSA004", "Test evidence",
                 "A test evidence bundle (.fusa-evidence.json) must be present.",
                 Severity::WARNING},
        [](const fs::path& dir, const config::ProjectConfig&) -> std::vector<Finding> {
            if (fs::exists(dir / ".fusa-evidence.json")) return {};
            return {Finding{"FUSA004", Severity::WARNING,
                            ".fusa-evidence.json not found — run 'cpfusa verify' after tests pass",
                            "", 0,
                            "cpfusa verify"}};
        }};
}

// FUSA005 – CHANGELOG.md must exist and be non-empty.
Rule make_fusa005() {
    return Rule{
        RuleInfo{"FUSA005", "CHANGELOG present",
                 "CHANGELOG.md must exist and contain at least one release entry.",
                 Severity::INFO},
        [](const fs::path& dir, const config::ProjectConfig&) -> std::vector<Finding> {
            auto p = dir / "CHANGELOG.md";
            if (fs::exists(p) && fs::file_size(p) > 10) return {};
            return {Finding{"FUSA005", Severity::INFO,
                            "CHANGELOG.md missing or empty — add a release history",
                            "CHANGELOG.md", 0,
                            "Create CHANGELOG.md with at least one version entry"}};
        }};
}

} // namespace cpfusa::engine
