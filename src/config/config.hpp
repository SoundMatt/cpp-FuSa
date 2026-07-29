//fusa:req REQ-CFG001 REQ-CFG002 REQ-CFG003 REQ-CFG004 REQ-CFG005 REQ-CFG006
#pragma once

#include "cpfusa/fusa.hpp"
#include <filesystem>
#include <string>
#include <vector>

namespace cpfusa::config {

struct ProjectConfig {
    std::string project;            // display name (project.name from §1.2.1)
    std::string version;            // project version (project.version from §1.2.1)
    std::string standard;           // canonical standard id (§2.4.1)
    std::string asil;               // integrity level value
    std::string language{"cpp"};    // registry language id (§1.1)
    std::vector<std::string> source_dirs;
    std::vector<std::string> exclude_patterns;
    bool strict{false};
    std::string project_root;       // absolute path to --dir (for envelope projectRoot)
};

constexpr std::string_view ConfigFile = ".fusa.json";

[[nodiscard]] Result<ProjectConfig> load(const std::filesystem::path& dir);
[[nodiscard]] Result<std::monostate> save(const std::filesystem::path& dir,
                                          const ProjectConfig& cfg);
[[nodiscard]] ProjectConfig defaults(const std::filesystem::path& dir);
[[nodiscard]] bool exists(const std::filesystem::path& dir);

// under_source_dirs reports whether `candidate` (any path under `project_root`,
// absolute or relative) falls inside one of cfg.source_dirs. Every
// source-walking command (check, trace, fmea, coupling, boundary, cyber —
// §1.2.1 MUST) should call this alongside its own exclude_patterns check so a
// stray/differently-named build directory or any other out-of-scope tree
// never gets scanned as project source. When cfg.source_dirs is empty (the
// field is MAY — a project need not set it), every path is in scope, which
// preserves the pre-existing whole-tree-scan default.
//
//fusa:req REQ-CFG006
[[nodiscard]] bool under_source_dirs(const std::filesystem::path& candidate,
                                     const std::filesystem::path& project_root,
                                     const ProjectConfig& cfg);

} // namespace cpfusa::config
