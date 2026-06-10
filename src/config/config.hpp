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

} // namespace cpfusa::config
