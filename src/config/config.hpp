#pragma once

#include "cpfusa/fusa.hpp"
#include <filesystem>
#include <string>
#include <vector>

namespace cpfusa::config {

struct ProjectConfig {
    std::string project;
    std::string version;
    std::string standard;   // iso26262 | iec61508 | iso21434 | do178c
    std::string asil;       // A|B|C|D or SIL-1..4 or DAL-A..E
    std::string language;   // cpp17 | cpp20
    std::vector<std::string> source_dirs;
    std::vector<std::string> exclude_patterns;
    bool strict{false};
};

constexpr std::string_view ConfigFile = ".fusa.json";

[[nodiscard]] Result<ProjectConfig> load(const std::filesystem::path& dir);
[[nodiscard]] Result<std::monostate> save(const std::filesystem::path& dir,
                                          const ProjectConfig& cfg);
[[nodiscard]] ProjectConfig defaults(const std::filesystem::path& dir);
[[nodiscard]] bool exists(const std::filesystem::path& dir);

} // namespace cpfusa::config
