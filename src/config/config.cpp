#include "config.hpp"
#include <nlohmann/json.hpp>
#include <fstream>
#include <sstream>

namespace cpfusa::config {

using json = nlohmann::json;

//fusa:req REQ-CFG001 REQ-CFG002 REQ-CFG003 REQ-CFG004 REQ-CFG005 REQ-CFG006
[[nodiscard]] ProjectConfig defaults(const std::filesystem::path& dir) {
    ProjectConfig cfg;
    cfg.project     = dir.filename().string();
    cfg.version     = "0.1.0";
    cfg.standard    = "iso26262";
    cfg.asil        = "B";
    cfg.language    = "cpp17";
    cfg.source_dirs = {"src", "include"};
    return cfg;
}

[[nodiscard]] bool exists(const std::filesystem::path& dir) {
    return std::filesystem::exists(dir / ConfigFile);
}

[[nodiscard]] Result<ProjectConfig> load(const std::filesystem::path& dir) {
    auto path = dir / ConfigFile;
    if (!std::filesystem::exists(path)) {
        return std::string(ErrNoConfig);
    }
    std::ifstream f(path);
    if (!f) {
        return std::string("failed to open ") + path.string();
    }
    try {
        json j = json::parse(f);
        ProjectConfig cfg;
        cfg.project  = j.value("project",  "");
        cfg.version  = j.value("version",  "0.1.0");
        cfg.standard = j.value("standard", "iso26262");
        cfg.asil     = j.value("asil",     "B");
        cfg.language = j.value("language", "cpp17");
        cfg.strict   = j.value("strict",   false);
        if (j.contains("source_dirs")) {
            cfg.source_dirs = j["source_dirs"].get<std::vector<std::string>>();
        }
        if (j.contains("exclude_patterns")) {
            cfg.exclude_patterns = j["exclude_patterns"].get<std::vector<std::string>>();
        }
        return cfg;
    } catch (const json::exception& ex) {
        return std::string("parse error: ") + ex.what();
    }
}

[[nodiscard]] Result<std::monostate> save(const std::filesystem::path& dir,
                                          const ProjectConfig& cfg) {
    auto path = dir / ConfigFile;
    json j;
    j["project"]      = cfg.project;
    j["version"]      = cfg.version;
    j["standard"]     = cfg.standard;
    j["asil"]         = cfg.asil;
    j["language"]     = cfg.language;
    j["strict"]       = cfg.strict;
    j["source_dirs"]  = cfg.source_dirs;
    if (!cfg.exclude_patterns.empty()) {
        j["exclude_patterns"] = cfg.exclude_patterns;
    }
    std::ofstream f(path);
    if (!f) {
        return std::string("failed to write ") + path.string();
    }
    f << j.dump(2) << "\n";
    return std::monostate{};
}

} // namespace cpfusa::config
