#include "config.hpp"
#include <nlohmann/json.hpp>
#include <fstream>
#include <sstream>

namespace cpfusa::config {

using json = nlohmann::json;

//fusa:req REQ-CFG001 REQ-CFG002 REQ-CFG003 REQ-CFG004 REQ-CFG005 REQ-CFG006
[[nodiscard]] ProjectConfig defaults(const std::filesystem::path& dir) {
    ProjectConfig cfg;
    cfg.project      = dir.filename().string();
    cfg.version      = "0.1.0";
    cfg.standard     = "iso26262";
    cfg.asil         = "ASIL-B";
    cfg.language     = "cpp";
    cfg.source_dirs  = {"src", "include"};
    cfg.project_root = std::filesystem::absolute(dir).string();
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

        // §1.2.1: project — accept nested {name,version} or legacy flat string.
        if (j.contains("project") && j["project"].is_object()) {
            cfg.project = j["project"].value("name", "");
            cfg.version = j["project"].value("version", "0.1.0");
        } else {
            cfg.project = j.value("project", "");
            // version may be a top-level sibling in legacy format
            cfg.version = j.value("version", "0.1.0");
        }

        cfg.standard = j.value("standard", "iso26262");

        // integrity field: asil | sil | dal
        if      (j.contains("asil")) cfg.asil = j["asil"].get<std::string>();
        else if (j.contains("sil"))  cfg.asil = j["sil"].get<std::string>();
        else if (j.contains("dal"))  cfg.asil = j["dal"].get<std::string>();
        else                         cfg.asil = "ASIL-B";

        cfg.language = j.value("language", "cpp");
        cfg.strict   = j.value("strict", false);

        // sourceDirs (camelCase, spec §1.2.1) with snake_case fallback
        if (j.contains("sourceDirs")) {
            cfg.source_dirs = j["sourceDirs"].get<std::vector<std::string>>();
        } else if (j.contains("source_dirs")) {
            cfg.source_dirs = j["source_dirs"].get<std::vector<std::string>>();
        }

        // excludePatterns with snake_case fallback
        if (j.contains("excludePatterns")) {
            cfg.exclude_patterns = j["excludePatterns"].get<std::vector<std::string>>();
        } else if (j.contains("exclude_patterns")) {
            cfg.exclude_patterns = j["exclude_patterns"].get<std::vector<std::string>>();
        }

        cfg.project_root = std::filesystem::absolute(dir).string();
        return cfg;
    } catch (const json::exception& ex) {
        return std::string("parse error: ") + ex.what();
    }
}

[[nodiscard]] Result<std::monostate> save(const std::filesystem::path& dir,
                                          const ProjectConfig& cfg) {
    auto path = dir / ConfigFile;
    json j;
    j["configVersion"]     = "1.0";
    j["project"]           = {{"name", cfg.project}, {"version", cfg.version}};
    j["standard"]          = cfg.standard;
    // Write only the relevant integrity key (§1.2.1: omit the other two)
    if (cfg.standard == "iec61508" || cfg.asil.rfind("SIL", 0) == 0)
        j["sil"]  = cfg.asil;
    else if (cfg.standard == "do178c" || cfg.asil.rfind("DAL", 0) == 0)
        j["dal"]  = cfg.asil;
    else
        j["asil"] = cfg.asil;
    j["sourceDirs"]        = cfg.source_dirs;
    if (!cfg.exclude_patterns.empty())
        j["excludePatterns"] = cfg.exclude_patterns;
    j["strict"]            = cfg.strict;
    std::ofstream f(path);
    if (!f) {
        return std::string("failed to write ") + path.string();
    }
    f << j.dump(2) << "\n";
    return std::monostate{};
}

} // namespace cpfusa::config
