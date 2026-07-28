#pragma once
// sci generates a Software Configuration Index per DO-178C §11.16 —
// x-FuSa spec §9.3.
#include "cpfusa/fusa.hpp"
#include <nlohmann/json.hpp>
#include <filesystem>
#include <string>
#include <vector>

namespace cpfusa::sci {

//fusa:req REQ-SCI001
constexpr const char* SCI_FILE = "sci.json";

// §9.3: artifacts[] — file/hash/version. `hash` is a field *named* "hash"
// (not "sha256"), so per §2.7 it MUST carry the "sha256:" prefix.
struct ConfigItem {
    std::string category;   // tool-defined grouping, additive to §9.3's shape
    std::string file;       // project-relative (§4 rule)
    std::string version;    // the project version this artifact was captured at
    std::string hash;       // "sha256:<hex>", empty when the file is absent
    bool present{false};
};

struct SCI {
    std::string project;
    std::string version;
    std::string generated_at;
    std::vector<ConfigItem> artifacts;
};

[[nodiscard]] SCI build(const std::filesystem::path& dir,
                         const std::string& project,
                         const std::string& version);

// to_json builds the §9.3 sci.json document.
//
//fusa:req REQ-SCI003
[[nodiscard]] nlohmann::json to_json(const SCI& s, const std::string& project_root);

void write_json(const std::filesystem::path& out, const SCI& s,
                const std::string& project_root = "");

} // namespace cpfusa::sci
