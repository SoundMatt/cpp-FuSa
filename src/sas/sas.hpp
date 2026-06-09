#pragma once
#include <filesystem>
#include <string>
#include <vector>

namespace cpfusa::sas {

//fusa:req REQ-SAS001
constexpr const char* SAS_MD_FILE   = "sas.md";
constexpr const char* SAS_JSON_FILE = "sas.json";

struct EvidenceItem {
    std::string id;
    std::string title;
    std::string artifact;
    bool present{false};
};

struct SAS {
    std::string project;
    std::string version;
    std::string generated_at;
    std::string dal;
    std::vector<EvidenceItem> evidence;
    int total{0};
    int complete{0};
};

[[nodiscard]] SAS build(const std::filesystem::path& dir,
                         const std::string& project,
                         const std::string& version,
                         const std::string& dal);
void write_json(const std::filesystem::path& out, const SAS& s);
void write_markdown(const std::filesystem::path& out, const SAS& s);

} // namespace cpfusa::sas
