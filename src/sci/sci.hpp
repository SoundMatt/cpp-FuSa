#pragma once
#include <filesystem>
#include <string>
#include <vector>

namespace cpfusa::sci {

//fusa:req REQ-SCI001
constexpr const char* SCI_FILE = "sci.json";

struct LifecycleItem {
    std::string category;
    std::string artifact;
    std::string path;
    std::string sha256;
    bool present{false};
};

struct SCI {
    std::string project;
    std::string version;
    std::string generated_at;
    std::vector<LifecycleItem> items;
};

[[nodiscard]] SCI build(const std::filesystem::path& dir,
                         const std::string& project,
                         const std::string& version);
void write_json(const std::filesystem::path& out, const SCI& s);

} // namespace cpfusa::sci
