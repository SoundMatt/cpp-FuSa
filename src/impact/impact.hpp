#pragma once
#include <filesystem>
#include <string>
#include <vector>

namespace cpfusa::impact {

//fusa:req REQ-IMPACT001
struct ChangedFile {
    std::string path;
    int insertions{0};
    int deletions{0};
};

struct ImpactedReq {
    std::string req_id;
    std::string file;
    std::string description;
};

struct StaleArtifact {
    std::string name;
    std::string path;
    bool stale{false};
};

struct ImpactReport {
    std::string generated_at;
    std::string from_ref;
    std::string to_ref;
    std::vector<ChangedFile> changed_files;
    std::vector<ImpactedReq> impacted_reqs;
    std::vector<StaleArtifact> stale_artifacts;
};

[[nodiscard]] ImpactReport analyse(const std::filesystem::path& dir,
                                    const std::string& from_ref,
                                    const std::string& to_ref);
void render_text(const ImpactReport& r);
void render_json(const std::filesystem::path& out, const ImpactReport& r);

} // namespace cpfusa::impact
