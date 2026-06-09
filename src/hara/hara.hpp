#pragma once
#include <filesystem>
#include <string>
#include <vector>

namespace cpfusa::hara {

//fusa:req REQ-HARA001
constexpr const char* HARA_FILE = ".fusa-hara.json";

enum class Severity { S0, S1, S2, S3 };
enum class Exposure { E0, E1, E2, E3, E4 };
enum class Controllability { C0, C1, C2, C3 };

std::string determine_asil(Severity s, Exposure e, Controllability c);
Severity    parse_severity(const std::string& s);
Exposure    parse_exposure(const std::string& s);
Controllability parse_controllability(const std::string& s);

struct RiskRating {
    std::string severity;
    std::string exposure;
    std::string controllability;
    std::string asil;
};

struct Hazard {
    std::string id;
    std::string description;
    std::vector<std::string> situations;
    RiskRating risk;
    std::vector<std::string> safety_goals;
};

struct SafetyGoal {
    std::string id;
    std::string description;
    std::vector<std::string> hazard_ids;
    std::string asil;
    std::string safe_state;
};

struct OperationalSituation {
    std::string id;
    std::string description;
};

struct HARA {
    std::string project;
    std::string standard;
    std::string created_at;
    std::vector<OperationalSituation> situations;
    std::vector<Hazard> hazards;
    std::vector<SafetyGoal> safety_goals;
};

[[nodiscard]] bool load(const std::filesystem::path& dir, HARA& out, std::string& err);
[[nodiscard]] bool save(const std::filesystem::path& path, const HARA& h, std::string& err);
[[nodiscard]] bool init(const std::filesystem::path& dir, const std::string& project,
                        const std::string& standard, std::string& err);
void render_text(const HARA& h);

} // namespace cpfusa::hara
