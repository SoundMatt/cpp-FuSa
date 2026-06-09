#pragma once
#include <filesystem>
#include <string>
#include <vector>

namespace cpfusa::disposition {

//fusa:req REQ-DISP001
constexpr const char* DISPOSITIONS_FILE = ".fusa-dispositions.json";

enum class Action { Accept, Fix };
std::string action_str(Action a);
Action      parse_action(const std::string& s);

struct Entry {
    std::string rule_id;
    std::string rationale;
    std::string reviewer;
    std::string date;
    Action      action{Action::Accept};
    std::string reference;
};

struct Log {
    std::vector<Entry> entries;
};

[[nodiscard]] Log  load(const std::filesystem::path& dir);
[[nodiscard]] bool save(const std::filesystem::path& path, const Log& log, std::string& err);
Log add(Log log, const Entry& e);
void render_entries(const Log& log);
bool find_by_rule(const Log& log, const std::string& rule_id, Entry& out);

} // namespace cpfusa::disposition
