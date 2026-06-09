#pragma once
#include <string>
#include <vector>
#include <filesystem>

namespace cpfusa::fix {

//fusa:req REQ-FIX001
struct FixEntry {
    std::string rule_id;
    std::string title;
    std::string description;
    std::string before;
    std::string after;
    std::string standard_ref;
};

[[nodiscard]] std::vector<FixEntry> catalog();
void show(const std::string& rule_id);
void list_all();

} // namespace cpfusa::fix
