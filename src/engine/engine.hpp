#pragma once

#include "cpfusa/fusa.hpp"
#include "../config/config.hpp"
#include <filesystem>
#include <functional>
#include <string>
#include <vector>
#include <map>

namespace cpfusa::engine {

struct RuleInfo {
    std::string id;
    std::string name;
    std::string description;
    Severity    default_severity;
};

using CheckFn = std::function<std::vector<Finding>(
    const std::filesystem::path&,
    const config::ProjectConfig&)>;

struct Rule {
    RuleInfo info;
    CheckFn  check;
};

class Engine {
public:
    void register_rule(Rule rule);
    [[nodiscard]] const std::vector<Rule>& rules() const { return rules_; }

    [[nodiscard]] std::vector<Finding> run(
        const std::filesystem::path&   dir,
        const config::ProjectConfig&   cfg) const;

    [[nodiscard]] std::vector<Finding> run_ids(
        const std::filesystem::path&        dir,
        const config::ProjectConfig&        cfg,
        const std::vector<std::string>&     ids) const;

private:
    std::vector<Rule> rules_;
};

// Returns a pre-populated engine with all built-in rules registered.
[[nodiscard]] Engine make_default_engine();

} // namespace cpfusa::engine
