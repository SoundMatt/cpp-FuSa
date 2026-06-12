#include "engine.hpp"
#include "rules.hpp"
#include <algorithm>

namespace cpfusa::engine {

//fusa:req REQ-ENG001 REQ-ENG002 REQ-ENG003 REQ-ENG004
void Engine::register_rule(Rule rule) {
    rules_.push_back(std::move(rule));
}

std::vector<Finding> Engine::run(const std::filesystem::path& dir,
                                  const config::ProjectConfig& cfg) const {
    std::vector<Finding> all;
    for (const auto& rule : rules_) {
        auto findings = rule.check(dir, cfg);
        all.insert(all.end(), findings.begin(), findings.end());
    }
    return all;
}

std::vector<Finding> Engine::run_ids(const std::filesystem::path& dir,
                                      const config::ProjectConfig& cfg,
                                      const std::vector<std::string>& ids) const {
    std::vector<Finding> all;
    for (const auto& rule : rules_) {
        if (std::find(ids.begin(), ids.end(), rule.info.id) != ids.end()) {
            auto findings = rule.check(dir, cfg);
            all.insert(all.end(), findings.begin(), findings.end());
        }
    }
    return all;
}

Engine make_default_engine() {
    Engine e;
    e.register_rule(make_fusa001());
    e.register_rule(make_fusa002());
    e.register_rule(make_fusa003());
    e.register_rule(make_fusa004());
    e.register_rule(make_fusa005());
    e.register_rule(make_coup003());
    e.register_rule(make_hara005());
    e.register_rule(make_iso26262002());
    e.register_rule(make_iso26262003());
    e.register_rule(make_hara002());
    e.register_rule(make_hara003());
    e.register_rule(make_hara004());
    e.register_rule(make_verify002());
    return e;
}

} // namespace cpfusa::engine
