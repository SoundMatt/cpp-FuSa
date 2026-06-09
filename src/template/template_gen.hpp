#pragma once

#include "../config/config.hpp"
#include "cpfusa/fusa.hpp"
#include <filesystem>
#include <string>

namespace cpfusa::tmpl {

enum class TemplateType { SAFETY_PLAN, TEST_EVIDENCE, HARA, SVP, SCMP, SQAP, ALL };

[[nodiscard]] Result<std::monostate> generate(
    const std::filesystem::path&  dir,
    const config::ProjectConfig&  cfg,
    TemplateType                  type);

[[nodiscard]] std::string safety_plan_content(const config::ProjectConfig& cfg);
[[nodiscard]] std::string test_evidence_content(const config::ProjectConfig& cfg);
[[nodiscard]] std::string hara_content(const config::ProjectConfig& cfg);
[[nodiscard]] std::string svp_content(const config::ProjectConfig& cfg);
[[nodiscard]] std::string scmp_content(const config::ProjectConfig& cfg);
[[nodiscard]] std::string sqap_content(const config::ProjectConfig& cfg);

} // namespace cpfusa::tmpl
