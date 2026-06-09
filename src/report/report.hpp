#pragma once

#include "cpfusa/fusa.hpp"
#include "../config/config.hpp"
#include <filesystem>
#include <string>
#include <vector>

namespace cpfusa::report {

enum class Format { TEXT, JSON, HTML, SARIF };

struct ReportOptions {
    Format      format{Format::TEXT};
    std::string output;  // empty = stdout
    bool        strict{false};
};

[[nodiscard]] std::string render_text(const std::vector<Finding>& findings,
                                      const config::ProjectConfig& cfg);
[[nodiscard]] std::string render_json(const std::vector<Finding>& findings,
                                      const config::ProjectConfig& cfg);
[[nodiscard]] std::string render_html(const std::vector<Finding>& findings,
                                      const config::ProjectConfig& cfg);
[[nodiscard]] std::string render_sarif(const std::vector<Finding>& findings,
                                       const config::ProjectConfig& cfg);

[[nodiscard]] Result<std::monostate> write_report(
    const std::vector<Finding>& findings,
    const config::ProjectConfig& cfg,
    const ReportOptions& opts);

// Returns non-zero exit code if findings exceed the threshold for the format.
[[nodiscard]] int exit_code(const std::vector<Finding>& findings, bool strict);

} // namespace cpfusa::report
