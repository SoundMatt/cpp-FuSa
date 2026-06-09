#pragma once
// badge generates Shields.io-compatible SVG status badges for cpfusa check reports.
#include "cpfusa/fusa.hpp"
#include <filesystem>
#include <string>

namespace cpfusa::badge {

enum class Status { PASS, WARN, FAIL };

struct Badge {
    Status      status{Status::PASS};
    int         errors{0};
    int         warnings{0};
    std::string version;
};

// from_findings derives a Badge from finding counts.
//
//fusa:req REQ-BADGE001
Badge from_findings(int errors, int warnings, const std::string& version);

// render returns a self-contained Shields.io-style SVG string.
//
//fusa:req REQ-BADGE002
std::string render(const Badge& b);

// write_badge writes the SVG badge to dir/fusa-badge.svg.
Result<std::monostate> write_badge(const std::filesystem::path& dir, const Badge& b);

} // namespace cpfusa::badge
