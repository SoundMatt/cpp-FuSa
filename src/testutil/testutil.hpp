#pragma once

#include "cpfusa/fusa.hpp"
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>
#include <stdexcept>

namespace cpfusa::testutil {

// Creates a temporary directory for a test and removes it on destruction.
class TempDir {
public:
    TempDir() {
        path_ = std::filesystem::temp_directory_path()
              / ("cpfusa_test_" + std::to_string(
                     std::hash<std::thread::id>{}(std::this_thread::get_id())));
        std::filesystem::create_directories(path_);
    }
    ~TempDir() noexcept {
        std::filesystem::remove_all(path_);
    }
    [[nodiscard]] const std::filesystem::path& path() const { return path_; }

    // Write a file relative to this temp dir.
    void write(const std::string& rel, const std::string& content) const {
        auto p = path_ / rel;
        std::filesystem::create_directories(p.parent_path());
        std::ofstream f(p);
        if (!f) throw std::runtime_error("TempDir::write failed: " + p.string());
        f << content;
    }

    TempDir(const TempDir&)            = delete;
    TempDir& operator=(const TempDir&) = delete;

private:
    std::filesystem::path path_;
};

// Checks whether findings contain a finding with the given rule_id.
[[nodiscard]] inline bool has_finding(const std::vector<Finding>& findings,
                                      const std::string& rule_id) {
    for (const auto& f : findings)
        if (f.rule_id == rule_id) return true;
    return false;
}

// Counts findings with a specific rule_id.
[[nodiscard]] inline int count_findings(const std::vector<Finding>& findings,
                                        const std::string& rule_id) {
    int n = 0;
    for (const auto& f : findings)
        if (f.rule_id == rule_id) ++n;
    return n;
}

} // namespace cpfusa::testutil
