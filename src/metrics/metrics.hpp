#pragma once
#include <filesystem>
#include <string>
#include <vector>

namespace cpfusa::metrics {

//fusa:req REQ-METRICS001
constexpr const char* METRICS_FILE = ".fusa-metrics.json";

struct Snapshot {
    std::string timestamp;
    int error_count{0};
    int warning_count{0};
    int info_count{0};
    int total_requirements{0};
    int traced_requirements{0};
    double coverage_pct{0.0};
    int cyber_findings{0};
};

struct TimeSeries {
    std::string project;
    std::vector<Snapshot> snapshots;
};

[[nodiscard]] TimeSeries load(const std::filesystem::path& dir);
[[nodiscard]] Snapshot   collect(const std::filesystem::path& dir);
TimeSeries               append(TimeSeries ts, const Snapshot& snap);
void save(const std::filesystem::path& path, const TimeSeries& ts);
void render_text(const TimeSeries& ts);
void render_json(const std::filesystem::path& out, const TimeSeries& ts);

} // namespace cpfusa::metrics
