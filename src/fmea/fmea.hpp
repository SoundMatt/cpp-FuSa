#pragma once
// fmea generates a Design FMEA from C++ class/function declarations.
// Outputs: fmea.json + fmea.csv
#include "cpfusa/fusa.hpp"
#include "../config/config.hpp"
#include <filesystem>
#include <string>
#include <vector>

namespace cpfusa::fmea {

constexpr std::string_view FmeaJsonFile = "fmea.json";
constexpr std::string_view FmeaCsvFile  = "fmea.csv";

struct FmeaEntry {
    std::string id;
    std::string component;   // class or function name
    std::string failure_mode;
    std::string effect;
    int         severity{5};    // 1-10
    int         occurrence{5};  // 1-10
    int         detectability{5}; // 1-10
    int         rpn{0};          // severity * occurrence * detectability
    std::string action;
    std::string file;
    int         line{0};
};

struct FMEAReport {
    std::string             generated_at;
    std::string             project;
    std::vector<FmeaEntry>  entries;
};

// generate scans source files for class/function declarations and creates FMEA entries.
//
//fusa:req REQ-FMEA001
Result<FMEAReport> generate(const std::filesystem::path& dir,
                            const config::ProjectConfig& cfg);

// write serialises the FMEA to fmea.json and fmea.csv in dir.
//
//fusa:req REQ-FMEA002
Result<std::monostate> write(const std::filesystem::path& dir, const FMEAReport& rpt);

} // namespace cpfusa::fmea
