#include "verify.hpp"
#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <ctime>
#include <cstdio>
#include <array>
#include <regex>

namespace fs = std::filesystem;
using json   = nlohmann::json;

namespace cpfusa::verify {

namespace {

std::string now_iso8601() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ss;
    ss << std::put_time(std::gmtime(&t), "%FT%TZ");
    return ss.str();
}

// Run a shell command and capture stdout+stderr.
std::string run_cmd(const std::string& cmd) {
    std::string output;
    std::array<char, 256> buf{};
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return output;
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe)) {
        output += buf.data();
    }
    pclose(pipe);
    return output;
}

// Locate build dir: try build/, cmake-build-debug/, cmake-build-release/
fs::path find_build_dir(const fs::path& project_dir) {
    for (const auto& name : {"build", "cmake-build-release", "cmake-build-debug", "out"}) {
        auto candidate = project_dir / name;
        if (fs::exists(candidate / "CTestTestfile.cmake") ||
            fs::exists(candidate / "CMakeCache.txt")) {
            return candidate;
        }
    }
    return project_dir / "build";
}

// Parse ctest --verbose output into test results.
std::vector<TestResult> parse_ctest_output(const std::string& output) {
    std::vector<TestResult> results;
    // Lines like: "  1/43 Test  #1: SomeName ......... Passed  0.01 sec"
    static const std::regex test_re(
        R"re(\s*\d+/\d+\s+Test\s+#\d+:\s+(\S+)\s+\.+\s+(Passed|Failed|Skipped)\s+([\d.]+)\s+sec)re",
        std::regex::icase);
    std::istringstream ss(output);
    std::string line;
    while (std::getline(ss, line)) {
        std::smatch m;
        if (std::regex_search(line, m, test_re)) {
            TestResult r;
            r.name = m[1].str();
            auto status_raw = m[2].str();
            // normalise to lowercase
            for (auto& c : status_raw) c = static_cast<char>(std::tolower(c));
            r.status = status_raw;
            try { r.elapsed_seconds = std::stod(m[3].str()); } catch (...) {}
            results.push_back(r);
        }
    }
    return results;
}

} // namespace

//fusa:req REQ-VERIFY001
Result<EvidenceBundle> run_ctest(const fs::path& project_dir,
                                 const config::ProjectConfig& cfg) {
    auto build_dir = find_build_dir(project_dir);
    if (!fs::exists(build_dir)) {
        return std::string("verify: build directory not found — build first with cmake --build");
    }

    std::string ctest_cmd = "ctest --test-dir \"" + build_dir.string()
                          + "\" --output-on-failure -V 2>&1";
    auto output = run_cmd(ctest_cmd);

    EvidenceBundle bundle;
    bundle.generated_at  = now_iso8601();
    bundle.project_root  = project_dir.string();
    bundle.cpp_version   = "C++17";
    bundle.results       = parse_ctest_output(output);

    for (const auto& r : bundle.results) {
        ++bundle.summary.total;
        if      (r.status == "passed")  ++bundle.summary.passed;
        else if (r.status == "failed")  ++bundle.summary.failed;
        else                            ++bundle.summary.skipped;
    }

    // If no test lines parsed, check for raw pass/fail counts in ctest output.
    if (bundle.results.empty()) {
        static const std::regex pass_re(R"re((\d+) tests? passed)re");
        static const std::regex fail_re(R"re((\d+) tests? failed)re");
        std::smatch m;
        if (std::regex_search(output, m, pass_re)) {
            bundle.summary.passed = std::stoi(m[1].str());
            bundle.summary.total += bundle.summary.passed;
        }
        if (std::regex_search(output, m, fail_re)) {
            bundle.summary.failed = std::stoi(m[1].str());
            bundle.summary.total += bundle.summary.failed;
        }
    }

    if (bundle.summary.failed > 0) {
        return std::string("verify: ") + std::to_string(bundle.summary.failed)
             + " test(s) failed";
    }

    return bundle;
}

//fusa:req REQ-VERIFY002
Result<std::monostate> write_evidence(const fs::path& dir, const EvidenceBundle& bundle) {
    json j;
    j["generatedAt"]  = bundle.generated_at;
    j["projectRoot"]  = bundle.project_root;
    j["cppVersion"]   = bundle.cpp_version;

    json ra = json::array();
    for (const auto& r : bundle.results) {
        json rj;
        rj["name"]           = r.name;
        rj["file"]           = r.file;
        rj["status"]         = r.status;
        rj["elapsedSeconds"] = r.elapsed_seconds;
        ra.push_back(rj);
    }
    j["results"] = ra;

    json sj;
    sj["total"]   = bundle.summary.total;
    sj["passed"]  = bundle.summary.passed;
    sj["failed"]  = bundle.summary.failed;
    sj["skipped"] = bundle.summary.skipped;
    j["summary"]  = sj;

    try {
        std::ofstream out(dir / ".fusa-evidence.json");
        out << j.dump(2) << "\n";
    } catch (const std::exception& e) {
        return std::string("verify: write evidence: ") + e.what();
    }
    return std::monostate{};
}

} // namespace cpfusa::verify
