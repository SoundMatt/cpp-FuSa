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
#include <vector>
#ifdef _WIN32
#  define popen  _popen
#  define pclose _pclose
#else
#  include <fcntl.h>
#  include <sys/wait.h>
#  include <unistd.h>
#endif
#include <regex>

namespace fs = std::filesystem;
using json   = nlohmann::json;

namespace cpfusa::verify {

namespace {

std::string now_iso8601() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tmv{};
    // Reentrant gmtime — std::gmtime is not thread-safe (CWE-676).
#ifdef _WIN32
    gmtime_s(&tmv, &t);
#else
    gmtime_r(&t, &tmv);
#endif
    std::ostringstream ss;
    ss << std::put_time(&tmv, "%FT%TZ");
    return ss.str();
}

// Run a command as an argv vector WITHOUT a shell, capturing stdout+stderr.
// Passing the build directory as a literal argv entry (never a shell string)
// makes command injection through a hostile --dir path impossible (CWE-78).
std::string run_argv(const std::vector<std::string>& args) {
    std::string output;
    if (args.empty()) return output;
#ifdef _WIN32
    std::string cmd;
    for (const auto& a : args) {
        if (!cmd.empty()) cmd += ' ';
        cmd += '"';
        for (char ch : a) { if (ch == '"') cmd += '\\'; cmd += ch; }
        cmd += '"';
    }
    cmd += " 2>&1";
    FILE* pipe = _popen(cmd.c_str(), "r");
    if (!pipe) return output;
    std::array<char, 256> buf{};
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe)) output += buf.data();
    _pclose(pipe);
    return output;
#else
    int fds[2];
    if (pipe(fds) != 0) return output;
    pid_t pid = fork();
    if (pid < 0) { close(fds[0]); close(fds[1]); return output; }
    if (pid == 0) {
        dup2(fds[1], STDOUT_FILENO);
        dup2(fds[1], STDERR_FILENO);
        close(fds[0]);
        close(fds[1]);
        std::vector<char*> argv;
        argv.reserve(args.size() + 1);
        for (const auto& a : args) argv.push_back(const_cast<char*>(a.c_str()));
        argv.push_back(nullptr);
        execvp(argv[0], argv.data());
        _exit(127);
    }
    close(fds[1]);
    std::array<char, 256> buf{};
    ssize_t n;
    while ((n = read(fds[0], buf.data(), buf.size())) > 0)
        output.append(buf.data(), static_cast<size_t>(n));
    close(fds[0]);
    int status = 0;
    waitpid(pid, &status, 0);
    return output;
#endif
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

} // namespace

// Parse ctest --verbose output into test results.
//
// Test names may contain internal spaces (Catch2's TEST_CASE convention is
// almost always multi-word, e.g. "validate_frame: valid frame ID 0x00").
// CTest always separates the name from its Passed/Failed/Skipped column with
// a fixed-width run of 2+ dots, so the name capture must be lazy and match
// up to that dot run — not `\S+`, which truncates at the name's first space
// and drops any line that doesn't happen to land back on a literal "." run
// immediately afterwards.
std::vector<TestResult> parse_ctest_output(const std::string& output) {
    std::vector<TestResult> results;
    // Lines like: "  1/43 Test  #1: Some Multi Word Name ......... Passed  0.01 sec"
    static const std::regex test_re(
        R"re(\s*\d+/\d+\s+Test\s+#\d+:\s+(.+?)\s+\.{2,}\s+(Passed|Failed|Skipped)\s+([\d.]+)\s+sec)re",
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

//fusa:req REQ-VERIFY001 REQ-VERIFY003 REQ-VERIFY004 REQ-VERIFY005
Result<EvidenceBundle> run_ctest(const fs::path& project_dir,
                                 const config::ProjectConfig& cfg) {
    auto build_dir = find_build_dir(project_dir);
    if (!fs::exists(build_dir)) {
        return std::string("verify: build directory not found — build first with cmake --build");
    }

    auto output = run_argv({"ctest", "--test-dir", build_dir.string(),
                            "--output-on-failure", "-V"});

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

//fusa:req REQ-VERIFY002 REQ-VERIFY003
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
