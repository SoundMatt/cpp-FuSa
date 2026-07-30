#include "impact.hpp"
#include <array>
#include <chrono>
#include <ctime>
#include <cstdio>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <regex>
#include <sstream>
#include <vector>
#include <nlohmann/json.hpp>
#ifdef _WIN32
#  include <windows.h>
#else
#  include <fcntl.h>
#  include <sys/wait.h>
#  include <unistd.h>
#endif

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace cpfusa::impact {

namespace {
std::string now_iso() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::tm tmv{};
    // Reentrant gmtime — std::gmtime is not thread-safe (CWE-676).
#ifdef _WIN32
    gmtime_s(&tmv, &t);
#else
    gmtime_r(&t, &tmv);
#endif
    std::ostringstream ss;
    ss << std::put_time(&tmv, "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

// Validate a git ref to prevent argument/command injection (CWE-78/CWE-88).
// Accepts only alphanumerics, '.', '-', '_', '/', '^', '~', and '@', and
// rejects a leading '-' so a ref can never be parsed by git as an option.
bool is_safe_git_ref(const std::string& ref) {
    static const std::regex safe_re(R"([A-Za-z0-9._\-/^~@]+)");
    return !ref.empty() && ref.front() != '-' && std::regex_match(ref, safe_re);
}

// Run a command as an argv vector WITHOUT a shell, capturing stdout.
// Using execvp (never system/popen) means directory paths and refs are passed
// as literal arguments and can never be interpreted as shell syntax (CWE-78).
std::string run_argv(const std::vector<std::string>& args) {
    std::string result;
    if (args.empty()) return result;
#ifdef _WIN32
    // Fall back to a quoted command line on Windows (no fork/exec).
    std::string cmd;
    for (const auto& a : args) {
        if (!cmd.empty()) cmd += ' ';
        cmd += '"';
        for (char ch : a) { if (ch == '"') cmd += '\\'; cmd += ch; }
        cmd += '"';
    }
    FILE* pipe = _popen(cmd.c_str(), "r");
    if (!pipe) return result;
    std::array<char, 256> buf{};
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe))
        result += buf.data();
    _pclose(pipe);
    return result;
#else
    int fds[2];
    if (pipe(fds) != 0) return result;
    pid_t pid = fork();
    if (pid < 0) { close(fds[0]); close(fds[1]); return result; }
    if (pid == 0) {
        // Child: stdout → pipe, stderr → /dev/null, then exec (no shell).
        dup2(fds[1], STDOUT_FILENO);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, STDERR_FILENO); close(devnull); }
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
        result.append(buf.data(), static_cast<size_t>(n));
    close(fds[0]);
    int status = 0;
    waitpid(pid, &status, 0);
    return result;
#endif
}

std::vector<ChangedFile> parse_git_diff(const std::string& from_ref,
                                         const std::string& to_ref,
                                         const fs::path& dir) {
    std::vector<ChangedFile> files;
    std::string safe_from = from_ref.empty() ? "HEAD" : from_ref;
    std::string safe_to   = to_ref.empty()   ? "HEAD" : to_ref;

    // Reject refs containing shell-unsafe characters or a leading dash.
    if (!is_safe_git_ref(safe_from) || !is_safe_git_ref(safe_to)) return files;

    // Build an argv vector — no shell, so dir/refs are always literal args.
    // The '--' separator guarantees refs are never treated as options.
    std::vector<std::string> args = {"git", "-C", dir.string(),
                                     "diff", "--numstat"};
    if (from_ref.empty() && to_ref.empty()) {
        args.push_back("HEAD");
    } else {
        args.push_back(safe_from);
        args.push_back(safe_to);
    }
    args.push_back("--");
    std::string out = run_argv(args);
    std::istringstream ss(out);
    std::string line;
    while (std::getline(ss, line)) {
        std::istringstream ls(line);
        int ins, del;
        std::string path;
        if (ls >> ins >> del >> path)
            files.push_back({path, ins, del});
    }
    return files;
}
} // anonymous namespace

//fusa:req REQ-IMPACT002
ImpactReport analyse(const fs::path& dir, const std::string& from_ref, const std::string& to_ref) {
    ImpactReport r;
    r.generated_at = now_iso();
    r.from_ref = from_ref.empty() ? "HEAD" : from_ref;
    r.to_ref   = to_ref.empty()   ? "HEAD" : to_ref;

    r.changed_files = parse_git_diff(from_ref, to_ref, dir);

    // Load requirements and find impacted ones
    auto reqs_path = dir / ".fusa-reqs.json";
    if (fs::exists(reqs_path)) {
        try {
            std::ifstream f(reqs_path);
            auto j = json::parse(f);
            for (auto& req : j.value("requirements", json::array())) {
                std::string req_id = req.value("id", "");
                bool matched = false;
                for (auto& impl : req.value("implementations", json::array())) {
                    if (matched) break;
                    std::string impl_file = impl.value("file", impl.is_string() ? impl.get<std::string>() : "");
                    for (auto& cf : r.changed_files) {
                        if (cf.path.find(impl_file) != std::string::npos || impl_file.find(cf.path) != std::string::npos) {
                            r.impacted_reqs.push_back({req_id, impl_file, req.value("description", "")});
                            matched = true;
                            break;
                        }
                    }
                }
            }
        } catch (...) {}
    }

    // Check which known evidence artifacts might be stale
    static const std::vector<std::pair<std::string,std::string>> artifacts = {
        {".fusa-evidence.json", ".fusa-evidence.json"},
        {"cyber-report.json",   "cyber-report.json"},
        {"fmea.json",           "fmea.json"},
        {"tara.json",           "tara.json"},
        {"sbom.json",           "sbom.json"},
    };
    for (auto& [name, path] : artifacts) {
        bool stale = !r.changed_files.empty(); // if any file changed, evidence may be stale
        r.stale_artifacts.push_back({name, path, stale && fs::exists(dir / path)});
    }

    return r;
}

void render_text(const ImpactReport& r) {
    std::cout << "Impact Analysis — " << r.from_ref << ".." << r.to_ref << "\n";
    std::cout << std::string(70, '-') << "\n";
    std::cout << "Changed files (" << r.changed_files.size() << "):\n";
    for (auto& cf : r.changed_files)
        std::cout << "  +" << cf.insertions << " -" << cf.deletions << "  " << cf.path << "\n";
    std::cout << "\nImpacted requirements (" << r.impacted_reqs.size() << "):\n";
    for (auto& req : r.impacted_reqs)
        std::cout << "  " << req.req_id << "  " << req.file << "\n";
    int stale = 0;
    for (auto& a : r.stale_artifacts) if (a.stale) stale++;
    std::cout << "\nPotentially stale artifacts: " << stale << "\n";
}

void render_json(const fs::path& out, const ImpactReport& r) {
    json j;
    j["generatedAt"] = r.generated_at;
    j["fromRef"]     = r.from_ref;
    j["toRef"]       = r.to_ref;
    j["changedFiles"] = json::array();
    for (auto& cf : r.changed_files)
        j["changedFiles"].push_back({{"path", cf.path},
            {"insertions", cf.insertions}, {"deletions", cf.deletions}});
    j["impactedReqs"] = json::array();
    for (auto& req : r.impacted_reqs)
        j["impactedReqs"].push_back({{"reqId", req.req_id}, {"file", req.file},
            {"description", req.description}});
    j["staleArtifacts"] = json::array();
    for (auto& a : r.stale_artifacts)
        j["staleArtifacts"].push_back({{"name", a.name}, {"path", a.path}, {"stale", a.stale}});
    std::ofstream f(out);
    f << j.dump(2);
}

} // namespace cpfusa::impact
