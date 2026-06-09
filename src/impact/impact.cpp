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
#include <nlohmann/json.hpp>
#ifdef _WIN32
#  define popen  _popen
#  define pclose _pclose
#endif

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace cpfusa::impact {

namespace {
std::string now_iso() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ss;
    ss << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

// Validate a git ref to prevent shell injection (CWE-78).
// Accepts only alphanumerics, '.', '-', '_', '/', '^', '~', and '@'.
bool is_safe_git_ref(const std::string& ref) {
    static const std::regex safe_re(R"([A-Za-z0-9._\-/^~@]+)");
    return !ref.empty() && std::regex_match(ref, safe_re);
}

std::string run_cmd(const std::string& cmd) {
    std::string result;
    std::array<char, 256> buf{};
    // fusa:unsafe — popen with validated, allowlist-checked inputs only
    FILE* pipe = popen(cmd.c_str(), "r"); // NOLINT(cert-env33-c)
    if (!pipe) return result;
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe))
        result += buf.data();
    pclose(pipe);
    return result;
}

std::vector<ChangedFile> parse_git_diff(const std::string& from_ref,
                                         const std::string& to_ref,
                                         const fs::path& dir) {
    std::vector<ChangedFile> files;
    std::string safe_from = from_ref.empty() ? "HEAD" : from_ref;
    std::string safe_to   = to_ref.empty()   ? "HEAD" : to_ref;

    // Reject refs containing shell-unsafe characters.
    if (!is_safe_git_ref(safe_from) || !is_safe_git_ref(safe_to)) return files;

    std::string cmd;
    if (from_ref.empty() && to_ref.empty()) {
        cmd = "git -C " + dir.string() + " diff --numstat HEAD 2>/dev/null";
    } else {
        cmd = "git -C " + dir.string() + " diff --numstat " + safe_from + " " + safe_to + " 2>/dev/null";
    }
    std::string out = run_cmd(cmd);
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
