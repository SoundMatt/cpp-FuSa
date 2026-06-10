#include "trace.hpp"
#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>
#include <regex>
#include <sstream>
#include <algorithm>
#include <iomanip>

namespace fs = std::filesystem;
using json   = nlohmann::json;

namespace cpfusa::trace {

namespace {

constexpr std::string_view ReqsFile = ".fusa-reqs.json";

} // namespace

//fusa:req REQ-TRACE001 REQ-TRACE002 REQ-TRACE003 REQ-TRACE004 REQ-TRACE005 REQ-TRACE006 REQ-TRACE007
Result<std::vector<Requirement>> load_requirements(const fs::path& dir) {
    auto path = dir / ReqsFile;
    if (!fs::exists(path)) {
        return std::vector<Requirement>{};
    }
    std::ifstream f(path);
    if (!f) return std::string("cannot open ") + path.string();
    try {
        json j = json::parse(f);
        std::vector<Requirement> reqs;
        for (const auto& item : j) {
            Requirement r;
            r.id           = item.value("id", "");
            r.title        = item.value("title", "");
            r.description  = item.value("description", "");
            r.standard_ref = item.value("standard_ref", "");
            r.severity     = item.value("severity", "safety");
            reqs.push_back(std::move(r));
        }
        return reqs;
    } catch (const json::exception& ex) {
        return std::string("parse error: ") + ex.what();
    }
}

std::vector<Annotation> scan_annotations(const fs::path& dir) {
    std::vector<Annotation> out;
    if (!fs::exists(dir)) return out;
    static const std::regex ext_re(R"(\.(cpp|hpp|h|hxx|cxx|cc|c\+\+)$)");
    // req_re / test_re: first match anchors to tag, then id_re finds each REQ-xxx token
    static const std::regex req_tag_re(R"(//\s*fusa:req\s+)");
    static const std::regex test_tag_re(R"(//\s*fusa:test\s+)");
    static const std::regex id_re(R"(REQ-\S+)");
    for (const auto& entry : fs::recursive_directory_iterator(
             dir, fs::directory_options::skip_permission_denied)) {
        if (!entry.is_regular_file()) continue;
        if (!std::regex_search(entry.path().string(), ext_re)) continue;
        std::ifstream f(entry.path());
        std::string line;
        int n = 0;
        while (std::getline(f, line)) {
            ++n;
            bool is_req  = std::regex_search(line, req_tag_re);
            bool is_test = std::regex_search(line, test_tag_re);
            if (!is_req && !is_test) continue;
            // Collect all REQ-xxx tokens on this line.
            for (std::sregex_iterator it(line.begin(), line.end(), id_re), end;
                 it != end; ++it) {
                out.push_back({(*it)[0].str(), entry.path().string(), n, is_test});
            }
        }
    }
    return out;
}

Result<TraceResult> run(const fs::path& dir,
                        const config::ProjectConfig& /*cfg*/,
                        const TraceOptions& opts) {
    auto reqs_result = load_requirements(dir);
    if (!is_ok(reqs_result)) return error_of(reqs_result);
    auto reqs = value_of(reqs_result);

    auto annotations = scan_annotations(dir);

    TraceResult result;
    result.requirements = reqs;
    result.annotations  = annotations;
    result.total        = static_cast<int>(reqs.size());

    // Index annotations by requirement ID.
    for (const auto& ann : annotations) {
        result.by_req[ann.req_id].push_back(ann);
    }

    // Count coverage.
    for (const auto& req : reqs) {
        auto it = result.by_req.find(req.id);
        if (it == result.by_req.end()) continue;
        bool has_impl = false, has_test = false;
        for (const auto& ann : it->second) {
            if (!ann.is_test) has_impl = true;
            else              has_test = true;
        }
        if (has_impl) ++result.annotated;
        if (has_test) ++result.tested;
    }

    if (result.total > 0) {
        result.annotation_coverage = 100.0 * result.annotated / result.total;
        result.test_coverage       = 100.0 * result.tested    / result.total;
    }

    // Gate checks — only apply when there are actual requirements to measure.
    if (result.total > 0 && opts.min_annotation_pct > 0
            && result.annotation_coverage < opts.min_annotation_pct) {
        return std::string("annotation coverage ")
             + std::to_string(static_cast<int>(result.annotation_coverage))
             + "% below required " + std::to_string(opts.min_annotation_pct) + "%";
    }
    if (result.total > 0 && opts.min_test_pct > 0
            && result.test_coverage < opts.min_test_pct) {
        return std::string("test coverage ")
             + std::to_string(static_cast<int>(result.test_coverage))
             + "% below required " + std::to_string(opts.min_test_pct) + "%";
    }

    return result;
}

std::string render_matrix(const TraceResult& result, const TraceOptions& opts) {
    std::ostringstream out;
    out << "Requirements Traceability Matrix\n"
        << std::string(70, '-') << "\n\n";

    if (result.requirements.empty()) {
        out << "No requirements loaded. Run 'cpfusa init' or create .fusa-reqs.json\n\n";
        // Still show source annotations.
        if (!result.annotations.empty()) {
            out << "Source annotations found:\n";
            for (const auto& ann : result.annotations) {
                out << "  [" << (ann.is_test ? "TEST" : "REQ ") << "] "
                    << ann.req_id << " — " << ann.file << ":" << ann.line << "\n";
            }
        }
        return out.str();
    }

    for (const auto& req : result.requirements) {
        auto it = result.by_req.find(req.id);
        bool has_impl = false, has_test = false;
        std::vector<const Annotation*> impls, tests;
        if (it != result.by_req.end()) {
            for (const auto& ann : it->second) {
                if (!ann.is_test) { has_impl = true; impls.push_back(&ann); }
                else              { has_test = true; tests.push_back(&ann); }
            }
        }

        if (opts.show_gaps && has_impl && has_test) continue; // only gaps

        std::string impl_mark = has_impl ? "[✓]" : "[ ]";
        std::string test_mark = has_test ? "[✓]" : "[ ]";

        out << req.id << " — " << req.title << "\n"
            << "  impl:" << impl_mark << "  test:" << test_mark;
        if (!req.standard_ref.empty()) out << "  [" << req.standard_ref << "]";
        out << "\n";

        for (const auto* ann : impls) {
            out << "    impl: " << ann->file << ":" << ann->line << "\n";
        }
        for (const auto* ann : tests) {
            out << "    test: " << ann->file << ":" << ann->line << "\n";
        }
        out << "\n";
    }

    out << std::string(70, '-') << "\n"
        << "Total: "  << result.total
        << "  Annotated: " << result.annotated
                           << " (" << std::fixed << std::setprecision(1)
                           << result.annotation_coverage << "%)"
        << "  Tested: " << result.tested
                        << " (" << result.test_coverage << "%)\n";
    return out.str();
}

std::string render_json(const TraceResult& result,
                        const config::ProjectConfig& cfg) {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto t   = system_clock::to_time_t(now);
    std::tm tm_buf{};
#ifdef _WIN32
    gmtime_s(&tm_buf, &t);
#else
    gmtime_r(&t, &tm_buf);
#endif
    std::ostringstream ts;
    ts << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%SZ");

    // Strip project root prefix so paths are project-relative (§4).
    const std::string& root = cfg.project_root;
    auto rel = [&](const std::string& p) -> std::string {
        if (!root.empty() && p.rfind(root, 0) == 0) {
            auto s = p.substr(root.size());
            if (!s.empty() && (s[0] == '/' || s[0] == '\\')) s = s.substr(1);
            return s;
        }
        return p;
    };

    json j;
    j["schemaVersion"] = "1.8";
    j["kind"]          = "trace-report";
    j["tool"]          = "cpp-FuSa";
    j["toolVersion"]   = std::string(Version);
    j["language"]      = "cpp";
    j["generatedAt"]   = ts.str();
    j["project"]       = cfg.project;

    j["requirements"] = json::array();
    for (const auto& req : result.requirements) {
        json entry;
        entry["id"]          = req.id;
        entry["title"]       = req.title;
        entry["severity"]    = req.severity;
        entry["standardRef"] = req.standard_ref;

        json impls = json::array();
        json tests = json::array();
        auto it = result.by_req.find(req.id);
        if (it != result.by_req.end()) {
            for (const auto& ann : it->second) {
                json loc = {{"file", rel(ann.file)}, {"line", ann.line}};
                if (ann.is_test) tests.push_back(loc);
                else             impls.push_back(loc);
            }
        }
        entry["implementedBy"] = impls;
        entry["testedBy"]      = tests;

        bool has_impl = !impls.empty();
        bool has_test = !tests.empty();
        entry["status"] = (has_impl && has_test) ? "covered"
                        : (has_impl || has_test)  ? "partial"
                                                   : "gap";
        j["requirements"].push_back(entry);
    }

    j["summary"] = {
        {"total",              result.total},
        {"annotated",         result.annotated},
        {"tested",            result.tested},
        {"annotationCoverage", result.annotation_coverage},
        {"testCoverage",       result.test_coverage}
    };
    return j.dump(2);
}

std::string render_req(const Requirement& req,
                       const std::vector<Annotation>& annotations) {
    std::ostringstream out;
    out << "Requirement: " << req.id << "\n"
        << "Title:       " << req.title << "\n"
        << "Description: " << req.description << "\n"
        << "Standard:    " << req.standard_ref << "\n"
        << "Severity:    " << req.severity << "\n\n";

    std::vector<const Annotation*> impls, tests;
    for (const auto& ann : annotations) {
        if (ann.req_id == req.id) {
            if (!ann.is_test) impls.push_back(&ann);
            else              tests.push_back(&ann);
        }
    }
    out << "Implementation annotations (" << impls.size() << "):\n";
    for (const auto* a : impls) out << "  " << a->file << ":" << a->line << "\n";
    out << "\nTest annotations (" << tests.size() << "):\n";
    for (const auto* a : tests) out << "  " << a->file << ":" << a->line << "\n";
    return out.str();
}

} // namespace cpfusa::trace
