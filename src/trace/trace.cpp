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

constexpr std::string_view ReqsFile     = ".fusa-reqs.json";
constexpr std::string_view EvidenceFile = ".fusa-evidence.json";

} // namespace

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
    static const std::regex req_re(R"(//\s*fusa:req\s+(\S+))");
    static const std::regex test_re(R"(//\s*fusa:test\s+(\S+))");
    for (const auto& entry : fs::recursive_directory_iterator(
             dir, fs::directory_options::skip_permission_denied)) {
        if (!entry.is_regular_file()) continue;
        if (!std::regex_search(entry.path().string(), ext_re)) continue;
        std::ifstream f(entry.path());
        std::string line;
        int n = 0;
        while (std::getline(f, line)) {
            ++n;
            std::smatch m;
            if (std::regex_search(line, m, req_re) && m.size() > 1) {
                out.push_back({m[1].str(), entry.path().string(), n, false});
            }
            if (std::regex_search(line, m, test_re) && m.size() > 1) {
                out.push_back({m[1].str(), entry.path().string(), n, true});
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
