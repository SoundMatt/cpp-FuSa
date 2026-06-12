#include "trace.hpp"
#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>
#include <regex>
#include <set>
#include <sstream>
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
        // §1.2.2: canonical format is {"requirements": [...]};
        // also accept legacy flat array for backward compatibility.
        const json& arr = j.is_array() ? j : j.at("requirements");
        std::vector<Requirement> reqs;
        for (const auto& item : arr) {
            Requirement r;
            r.id           = item.value("id", "");
            r.title        = item.value("title", "");
            r.description  = item.value("description", "");
            r.standard_ref = item.value("standard_ref", "");
            r.severity     = item.value("severity", "safety");
            r.asil         = item.value("asil", "");
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
    j["schemaVersion"] = std::string(SpecVersion);
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
        if (!req.asil.empty()) entry["asil"] = req.asil;

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


//fusa:req REQ-REQ001 REQ-REQ002 REQ-REQ003
Result<int> import_csv(const fs::path& file, std::vector<Requirement>& reqs) {
    std::ifstream f(file);
    if (!f) return std::string("cannot open: ") + file.string();

    // Build set of existing ids to skip duplicates.
    std::set<std::string> existing;
    for (const auto& r : reqs) existing.insert(r.id);

    std::string line;
    std::getline(f, line); // skip header: id,title,description,standard_ref,severity,asil
    int added = 0;
    while (std::getline(f, line)) {
        if (line.empty()) continue;
        // Minimal CSV parse: split on first 5 commas, rest is asil.
        std::istringstream ss(line);
        std::string id, title, desc, std_ref, sev, asil;
        std::getline(ss, id,      ',');
        std::getline(ss, title,   ',');
        std::getline(ss, desc,    ',');
        std::getline(ss, std_ref, ',');
        std::getline(ss, sev,     ',');
        std::getline(ss, asil);
        if (id.empty()) continue;
        if (existing.count(id)) continue;
        Requirement r;
        r.id           = id;
        r.title        = title;
        r.description  = desc;
        r.standard_ref = std_ref;
        r.severity     = sev.empty() ? "safety" : sev;
        r.asil         = asil;
        reqs.push_back(std::move(r));
        existing.insert(id);
        ++added;
    }
    return added;
}

std::string export_csv(const std::vector<Requirement>& reqs) {
    std::ostringstream out;
    out << "id,title,description,standard_ref,severity,asil\n";
    for (const auto& r : reqs) {
        // Minimal escaping: replace comma in fields with semicolon.
        auto esc = [](const std::string& s) {
            std::string res;
            for (char c : s) res += (c == ',') ? ';' : c;
            return res;
        };
        out << esc(r.id)           << ','
            << esc(r.title)        << ','
            << esc(r.description)  << ','
            << esc(r.standard_ref) << ','
            << esc(r.severity)     << ','
            << esc(r.asil)         << '\n';
    }
    return out.str();
}

bool save_requirements(const fs::path& dir, const std::vector<Requirement>& reqs) {
    auto path = dir / ".fusa-reqs.json";
    json arr  = json::array();
    for (const auto& r : reqs) {
        json obj = {
            {"id",           r.id},
            {"title",        r.title},
            {"description",  r.description},
            {"standard_ref", r.standard_ref},
            {"severity",     r.severity}
        };
        if (!r.asil.empty()) obj["asil"] = r.asil;
        arr.push_back(obj);
    }
    json doc;
    doc["requirements"] = arr;
    std::ofstream f(path);
    if (!f) return false;
    f << doc.dump(2) << "\n";
    return true;
}

// DOORS ReqIF XML import/export
//fusa:req REQ-TRACE008
Result<int> import_doors(const fs::path& file, std::vector<Requirement>& reqs) {
    std::ifstream f(file);
    if (!f) return std::string("cannot open: ") + file.string();

    std::set<std::string> existing;
    for (const auto& r : reqs) existing.insert(r.id);

    std::string content((std::istreambuf_iterator<char>(f)), {});
    int added = 0;

    // Line-by-line approach: look for THE-VALUE="..." attributes
    // Each SPEC-OBJECT has two key attribute values: the ID and the title
    std::istringstream ss(content);
    std::string line;
    bool in_spec_object = false;
    std::vector<std::string> vals;

    static const std::regex open_re(R"X(<SPEC-OBJECT[\s>])X");
    static const std::regex close_re(R"X(</SPEC-OBJECT>)X");
    static const std::regex val_re(R"X(THE-VALUE="([^"]+)")X");

    while (std::getline(ss, line)) {
        if (std::regex_search(line, open_re)) {
            in_spec_object = true;
            vals.clear();
        }
        if (in_spec_object) {
            std::sregex_iterator it(line.begin(), line.end(), val_re);
            std::sregex_iterator end;
            for (; it != end; ++it) {
                vals.push_back((*it)[1].str());
            }
        }
        if (in_spec_object && std::regex_search(line, close_re)) {
            in_spec_object = false;
            if (!vals.empty()) {
                std::string id    = vals[0];
                std::string title = vals.size() > 1 ? vals[1] : id;
                if (!id.empty() && !existing.count(id)) {
                    Requirement r;
                    r.id       = id;
                    r.title    = title;
                    r.severity = "safety";
                    reqs.push_back(r);
                    existing.insert(id);
                    ++added;
                }
            }
            vals.clear();
        }
    }
    return added;
}

std::string export_doors(const std::vector<Requirement>& reqs) {
    std::ostringstream out;
    out << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        << "<REQ-IF xmlns=\"http://www.omg.org/spec/ReqIF/20110401/reqif.xsd\">\n"
        << "  <CORE-CONTENT>\n"
        << "    <SPEC-OBJECTS>\n";
    for (const auto& r : reqs) {
        out << "      <SPEC-OBJECT>\n"
            << "        <VALUES>\n"
            << "          <ATTRIBUTE-VALUE-STRING THE-VALUE=\"" << r.id << "\"/>\n"
            << "          <ATTRIBUTE-VALUE-STRING THE-VALUE=\"" << r.title << "\"/>\n";
        if (!r.asil.empty()) {
            out << "          <ATTRIBUTE-VALUE-STRING THE-VALUE=\"" << r.asil << "\"/>\n";
        }
        out << "        </VALUES>\n"
            << "      </SPEC-OBJECT>\n";
    }
    out << "    </SPEC-OBJECTS>\n"
        << "  </CORE-CONTENT>\n"
        << "</REQ-IF>\n";
    return out.str();
}

// Polarion work-item XML import/export
//fusa:req REQ-TRACE009
Result<int> import_polarion(const fs::path& file, std::vector<Requirement>& reqs) {
    std::ifstream f(file);
    if (!f) return std::string("cannot open: ") + file.string();

    std::set<std::string> existing;
    for (const auto& r : reqs) existing.insert(r.id);

    std::string content((std::istreambuf_iterator<char>(f)), {});
    int added = 0;

    // Look for <workItem id="REQ-001"> ... <title>Title text</title> ... </workItem>
    static const std::regex wi_re(R"X(<workItem[^>]*id="([^"]+)"[^>]*>)X");
    static const std::regex title_re(R"X(<title>([^<]+)</title>)X");
    static const std::regex close_wi_re(R"X(</workItem>)X");

    std::istringstream ss(content);
    std::string line;
    bool in_wi = false;
    std::string current_id;
    std::string current_title;

    while (std::getline(ss, line)) {
        std::smatch m;
        if (!in_wi && std::regex_search(line, m, wi_re)) {
            in_wi = true;
            current_id = m[1].str();
            current_title.clear();
        }
        if (in_wi) {
            std::smatch tm;
            if (std::regex_search(line, tm, title_re)) {
                current_title = tm[1].str();
            }
        }
        if (in_wi && std::regex_search(line, close_wi_re)) {
            in_wi = false;
            if (!current_id.empty() && !existing.count(current_id)) {
                Requirement r;
                r.id       = current_id;
                r.title    = current_title.empty() ? current_id : current_title;
                r.severity = "safety";
                reqs.push_back(r);
                existing.insert(current_id);
                ++added;
            }
            current_id.clear();
            current_title.clear();
        }
    }
    return added;
}

std::string export_polarion(const std::vector<Requirement>& reqs) {
    std::ostringstream out;
    out << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        << "<workItems>\n";
    for (const auto& r : reqs) {
        out << "  <workItem id=\"" << r.id << "\">\n"
            << "    <title>" << r.title << "</title>\n"
            << "    <description>" << r.description << "</description>\n"
            << "    <severity>" << r.severity << "</severity>\n";
        if (!r.asil.empty()) {
            out << "    <asil>" << r.asil << "</asil>\n";
        }
        out << "  </workItem>\n";
    }
    out << "</workItems>\n";
    return out.str();
}

} // namespace cpfusa::trace
