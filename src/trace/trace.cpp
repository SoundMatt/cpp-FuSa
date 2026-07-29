#include "trace.hpp"
#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>
#include <functional>
#include <regex>
#include <set>
#include <sstream>
#include <iomanip>

namespace fs = std::filesystem;
using json   = nlohmann::json;

namespace cpfusa::trace {

namespace {

constexpr std::string_view ReqsFile = ".fusa-reqs.json";

std::string trim(const std::string& s) {
    auto a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    auto b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

} // namespace

// §1.4.1 — trivial enum/string converters and pure serialisation helpers are
// exempt from --func-coverage counting (this repo's existing tagging
// convention never expects render_text/render_json/write_json/parse_*/*_str
// to carry their own req tag; they merely surface data already validated
// elsewhere).
//fusa:req REQ-TRACE018
bool is_func_exempt(const std::string& name) {
    static const std::regex exempt_re(R"(^(render|write_json|export_|parse_|to_)|_str$)");
    return std::regex_search(name, exempt_re);
}

//fusa:req REQ-TRACE021
bool is_test_tree_path(const fs::path& p) {
    for (const auto& part : p) {
        auto s = part.string();
        if (s == "test" || s == "tests") return true;
    }
    return false;
}

namespace {

// Strips // and /* */ comments (respecting string/char literals) so brace
// tracking below isn't confused by tag text or commented-out code.
std::string strip_comments(const std::string& content) {
    std::string out;
    out.reserve(content.size());
    bool in_str = false, in_chr = false;
    for (size_t i = 0; i < content.size(); ) {
        char c = content[i];
        if (!in_str && !in_chr && c == '/' && i + 1 < content.size() && content[i + 1] == '/') {
            while (i < content.size() && content[i] != '\n') ++i;
            continue;
        }
        if (!in_str && !in_chr && c == '/' && i + 1 < content.size() && content[i + 1] == '*') {
            i += 2;
            while (i + 1 < content.size() && !(content[i] == '*' && content[i + 1] == '/')) ++i;
            i += 2;
            continue;
        }
        if (!in_chr && c == '"' && (i == 0 || content[i - 1] != '\\')) in_str = !in_str;
        if (!in_str && c == '\'' && (i == 0 || content[i - 1] != '\\')) in_chr = !in_chr;
        out += c;
        ++i;
    }
    return out;
}

struct DeclaredFunc {
    std::string name;      // function/method name
    std::string qualifier; // enclosing class/struct name, or "" for a free function
};

// Does `stmt` look like a callable declaration (`name(...)`) and, if so, what
// is the declared name? Empty return means "not a function declaration"
// (data member, using/typedef, access specifier, constructor/destructor, …).
std::string extract_func_name(const std::string& raw_stmt, const std::string& enclosing_class) {
    std::string s = trim(raw_stmt);
    if (s.empty()) return "";
    if (s.rfind("using ", 0) == 0 || s.rfind("typedef ", 0) == 0) return "";
    if (s.rfind("friend ", 0) == 0) return "";
    if (s.find('(') == std::string::npos) return "";
    static const std::regex name_re(R"(([A-Za-z_]\w*)\s*\()");
    std::smatch m;
    if (!std::regex_search(s, m, name_re)) return "";
    std::string name = m[1].str();
    if (!enclosing_class.empty() && name == enclosing_class) return ""; // constructor
    if (!name.empty() && name[0] == '~')                        return ""; // destructor
    static const std::set<std::string> kw = {
        "if", "for", "while", "switch", "sizeof", "static_assert", "return",
        "catch", "decltype", "noexcept", "alignas", "alignof"};
    if (kw.count(name)) return "";
    return name;
}

// Parses a header's content for namespace-scope free functions and
// public class/struct methods that are *declared but not inline-defined*
// (i.e. they have a separate .cpp definition to check for a req tag).
std::vector<DeclaredFunc> parse_hpp_functions(const std::string& raw) {
    std::vector<DeclaredFunc> out;
    std::string content = strip_comments(raw);

    struct Block { std::string kind; std::string name; std::string access; };
    std::vector<Block> stack;
    std::string stmt;

    auto enclosing_class = [&]() -> std::string {
        for (auto it = stack.rbegin(); it != stack.rend(); ++it)
            if (it->kind == "class" || it->kind == "struct") return it->name;
        return "";
    };
    auto reachable = [&]() -> bool {
        for (auto it = stack.rbegin(); it != stack.rend(); ++it) {
            if (it->kind == "class" || it->kind == "struct") return it->access == "public";
            if (it->kind == "enum" || it->kind == "func" || it->kind == "other") return false;
        }
        return true; // only namespace blocks (or nothing) enclosing
    };

    for (size_t i = 0; i < content.size(); ++i) {
        char c = content[i];
        if (c == ':' && !(i + 1 < content.size() && content[i + 1] == ':')
                     && !(i > 0 && content[i - 1] == ':')) {
            std::string t = trim(stmt);
            if ((t == "public" || t == "private" || t == "protected") && !stack.empty()
                    && (stack.back().kind == "class" || stack.back().kind == "struct")) {
                stack.back().access = t;
                stmt.clear();
                continue;
            }
            stmt += c;
            continue;
        }
        if (c == '{') {
            // `t` is everything accumulated since the last `;`/`{`/`}` — for the
            // very first block this includes leading #include/#pragma noise, so
            // block-kind detection below matches the *end* of `t` (immediately
            // before this '{'), not its start.
            std::string t = trim(stmt);
            Block b;
            static const std::regex class_re(R"(\bclass\s+(\w+))");
            static const std::regex struct_re(R"(\bstruct\s+(\w+))");
            static const std::regex ns_re(R"(\bnamespace(\s+[\w:]+)?\s*$)");
            static const std::regex enum_re(R"(\benum\b)");
            std::smatch m;
            // enum must be checked before class/struct: "enum class X" would
            // otherwise match class_re on the "class X" substring.
            if (std::regex_search(t, enum_re)) {
                b.kind = "enum";
            } else if (std::regex_search(t, m, class_re) && t.find('(') == std::string::npos) {
                b.kind = "class"; b.name = m[1].str(); b.access = "private";
            } else if (std::regex_search(t, m, struct_re) && t.find('(') == std::string::npos) {
                b.kind = "struct"; b.name = m[1].str(); b.access = "public";
            } else if (std::regex_search(t, ns_re)) {
                b.kind = "namespace";
            } else if (reachable() && !extract_func_name(t, enclosing_class()).empty()) {
                b.kind = "func"; // inline-defined function body — no separate .cpp def to check
            } else {
                b.kind = "other";
            }
            stack.push_back(b);
            stmt.clear();
            continue;
        }
        if (c == '}') {
            if (!stack.empty()) stack.pop_back();
            stmt.clear();
            continue;
        }
        if (c == ';') {
            if (reachable()) {
                std::string name = extract_func_name(stmt, enclosing_class());
                if (!name.empty()) out.push_back({name, enclosing_class()});
            }
            stmt.clear();
            continue;
        }
        stmt += c;
    }
    return out;
}

// Finds the first top-level (column-0) definition line for `name` (optionally
// qualified as `qualifier::name`) in `cpp_lines`, then reports whether a
// //fusa:req tag sits directly above it (a contiguous run of `//` comment
// lines immediately preceding, no blank-line gap).
bool func_has_tag_above(const std::vector<std::string>& cpp_lines,
                        const std::string& name, const std::string& qualifier) {
    std::regex target = qualifier.empty()
        ? std::regex(R"(\b)" + name + R"(\s*\()")
        : std::regex(R"(\b)" + qualifier + "::" + name + R"(\s*\()");

    int def_idx = -1;
    for (size_t i = 0; i < cpp_lines.size(); ++i) {
        const std::string& line = cpp_lines[i];
        if (line.empty() || (line[0] == ' ' || line[0] == '\t')) continue; // top-level only
        std::smatch m;
        if (!std::regex_search(line, m, target)) continue;
        if (qualifier.empty()) {
            auto pos = static_cast<size_t>(m.position(0));
            if (pos >= 2 && line.substr(pos - 2, 2) == "::") continue; // some_other::name — not ours
        }
        def_idx = static_cast<int>(i);
        break;
    }
    if (def_idx < 0) return false;

    for (int j = def_idx - 1; j >= 0; --j) {
        std::string t = trim(cpp_lines[j]);
        if (t.empty()) break;
        if (t.rfind("//", 0) != 0) break;
        if (t.find("fusa:req") != std::string::npos) return true;
    }
    return false;
}

} // namespace

// §1.4.1 item 2 / §5 --func-coverage
//fusa:req REQ-TRACE018
FuncCoverage scan_func_coverage(const fs::path& dir) {
    FuncCoverage fc;
    auto src_dir = dir / "src";
    if (!fs::exists(src_dir)) return fc;

    static const std::regex hpp_ext(R"(\.hpp$)");

    for (const auto& mod : fs::directory_iterator(src_dir, fs::directory_options::skip_permission_denied)) {
        if (!mod.is_directory()) continue;
        for (const auto& file : fs::directory_iterator(mod.path(), fs::directory_options::skip_permission_denied)) {
            if (!file.is_regular_file()) continue;
            const auto& hpp_path = file.path();
            if (!std::regex_search(hpp_path.string(), hpp_ext)) continue;
            auto cpp_path = hpp_path;
            cpp_path.replace_extension(".cpp");
            if (!fs::exists(cpp_path)) continue; // no matching definition file — nothing to check

            std::ifstream hf(hpp_path);
            std::string hpp_content((std::istreambuf_iterator<char>(hf)), std::istreambuf_iterator<char>());
            auto decls = parse_hpp_functions(hpp_content);
            if (decls.empty()) continue;

            std::ifstream cf(cpp_path);
            std::vector<std::string> cpp_lines;
            std::string line;
            while (std::getline(cf, line)) cpp_lines.push_back(line);

            fs::path rel_hpp = fs::relative(hpp_path, dir);

            for (const auto& d : decls) {
                if (is_func_exempt(d.name)) continue;
                ++fc.total;
                if (func_has_tag_above(cpp_lines, d.name, d.qualifier)) {
                    ++fc.covered;
                } else {
                    fc.uncovered.push_back(rel_hpp.generic_string() + ":" +
                        (d.qualifier.empty() ? d.name : d.qualifier + "::" + d.name));
                }
            }
        }
    }

    if (fc.total > 0) fc.pct = 100.0 * fc.covered / fc.total;
    return fc;
}

//fusa:req REQ-TRACE001 REQ-TRACE002 REQ-TRACE003 REQ-TRACE004 REQ-TRACE005 REQ-TRACE006 REQ-TRACE007 REQ-TRACE010 REQ-TRACE011 REQ-TRACE012
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
            r.parent_id    = item.value("parent_id", "");
            reqs.push_back(std::move(r));
        }
        return reqs;
    } catch (const json::exception& ex) {
        return std::string("parse error: ") + ex.what();
    }
}

namespace {
std::vector<Annotation> scan_annotations_impl(
        const fs::path& dir, const std::function<bool(const fs::path&)>& in_scope) {
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
        if (!in_scope(entry.path())) continue;
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
} // namespace

//fusa:req REQ-TRACE020
std::vector<Annotation> scan_annotations(const fs::path& dir) {
    return scan_annotations_impl(dir, [](const fs::path&) { return true; });
}

//fusa:req REQ-CFG006
std::vector<Annotation> scan_annotations(const fs::path& dir, const config::ProjectConfig& cfg) {
    return scan_annotations_impl(dir, [&](const fs::path& p) {
        if (!config::under_source_dirs(p, dir, cfg)) return false;
        auto s = p.string();
        for (const auto& pat : cfg.exclude_patterns)
            if (s.find(pat) != std::string::npos) return false;
        return true;
    });
}

//fusa:req REQ-TRACE018 REQ-TRACE019
Result<TraceResult> run(const fs::path& dir,
                        const config::ProjectConfig& cfg,
                        const TraceOptions& opts) {
    auto reqs_result = load_requirements(dir);
    if (!is_ok(reqs_result)) return error_of(reqs_result);
    auto reqs = value_of(reqs_result);

    auto annotations = scan_annotations(dir, cfg);

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
        if (has_test) {
            ++result.tested;
            if (req.severity == "cybersecurity") ++result.sec_tested;
        }
    }

    // §1.4.1 item 3 — dangling //fusa:test references: a test tag whose ID
    // does not exist in .fusa-reqs.json is surfaced as a WARNING, the same
    // way a malformed annotation would be, never silently accepted.
    {
        std::set<std::string> known_ids;
        for (const auto& req : reqs) known_ids.insert(req.id);
        for (const auto& ann : annotations) {
            if (ann.is_test && !known_ids.count(ann.req_id)) {
                result.dangling_tags.push_back({
                    ann.req_id, ann.file, ann.line,
                    "dangling //fusa:test reference — " + ann.req_id +
                        " not found in .fusa-reqs.json"
                });
            }
        }
    }

    // §1.4.1 item 2 / §5 --func-coverage
    result.func_coverage = scan_func_coverage(dir);

    if (result.total > 0) {
        result.annotation_coverage = 100.0 * result.annotated / result.total;
        result.test_coverage       = 100.0 * result.tested    / result.total;
    }

    // ── HLR/LLR hierarchy validation (REQ-HLR001..REQ-HLR005) ─────────────────
    {
        std::set<std::string> hlr_ids;
        for (const auto& req : reqs) {
            if (req.parent_id.empty()) hlr_ids.insert(req.id);
        }

        for (const auto& req : reqs) {
            if (req.parent_id.empty()) {
                ++result.hlr_count;
            } else {
                ++result.llr_count;
                // Validate: LLR must reference existing HLR.
                if (hlr_ids.find(req.parent_id) == hlr_ids.end()) {
                    result.hlr_violations.push_back({
                        req.parent_id, req.id,
                        "LLR " + req.id + " references unknown HLR " + req.parent_id
                    });
                }
            }
        }

        // Validate: every HLR must have at least one LLR child.
        std::set<std::string> hlrs_with_children;
        for (const auto& req : reqs) {
            if (!req.parent_id.empty() && hlr_ids.count(req.parent_id))
                hlrs_with_children.insert(req.parent_id);
        }
        result.hlr_covered = static_cast<int>(hlrs_with_children.size());
        for (const auto& hid : hlr_ids) {
            if (!hlrs_with_children.count(hid)) {
                result.hlr_violations.push_back({
                    hid, "", "HLR " + hid + " has no LLR children"
                });
            }
        }

        // Determine gate level: strict flag or project ASIL-C/D (REQ-HLR004 / REQ-HLR005).
        // Use the project's ASIL from config, not individual requirement ASIL fields.
        const auto& pa = cfg.asil;
        bool any_high_asil = (pa == "ASIL-C" || pa == "ASIL-D");

        if (!result.hlr_violations.empty()) {
            bool do_error = opts.strict_hlr_llr || any_high_asil;
            if (do_error) {
                // Gate failure (exit 1), not a runtime error (exit 3) — the
                // tool ran fine and found a gap. Per spec §2.3 the JSON/text
                // artefact MUST still be produced; record the gate outcome
                // in the result and let the caller decide the exit code
                // after rendering, instead of discarding the result here.
                result.hlr_gate_failed = true;
            }
            // warn-only for lower ASIL levels — violations are recorded in result
        }
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
    // §5 --func-coverage N: N=0 disables the gate.
    if (result.func_coverage.total > 0 && opts.min_func_pct > 0
            && result.func_coverage.pct < opts.min_func_pct) {
        return std::string("function coverage ")
             + std::to_string(static_cast<int>(result.func_coverage.pct))
             + "% below required " + std::to_string(opts.min_func_pct) + "%";
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

    // HLR/LLR hierarchy summary
    if (result.hlr_count > 0 || result.llr_count > 0) {
        out << "HLR: " << result.hlr_count
            << "  LLR: " << result.llr_count
            << "  HLR-covered: " << result.hlr_covered << "/" << result.hlr_count << "\n";
    }
    if (!result.hlr_violations.empty()) {
        out << "HLR/LLR Violations:\n";
        for (const auto& v : result.hlr_violations)
            out << "  WARN: " << v.message << "\n";
    }

    // §1.4.1 item 3 — dangling //fusa:test references.
    if (!result.dangling_tags.empty()) {
        out << "Dangling Test-Tag References:\n";
        for (const auto& d : result.dangling_tags)
            out << "  WARN: " << d.message << " (" << d.file << ":" << d.line << ")\n";
    }

    // §1.4.1 item 2 / §5 --func-coverage
    if (result.func_coverage.total > 0) {
        out << "Func Coverage: " << result.func_coverage.covered << "/"
            << result.func_coverage.total << " (" << std::fixed << std::setprecision(1)
            << result.func_coverage.pct << "%)\n";
    }
    return out.str();
}

//fusa:req REQ-TRACE016 REQ-TRACE017
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
    j["kind"]          = "trace-matrix";
    j["tool"]          = "cpp-FuSa";
    j["toolVersion"]   = std::string(Version);
    j["language"]      = "cpp";
    j["generatedAt"]   = ts.str();
    j["project"]       = cfg.project;

    // §5: requirements[] — metadata only; no nested tags.
    j["requirements"] = json::array();
    for (const auto& req : result.requirements) {
        json entry;
        entry["id"]          = req.id;
        entry["title"]       = req.title;
        entry["severity"]    = req.severity;
        entry["standard"]    = req.standard_ref;
        if (!req.asil.empty())      entry["asil"]     = req.asil;
        if (!req.parent_id.empty()) entry["parentId"] = req.parent_id;
        j["requirements"].push_back(entry);
    }

    // §5: flat top-level tags[] with kind ∈ {impl, test, sec-test}.
    // A sec-test tag is a test annotation on a cybersecurity requirement;
    // it counts toward both testedRequirements and secTestedRequirements.
    std::map<std::string, std::string> req_severity_map;
    for (const auto& req : result.requirements)
        req_severity_map[req.id] = req.severity;

    json tags_arr = json::array();
    for (const auto& req : result.requirements) {
        auto it = result.by_req.find(req.id);
        if (it == result.by_req.end()) continue;
        const bool is_cyber = (req.severity == "cybersecurity");
        for (const auto& ann : it->second) {
            std::string kind = ann.is_test ? (is_cyber ? "sec-test" : "test") : "impl";
            tags_arr.push_back({
                {"requirementId", req.id},
                {"file",          rel(ann.file)},
                {"line",          ann.line},
                {"kind",          kind}
            });
        }
    }
    j["tags"] = tags_arr;

    // §5: coverage block — spec-canonical field names.
    j["coverage"] = {
        {"totalRequirements",    result.total},
        {"tracedRequirements",   result.annotated},
        {"testedRequirements",   result.tested},
        {"secTestedRequirements", result.sec_tested}
    };
    // §1.4.1 item 2 / §5 --func-coverage
    j["coverage"]["funcCoverage"] = {
        {"total",   result.func_coverage.total},
        {"covered", result.func_coverage.covered},
        {"pct",     result.func_coverage.pct}
    };

    // §1.4.1 item 3 — dangling //fusa:test references (WARNING-level, never
    // silently accepted; same treatment as a malformed annotation).
    if (!result.dangling_tags.empty()) {
        json darr = json::array();
        for (const auto& d : result.dangling_tags) {
            darr.push_back({
                {"requirementId", d.req_id},
                {"file",          rel(d.file)},
                {"line",          d.line},
                {"message",       d.message}
            });
        }
        j["danglingTags"] = darr;
    }

    // HLR/LLR hierarchy block (only when hierarchy is present)
    if (result.hlr_count > 0 || result.llr_count > 0) {
        json hier;
        hier["hlrCount"]     = result.hlr_count;
        hier["llrCount"]     = result.llr_count;
        hier["hlrCovered"]   = result.hlr_covered;
        if (!result.hlr_violations.empty()) {
            json varr = json::array();
            for (const auto& v : result.hlr_violations) {
                json vobj;
                if (!v.hlr_id.empty()) vobj["hlrId"] = v.hlr_id;
                if (!v.llr_id.empty()) vobj["llrId"] = v.llr_id;
                vobj["message"] = v.message;
                varr.push_back(vobj);
            }
            hier["violations"] = varr;
        }
        j["hierarchy"] = hier;
    }
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
    std::getline(f, line); // skip header: id,title,description,standard_ref,severity,asil,parent_id
    int added = 0;
    while (std::getline(f, line)) {
        if (line.empty()) continue;
        // Minimal CSV parse: split on first 6 commas, rest is parent_id.
        std::istringstream ss(line);
        std::string id, title, desc, std_ref, sev, asil, parent_id;
        std::getline(ss, id,        ',');
        std::getline(ss, title,     ',');
        std::getline(ss, desc,      ',');
        std::getline(ss, std_ref,   ',');
        std::getline(ss, sev,       ',');
        std::getline(ss, asil,      ',');
        std::getline(ss, parent_id);
        if (id.empty()) continue;
        if (existing.count(id)) continue;
        Requirement r;
        r.id           = id;
        r.title        = title;
        r.description  = desc;
        r.standard_ref = std_ref;
        r.severity     = sev.empty() ? "safety" : sev;
        r.asil         = asil;
        r.parent_id    = parent_id;
        reqs.push_back(std::move(r));
        existing.insert(id);
        ++added;
    }
    return added;
}

std::string export_csv(const std::vector<Requirement>& reqs) {
    std::ostringstream out;
    out << "id,title,description,standard_ref,severity,asil,parent_id\n";
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
            << esc(r.asil)         << ','
            << esc(r.parent_id)    << '\n';
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
        if (!r.asil.empty())      obj["asil"]      = r.asil;
        if (!r.parent_id.empty()) obj["parent_id"] = r.parent_id;
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
