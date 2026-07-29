// fusa:file-suppress LINT004 — CLI dispatcher; std::exit() is the intended error-path mechanism
#include "cli.hpp"
#include "../config/config.hpp"
#include "../engine/engine.hpp"
#include "../report/report.hpp"
#include "../lint/lint.hpp"
#include "../analyze/analyze.hpp"
#include "../trace/trace.hpp"
#include "../template/template_gen.hpp"
#include "../cyber/cyber.hpp"
#include "../verify/verify.hpp"
#include "../qualify/qualify.hpp"
#include "../release/release.hpp"
#include "../auditpack/auditpack.hpp"
#include "../badge/badge.hpp"
#include "../diff/diff.hpp"
#include "../sign/sign.hpp"
#include "../hooks/hooks.hpp"
#include "../tara/tara.hpp"
#include "../fmea/fmea.hpp"
#include "../safety_case/safety_case.hpp"
#include "../hara/hara.hpp"
#include "../iso26262/iso26262.hpp"
#include "../iec61508/iec61508.hpp"
#include "../boundary/boundary.hpp"
#include "../metrics/metrics.hpp"
#include "../vuln/vuln.hpp"
#include "../coverage/coverage.hpp"
#include "../disposition/disposition.hpp"
#include "../impact/impact.hpp"
#include "../do178/do178.hpp"
#include "../sas/sas.hpp"
#include "../sci/sci.hpp"
#include "../pr/pr.hpp"
#include "../fix/fix.hpp"
#include "../misra/misra.hpp"
#include "../coupling/coupling.hpp"
#include "../iec62443/iec62443.hpp"
#include "../slsa/slsa.hpp"
#include "../iso21434/iso21434.hpp"
#include "../unece/unece.hpp"
#include "../ast/ast.hpp"
#include "../comp/comp.hpp"
#include "../quality/quality.hpp"
#include "cpfusa/fusa.hpp"

#include <CLI/CLI.hpp>
#include <nlohmann/json.hpp>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <optional>
#include <string>

namespace fs = std::filesystem;

namespace cpfusa::cli {

namespace {

std::optional<config::ProjectConfig> load_config(const fs::path& dir) {
    auto r = config::load(dir);
    if (!is_ok(r)) {
        if (error_of(r) == std::string(ErrNoConfig)) {
            std::cerr << "No .fusa.json found. Run 'cpfusa init' first.\n";
        } else {
            std::cerr << "Config error: " << error_of(r) << "\n";
        }
        return std::nullopt;
    }
    return value_of(r);
}

void print_ok(const std::string& msg)  { std::cout << "[OK] "    << msg << "\n"; }
void print_err(const std::string& msg) { std::cerr << "[ERROR] " << msg << "\n"; }

std::string fmt_pct(double v) {
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(1) << v;
    return ss.str();
}

// §1.6.1/§1.6.2 gating shared by fmea/hara/tara/safety-case/sas: FUSA-STUB001
// (Rule A) always gates unless waived via a rule-level disposition Accept
// entry (§1.6.1 — "disposition-suppressible only, never via attestation").
// FUSA-STUB002 (Rule B) is suppressed outright by a valid "reviewed"
// attestation (§1.6.2); otherwise it stays advisory unless
// --strict/--require-attestation is set, in which case an unsuppressed
// Rule B WARNING escalates to exit 1 too. Returns true when the caller
// should exit(1).
// content_only strips the two fields §1.6.2 excludes from a content hash —
// `attestation` itself (self-referential) and `generatedAt` (varies every
// run) — from an already-built §3.1-headered document.
nlohmann::json content_only(nlohmann::json doc) {
    doc.erase("generatedAt");
    doc.erase("attestation");
    return doc;
}

// preserve_attestation implements §1.6.2's "carry-forward across
// regeneration" MUST: loads whatever attestation object (if any) the
// artifact already on disk at `path` carries and returns it *unchanged* —
// regardless of whether it is still valid against the freshly-built content.
// It deliberately does not decide validity/staleness here (that is
// quality::is_valid_reviewed's job, applied separately by each call site
// below) — a stale or self-attested attestation is still carried into the
// regenerated artifact's JSON so a human can see a review happened, even
// though it no longer gates FUSA-STUB002. Discarding it outright here would
// silently wipe every human attestation on the very next regeneration, which
// is exactly the gap this MUST closes.
quality::Attestation preserve_attestation(const fs::path& path) {
    return quality::carry_forward(path);
}

bool apply_quality_gate(const std::vector<Finding>& findings, const fs::path& dir,
                        bool attestation_valid, bool require_attestation) {
    auto log = disposition::load(dir);
    bool gate = false;
    for (const auto& f : findings) {
        bool suppressed = false;
        if (f.rule_id == std::string(quality::kStub001RuleId)) {
            disposition::Entry e;
            // §4.1: "accepted" and "deferred" are both waivers that suppress
            // the gate; "rejected" is a denied waiver — the finding must
            // still gate.
            if (disposition::find_by_rule(log, f.rule_id, e) &&
                (e.status == disposition::Status::Accepted ||
                 e.status == disposition::Status::Deferred))
                suppressed = true;
        } else if (f.rule_id == std::string(quality::kStub002RuleId)) {
            if (attestation_valid) suppressed = true;
        }
        std::string sev = f.severity == Severity::ERROR ? "ERROR" : "WARNING";
        std::cout << "[" << sev << "] " << f.rule_id << " " << f.file;
        if (f.line > 0) std::cout << ":" << f.line;
        std::cout << " — " << f.message << (suppressed ? "  (suppressed)" : "") << "\n";
        if (suppressed) continue;
        if (f.severity == Severity::ERROR) gate = true;
        if (f.severity == Severity::WARNING && require_attestation) gate = true;
    }
    return gate;
}

} // anonymous namespace

//fusa:req REQ-CLI001 REQ-CLI002 REQ-CLI003 REQ-CLI004 REQ-CLI005 REQ-CLI006 REQ-CLI007 REQ-CLI008 REQ-CLI009 REQ-CLI010 REQ-NF001 REQ-NF002 REQ-NF003
int run(int argc, char* argv[]) {
    CLI::App app{"cpfusa — C++ Functional Safety Toolkit v" + std::string(Version)};

    std::string dir_str = fs::current_path().string();
    bool no_color_flag = false;
    app.add_option("--dir", dir_str, "Project directory (default: cwd)");
    app.add_flag("--no-color", no_color_flag, "Disable ANSI colour (also honoured via NO_COLOR env)");
    app.fallthrough(true);

    // §2.6: honour NO_COLOR environment variable
    auto* nc_env = std::getenv("NO_COLOR");
    if (nc_env != nullptr) no_color_flag = true;

    // ── init ──────────────────────────────────────────────────────────────────
    auto* init      = app.add_subcommand("init", "Initialise .fusa.json and .fusa-reqs.json");
    std::string init_standard = "iso26262", init_asil = "ASIL-B";
    std::string init_name, init_project_version;
    bool init_force = false;
    init->add_option("--standard",        init_standard,        "iso26262|iec61508|iso21434|do178c");
    init->add_option("--asil",            init_asil,            "ASIL-A..D | SIL-1..4 | DAL-A..E");
    init->add_option("--name",            init_name,            "Project name (default: directory name)");
    init->add_option("--project-version", init_project_version, "Project version (default: 0.1.0)");
    init->add_flag("--force",             init_force,           "Overwrite existing files");
    init->callback([&] {
        fs::path dir{dir_str};
        bool wrote_any = false;

        // .fusa.json — per-file: create if missing, leave untouched unless --force
        if (!config::exists(dir) || init_force) {
            auto cfg     = config::defaults(dir);
            cfg.standard = init_standard;
            cfg.asil     = init_asil;
            if (!init_name.empty())           cfg.project = init_name;
            if (!init_project_version.empty()) cfg.version = init_project_version;
            auto r = config::save(dir, cfg);
            if (!is_ok(r)) { print_err(error_of(r)); std::exit(3); }
            print_ok("Created .fusa.json for project '" + cfg.project + "'");
            wrote_any = true;
        } else {
            std::cerr << ".fusa.json already exists (use --force to overwrite)\n";
        }

        // .fusa-reqs.json — §9.1: create with empty requirements array
        auto reqs_path = dir / ".fusa-reqs.json";
        if (!fs::exists(reqs_path) || init_force) {
            std::ofstream rf(reqs_path);
            if (!rf) { print_err("failed to write .fusa-reqs.json"); std::exit(3); }
            rf << "{\"requirements\":[]}\n";
            print_ok("Created .fusa-reqs.json");
            wrote_any = true;
        } else {
            std::cerr << ".fusa-reqs.json already exists (use --force to overwrite)\n";
        }

        if (wrote_any)
            std::cout << "Next: add //fusa:req REQ-XXX annotations, then run 'cpfusa check'\n";
    });

    // ── check ─────────────────────────────────────────────────────────────────
    auto* check      = app.add_subcommand("check", "Run all safety checks");
    bool strict_flag = false;
    std::string fmt  = "text", out;
    check->add_flag("--strict",  strict_flag, "Exit 1 on WARNING too");
    check->add_option("--format", fmt,  "text|json|html|sarif");
    check->add_option("--output", out,  "Write output to file (default: stdout)");
    check->callback([&]() -> void {
        fs::path dir{dir_str};
        auto cfg_opt = load_config(dir);
        if (!cfg_opt) { std::exit(3); }
        auto& cfg = *cfg_opt;
        cfg.strict = strict_flag;
        auto eng      = engine::make_default_engine();
        auto findings = eng.run(dir, cfg);
        report::ReportOptions ropts;
        ropts.strict   = strict_flag;
        ropts.output   = out;
        ropts.no_color = no_color_flag;
        if (fmt == "json")       ropts.format = report::Format::JSON;
        else if (fmt == "html")  ropts.format = report::Format::HTML;
        else if (fmt == "sarif") ropts.format = report::Format::SARIF;
        auto wr = report::write_report(findings, cfg, ropts);
        if (!is_ok(wr)) { print_err(error_of(wr)); std::exit(1); }
        std::exit(report::exit_code(findings, strict_flag));
    });

    // ── lint ──────────────────────────────────────────────────────────────────
    auto* lint_cmd   = app.add_subcommand("lint", "Run MISRA/AUTOSAR lint rules");
    bool lint_strict = false;
    lint_cmd->add_flag("--strict", lint_strict);
    lint_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        auto cfg_opt = load_config(dir);
        if (!cfg_opt) { std::exit(3); }
        auto findings = lint::run(dir, *cfg_opt);
        report::ReportOptions ropts; ropts.strict = lint_strict; ropts.no_color = no_color_flag;
        (void)report::write_report(findings, *cfg_opt, ropts);
        std::exit(report::exit_code(findings, lint_strict));
    });

    // ── analyze ───────────────────────────────────────────────────────────────
    auto* analyze_cmd  = app.add_subcommand("analyze", "Run static analysis (clang-tidy, cppcheck, own passes)");
    bool no_clang_tidy = false, no_cppcheck = false;
    analyze_cmd->add_flag("--no-clang-tidy", no_clang_tidy);
    analyze_cmd->add_flag("--no-cppcheck",   no_cppcheck);
    analyze_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        auto cfg_opt = load_config(dir);
        if (!cfg_opt) { std::exit(3); }
        analyze::AnalyzeOptions aopts;
        aopts.run_clang_tidy = !no_clang_tidy;
        aopts.run_cppcheck   = !no_cppcheck;
        auto findings = analyze::run(dir, *cfg_opt, aopts);
        (void)report::write_report(findings, *cfg_opt, {});
        std::exit(report::exit_code(findings, false));
    });

    // ── cyber ─────────────────────────────────────────────────────────────────
    auto* cyber_cmd    = app.add_subcommand("cyber", "Run cybersecurity rules (CWE-mapped, ISO 21434)");
    bool cyber_strict  = false, cyber_write = false;
    cyber_cmd->add_flag("--strict", cyber_strict, "Exit 1 on warnings too");
    cyber_cmd->add_flag("--write",  cyber_write,  "Write cyber-report.json");
    cyber_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        auto cfg_opt = load_config(dir);
        if (!cfg_opt) { std::exit(3); }
        auto rpt = cyber::run(dir, *cfg_opt);
        if (cyber_write) {
            auto wr = cyber::write_report(dir, rpt);
            if (!is_ok(wr)) { print_err(error_of(wr)); std::exit(1); }
            print_ok("cyber-report.json written (" + std::to_string(rpt.findings.size()) + " findings)");
        }
        int errors = 0, warnings = 0;
        for (const auto& f : rpt.findings) {
            auto sev = f.severity == Severity::ERROR ? "ERROR" : f.severity == Severity::WARNING ? "WARNING" : "INFO";
            std::cout << "[" << sev << "] " << f.rule_id << " (" << f.cwe << ") "
                      << f.file << ":" << f.line << " — " << f.message << "\n";
            if (f.severity == Severity::ERROR)   ++errors;
            if (f.severity == Severity::WARNING) ++warnings;
        }
        std::cout << "\nFiles: " << rpt.total_files << "  Findings: " << rpt.findings.size() << "\n";
        if (errors > 0) std::exit(2);
        if (cyber_strict && warnings > 0) std::exit(1);
    });

    // ── trace ─────────────────────────────────────────────────────────────────
    auto* trace_cmd = app.add_subcommand("trace", "Show requirements traceability matrix");
    bool show_gaps      = false;
    bool strict_hlr_llr = false;
    int  req_cov = 0, sec_tested = 0, func_cov = 0;
    std::string trace_fmt, trace_out;
    trace_cmd->add_flag("--gaps",           show_gaps,       "Show only gaps");
    trace_cmd->add_flag("--strict-hlr-llr", strict_hlr_llr,  "Fail on any HLR/LLR violation regardless of ASIL");
    trace_cmd->add_option("--req-coverage", req_cov,         "Fail if annotation coverage < N%");
    trace_cmd->add_option("--sec-tested",   sec_tested,      "Fail if test coverage < N%");
    trace_cmd->add_option("--func-coverage",func_cov,        "Fail if header-declared public function req-tag density < N% (§1.4.1); 0 disables");
    trace_cmd->add_option("--format",       trace_fmt,       "text|json (default: text)");
    trace_cmd->add_option("--output",       trace_out,       "Write output to file instead of stdout");
    trace_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        auto cfg_opt = load_config(dir);
        if (!cfg_opt) { std::exit(3); }
        cfg_opt->project_root = fs::canonical(dir).string();
        trace::TraceOptions topts;
        topts.show_gaps          = show_gaps;
        topts.min_annotation_pct = req_cov;
        topts.min_test_pct       = sec_tested;
        topts.min_func_pct       = func_cov;
        topts.strict_hlr_llr     = strict_hlr_llr;
        auto r = trace::run(dir, *cfg_opt, topts);
        if (!is_ok(r)) { print_err(error_of(r)); std::exit(1); }
        const auto& result = value_of(r);
        const bool as_json = (trace_fmt == "json");
        std::string out_str = as_json
            ? trace::render_json(result, *cfg_opt)
            : trace::render_matrix(result, topts);
        if (!trace_out.empty()) {
            std::ofstream f(trace_out);
            if (!f) { print_err("cannot write " + trace_out); std::exit(3); }
            f << out_str;
        } else {
            // §2.2: all output goes to stdout by default; use --output to write a file.
            std::cout << out_str;
        }
        // §2.3: a gate failure (HLR/LLR decomposition here) MUST NOT prevent
        // the requested artefact from being written — exit 1 only after the
        // output above has already been emitted.
        if (result.hlr_gate_failed) std::exit(1);
    });

    // ── req ───────────────────────────────────────────────────────────────────
    auto* req_cmd = app.add_subcommand("req", "Requirement lookup, import, and export");
    req_cmd->require_subcommand(0, 1);

    // req show [REQ-ID ...]
    auto* req_show = req_cmd->add_subcommand("show", "Show requirement(s) and their annotations");
    std::string req_id_arg;
    req_show->add_option("id", req_id_arg, "Requirement ID (show all if omitted)");
    auto req_show_cb = [&]() -> void {
        fs::path dir{dir_str};
        auto cfg_opt = load_config(dir);
        if (!cfg_opt) { std::exit(3); }
        auto reqs_r = trace::load_requirements(dir);
        if (!is_ok(reqs_r)) { print_err(error_of(reqs_r)); std::exit(1); }
        const auto& reqs = value_of(reqs_r);
        auto anns = trace::scan_annotations(dir);
        if (req_id_arg.empty()) {
            for (const auto& r : reqs) std::cout << trace::render_req(r, anns);
        } else {
            auto it = std::find_if(reqs.begin(), reqs.end(),
                                   [&](const trace::Requirement& r){ return r.id == req_id_arg; });
            if (it == reqs.end()) { print_err("Requirement not found: " + req_id_arg); std::exit(1); }
            std::cout << trace::render_req(*it, anns);
        }
    };
    req_show->callback(req_show_cb);

    // req import --file <csv>
    auto* req_import = req_cmd->add_subcommand("import", "Import requirements from CSV file");
    std::string req_import_file, req_import_fmt = "csv";
    req_import->add_option("--file",   req_import_file, "Input file path")->required();
    req_import->add_option("--format", req_import_fmt,  "csv (default)");
    req_import->callback([&]() -> void {
        fs::path dir{dir_str};
        auto reqs_r = trace::load_requirements(dir);
        if (!is_ok(reqs_r)) { print_err(error_of(reqs_r)); std::exit(1); }
        auto reqs = value_of(reqs_r);
        auto result = trace::import_csv(fs::path(req_import_file), reqs);
        if (!is_ok(result)) { print_err(error_of(result)); std::exit(1); }
        int added = value_of(result);
        if (!trace::save_requirements(dir, reqs)) {
            print_err("Failed to write .fusa-reqs.json"); std::exit(3);
        }
        print_ok("Imported " + std::to_string(added) + " requirement(s) from " + req_import_file);
    });

    // req export [--format csv] [--output file]
    auto* req_export = req_cmd->add_subcommand("export", "Export requirements to CSV");
    std::string req_export_file, req_export_fmt = "csv";
    req_export->add_option("--output", req_export_file, "Output file (default: stdout)");
    req_export->add_option("--format", req_export_fmt,  "csv (default)");
    req_export->callback([&]() -> void {
        fs::path dir{dir_str};
        auto reqs_r = trace::load_requirements(dir);
        if (!is_ok(reqs_r)) { print_err(error_of(reqs_r)); std::exit(1); }
        const auto& reqs = value_of(reqs_r);
        std::string csv = trace::export_csv(reqs);
        if (req_export_file.empty()) {
            std::cout << csv;
        } else {
            std::ofstream f(req_export_file);
            if (!f) { print_err("Cannot write: " + req_export_file); std::exit(3); }
            f << csv;
            print_ok("Exported " + std::to_string(reqs.size()) + " requirement(s) to " + req_export_file);
        }
    });

    // req (no subcommand) — default to show with positional ID for backward compat
    req_cmd->callback([&]() -> void {
        if (req_cmd->get_subcommands().empty()) req_show_cb();
    });

    // ── template ──────────────────────────────────────────────────────────────
    auto* tmpl_cmd  = app.add_subcommand("template", "Generate safety document templates");
    std::string tmpl_type = "all";
    tmpl_cmd->add_option("--type", tmpl_type,
                         "all|safety-plan|test-evidence|hara|svp|scmp|sqap");
    tmpl_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        auto cfg_opt = load_config(dir);
        if (!cfg_opt) { std::exit(3); }
        tmpl::TemplateType tt = tmpl::TemplateType::ALL;
        if (tmpl_type == "safety-plan")       tt = tmpl::TemplateType::SAFETY_PLAN;
        else if (tmpl_type == "test-evidence") tt = tmpl::TemplateType::TEST_EVIDENCE;
        else if (tmpl_type == "hara")         tt = tmpl::TemplateType::HARA;
        else if (tmpl_type == "svp")          tt = tmpl::TemplateType::SVP;
        else if (tmpl_type == "scmp")         tt = tmpl::TemplateType::SCMP;
        else if (tmpl_type == "sqap")         tt = tmpl::TemplateType::SQAP;
        auto r = tmpl::generate(dir, *cfg_opt, tt);
        if (!is_ok(r)) { print_err(error_of(r)); std::exit(1); }
        print_ok("Generated template(s) — type: " + tmpl_type);
    });

    // ── report ────────────────────────────────────────────────────────────────
    auto* rpt_cmd    = app.add_subcommand("report", "Generate full compliance report");
    std::string rpt_fmt = "text", rpt_out;
    rpt_cmd->add_option("--format", rpt_fmt, "text|json|html|sarif");
    rpt_cmd->add_option("--output", rpt_out, "Output file");
    rpt_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        auto cfg_opt = load_config(dir);
        if (!cfg_opt) { std::exit(3); }
        auto eng      = engine::make_default_engine();
        auto findings = eng.run(dir, *cfg_opt);
        auto lint_findings = lint::run(dir, *cfg_opt);
        findings.insert(findings.end(), lint_findings.begin(), lint_findings.end());
        report::ReportOptions ropts;
        ropts.output   = rpt_out;
        ropts.no_color = no_color_flag;
        if (rpt_fmt == "json")       ropts.format = report::Format::JSON;
        else if (rpt_fmt == "html")  ropts.format = report::Format::HTML;
        else if (rpt_fmt == "sarif") ropts.format = report::Format::SARIF;
        auto wr = report::write_report(findings, *cfg_opt, ropts);
        if (!is_ok(wr)) { print_err(error_of(wr)); std::exit(1); }
    });

    // ── verify ────────────────────────────────────────────────────────────────
    auto* verify_cmd = app.add_subcommand("verify", "Run tests and collect evidence bundle");
    verify_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        auto cfg_opt = load_config(dir);
        if (!cfg_opt) { std::exit(3); }
        std::cout << "Running ctest...\n";
        auto r = verify::run_ctest(dir, *cfg_opt);
        if (!is_ok(r)) { print_err(error_of(r)); std::exit(1); }
        const auto& bundle = value_of(r);
        auto wr = verify::write_evidence(dir, bundle);
        if (!is_ok(wr)) { print_err(error_of(wr)); std::exit(1); }
        std::cout << "Tests: " << bundle.summary.total
                  << "  Passed: " << bundle.summary.passed
                  << "  Failed: " << bundle.summary.failed
                  << "  Skipped: " << bundle.summary.skipped << "\n";
        print_ok(".fusa-evidence.json written");
    });

    // ── qualify ───────────────────────────────────────────────────────────────
    auto* qualify_cmd = app.add_subcommand("qualify", "Run tool qualification suite");
    std::string qualify_method, qualify_record_uri, qualifier_identity;
    std::string impl_author, ind_reviewer, ind_test_executor, achievable_asil;
    qualify_cmd->add_option("--qualification-method",  qualify_method,
                            "Qualification method: self|independent");
    qualify_cmd->add_option("--record-uri",            qualify_record_uri,
                            "URI to qualification dossier");
    qualify_cmd->add_option("--qualifier",             qualifier_identity,
                            "Name/org of qualifier");
    qualify_cmd->add_option("--implementation-author", impl_author,
                            "Author of the implementation");
    qualify_cmd->add_option("--independent-reviewer",  ind_reviewer,
                            "Independent reviewer (must differ from author for independence)");
    qualify_cmd->add_option("--independent-test-executor", ind_test_executor,
                            "Independent test executor");
    qualify_cmd->add_option("--achievable-asil",       achievable_asil,
                            "Achievable ASIL level given independence");
    std::string qualify_out;
    qualify_cmd->add_option("--output", qualify_out,
                            "Output file path (default: <dir>/qualify-report.json)");
    std::string qualify_fmt = "text";
    qualify_cmd->add_option("--format", qualify_fmt,
                            "text|json (default: text). §2.2: JSON is always also "
                            "written to the qualify-report.json default/--output path.");
    qualify_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        const bool as_json = (qualify_fmt == "json");
        // §2.2: progress/diagnostic lines are fine on stdout in text mode;
        // in JSON mode keep stdout reserved for the machine-readable payload.
        if (!as_json)
            std::cout << "Running qualification suite for cpfusa v" << Version << "...\n";
        auto cases  = qualify::builtin_cases();
        auto r = qualify::run(cases);
        if (!is_ok(r)) { print_err(error_of(r)); std::exit(1); }
        auto rpt = value_of(r);

        // Propagate CLI flags into report
        rpt.qualification_method     = qualify_method;
        rpt.qualification_record_uri = qualify_record_uri;
        rpt.qualifier_identity       = qualifier_identity;
        rpt.implementation_author    = impl_author;
        rpt.independent_reviewer     = ind_reviewer;
        rpt.independent_test_executor = ind_test_executor;
        rpt.achievable_asil          = achievable_asil;

        // §6: "Writes qualify-report.json by default" — the evidence file is
        // always produced regardless of --format (other commands, e.g.
        // audit-pack/safety-case, depend on it existing on disk).
        fs::path out_path = qualify_out.empty() ? dir / std::string(qualify::ReportFile)
                                                : fs::path(qualify_out);
        auto wr = qualify::save(out_path, rpt);
        if (!is_ok(wr)) { print_err(error_of(wr)); std::exit(1); }

        if (as_json) {
            // §2.2: "--output redirects the report (MUST) ... MUST NOT also
            // write it to stdout" — when --output was given the JSON already
            // landed there via qualify::save() above.
            if (qualify_out.empty())
                std::cout << qualify::to_json(rpt).dump(2) << "\n";
        } else {
            std::cout << "Cases: " << rpt.total
                      << "  Passed: " << rpt.passed
                      << "  Failed: " << rpt.failed << "\n"
                      << "Hash: sha256:" << rpt.hash << "\n";

            // Show badge and independence status
            std::string status = rpt.independence_status();
            std::string badge;
            if (rpt.qualification_method == "independent" || status == "independent")
                badge = "independently-qualified";
            else if (rpt.qualification_method == "self" || status == "self")
                badge = "self-qualified";
            else
                badge = "unqualified";
            std::cout << "Badge: [" << badge << "]\n";
            if (!rpt.achievable_asil.empty())
                std::cout << "Achievable ASIL: " << rpt.achievable_asil << "\n";
        }

        if (rpt.failed > 0) {
            if (!as_json) {
                for (const auto& cr : rpt.results)
                    if (!cr.passed)
                        std::cerr << "  FAIL " << cr.test_case.name << ": " << cr.error << "\n";
            }
            std::exit(1);
        }
        if (!as_json) print_ok(out_path.filename().string() + " written");
    });

    // ── release ───────────────────────────────────────────────────────────────
    auto* release_cmd = app.add_subcommand("release", "Generate SBOM, provenance, and artifact manifest");
    bool release_full = false;
    std::string spdx_ver_str = "3.0.1";
    std::string release_out_dir;
    release_cmd->add_flag("--full", release_full, "Also run tara, fmea, safety-case before packaging");
    release_cmd->add_option("--spdx-version", spdx_ver_str, "SBOM SPDX version: 3.0.1 (default), 2.3, 2.2");
    release_cmd->add_option("--output-dir", release_out_dir,
                            "Directory for sbom.json/provenance.json/artifact-manifest.json (default: --dir)");
    release_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        auto cfg_opt = load_config(dir);
        if (!cfg_opt) { std::exit(3); }
        fs::path out_dir = release_out_dir.empty() ? dir : fs::path(release_out_dir);
        std::error_code od_ec;
        fs::create_directories(out_dir, od_ec);
        if (od_ec) { print_err("cannot create output dir " + out_dir.string() + ": " + od_ec.message()); std::exit(3); }

        if (release_full) {
            // Run tara
            auto tr = tara::generate(dir, *cfg_opt);
            if (is_ok(tr)) tara::write(dir, value_of(tr));
            // Run fmea
            auto fr = fmea::generate(dir, *cfg_opt);
            if (is_ok(fr)) fmea::write(dir, value_of(fr));
            // Run safety-case
            auto sr = safety_case::generate(dir, *cfg_opt);
            if (is_ok(sr)) safety_case::write(dir, value_of(sr));
        }

        auto sbom_r = release::build_sbom(dir, *cfg_opt);
        if (!is_ok(sbom_r)) { print_err(error_of(sbom_r)); std::exit(1); }
        auto prov_r = release::build_provenance(dir, *cfg_opt);
        if (!is_ok(prov_r)) { print_err(error_of(prov_r)); std::exit(1); }
        auto manifest = release::hash_artifacts(dir);
        auto spdx_ver = release::parse_spdx_version(spdx_ver_str);
        if (spdx_ver != release::SpdxVersion::V3_0_1) {
            release::write_sbom(out_dir / std::string(release::SBOMFile), value_of(sbom_r), spdx_ver);
            auto prov_manifest = release::hash_artifacts(dir);
            (void)prov_manifest;
            // Write provenance and manifest separately
            nlohmann::json pj;
            pj["schemaVersion"] = std::string(SpecVersion);
            pj["kind"]          = "provenance";
            pj["tool"]          = "cpp-FuSa";
            pj["generatedAt"]   = value_of(prov_r).generated_at;
            pj["format"]        = "x-FuSa provenance v1";
            pj["module"]        = "github.com/SoundMatt/cpp-FuSa";
            pj["builder"]       = "local";
            pj["vcsRevision"]   = value_of(prov_r).vcs_revision;
            pj["vcsModified"]   = value_of(prov_r).vcs_modified;
            pj["os"]            = value_of(prov_r).platform;
            std::ofstream pf(out_dir / std::string(release::ProvenanceFile));
            pf << pj.dump(2) << "\n";
            nlohmann::json mj;
            mj["schemaVersion"] = std::string(SpecVersion);
            mj["kind"]          = "artifact-manifest";
            mj["tool"]          = "cpp-FuSa";
            mj["generatedAt"]   = manifest.generated_at;
            mj["format"]        = "x-FuSa manifest v1";
            nlohmann::json ar = nlohmann::json::array();
            for (const auto& a : manifest.artifacts)
                ar.push_back({{"path", a.path}, {"sha256", a.sha256}});
            mj["artifacts"] = ar;
            std::ofstream mf(out_dir / std::string(release::ManifestFile));
            mf << mj.dump(2) << "\n";
        } else {
            auto wr = release::write_all(out_dir, value_of(sbom_r), value_of(prov_r), manifest);
            if (!is_ok(wr)) { print_err(error_of(wr)); std::exit(1); }
        }
        print_ok("sbom.json written");
        print_ok("provenance.json written");
        print_ok("artifact-manifest.json written");
    });

    // ── audit-pack ────────────────────────────────────────────────────────────
    auto* auditpack_cmd = app.add_subcommand("audit-pack", "Bundle evidence into audit-pack.zip");
    std::string auditpack_out;
    auditpack_cmd->add_option("--output", auditpack_out, "Output path (default: <dir>/audit-pack.zip)");
    auditpack_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        auto cfg_opt = load_config(dir);
        if (!cfg_opt) { std::exit(3); }
        fs::path out_path = auditpack_out.empty() ? dir / std::string(auditpack::AuditPackFile)
                                                  : fs::path(auditpack_out);
        auto r = auditpack::pack(dir, out_path);
        if (!is_ok(r)) { print_err(error_of(r)); std::exit(1); }
        const auto& m = value_of(r);
        std::cout << "Packed " << m.files.size() << " evidence file(s) into " << out_path << "\n";
        for (const auto& f : m.files)
            std::cout << "  " << f.sha256.substr(0,12) << "  " << f.path << "\n";
        print_ok(out_path.filename().string() + " written");
    });

    // ── badge ─────────────────────────────────────────────────────────────────
    auto* badge_cmd = app.add_subcommand("badge", "Generate SVG status badge (fusa-badge.svg)");
    std::string badge_report;
    badge_cmd->add_option("--report", badge_report, "Path to check JSON report (uses live check if omitted)");
    badge_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        auto cfg_opt = load_config(dir);
        if (!cfg_opt) { std::exit(3); }
        int errors = 0, warnings = 0;
        if (!badge_report.empty()) {
            // Load from JSON report file.
            auto r = diff::load_findings(badge_report);
            if (is_ok(r)) {
                for (const auto& f : value_of(r)) {
                    if (f.severity == "error") ++errors;
                    else if (f.severity == "warning") ++warnings;
                }
            }
        } else {
            auto eng      = engine::make_default_engine();
            auto findings = eng.run(dir, *cfg_opt);
            for (const auto& f : findings) {
                if (f.severity == Severity::ERROR)   ++errors;
                if (f.severity == Severity::WARNING) ++warnings;
            }
        }
        auto b  = badge::from_findings(errors, warnings, std::string(Version));
        auto wr = badge::write_badge(dir, b);
        if (!is_ok(wr)) { print_err(error_of(wr)); std::exit(1); }
        print_ok("fusa-badge.svg written");
    });

    // ── diff ──────────────────────────────────────────────────────────────────
    auto* diff_cmd = app.add_subcommand("diff", "Compare two check reports for regression gating");
    std::string diff_base, diff_cur, diff_fmt = "text";
    diff_cmd->add_option("baseline", diff_base, "Path to baseline JSON report")->required();
    diff_cmd->add_option("current",  diff_cur,  "Path to current JSON report")->required();
    diff_cmd->add_option("--format", diff_fmt,  "text|json");
    diff_cmd->callback([&]() -> void {
        auto base_r = diff::load_findings(diff_base);
        if (!is_ok(base_r)) { print_err(error_of(base_r)); std::exit(1); }
        auto cur_r  = diff::load_findings(diff_cur);
        if (!is_ok(cur_r))  { print_err(error_of(cur_r));  std::exit(1); }
        auto d = diff::compare(value_of(base_r), value_of(cur_r));
        if (diff_fmt == "json") std::cout << diff::render_json(d) << "\n";
        else                    std::cout << diff::render_text(d);
        if (!d.introduced.empty()) std::exit(1);
    });

    // ── sign ──────────────────────────────────────────────────────────────────
    auto* sign_cmd = app.add_subcommand("sign", "Sign or verify a file using HMAC-SHA256");
    std::string sign_key, sign_keygen_path, sign_target;
    bool sign_verify_flag = false;
    sign_cmd->add_option("--key",    sign_key,         "Path to HMAC key file (64-char hex)");
    sign_cmd->add_option("--keygen", sign_keygen_path, "Generate a new key and write to this path");
    sign_cmd->add_flag("--verify",   sign_verify_flag, "Verify an existing signature");
    sign_cmd->add_option("file",     sign_target,      "File to sign or verify");
    sign_cmd->callback([&]() -> void {
        if (!sign_keygen_path.empty()) {
            auto r = sign::keygen(sign_keygen_path);
            if (!is_ok(r)) { print_err(error_of(r)); std::exit(1); }
            print_ok("Key written to " + sign_keygen_path + " (keep secret)");
            return;
        }
        if (sign_target.empty()) { std::cerr << "sign: file argument required\n"; std::exit(1); }
        if (sign_key.empty())    { std::cerr << "sign: --key required\n"; std::exit(1); }
        if (sign_verify_flag) {
            auto r = sign::verify_file(sign_target, sign_key);
            if (!is_ok(r)) { print_err(error_of(r)); std::exit(1); }
            if (value_of(r)) print_ok("Signature valid: " + sign_target);
            else { print_err("Signature INVALID: " + sign_target); std::exit(2); }
        } else {
            auto r = sign::sign_file(sign_target, sign_key);
            if (!is_ok(r)) { print_err(error_of(r)); std::exit(1); }
            print_ok("Signature written to " + sign_target + ".sig");
        }
    });

    // ── hooks ─────────────────────────────────────────────────────────────────
    auto* hooks_cmd = app.add_subcommand("hooks", "Manage git pre-commit hooks");
    auto* hooks_install = hooks_cmd->add_subcommand("install", "Install cpfusa pre-commit hook");
    auto* hooks_remove  = hooks_cmd->add_subcommand("remove",  "Remove cpfusa pre-commit hook");
    auto* hooks_show    = hooks_cmd->add_subcommand("show",    "Print the hook script");
    hooks_install->callback([&]() -> void {
        auto r = hooks::install(dir_str);
        if (!is_ok(r)) { print_err(error_of(r)); std::exit(1); }
        print_ok("Pre-commit hook installed at .git/hooks/pre-commit");
    });
    hooks_remove->callback([&]() -> void {
        auto r = hooks::remove(dir_str);
        if (!is_ok(r)) { print_err(error_of(r)); std::exit(1); }
        print_ok("Pre-commit hook removed");
    });
    hooks_show->callback([&] {
        std::cout << hooks::show();
    });

    // ── tara ──────────────────────────────────────────────────────────────────
    auto* tara_cmd = app.add_subcommand("tara", "Generate TARA per ISO/SAE 21434 Clause 15");
    bool tara_strict = false, tara_require_attestation = false;
    int  tara_min_coverage = 0;
    tara_cmd->add_flag("--strict", tara_strict,
                       "Exit 1 on an unsuppressed FUSA-STUB002 warning too (implies --require-attestation)");
    tara_cmd->add_flag("--require-attestation", tara_require_attestation,
                       "Exit 1 on an unsuppressed FUSA-STUB002 warning (§1.6.2)");
    tara_cmd->add_option("--min-coverage", tara_min_coverage,
                         "Exit 1 if summary.coveragePct < N (0 disables, default)");
    tara_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        auto cfg_opt = load_config(dir);
        if (!cfg_opt) { std::exit(3); }
        cfg_opt->project_root = fs::canonical(dir).string();
        auto r = tara::generate(dir, *cfg_opt);
        if (!is_ok(r)) { print_err(error_of(r)); std::exit(1); }
        auto rpt = value_of(r);
        auto content = content_only(tara::to_json(rpt, *cfg_opt));
        rpt.attestation = preserve_attestation(dir / tara::TaraJsonFile);
        auto wr = tara::write(dir, rpt);
        if (!is_ok(wr)) { print_err(error_of(wr)); std::exit(1); }
        print_ok("tara.json written (" + std::to_string(rpt.scenarios.size()) + " scenarios)");
        print_ok("tara.md written");
        std::cout << "Coverage: " << rpt.summary.assets_analyzed << "/"
                  << rpt.summary.assets_in_project << " assets ("
                  << std::fixed << std::setprecision(1) << rpt.summary.coverage_pct << "%)\n";

        bool attested = quality::is_valid_reviewed(rpt.attestation, content);
        auto findings = tara::scan_quality(rpt);
        bool gate = apply_quality_gate(findings, dir, attested, tara_require_attestation || tara_strict);
        if (tara_min_coverage > 0 && rpt.summary.coverage_pct < tara_min_coverage) {
            print_err("coveragePct " + fmt_pct(rpt.summary.coverage_pct) +
                      " < --min-coverage " + std::to_string(tara_min_coverage));
            gate = true;
        }
        if (gate) std::exit(1);
    });

    // ── fmea ──────────────────────────────────────────────────────────────────
    auto* fmea_cmd  = app.add_subcommand("fmea", "Generate dFMEA from class/function declarations");
    bool fmea_cyber = false;
    bool fmea_strict = false, fmea_require_attestation = false;
    int  fmea_min_coverage = 0;
    fmea_cmd->add_flag("--cyber", fmea_cyber, "Enrich FMEA entries with findings from cyber-report.json");
    fmea_cmd->add_flag("--strict", fmea_strict,
                       "Exit 1 on an unsuppressed FUSA-STUB002 warning too (implies --require-attestation)");
    fmea_cmd->add_flag("--require-attestation", fmea_require_attestation,
                       "Exit 1 on an unsuppressed FUSA-STUB002 warning (§1.6.2)");
    fmea_cmd->add_option("--min-coverage", fmea_min_coverage,
                         "Exit 1 if summary.coveragePct < N (0 disables, default)");
    fmea_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        auto cfg_opt = load_config(dir);
        if (!cfg_opt) { std::exit(3); }
        cfg_opt->project_root = fs::canonical(dir).string();
        auto r = fmea::generate(dir, *cfg_opt, fmea_cyber);
        if (!is_ok(r)) { print_err(error_of(r)); std::exit(1); }
        auto rpt = value_of(r);
        auto content = content_only(fmea::to_json(rpt, *cfg_opt));
        rpt.attestation = preserve_attestation(dir / fmea::FmeaJsonFile);
        auto wr = fmea::write(dir, rpt);
        if (!is_ok(wr)) { print_err(error_of(wr)); std::exit(1); }
        print_ok("fmea.json written (" + std::to_string(rpt.entries.size()) + " entries)");
        print_ok("fmea.csv written");
        std::cout << "Coverage: " << rpt.summary.components_analyzed << "/"
                  << rpt.summary.components_in_project << " components ("
                  << std::fixed << std::setprecision(1) << rpt.summary.coverage_pct << "%)\n";

        bool attested = quality::is_valid_reviewed(rpt.attestation, content);
        auto findings = fmea::scan_quality(rpt);
        bool gate = apply_quality_gate(findings, dir, attested, fmea_require_attestation || fmea_strict);
        if (fmea_min_coverage > 0 && rpt.summary.coverage_pct < fmea_min_coverage) {
            print_err("coveragePct " + fmt_pct(rpt.summary.coverage_pct) +
                      " < --min-coverage " + std::to_string(fmea_min_coverage));
            gate = true;
        }
        if (gate) std::exit(1);
    });

    // ── safety-case ───────────────────────────────────────────────────────────
    auto* sc_cmd = app.add_subcommand("safety-case", "Generate GSN safety case argument");
    bool sc_strict = false, sc_require_attestation = false;
    sc_cmd->add_flag("--strict", sc_strict,
                     "Exit 1 on an unsuppressed FUSA-STUB002 warning too (implies --require-attestation)");
    sc_cmd->add_flag("--require-attestation", sc_require_attestation,
                     "Exit 1 on an unsuppressed FUSA-STUB002 warning (§1.6.2)");
    sc_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        auto cfg_opt = load_config(dir);
        if (!cfg_opt) { std::exit(3); }
        cfg_opt->project_root = fs::canonical(dir).string();
        auto r = safety_case::generate(dir, *cfg_opt);
        if (!is_ok(r)) { print_err(error_of(r)); std::exit(1); }
        auto sc = value_of(r);
        auto content = content_only(safety_case::to_json(sc, *cfg_opt));
        sc.attestation = preserve_attestation(dir / safety_case::SafetyCaseJson);
        auto wr = safety_case::write(dir, sc);
        if (!is_ok(wr)) { print_err(error_of(wr)); std::exit(1); }
        print_ok("safety-case.json written (" + std::to_string(sc.nodes.size()) + " nodes)");
        print_ok("safety-case.mermaid written");
        print_ok("safety-case.md written");
        print_ok("Evidence collected: " + std::to_string(sc.evidence.size()) + " file(s)");

        bool attested = quality::is_valid_reviewed(sc.attestation, content);
        auto findings = safety_case::scan_quality(sc);
        bool gate = apply_quality_gate(findings, dir, attested, sc_require_attestation || sc_strict);
        if (gate) std::exit(1);
    });

    // ── hara ──────────────────────────────────────────────────────────────────
    auto* hara_cmd    = app.add_subcommand("hara", "Hazard Analysis and Risk Assessment (.fusa-hara.json)");
    auto* hara_show   = hara_cmd->add_subcommand("show", "Display HARA");
    auto* hara_init   = hara_cmd->add_subcommand("init", "Create starter .fusa-hara.json");
    auto* hara_asil   = hara_cmd->add_subcommand("asil", "Derive ASIL from S/E/C parameters");
    std::string hara_project, hara_standard = "ISO 26262";
    std::string asil_s, asil_e, asil_c;
    std::string hara_fmt, hara_out;
    bool hara_strict = false, hara_require_attestation = false;
    hara_init->add_option("--project",  hara_project,  "Project name");
    hara_init->add_option("--standard", hara_standard, "Safety standard");
    hara_asil->add_option("-s", asil_s, "Severity: S0, S1, S2, S3")->required();
    hara_asil->add_option("-e", asil_e, "Exposure: E0..E4")->required();
    hara_asil->add_option("-c", asil_c, "Controllability: C0..C3")->required();
    hara_cmd->add_option("--format", hara_fmt, "text|json (§9.2 hara-report; default: text)");
    hara_cmd->add_option("--output", hara_out, "Write output to file instead of stdout");
    hara_cmd->add_flag("--strict", hara_strict,
                       "Exit 1 on an unsuppressed FUSA-STUB002 warning too (implies --require-attestation)");
    hara_cmd->add_flag("--require-attestation", hara_require_attestation,
                       "Exit 1 on an unsuppressed FUSA-STUB002 warning (§1.6.2)");
    hara_show->callback([&]() -> void {
        fs::path dir{dir_str};
        hara::HARA h;
        std::string err;
        if (!hara::load(dir, h, err)) { print_err(err); std::exit(1); }
        hara::render_text(h);
    });
    hara_init->callback([&]() -> void {
        fs::path dir{dir_str};
        std::string project = hara_project.empty() ? dir.filename().string() : hara_project;
        std::string err;
        if (!hara::init(dir, project, hara_standard, err)) { print_err(err); std::exit(1); }
        print_ok("Created " + std::string(hara::HARA_FILE));
        std::cout << "Edit " << hara::HARA_FILE << " to document hazards and safety goals.\n";
    });
    hara_asil->callback([&]() -> void {
        auto s_val = hara::parse_severity(asil_s);
        auto e_val = hara::parse_exposure(asil_e);
        auto c_val = hara::parse_controllability(asil_c);
        std::cout << "S=" << asil_s << "  E=" << asil_e << "  C=" << asil_c
                  << "  →  " << hara::determine_asil(s_val, e_val, c_val) << "\n";
    });
    hara_cmd->callback([&]() -> void {
        if (!hara_cmd->get_subcommands().empty()) return;
        fs::path dir{dir_str};
        hara::HARA h;
        std::string err;
        if (!hara::load(dir, h, err)) { print_err(err); std::exit(1); }

        config::ProjectConfig cfg;
        cfg.project = h.project;
        cfg.standard = h.standard;
        std::error_code canon_ec;
        auto cd = fs::canonical(dir, canon_ec);
        cfg.project_root = canon_ec ? dir.string() : cd.string();

        // §1.4.1/§1.2.5: fssrRefs MUST resolve into .fusa-reqs.json; load the
        // known ids so dangling references surface in `completeness`.
        std::vector<std::string> req_ids;
        auto reqs_r = trace::load_requirements(dir);
        if (is_ok(reqs_r)) for (auto& rq : value_of(reqs_r)) req_ids.push_back(rq.id);

        if (hara_fmt == "json") {
            auto j = hara::to_report_json(h, cfg, req_ids);
            std::string out_str = j.dump(2);
            if (!hara_out.empty()) {
                std::ofstream of(hara_out);
                of << out_str << "\n";
            } else {
                std::cout << out_str << "\n";
            }
        } else {
            hara::render_text(h);
        }

        auto findings = hara::scan_quality(h);
        bool attested = quality::is_valid_reviewed(h.attestation, hara::content_json(h));
        bool gate = apply_quality_gate(findings, dir, attested, hara_require_attestation || hara_strict);
        if (gate) std::exit(1);
    });

    // ── iso26262 ──────────────────────────────────────────────────────────────
    auto* iso_cmd = app.add_subcommand("iso26262", "Generate ISO 26262 Part 6 compliance gap report");
    std::string iso_asil = "ASIL-B", iso_output;
    bool iso_json = false;
    iso_cmd->add_option("--asil",   iso_asil,   "ASIL-A|ASIL-B|ASIL-C|ASIL-D");
    iso_cmd->add_option("--output", iso_output, "Write JSON report to file");
    iso_cmd->add_flag("--json",     iso_json,   "Output JSON (instead of text)");
    iso_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        auto asil_val = iso26262::parse_asil(iso_asil);
        auto rep = iso26262::assess(dir, dir.filename().string(), asil_val);
        if (!iso_output.empty()) {
            iso26262::write_json(iso_output, rep);
            print_ok("ISO 26262 gap report written to " + iso_output +
                     " (" + std::to_string(rep.gap) + " gaps)");
        }
        if (iso_output.empty() || !iso_json) iso26262::render_text(rep);
        if (rep.gap > 0) std::exit(1);
    });

    // ── iec61508 ──────────────────────────────────────────────────────────────
    auto* iec_cmd = app.add_subcommand("iec61508", "Generate IEC 61508 compliance gap report");
    std::string iec_sil = "SIL-2", iec_output;
    bool iec_json = false;
    iec_cmd->add_option("--sil",    iec_sil,    "SIL-1|SIL-2|SIL-3|SIL-4");
    iec_cmd->add_option("--output", iec_output, "Write JSON report to file");
    iec_cmd->add_flag("--json",     iec_json,   "Output JSON (instead of text)");
    iec_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        auto sil_val = iec61508::parse_sil(iec_sil);
        auto rep = iec61508::assess(dir, dir.filename().string(), sil_val);
        if (!iec_output.empty()) {
            iec61508::write_json(iec_output, rep);
            print_ok("IEC 61508 gap report written to " + iec_output +
                     " (" + std::to_string(rep.gap) + " gaps)");
        }
        if (iec_output.empty() || !iec_json) iec61508::render_text(rep);
        if (rep.gap > 0) std::exit(1);
    });

    // ── iso21434 ──────────────────────────────────────────────────────────────
    auto* iso21434_cmd = app.add_subcommand("iso21434",
        "Generate ISO 21434 cybersecurity compliance gap report");
    std::string iso21434_cal = "CAL-2", iso21434_output;
    iso21434_cmd->add_option("--cal",    iso21434_cal,   "CAL-1|CAL-2|CAL-3|CAL-4");
    iso21434_cmd->add_option("--output", iso21434_output, "Write JSON report to file");
    iso21434_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        auto cfg_opt = load_config(dir);
        if (!cfg_opt) { std::exit(3); }
        auto cal = iso21434::parse_cal(iso21434_cal);
        auto rep = iso21434::assess(dir, cfg_opt->project, cal);
        fs::path out = iso21434_output.empty()
                       ? dir / iso21434::ISO21434_REPORT_FILE
                       : fs::path(iso21434_output);
        iso21434::write_json(out, rep);
        iso21434::render_text(rep);
        print_ok("iso21434-gap-report.json written (" + std::to_string(rep.gap) + " gaps)");
        if (rep.gap > 0) std::exit(1);
    });

    // ── unece ─────────────────────────────────────────────────────────────────
    auto* unece_cmd = app.add_subcommand("unece",
        "Generate UNECE R155/R156 cybersecurity compliance gap report");
    std::string unece_reg = "r155", unece_output;
    unece_cmd->add_option("--regulation", unece_reg,    "r155|r156|both (default: r155)");
    unece_cmd->add_option("--output",     unece_output, "Write JSON report to file");
    unece_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        auto cfg_opt = load_config(dir);
        if (!cfg_opt) { std::exit(3); }
        bool do_r155 = (unece_reg != "r156");
        bool do_r156 = (unece_reg == "r156" || unece_reg == "both");
        if (do_r155) {
            auto rep = unece::assess_r155(dir, cfg_opt->project);
            fs::path out = unece_output.empty()
                           ? dir / unece::UNECE_R155_FILE
                           : fs::path(unece_output);
            unece::write_json(out, rep);
            unece::render_text(rep);
            print_ok("unece-r155-gap-report.json written (" +
                     std::to_string(rep.gap) + " gaps)");
            if (rep.gap > 0) std::exit(1);
        }
        if (do_r156) {
            auto rep = unece::assess_r156(dir, cfg_opt->project);
            fs::path out = unece_output.empty()
                           ? dir / unece::UNECE_R156_FILE
                           : fs::path(unece_output);
            unece::write_json(out, rep);
            unece::render_text(rep);
            print_ok("unece-r156-gap-report.json written (" +
                     std::to_string(rep.gap) + " gaps)");
            if (rep.gap > 0) std::exit(1);
        }
    });

    // ── boundary ──────────────────────────────────────────────────────────────
    auto* boundary_cmd = app.add_subcommand("boundary", "Generate component boundary diagram");
    std::string boundary_outdir;
    boundary_cmd->add_option("--output-dir", boundary_outdir, "Output directory (default: project root)");
    boundary_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        fs::path outdir = boundary_outdir.empty() ? dir : fs::path(boundary_outdir);
        auto d = boundary::scan(dir);
        boundary::write_mermaid(outdir / boundary::BOUNDARY_FILE, d);
        boundary::write_dot(outdir / boundary::BOUNDARY_DOT_FILE, d);
        print_ok("boundary.mermaid written");
        print_ok("boundary.dot written");
        std::cout << "Nodes: " << d.nodes.size() << "  Edges: " << d.edges.size() << "\n";
    });

    // ── metrics ───────────────────────────────────────────────────────────────
    auto* metrics_cmd    = app.add_subcommand("metrics", "Track safety metrics over time");
    auto* metrics_record = metrics_cmd->add_subcommand("record", "Collect and append a metrics snapshot");
    auto* metrics_show   = metrics_cmd->add_subcommand("show",   "Display the metrics time series");
    metrics_record->callback([&]() -> void {
        fs::path dir{dir_str};
        auto ts   = metrics::load(dir);
        auto snap = metrics::collect(dir);
        ts = metrics::append(ts, snap);
        metrics::save(dir / metrics::METRICS_FILE, ts);
        std::cout << "Metrics recorded: errors=" << snap.error_count
                  << " warnings=" << snap.warning_count
                  << " reqs=" << snap.total_requirements
                  << " coverage=" << std::fixed << std::setprecision(1) << snap.coverage_pct << "%\n";
        print_ok(".fusa-metrics.json updated (" + std::to_string(ts.snapshots.size()) + " snapshots)");
    });
    metrics_show->callback([&]() -> void {
        fs::path dir{dir_str};
        auto ts = metrics::load(dir);
        metrics::render_text(ts);
    });

    // ── vuln ──────────────────────────────────────────────────────────────────
    auto* vuln_cmd = app.add_subcommand("vuln", "Scan CMake dependencies for known vulnerabilities");
    vuln_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        auto rep = vuln::scan(dir);
        vuln::write_json(dir / vuln::VULN_FILE, rep);
        print_ok("vuln.json written");
        vuln::render_text(rep);
    });

    // ── coverage ──────────────────────────────────────────────────────────────
    auto* cov_cmd = app.add_subcommand("coverage", "Parse LCOV coverage profile and report DO-178C compliance");
    std::string cov_dal = "DAL-B", cov_profile, cov_out, cov_mcdc_file;
    bool        cov_mcdc = false;
    double      cov_mcdc_threshold = 100.0;
    cov_cmd->add_option("--dal",            cov_dal,            "DAL-A|DAL-B|DAL-C|DAL-D");
    cov_cmd->add_option("--profile",        cov_profile,        "LCOV coverage.info file (default: coverage.info)");
    cov_cmd->add_option("--output",         cov_out,            "Write JSON report to file");
    cov_cmd->add_flag  ("--mcdc",           cov_mcdc,           "Enable MC/DC coverage analysis");
    cov_cmd->add_option("--mcdc-file",      cov_mcdc_file,      "Path to LLVM MC/DC JSON export");
    cov_cmd->add_option("--mcdc-threshold", cov_mcdc_threshold, "MC/DC threshold %% (default: 100)");
    cov_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        fs::path profile = cov_profile.empty() ? dir / coverage::COVERAGE_FILE
                                               : fs::path(cov_profile);
        auto dal = coverage::parse_dal(cov_dal);
        try {
            auto rep = coverage::build_from_lcov(profile, dal);
            // MC/DC analysis
            if (cov_mcdc && !cov_mcdc_file.empty()) {
                coverage::apply_mcdc(rep, fs::path(cov_mcdc_file), cov_mcdc_threshold);
            }
            auto json_out = cov_out.empty() ? dir / coverage::COVERAGE_REPORT_FILE
                                            : fs::path(cov_out);
            coverage::write_json(json_out, rep);
            coverage::render_text(rep);
            print_ok("coverage-report.json written");
            bool ok = rep.meets_dal;
            if (rep.mcdc_enabled && !rep.meets_mcdc) ok = false;
            if (!ok) std::exit(1);
        } catch (const std::exception& ex) {
            print_err(std::string(ex.what()));
            std::cerr << "Tip: generate LCOV with: cmake --build build && lcov --capture "
                         "--directory build --output-file coverage.info\n";
            std::exit(1);
        }
    });

    // ── disposition ───────────────────────────────────────────────────────────
    auto* disp_cmd   = app.add_subcommand("disposition", "Manage finding dispositions");
    auto* disp_add   = disp_cmd->add_subcommand("add",  "Add a disposition");
    auto* disp_list  = disp_cmd->add_subcommand("list", "List dispositions");
    auto* disp_show  = disp_cmd->add_subcommand("show", "Show disposition for a rule");
    std::string disp_rule, disp_status = "accepted", disp_by, disp_note, disp_ref;
    disp_add->add_option("--rule",      disp_rule,      "Rule ID")->required();
    disp_add->add_option("--status",    disp_status,    "accepted|deferred|rejected (§1.2.3)");
    disp_add->add_option("--by",        disp_by,        "Reviewer identity")->required();
    disp_add->add_option("--note",      disp_note,      "Rationale / note")->required();
    disp_add->add_option("--ref",       disp_ref,       "Reference (ticket, issue)");
    disp_show->add_option("--rule",     disp_rule,      "Rule ID")->required();
    disp_add->callback([&]() -> void {
        fs::path dir{dir_str};
        auto log = disposition::load(dir);
        auto now = std::chrono::system_clock::now();
        auto t   = std::chrono::system_clock::to_time_t(now);
        std::tm tm_buf{};
#ifdef _WIN32
        gmtime_s(&tm_buf, &t);
#else
        gmtime_r(&t, &tm_buf);
#endif
        char buf[32];
        std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_buf); // §1.2.3: `at` is RFC 3339
        disposition::Entry e;
        e.rule_id = disp_rule;
        e.status  = disposition::parse_status(disp_status);
        e.note    = disp_note;
        e.by      = disp_by;
        e.at      = std::string(buf);
        e.reference = disp_ref;
        log = disposition::add(log, e);
        std::string err;
        if (!disposition::save(dir / disposition::DISPOSITIONS_FILE, log, err)) {
            print_err(err); std::exit(1);
        }
        print_ok("Disposition added: rule=" + disp_rule + " status=" + disp_status);
    });
    disp_list->callback([&]() -> void {
        disposition::render_entries(disposition::load(fs::path(dir_str)));
    });
    disp_show->callback([&]() -> void {
        auto log = disposition::load(fs::path(dir_str));
        disposition::Entry e;
        if (!disposition::find_by_rule(log, disp_rule, e)) {
            print_err("No disposition for rule: " + disp_rule); std::exit(1);
        }
        std::cout << "Rule:      " << e.rule_id << "\n"
                  << "Status:    " << disposition::status_str(e.status) << "\n"
                  << "By:        " << e.by << "\n"
                  << "At:        " << e.at << "\n"
                  << "Note:      " << e.note << "\n";
        if (!e.reference.empty()) std::cout << "Reference: " << e.reference << "\n";
    });

    // ── impact ────────────────────────────────────────────────────────────────
    auto* impact_cmd = app.add_subcommand("impact", "Analyse impact of source changes on requirements");
    std::string impact_from, impact_to, impact_out, impact_fmt = "text";
    impact_cmd->add_option("--from",   impact_from, "From git ref");
    impact_cmd->add_option("--to",     impact_to,   "To git ref");
    impact_cmd->add_option("--output", impact_out,  "Write JSON report to file");
    impact_cmd->add_option("--format", impact_fmt,  "text|json");
    impact_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        auto rep = impact::analyse(dir, impact_from, impact_to);
        if (!impact_out.empty() || impact_fmt == "json") {
            fs::path jout = impact_out.empty() ? dir / "impact-report.json" : fs::path(impact_out);
            impact::render_json(jout, rep);
            if (!impact_out.empty()) print_ok("impact-report.json written");
        }
        if (impact_fmt == "text") impact::render_text(rep);
    });

    // ── do178 ─────────────────────────────────────────────────────────────────
    auto* do178_cmd = app.add_subcommand("do178", "Generate DO-178C objectives gap report");
    std::string do178_dal = "DAL-B", do178_out;
    do178_cmd->add_option("--dal",    do178_dal, "DAL-A|DAL-B|DAL-C|DAL-D");
    do178_cmd->add_option("--output", do178_out, "Write JSON report to file");
    do178_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        auto dal = do178::parse_dal(do178_dal);
        auto rep = do178::assess(dir, dir.filename().string(), dal);
        fs::path out = do178_out.empty() ? dir / do178::DO178_REPORT_FILE : fs::path(do178_out);
        do178::write_json(out, rep);
        do178::render_text(rep);
        print_ok("do178-gap-report.json written (" + std::to_string(rep.gap) + " gaps)");
        if (rep.gap > 0) std::exit(1);
    });

    // ── sas ───────────────────────────────────────────────────────────────────
    auto* sas_cmd = app.add_subcommand("sas", "Generate Software Accomplishment Summary");
    std::string sas_dal = "DAL-B";
    bool sas_strict = false, sas_require_attestation = false;
    sas_cmd->add_option("--dal", sas_dal, "DAL/ASIL/SIL level");
    sas_cmd->add_flag("--strict", sas_strict,
                      "Exit 1 on an unsuppressed FUSA-STUB002 warning too (implies --require-attestation)");
    sas_cmd->add_flag("--require-attestation", sas_require_attestation,
                      "Exit 1 on an unsuppressed FUSA-STUB002 warning (§1.6.2)");
    sas_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        auto cfg_opt = load_config(dir);
        if (!cfg_opt) { std::exit(3); }
        std::error_code canon_ec;
        auto cd = fs::canonical(dir, canon_ec);
        std::string project_root = canon_ec ? dir.string() : cd.string();
        auto s = sas::build(dir, cfg_opt->project, cfg_opt->version, sas_dal);
        auto content = content_only(sas::to_json(s, project_root));
        s.attestation = preserve_attestation(dir / sas::SAS_JSON_FILE);
        sas::write_json(dir / sas::SAS_JSON_FILE, s, project_root);
        sas::write_markdown(dir / sas::SAS_MD_FILE, s);
        print_ok("sas.json written");
        print_ok("sas.md written");
        std::cout << "Evidence: " << s.present << "/" << s.total << " items present\n";

        bool attested = quality::is_valid_reviewed(s.attestation, content);
        auto findings = sas::scan_quality(s);
        bool gate = apply_quality_gate(findings, dir, attested, sas_require_attestation || sas_strict);
        if (gate) std::exit(1);
    });

    // ── sci ───────────────────────────────────────────────────────────────────
    auto* sci_cmd = app.add_subcommand("sci", "Generate Software Configuration Index");
    sci_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        auto cfg_opt = load_config(dir);
        if (!cfg_opt) { std::exit(3); }
        std::error_code canon_ec;
        auto cd = fs::canonical(dir, canon_ec);
        std::string project_root = canon_ec ? dir.string() : cd.string();
        auto s = sci::build(dir, cfg_opt->project, cfg_opt->version);
        sci::write_json(dir / sci::SCI_FILE, s, project_root);
        print_ok("sci.json written (" + std::to_string(s.artifacts.size()) + " artifacts)");
    });

    // ── pr ────────────────────────────────────────────────────────────────────
    auto* pr_cmd  = app.add_subcommand("pr", "Problem Report log management");
    auto* pr_add  = pr_cmd->add_subcommand("add",  "Add a problem report");
    auto* pr_list = pr_cmd->add_subcommand("list", "List problem reports");
    std::string pr_title, pr_desc, pr_sev = "minor", pr_filter;
    pr_add->add_option("--title",       pr_title, "Report title")->required();
    pr_add->add_option("--description", pr_desc,  "Report description");
    pr_add->add_option("--severity",    pr_sev,   "critical|major|minor");
    pr_list->add_option("--status",     pr_filter,"Filter: open|in-progress|closed");
    pr_add->callback([&]() -> void {
        fs::path dir{dir_str};
        auto log = pr::load(dir);
        auto now = std::chrono::system_clock::now();
        auto t   = std::chrono::system_clock::to_time_t(now);
        char buf[32];
        std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&t));
        std::string new_id = "PR-" + std::to_string(log.reports.size() + 1);
        pr::ProblemReport report{
            new_id, pr_title, pr_desc, std::string(buf), "",
            pr::parse_severity(pr_sev), pr::PRStatus::Open, "", ""
        };
        log = pr::add(log, report);
        std::string err;
        if (!pr::save(dir / pr::PR_FILE, log, err)) { print_err(err); std::exit(1); }
        print_ok("Problem report " + new_id + " added");
    });
    pr_list->callback([&]() -> void {
        pr::render(pr::load(fs::path(dir_str)), pr_filter);
    });

    // ── fix ───────────────────────────────────────────────────────────────────
    auto* fix_cmd = app.add_subcommand("fix", "Show fix guidance for a rule ID");
    std::string fix_rule;
    fix_cmd->add_option("rule", fix_rule, "Rule ID (e.g. LINT001)");
    fix_cmd->callback([&]() -> void {
        if (fix_rule.empty()) fix::list_all();
        else                  fix::show(fix_rule);
    });

    // ── version ───────────────────────────────────────────────────────────────
    auto* ver_cmd = app.add_subcommand("version", "Print version and exit");
    std::string ver_fmt;
    ver_cmd->add_option("--format", ver_fmt, "text|json");
    ver_cmd->callback([&]() -> void {
        if (ver_fmt == "json") {
            nlohmann::json j;
            j["tool"]        = "cpp-FuSa";
            j["version"]     = std::string(Version);
            j["specVersion"] = std::string(SpecVersion);
            std::cout << j.dump(2) << "\n";
        } else {
            // §9.1: MUST match ^(\S+) (\d+\.\d+\.\d+)$
            std::cout << "cpp-FuSa " << Version << "\n";
        }
    });

    // ── capabilities ──────────────────────────────────────────────────────────
    // §10 (SHOULD): machine-readable discovery for FuSaOps orchestration
    auto* caps_cmd = app.add_subcommand("capabilities", "Emit machine-readable tool capabilities");
    std::string caps_fmt;
    caps_cmd->add_option("--format", caps_fmt, "json (default)");
    caps_cmd->callback([&]() -> void {
        nlohmann::json j;
        j["schemaVersion"] = std::string(SpecVersion);
        j["kind"]          = "capabilities";
        j["tool"]          = "cpp-FuSa";
        j["toolVersion"]   = std::string(Version);
        j["language"]      = "cpp";
        {
            auto t = std::time(nullptr);
            std::tm tm_buf{};
#ifdef _WIN32
            gmtime_s(&tm_buf, &t);
#else
            gmtime_r(&t, &tm_buf);
#endif
            std::ostringstream ss;
            ss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%SZ");
            j["generatedAt"] = ss.str();
        }
        j["specVersion"] = std::string(SpecVersion);
        j["commands"]    = nlohmann::json::array({"check","lint","analyze","trace","report",
                                                   "init","version","capabilities","cyber","verify",
                                                   "qualify","release","audit-pack","badge","diff",
                                                   "sign","hooks","tara","fmea","safety-case","hara",
                                                   "iso26262","iec61508","iso21434","unece","boundary",
                                                   "metrics","vuln","coverage","disposition","impact",
                                                   "do178","sas","sci","pr","fix","misra","coupling",
                                                   "iec62443","slsa","req","ast"});
        nlohmann::json fmts;
        fmts["check"]   = {"text","json","html","sarif"};
        fmts["report"]  = {"text","json","html","sarif"};
        fmts["trace"]   = {"text","json"};
        fmts["diff"]    = {"text","json"};
        fmts["version"] = {"text","json"};
        fmts["qualify"] = {"text","json"};
        j["formats"]    = fmts;
        j["standards"]  = nlohmann::json::array({"iso26262","iec61508","iso21434","do178c",
                                                   "iec62443","unece-r155","unece-r156","slsa"});
        std::cout << j.dump(2) << "\n";
    });

    // ── misra ─────────────────────────────────────────────────────────────────
    auto* misra_cmd = app.add_subcommand("misra", "Show MISRA C++:2023 → cpfusa rule mapping");
    std::string misra_output;
    bool misra_gaps = false;
    misra_cmd->add_option("--output", misra_output, "Write JSON report to file");
    misra_cmd->add_flag("--gaps",     misra_gaps,   "Show only manually-reviewed rules");
    misra_cmd->callback([&]() -> void {
        auto r = misra::build_report(misra_gaps);
        if (!misra_output.empty()) {
            misra::write_json(misra_output, r);
            print_ok("MISRA report written to " + misra_output);
        }
        misra::render_text(r, misra_gaps);
    });

    // ── coupling ──────────────────────────────────────────────────────────────
    auto* coupling_cmd = app.add_subcommand("coupling", "Analyse data and control coupling (DO-178C §6.4.4.3)");
    std::string coupling_output;
    coupling_cmd->add_option("--output", coupling_output, "Write JSON report to file");
    coupling_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        auto r = coupling::analyse(dir);
        if (!coupling_output.empty()) {
            coupling::write_json(fs::path(coupling_output), r);
            print_ok("coupling-report.json written");
        }
        coupling::render_text(r);
    });

    // ── iec62443 ──────────────────────────────────────────────────────────────
    auto* iec62443_cmd = app.add_subcommand("iec62443", "IEC 62443 Security Level compliance checks");
    std::string iec62443_sl = "SL-1", iec62443_output;
    iec62443_cmd->add_option("--sl",     iec62443_sl,    "SL-1|SL-2|SL-3|SL-4");
    iec62443_cmd->add_option("--output", iec62443_output,"Write JSON report to file");
    iec62443_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        auto sl_val = iec62443::parse_sl(iec62443_sl);
        auto rep = iec62443::assess(dir, dir.filename().string(), sl_val);
        if (!iec62443_output.empty()) {
            iec62443::write_json(fs::path(iec62443_output), rep);
            print_ok("IEC 62443 report written to " + iec62443_output);
        }
        iec62443::render_text(rep);
    });

    // ── slsa ──────────────────────────────────────────────────────────────────
    auto* slsa_cmd = app.add_subcommand("slsa", "SLSA L1/L2/L3 provenance compliance checks");
    std::string slsa_level = "L1", slsa_output;
    slsa_cmd->add_option("--level",  slsa_level,  "L1|L2|L3|L4");
    slsa_cmd->add_option("--output", slsa_output, "Write JSON report to file");
    slsa_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        auto lvl = slsa::parse_level(slsa_level);
        auto rep = slsa::assess(dir, dir.filename().string(), lvl);
        if (!slsa_output.empty()) {
            slsa::write_json(fs::path(slsa_output), rep);
            print_ok("SLSA report written to " + slsa_output);
        }
        slsa::render_text(rep);
    });

    // ── ast ───────────────────────────────────────────────────────────────────
    auto* ast_cmd = app.add_subcommand("ast", "Deep AST-based safety analysis (requires libclang)");
    std::string ast_fmt, ast_out;
    ast_cmd->add_option("--format", ast_fmt, "text|json (default: text)");
    ast_cmd->add_option("--output", ast_out,  "Write output to file");
    ast_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        auto cfg_opt = load_config(dir);
        if (!cfg_opt) { std::exit(3); }
        if (!ast::libclang_available())
            std::cerr << "[WARN] libclang not available — rebuild with LLVM installed for full AST analysis\n";
        auto findings = ast::run(dir, *cfg_opt);
        report::ReportOptions ropts;
        ropts.no_color = no_color_flag;
        if (ast_fmt == "json")  ropts.format = report::Format::JSON;
        if (!ast_out.empty())   ropts.output  = ast_out;
        (void)report::write_report(findings, *cfg_opt, ropts);
        std::exit(report::exit_code(findings, false));
    });

    // ── comp ──────────────────────────────────────────────────────────────────
    auto* comp_cmd = app.add_subcommand("comp", "Cyclomatic complexity analysis (DO-178C)");
    int comp_threshold = comp::THRESHOLD_DAL_B;
    std::string comp_output;
    comp_cmd->add_option("--threshold", comp_threshold, "Max V(G) before violation (default 10)");
    comp_cmd->add_option("--output", comp_output, "Write JSON report to file");
    comp_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        auto cfg_opt = load_config(dir);
        if (!cfg_opt) { std::exit(3); }
        auto r = comp::analyse(dir, cfg_opt->project, comp_threshold);
        if (!comp_output.empty()) {
            comp::write_json(fs::path(comp_output), r);
            print_ok(std::string(comp::COMP_REPORT_FILE) + " written");
        }
        comp::render_text(r);
        if (r.violations > 0) std::exit(1);
    });

    // §2.3: usage errors → exit 2; parse success (including --help/--version) → 0
    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        int ret = app.exit(e);
        if (ret != 0) std::exit(2);
        return ret;
    }
    return 0;
}

} // namespace cpfusa::cli
