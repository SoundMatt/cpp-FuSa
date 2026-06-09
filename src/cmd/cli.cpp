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
#include "cpfusa/fusa.hpp"

#include <CLI/CLI.hpp>
#include <filesystem>
#include <iostream>
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

} // anonymous namespace

int run(int argc, char* argv[]) {
    CLI::App app{"cpfusa — C++ Functional Safety Toolkit v" + std::string(Version)};
    app.set_version_flag("--version", std::string(Version));

    std::string dir_str = fs::current_path().string();
    app.add_option("--dir", dir_str, "Project directory (default: cwd)");
    app.fallthrough(true);

    // ── init ──────────────────────────────────────────────────────────────────
    auto* init      = app.add_subcommand("init", "Initialise a .fusa.json project configuration");
    std::string standard = "iso26262", asil = "B";
    init->add_option("--standard", standard, "iso26262|iec61508|iso21434|do178c");
    init->add_option("--asil",     asil,     "A|B|C|D or SIL-1..4 or DAL-A..E");
    init->callback([&] {
        fs::path dir{dir_str};
        if (config::exists(dir)) {
            std::cerr << ".fusa.json already exists. Remove it to re-initialise.\n";
            return;
        }
        auto cfg     = config::defaults(dir);
        cfg.standard = standard;
        cfg.asil     = asil;
        auto r = config::save(dir, cfg);
        if (!is_ok(r)) { print_err(error_of(r)); return; }
        print_ok("Created .fusa.json for project '" + cfg.project + "'");
        std::cout << "  Standard: " << cfg.standard << "  ASIL/SIL: " << cfg.asil << "\n";
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
        if (!cfg_opt) { std::exit(1); }
        auto& cfg = *cfg_opt;
        cfg.strict = strict_flag;
        auto eng      = engine::make_default_engine();
        auto findings = eng.run(dir, cfg);
        report::ReportOptions ropts;
        ropts.strict = strict_flag;
        ropts.output = out;
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
        if (!cfg_opt) { std::exit(1); }
        auto findings = lint::run(dir, *cfg_opt);
        report::ReportOptions ropts; ropts.strict = lint_strict;
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
        if (!cfg_opt) { std::exit(1); }
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
        if (!cfg_opt) { std::exit(1); }
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
    bool show_gaps  = false;
    int  req_cov = 0, sec_tested = 0;
    trace_cmd->add_flag("--gaps",         show_gaps,  "Show only gaps");
    trace_cmd->add_option("--req-coverage", req_cov,  "Fail if annotation coverage < N%");
    trace_cmd->add_option("--sec-tested",  sec_tested, "Fail if test coverage < N%");
    trace_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        auto cfg_opt = load_config(dir);
        if (!cfg_opt) { std::exit(1); }
        trace::TraceOptions topts;
        topts.show_gaps          = show_gaps;
        topts.min_annotation_pct = req_cov;
        topts.min_test_pct       = sec_tested;
        auto r = trace::run(dir, *cfg_opt, topts);
        if (!is_ok(r)) { print_err(error_of(r)); std::exit(1); }
        std::cout << trace::render_matrix(value_of(r), topts);
    });

    // ── req ───────────────────────────────────────────────────────────────────
    auto* req_cmd = app.add_subcommand("req", "Show a specific requirement and its annotations");
    std::string req_id_arg;
    req_cmd->add_option("id", req_id_arg, "Requirement ID (e.g. REQ-001)")->required();
    req_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        auto cfg_opt = load_config(dir);
        if (!cfg_opt) { std::exit(1); }
        auto reqs_r = trace::load_requirements(dir);
        if (!is_ok(reqs_r)) { print_err(error_of(reqs_r)); std::exit(1); }
        const auto& reqs = value_of(reqs_r);
        auto it = std::find_if(reqs.begin(), reqs.end(),
                               [&](const trace::Requirement& r){ return r.id == req_id_arg; });
        if (it == reqs.end()) { print_err("Requirement not found: " + req_id_arg); std::exit(1); }
        auto anns = trace::scan_annotations(dir);
        std::cout << trace::render_req(*it, anns);
    });

    // ── template ──────────────────────────────────────────────────────────────
    auto* tmpl_cmd  = app.add_subcommand("template", "Generate safety document templates");
    std::string tmpl_type = "all";
    tmpl_cmd->add_option("--type", tmpl_type,
                         "all|safety-plan|test-evidence|hara|svp|scmp|sqap");
    tmpl_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        auto cfg_opt = load_config(dir);
        if (!cfg_opt) { std::exit(1); }
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
        if (!cfg_opt) { std::exit(1); }
        auto eng      = engine::make_default_engine();
        auto findings = eng.run(dir, *cfg_opt);
        auto lint_findings = lint::run(dir, *cfg_opt);
        findings.insert(findings.end(), lint_findings.begin(), lint_findings.end());
        report::ReportOptions ropts;
        ropts.output = rpt_out;
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
        if (!cfg_opt) { std::exit(1); }
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
    qualify_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        std::cout << "Running qualification suite for cpfusa v" << Version << "...\n";
        auto cases  = qualify::builtin_cases();
        auto r = qualify::run(cases);
        if (!is_ok(r)) { print_err(error_of(r)); std::exit(1); }
        const auto& rpt = value_of(r);
        auto wr = qualify::save(dir / std::string(qualify::ReportFile), rpt);
        if (!is_ok(wr)) { print_err(error_of(wr)); std::exit(1); }
        std::cout << "Cases: " << rpt.total
                  << "  Passed: " << rpt.passed
                  << "  Failed: " << rpt.failed << "\n"
                  << "Hash: " << rpt.hash << "\n";
        if (rpt.failed > 0) {
            for (const auto& cr : rpt.results)
                if (!cr.passed)
                    std::cerr << "  FAIL " << cr.test_case.name << ": " << cr.error << "\n";
            std::exit(1);
        }
        print_ok("qualify-report.json written");
    });

    // ── release ───────────────────────────────────────────────────────────────
    auto* release_cmd = app.add_subcommand("release", "Generate SBOM, provenance, and artifact manifest");
    bool release_full = false;
    release_cmd->add_flag("--full", release_full, "Also run tara, fmea, safety-case before packaging");
    release_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        auto cfg_opt = load_config(dir);
        if (!cfg_opt) { std::exit(1); }

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
        auto wr = release::write_all(dir, value_of(sbom_r), value_of(prov_r), manifest);
        if (!is_ok(wr)) { print_err(error_of(wr)); std::exit(1); }
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
        if (!cfg_opt) { std::exit(1); }
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
        if (!cfg_opt) { std::exit(1); }
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
    auto* tara_cmd = app.add_subcommand("tara", "Generate TARA per ISO 21434 Chapter 9");
    tara_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        auto cfg_opt = load_config(dir);
        if (!cfg_opt) { std::exit(1); }
        auto r = tara::generate(dir, *cfg_opt);
        if (!is_ok(r)) { print_err(error_of(r)); std::exit(1); }
        auto wr = tara::write(dir, value_of(r));
        if (!is_ok(wr)) { print_err(error_of(wr)); std::exit(1); }
        const auto& rpt = value_of(r);
        print_ok("tara.json written (" + std::to_string(rpt.scenarios.size()) + " scenarios)");
        print_ok("tara.md written");
    });

    // ── fmea ──────────────────────────────────────────────────────────────────
    auto* fmea_cmd = app.add_subcommand("fmea", "Generate dFMEA from class/function declarations");
    fmea_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        auto cfg_opt = load_config(dir);
        if (!cfg_opt) { std::exit(1); }
        auto r = fmea::generate(dir, *cfg_opt);
        if (!is_ok(r)) { print_err(error_of(r)); std::exit(1); }
        auto wr = fmea::write(dir, value_of(r));
        if (!is_ok(wr)) { print_err(error_of(wr)); std::exit(1); }
        const auto& rpt = value_of(r);
        print_ok("fmea.json written (" + std::to_string(rpt.entries.size()) + " entries)");
        print_ok("fmea.csv written");
    });

    // ── safety-case ───────────────────────────────────────────────────────────
    auto* sc_cmd = app.add_subcommand("safety-case", "Generate GSN safety case argument");
    sc_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        auto cfg_opt = load_config(dir);
        if (!cfg_opt) { std::exit(1); }
        auto r = safety_case::generate(dir, *cfg_opt);
        if (!is_ok(r)) { print_err(error_of(r)); std::exit(1); }
        auto wr = safety_case::write(dir, value_of(r));
        if (!is_ok(wr)) { print_err(error_of(wr)); std::exit(1); }
        const auto& sc = value_of(r);
        print_ok("safety-case.json written (" + std::to_string(sc.nodes.size()) + " nodes)");
        print_ok("safety-case.mermaid written");
        print_ok("Evidence collected: " + std::to_string(sc.evidence.size()) + " file(s)");
    });

    CLI11_PARSE(app, argc, argv);
    return 0;
}

} // namespace cpfusa::cli
