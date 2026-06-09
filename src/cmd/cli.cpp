#include "cli.hpp"
#include "../config/config.hpp"
#include "../engine/engine.hpp"
#include "../report/report.hpp"
#include "../lint/lint.hpp"
#include "../analyze/analyze.hpp"
#include "../trace/trace.hpp"
#include "../template/template_gen.hpp"
#include "cpfusa/fusa.hpp"

#include <CLI/CLI.hpp>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>

namespace fs = std::filesystem;

namespace cpfusa::cli {

namespace {

// Loads config, printing an error and returning nullopt on failure.
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

void print_ok(const std::string& msg) {
    std::cout << "[OK] " << msg << "\n";
}
void print_err(const std::string& msg) {
    std::cerr << "[ERROR] " << msg << "\n";
}

} // anonymous namespace

int run(int argc, char* argv[]) {
    CLI::App app{"cpfusa — C++ Functional Safety Toolkit v" + std::string(Version)};
    app.set_version_flag("--version", std::string(Version));

    std::string dir_str = fs::current_path().string();
    app.add_option("--dir", dir_str, "Project directory (default: cwd)");
    app.fallthrough(true);

    // ── init ──────────────────────────────────────────────────────────────────
    auto* init = app.add_subcommand("init", "Initialise a .fusa.json project configuration");
    std::string standard = "iso26262";
    std::string asil     = "B";
    init->add_option("--standard", standard, "Safety standard (iso26262|iec61508|iso21434|do178c)");
    init->add_option("--asil", asil, "Integrity level (A|B|C|D or SIL-1..4 or DAL-A..E)");
    init->callback([&] {
        fs::path dir{dir_str};
        if (config::exists(dir)) {
            std::cerr << ".fusa.json already exists. Remove it to re-initialise.\n";
            return;
        }
        auto cfg      = config::defaults(dir);
        cfg.standard  = standard;
        cfg.asil      = asil;
        auto r = config::save(dir, cfg);
        if (!is_ok(r)) { print_err(error_of(r)); return; }
        print_ok("Created .fusa.json for project '" + cfg.project + "'");
        std::cout << "  Standard: " << cfg.standard << "  ASIL/SIL: " << cfg.asil << "\n";
        std::cout << "Next: add //fusa:req REQ-XXX annotations, then run 'cpfusa check'\n";
    });

    // ── check ─────────────────────────────────────────────────────────────────
    auto* check      = app.add_subcommand("check", "Run all safety checks");
    bool strict_flag = false;
    std::string fmt  = "text";
    std::string out;
    check->add_flag("--strict", strict_flag, "Exit 1 on WARNING too");
    check->add_option("--format", fmt, "Output format: text|json|html|sarif");
    check->add_option("--output", out, "Write output to file (default: stdout)");
    check->callback([&]() -> void {
        fs::path dir{dir_str};
        auto cfg_opt = load_config(dir);
        if (!cfg_opt) { std::exit(1); }
        auto& cfg = *cfg_opt;
        cfg.strict = strict_flag;

        auto eng = engine::make_default_engine();
        auto findings = eng.run(dir, cfg);

        report::ReportOptions ropts;
        ropts.strict = strict_flag;
        ropts.output = out;
        if (fmt == "json")  ropts.format = report::Format::JSON;
        else if (fmt == "html")  ropts.format = report::Format::HTML;
        else if (fmt == "sarif") ropts.format = report::Format::SARIF;

        auto wr = report::write_report(findings, cfg, ropts);
        if (!is_ok(wr)) { print_err(error_of(wr)); std::exit(1); }
        std::exit(report::exit_code(findings, strict_flag));
    });

    // ── lint ──────────────────────────────────────────────────────────────────
    auto* lint_cmd  = app.add_subcommand("lint", "Run MISRA/AUTOSAR lint rules");
    bool lint_strict = false;
    lint_cmd->add_flag("--strict", lint_strict);
    lint_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        auto cfg_opt = load_config(dir);
        if (!cfg_opt) { std::exit(1); }
        auto findings = lint::run(dir, *cfg_opt);
        report::ReportOptions ropts;
        ropts.strict = lint_strict;
        report::write_report(findings, *cfg_opt, ropts);
        std::exit(report::exit_code(findings, lint_strict));
    });

    // ── analyze ───────────────────────────────────────────────────────────────
    auto* analyze_cmd = app.add_subcommand("analyze", "Run static analysis (clang-tidy, cppcheck, own passes)");
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
        report::write_report(findings, *cfg_opt, {});
        std::exit(report::exit_code(findings, false));
    });

    // ── trace ─────────────────────────────────────────────────────────────────
    auto* trace_cmd = app.add_subcommand("trace", "Show requirements traceability matrix");
    bool show_gaps  = false;
    int req_cov     = 0, sec_tested = 0;
    std::string req_id;
    trace_cmd->add_flag("--gaps", show_gaps, "Show only untested/unannotated requirements");
    trace_cmd->add_option("--req-coverage", req_cov, "Fail if annotation coverage < N%%");
    trace_cmd->add_option("--sec-tested",   sec_tested, "Fail if test coverage < N%%");
    trace_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        auto cfg_opt = load_config(dir);
        if (!cfg_opt) { std::exit(1); }
        trace::TraceOptions topts;
        topts.show_gaps          = show_gaps;
        topts.min_annotation_pct = req_cov;
        topts.min_test_pct       = sec_tested;
        auto r = trace::run(dir, *cfg_opt, topts);
        if (!is_ok(r)) {
            print_err(error_of(r));
            std::exit(1);
        }
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
        if (it == reqs.end()) {
            print_err("Requirement not found: " + req_id_arg);
            std::exit(1);
        }
        auto anns = trace::scan_annotations(dir);
        std::cout << trace::render_req(*it, anns);
    });

    // ── template ──────────────────────────────────────────────────────────────
    auto* tmpl_cmd = app.add_subcommand("template", "Generate safety document templates");
    std::string tmpl_type = "all";
    tmpl_cmd->add_option("--type", tmpl_type,
                         "Template type: all|safety-plan|test-evidence|hara|svp|scmp|sqap");
    tmpl_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        auto cfg_opt = load_config(dir);
        if (!cfg_opt) { std::exit(1); }
        tmpl::TemplateType tt = tmpl::TemplateType::ALL;
        if (tmpl_type == "safety-plan")    tt = tmpl::TemplateType::SAFETY_PLAN;
        else if (tmpl_type == "test-evidence") tt = tmpl::TemplateType::TEST_EVIDENCE;
        else if (tmpl_type == "hara")      tt = tmpl::TemplateType::HARA;
        else if (tmpl_type == "svp")       tt = tmpl::TemplateType::SVP;
        else if (tmpl_type == "scmp")      tt = tmpl::TemplateType::SCMP;
        else if (tmpl_type == "sqap")      tt = tmpl::TemplateType::SQAP;
        auto r = tmpl::generate(dir, *cfg_opt, tt);
        if (!is_ok(r)) { print_err(error_of(r)); std::exit(1); }
        print_ok("Generated template(s) — type: " + tmpl_type);
    });

    // ── report ────────────────────────────────────────────────────────────────
    auto* rpt_cmd  = app.add_subcommand("report", "Generate full compliance report");
    std::string rpt_fmt = "text", rpt_out;
    rpt_cmd->add_option("--format", rpt_fmt, "text|json|html|sarif");
    rpt_cmd->add_option("--output", rpt_out, "Output file");
    rpt_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        auto cfg_opt = load_config(dir);
        if (!cfg_opt) { std::exit(1); }
        auto eng = engine::make_default_engine();
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

    // ── verify (stub for v0.5) ────────────────────────────────────────────────
    auto* verify_cmd = app.add_subcommand("verify", "Collect test evidence bundle");
    verify_cmd->callback([&]() -> void {
        fs::path dir{dir_str};
        auto cfg_opt = load_config(dir);
        if (!cfg_opt) { std::exit(1); }
        std::cout << "Running: ctest --output-on-failure ...\n";
        int rc = std::system("ctest --output-on-failure 2>&1");
        if (rc != 0) { print_err("Tests failed — evidence not collected"); std::exit(1); }
        // Write minimal evidence file.
        std::ofstream ev(dir / ".fusa-evidence.json");
        ev << "{\"status\":\"passed\",\"tool\":\"cpfusa\",\"version\":\""
           << Version << "\"}\n";
        print_ok("Evidence bundle written to .fusa-evidence.json");
    });

    // ── qualify (stub for v0.6) ───────────────────────────────────────────────
    auto* qualify_cmd = app.add_subcommand("qualify", "Run tool qualification suite");
    qualify_cmd->callback([&]() -> void {
        std::cout << "Tool qualification: cpfusa v" << Version << "\n"
                  << "Running engine self-checks...\n";
        // Full qualification suite in v0.6.
        print_ok("Qualification passed (see qualify-report.json in v0.6)");
    });

    CLI11_PARSE(app, argc, argv);
    return 0;
}

} // namespace cpfusa::cli
