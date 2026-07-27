//fusa:test REQ-ANAL001
//fusa:test REQ-ANAL002
//fusa:test REQ-ANAL003
//fusa:test REQ-ANAL004
//fusa:test REQ-ANAL005
//fusa:test REQ-ANAL008
//fusa:test REQ-ANAL009
//fusa:test REQ-ANAL010
//fusa:test REQ-ANAL011
//fusa:test REQ-ANAL012
//fusa:test REQ-ANAL013
//fusa:test REQ-ANAL014
//fusa:test REQ-ANAL015
//fusa:test REQ-ANAL016
#include <catch2/catch_all.hpp>
#include "analyze/analyze.hpp"
#include "testutil/testutil.hpp"

using namespace cpfusa;
using namespace cpfusa::testutil;

// ─── ANAL003 – thread-unsafe global ──────────────────────────────────────────

TEST_CASE("analyze: ANAL003 detects unguarded global write", "[analyze][anal003]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "int g_counter = 0;\nvoid inc() { g_counter = 1; }\n");
    auto f = analyze::check_thread_unsafe_global(tmp.path());
    REQUIRE(has_finding(f, "ANAL003"));
}

TEST_CASE("analyze: ANAL003 passes when fusa:shared annotation present", "[analyze][anal003]") {
    TempDir tmp;
    tmp.write("src/ok.cpp", "int g_counter = 0; // fusa:shared\nvoid inc() { g_counter = 1; // fusa:shared\n}\n");
    auto f = analyze::check_thread_unsafe_global(tmp.path());
    REQUIRE(f.empty());
}

TEST_CASE("analyze: ANAL003 passes when lock_guard present", "[analyze][anal003]") {
    TempDir tmp;
    tmp.write("src/ok.cpp",
        "std::mutex m;\nvoid inc() {\n  std::lock_guard<std::mutex> lock(m);\n  g_counter_ = 1;\n}\n");
    auto f = analyze::check_thread_unsafe_global(tmp.path());
    REQUIRE(f.empty());
}

// ─── ANAL004 – raw pointer arithmetic ────────────────────────────────────────

TEST_CASE("analyze: ANAL004 detects raw pointer arithmetic", "[analyze][anal004]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "void f(int* p) { int* q = p + 1; }\n");
    auto f = analyze::check_raw_ptr_arithmetic(tmp.path());
    REQUIRE(has_finding(f, "ANAL004"));
}

TEST_CASE("analyze: ANAL004 passes when fusa:unsafe annotation present", "[analyze][anal004]") {
    TempDir tmp;
    tmp.write("src/ok.cpp", "void f(int* p) { int* q = p + 1; // fusa:unsafe\n}\n");
    auto f = analyze::check_raw_ptr_arithmetic(tmp.path());
    REQUIRE(f.empty());
}

// ─── ANAL005 – unbounded loop ─────────────────────────────────────────────────

TEST_CASE("analyze: ANAL005 detects unbounded while(true) with no exit", "[analyze][anal005]") {
    TempDir tmp;
    tmp.write("src/bad.cpp",
        "void f() {\n  while (true) {\n    int x = 1;\n    int y = 2;\n    int z = 3;\n"
        "    int a = 4;\n    int b = 5;\n    int c = 6;\n    int d = 7;\n    int e = 8;\n"
        "    int f2 = 9;\n    int g = 10;\n    int h = 11;\n    int i = 12;\n    int j = 13;\n"
        "    int k = 14;\n    int l = 15;\n    int m = 16;\n    int n = 17;\n    int o = 18;\n  }\n}\n");
    auto f = analyze::check_unbounded_loop(tmp.path());
    REQUIRE(has_finding(f, "ANAL005"));
}

TEST_CASE("analyze: ANAL005 passes when fusa:bounded annotation present", "[analyze][anal005]") {
    TempDir tmp;
    tmp.write("src/ok.cpp", "void f() { while (true) { // fusa:bounded 1000\n  break;\n} }\n");
    auto f = analyze::check_unbounded_loop(tmp.path());
    REQUIRE(f.empty());
}

TEST_CASE("analyze: ANAL005 passes when loop has break within 20 lines", "[analyze][anal005]") {
    TempDir tmp;
    tmp.write("src/ok.cpp", "void f() {\n  while (true) {\n    if (done) break;\n  }\n}\n");
    auto f = analyze::check_unbounded_loop(tmp.path());
    REQUIRE(f.empty());
}

// ─── ANAL007 – memcpy on class ────────────────────────────────────────────────

TEST_CASE("analyze: ANAL007 detects memcpy usage", "[analyze][anal007]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "#include <cstring>\nvoid f() { char a[4]; char b[4]; memcpy(a, b, 4); }\n");
    auto f = analyze::check_memcpy_on_class(tmp.path());
    REQUIRE(has_finding(f, "ANAL007"));
}

TEST_CASE("analyze: ANAL007 passes when fusa:unsafe annotation present", "[analyze][anal007]") {
    TempDir tmp;
    tmp.write("src/ok.cpp",
        "#include <cstring>\n"
        "void f() { char a[4]; char b[4]; memcpy(a, b, 4); // fusa:unsafe POD only\n}\n");
    auto f = analyze::check_memcpy_on_class(tmp.path());
    REQUIRE(f.empty());
}

// ─── run_own_passes aggregates all passes ─────────────────────────────────────

TEST_CASE("analyze: run_own_passes aggregates all own checks", "[analyze]") {
    TempDir tmp;
    tmp.write("src/bad.cpp",
        "int g_val = 0;\n"
        "void f() { g_val = 1; }\n");
    auto f = analyze::run_own_passes(tmp.path());
    REQUIRE(has_finding(f, "ANAL003"));
}

// ─── ANAL008 – function length ────────────────────────────────────────────────

TEST_CASE("analyze: ANAL008 detects function body over 60 lines", "[analyze][anal008]") {
    TempDir tmp;
    std::string src = "void long_func() {\n";
    for (int i = 0; i < 65; ++i)
        src += "    int x" + std::to_string(i) + " = " + std::to_string(i) + ";\n";
    src += "}\n";
    tmp.write("src/bad.cpp", src);
    auto f = analyze::check_function_length(tmp.path());
    REQUIRE(has_finding(f, "ANAL008"));
}

TEST_CASE("analyze: ANAL008 passes when function is within 60 lines", "[analyze][anal008]") {
    TempDir tmp;
    tmp.write("src/ok.cpp", "void short_func() {\n    int x = 0;\n    int y = 1;\n}\n");
    auto f = analyze::check_function_length(tmp.path());
    REQUIRE(f.empty());
}

// ─── ANAL009 – nesting depth ─────────────────────────────────────────────────

TEST_CASE("analyze: ANAL009 detects nesting depth over 5", "[analyze][anal009]") {
    TempDir tmp;
    tmp.write("src/bad.cpp",
        "void deep(int x) {\n"
        "  if (x>0) {\n"
        "    if (x>1) {\n"
        "      if (x>2) {\n"
        "        if (x>3) {\n"
        "          if (x>4) {\n"
        "            if (x>5) {\n"  // depth 6 inside body — FLAGGED
        "              x=0;\n"
        "            }\n"
        "          }\n"
        "        }\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n");
    auto f = analyze::check_nesting_depth(tmp.path());
    REQUIRE(has_finding(f, "ANAL009"));
}

TEST_CASE("analyze: ANAL009 passes when nesting depth is 5 or less", "[analyze][anal009]") {
    TempDir tmp;
    tmp.write("src/ok.cpp",
        "void moderate(int x) {\n"
        "  if (x>0) {\n"
        "    if (x>1) {\n"
        "      if (x>2) {\n"
        "        if (x>3) {\n"
        "          x = 0;\n"
        "        }\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n");
    auto f = analyze::check_nesting_depth(tmp.path());
    REQUIRE(f.empty());
}

// ─── ANAL010 – parameter count ────────────────────────────────────────────────

TEST_CASE("analyze: ANAL010 detects function with more than 7 parameters", "[analyze][anal010]") {
    TempDir tmp;
    tmp.write("src/bad.cpp",
        "int too_many(int a, int b, int c, int d, int e, int f, int g, int h) {\n"
        "    return a;\n"
        "}\n");
    auto f = analyze::check_parameter_count(tmp.path());
    REQUIRE(has_finding(f, "ANAL010"));
}

TEST_CASE("analyze: ANAL010 passes with 7 or fewer parameters", "[analyze][anal010]") {
    TempDir tmp;
    tmp.write("src/ok.cpp",
        "int fine(int a, int b, int c, int d, int e, int f, int g) {\n"
        "    return a;\n"
        "}\n");
    auto f = analyze::check_parameter_count(tmp.path());
    REQUIRE(f.empty());
}

// ─── ANAL011 – integer truncating cast ───────────────────────────────────────

TEST_CASE("analyze: ANAL011 detects uint8_t narrowing cast", "[analyze][anal011]") {
    TempDir tmp;
    tmp.write("src/bad.cpp",
        "void narrow() {\n"
        "    int x = 300;\n"
        "    auto y = (uint8_t)x;\n"
        "}\n");
    auto f = analyze::check_integer_truncating_cast(tmp.path());
    REQUIRE(has_finding(f, "ANAL011"));
}

TEST_CASE("analyze: ANAL011 detects uint16_t narrowing cast", "[analyze][anal011]") {
    TempDir tmp;
    tmp.write("src/bad.cpp",
        "void narrow16() {\n"
        "    long x = 70000L;\n"
        "    auto y = (uint16_t)x;\n"
        "}\n");
    auto f = analyze::check_integer_truncating_cast(tmp.path());
    REQUIRE(has_finding(f, "ANAL011"));
}

TEST_CASE("analyze: ANAL011 passes when fusa:unsafe annotation present", "[analyze][anal011]") {
    TempDir tmp;
    tmp.write("src/ok.cpp",
        "void narrow_ok() {\n"
        "    int x = 10;\n"
        "    auto y = (uint8_t)x; // fusa:unsafe value always fits 0-10\n"
        "}\n");
    auto f = analyze::check_integer_truncating_cast(tmp.path());
    REQUIRE(f.empty());
}

// ─── ANAL012 – multiple return points ────────────────────────────────────────

TEST_CASE("analyze: ANAL012 detects more than 3 return points", "[analyze][anal012]") {
    TempDir tmp;
    tmp.write("src/bad.cpp",
        "int multi(int x) {\n"
        "    if (x == 1) return 1;\n"
        "    if (x == 2) return 2;\n"
        "    if (x == 3) return 3;\n"
        "    return 4;\n"
        "}\n");
    auto f = analyze::check_multiple_returns(tmp.path());
    REQUIRE(has_finding(f, "ANAL012"));
}

TEST_CASE("analyze: ANAL012 passes with 3 or fewer return points", "[analyze][anal012]") {
    TempDir tmp;
    tmp.write("src/ok.cpp",
        "int few_returns(int x) {\n"
        "    if (x < 0) return -1;\n"
        "    if (x > 0) return 1;\n"
        "    return 0;\n"
        "}\n");
    auto f = analyze::check_multiple_returns(tmp.path());
    REQUIRE(f.empty());
}

// ─── §4 MUST: findings emit project-relative file paths ──────────────────────

TEST_CASE("analyze: own-pass findings emit relative not absolute paths", "[analyze][anal013]") {
    //fusa:test REQ-ANAL013
    TempDir tmp;
    tmp.write("src/bad.cpp", "int g_counter = 0;\nvoid inc() { g_counter = 1; }\n");
    auto f = analyze::check_thread_unsafe_global(tmp.path());
    REQUIRE(has_finding(f, "ANAL003"));
    for (const auto& finding : f) {
        if (finding.rule_id == "ANAL003") {
            // Must not be an absolute path.
            REQUIRE_FALSE(finding.file.empty());
            REQUIRE(finding.file[0] != '/');
#ifdef _WIN32
            REQUIRE((finding.file.size() < 3 || finding.file[1] != ':'));
#endif
            // Must be just the relative portion.
            bool has_rel = (finding.file.find("src/bad.cpp") != std::string::npos ||
                            finding.file.find("src\\bad.cpp") != std::string::npos);
            REQUIRE(has_rel);
        }
    }
}

// ─── run_clang_tidy — tool-not-found path ─────────────────────────────────────

TEST_CASE("analyze: run_clang_tidy returns ANAL000 when tool not installed", "[analyze]") {
    TempDir tmp;
    // Use a non-existent binary name so tool_available returns false.
    auto findings = analyze::run_clang_tidy(tmp.path(), "__cpfusa_no_such_tidy__");
    REQUIRE(has_finding(findings, "ANAL000"));
    REQUIRE(findings[0].severity == Severity::INFO);
}

TEST_CASE("analyze: run_clang_tidy ANAL000 has non-empty remediation", "[analyze]") {
    TempDir tmp;
    auto findings = analyze::run_clang_tidy(tmp.path(), "__cpfusa_no_such_tidy__");
    REQUIRE_FALSE(findings.empty());
    REQUIRE_FALSE(findings[0].remediation.empty());
}

// ─── run_cppcheck — tool-not-found path ──────────────────────────────────────

TEST_CASE("analyze: run_cppcheck returns ANAL000 when tool not installed", "[analyze]") {
    TempDir tmp;
    auto findings = analyze::run_cppcheck(tmp.path(), "__cpfusa_no_such_check__");
    REQUIRE(has_finding(findings, "ANAL000"));
}

TEST_CASE("analyze: run_cppcheck ANAL000 has non-empty remediation", "[analyze]") {
    TempDir tmp;
    auto findings = analyze::run_cppcheck(tmp.path(), "__cpfusa_no_such_check__");
    REQUIRE_FALSE(findings.empty());
    REQUIRE_FALSE(findings[0].remediation.empty());
}

// ─── run() dispatch ──────────────────────────────────────────────────────────

TEST_CASE("analyze: run with all options false returns empty vector", "[analyze]") {
    TempDir tmp;
    tmp.write("src/foo.cpp", "int x = 0;\n");
    config::ProjectConfig cfg;
    analyze::AnalyzeOptions opts;
    opts.run_clang_tidy = false;
    opts.run_cppcheck   = false;
    opts.run_own_passes = false;
    auto findings = analyze::run(tmp.path(), cfg, opts);
    REQUIRE(findings.empty());
}

TEST_CASE("analyze: run with only own passes enabled returns own-pass findings", "[analyze]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "int g_val = 0;\nvoid f() { g_val = 1; }\n");
    config::ProjectConfig cfg;
    analyze::AnalyzeOptions opts;
    opts.run_clang_tidy = false;
    opts.run_cppcheck   = false;
    opts.run_own_passes = true;
    auto findings = analyze::run(tmp.path(), cfg, opts);
    REQUIRE(has_finding(findings, "ANAL003"));
}

TEST_CASE("analyze: run with clang_tidy enabled adds stub finding", "[analyze]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    analyze::AnalyzeOptions opts;
    opts.run_clang_tidy  = true;
    opts.clang_tidy_bin  = "__cpfusa_no_such_tidy__";
    opts.run_cppcheck    = false;
    opts.run_own_passes  = false;
    auto findings = analyze::run(tmp.path(), cfg, opts);
    REQUIRE(has_finding(findings, "ANAL000"));
}

TEST_CASE("analyze: run with cppcheck enabled adds stub finding", "[analyze]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    analyze::AnalyzeOptions opts;
    opts.run_clang_tidy = false;
    opts.run_cppcheck   = true;
    opts.cppcheck_bin   = "__cpfusa_no_such_check__";
    opts.run_own_passes = false;
    auto findings = analyze::run(tmp.path(), cfg, opts);
    REQUIRE(has_finding(findings, "ANAL000"));
}

TEST_CASE("analyze: run_clang_tidy returns ANAL000 when compile_commands.json absent", "[analyze]") {
    // This test only applies when the tool IS installed but db is missing.
    // If the tool is not installed, we still get ANAL000 (tool not found).
    TempDir tmp;
    // Try with "clang-tidy" — if it's not installed we get ANAL000 (tool),
    // if it IS installed we get ANAL000 (no compile_commands.json).
    auto findings = analyze::run_clang_tidy(tmp.path(), "clang-tidy");
    REQUIRE(has_finding(findings, "ANAL000"));
}

// ─── ANAL006 – large stack allocation ────────────────────────────────────────

TEST_CASE("analyze: ANAL006 detects large stack buffer", "[analyze]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "void f() { char buf[8192]; (void)buf; }\n");
    auto f = analyze::check_large_stack_alloc(tmp.path());
    REQUIRE(has_finding(f, "ANAL006"));
}

TEST_CASE("analyze: ANAL006 passes for buffer within limit", "[analyze]") {
    TempDir tmp;
    tmp.write("src/ok.cpp", "void f() { char buf[256]; (void)buf; }\n");
    auto f = analyze::check_large_stack_alloc(tmp.path());
    REQUIRE(f.empty());
}
