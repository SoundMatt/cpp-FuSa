//fusa:test REQ-ANAL001 REQ-ANAL002 REQ-ANAL003 REQ-ANAL004 REQ-ANAL005 REQ-ANAL008 REQ-ANAL009 REQ-ANAL010 REQ-ANAL011 REQ-ANAL012
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
