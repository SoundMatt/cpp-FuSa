//fusa:test REQ-ANAL001 REQ-ANAL002 REQ-ANAL003 REQ-ANAL004 REQ-ANAL005
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
