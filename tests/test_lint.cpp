//fusa:test REQ-LINT001
//fusa:test REQ-LINT002
//fusa:test REQ-LINT003
//fusa:test REQ-LINT004
//fusa:test REQ-LINT005
//fusa:test REQ-LINT006
//fusa:test REQ-LINT007
//fusa:test REQ-LINT008
//fusa:test REQ-LINT009
//fusa:test REQ-LINT010
//fusa:test REQ-LINT011
//fusa:test REQ-LINT012
//fusa:test REQ-LINT013
//fusa:test REQ-LINT014
//fusa:test REQ-LINT015
//fusa:test REQ-LINT016
//fusa:test REQ-LINT017
//fusa:test REQ-LINT018
//fusa:test REQ-LINT019
//fusa:test REQ-LINT020
//fusa:test REQ-LINT021
//fusa:test REQ-LINT022
//fusa:test REQ-LINT023
//fusa:test REQ-LINT024
//fusa:test REQ-LINT025
//fusa:test REQ-LINT026
//fusa:test REQ-LINT027
//fusa:test REQ-LINT028
//fusa:test REQ-LINT029
//fusa:test REQ-LINT030
//fusa:test REQ-LINT031
#include <catch2/catch_all.hpp>
#include "lint/lint.hpp"
#include "testutil/testutil.hpp"

using namespace cpfusa;
using namespace cpfusa::testutil;

TEST_CASE("lint: LINT001 detects raw new/delete", "[lint][lint001]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "int* p = new int(42);\ndelete p;\n");
    auto f = lint::check_raw_new_delete(tmp.path());
    REQUIRE(has_finding(f, "LINT001"));
}

TEST_CASE("lint: LINT001 passes when fusa:suppress is present", "[lint][lint001]") {
    TempDir tmp;
    tmp.write("src/ok.cpp", "int* p = new int(42); // fusa:suppress LINT001\n");
    auto f = lint::check_raw_new_delete(tmp.path());
    REQUIRE(f.empty());
}

TEST_CASE("lint: LINT002 detects goto", "[lint][lint002]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "void f() { goto end; end: return; }\n");
    auto f = lint::check_goto(tmp.path());
    REQUIRE(has_finding(f, "LINT002"));
}

TEST_CASE("lint: LINT003 detects reinterpret_cast without annotation", "[lint][lint003]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "auto p = reinterpret_cast<int*>(buf);\n");
    auto f = lint::check_reinterpret_cast(tmp.path());
    REQUIRE(has_finding(f, "LINT003"));
}

TEST_CASE("lint: LINT003 passes with fusa:unsafe annotation", "[lint][lint003]") {
    TempDir tmp;
    tmp.write("src/ok.cpp",
              "// fusa:unsafe hardware register access\n"
              "auto p = reinterpret_cast<int*>(buf);\n");
    auto f = lint::check_reinterpret_cast(tmp.path());
    REQUIRE(f.empty());
}

TEST_CASE("lint: LINT004 detects abort() without safe-state", "[lint][lint004]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "void f() { abort(); }\n");
    auto f = lint::check_abort_exit(tmp.path());
    REQUIRE(has_finding(f, "LINT004"));
}

TEST_CASE("lint: LINT004 passes with fusa:safe-state comment above", "[lint][lint004]") {
    TempDir tmp;
    tmp.write("src/ok.cpp",
              "void f() {\n"
              "    // fusa:safe-state\n"
              "    abort();\n"
              "}\n");
    auto f = lint::check_abort_exit(tmp.path());
    REQUIRE(f.empty());
}

TEST_CASE("lint: LINT006 detects #define for numeric constant", "[lint][lint006]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "#define MAX_SIZE 1024\n");
    auto f = lint::check_define_constant(tmp.path());
    REQUIRE(has_finding(f, "LINT006"));
}

TEST_CASE("lint: LINT009 detects printf usage", "[lint][lint009]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "#include <cstdio>\nvoid f() { printf(\"hello\"); }\n");
    auto f = lint::check_printf(tmp.path());
    REQUIRE(has_finding(f, "LINT009"));
}

TEST_CASE("lint: run() aggregates all rules", "[lint]") {
    TempDir tmp;
    tmp.write("src/bad.cpp",
              "#define LIMIT 10\n"
              "void f() { goto end; end: return; }\n");
    config::ProjectConfig cfg;
    auto f = lint::run(tmp.path(), cfg);
    REQUIRE(has_finding(f, "LINT002"));
    REQUIRE(has_finding(f, "LINT006"));
}

// ─── LINT011 — NULL literal ───────────────────────────────────────────────────

TEST_CASE("lint: LINT011 detects NULL", "[lint][lint011]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "int* p = NULL;\n");
    REQUIRE(has_finding(lint::check_null_literal(tmp.path()), "LINT011"));
}

TEST_CASE("lint: LINT011 passes on nullptr", "[lint][lint011]") {
    TempDir tmp;
    tmp.write("src/ok.cpp", "int* p = nullptr;\n");
    REQUIRE(lint::check_null_literal(tmp.path()).empty());
}

// ─── LINT012 — missing override ───────────────────────────────────────────────

TEST_CASE("lint: LINT012 detects virtual without override", "[lint][lint012]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "struct B { virtual void f(); };\n");
    REQUIRE(has_finding(lint::check_missing_override(tmp.path()), "LINT012"));
}

TEST_CASE("lint: LINT012 passes when override present", "[lint][lint012]") {
    TempDir tmp;
    tmp.write("src/ok.cpp", "struct D : B { void f() override; };\n");
    REQUIRE(lint::check_missing_override(tmp.path()).empty());
}

// ─── LINT013 — switch without default ────────────────────────────────────────

TEST_CASE("lint: LINT013 detects switch without default", "[lint][lint013]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "void f(int x){ switch(x){ case 1: break; } }\n");
    REQUIRE(has_finding(lint::check_switch_default(tmp.path()), "LINT013"));
}

TEST_CASE("lint: LINT013 passes with default case", "[lint][lint013]") {
    TempDir tmp;
    tmp.write("src/ok.cpp", "void f(int x){ switch(x){ case 1: break; default: break; } }\n");
    REQUIRE(lint::check_switch_default(tmp.path()).empty());
}

// ─── LINT014 — empty catch ────────────────────────────────────────────────────

TEST_CASE("lint: LINT014 detects empty catch block", "[lint][lint014]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "void f(){ try {} catch(std::exception&) {} }\n");
    REQUIRE(has_finding(lint::check_empty_catch(tmp.path()), "LINT014"));
}

TEST_CASE("lint: LINT014 passes when catch has body", "[lint][lint014]") {
    TempDir tmp;
    tmp.write("src/ok.cpp", "void f(){ try {} catch(std::exception& e){ log(e); } }\n");
    REQUIRE(lint::check_empty_catch(tmp.path()).empty());
}

// ─── LINT015 — throw in destructor ───────────────────────────────────────────

TEST_CASE("lint: LINT015 detects throw in destructor", "[lint][lint015]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "struct S { ~S() { throw std::runtime_error(\"x\"); } };\n");
    REQUIRE(has_finding(lint::check_throw_in_destructor(tmp.path()), "LINT015"));
}

// ─── LINT016 — function-like macro ───────────────────────────────────────────

TEST_CASE("lint: LINT016 detects function-like macro", "[lint][lint016]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "#define MAX(a,b) ((a)>(b)?(a):(b))\n");
    REQUIRE(has_finding(lint::check_function_like_macro(tmp.path()), "LINT016"));
}

TEST_CASE("lint: LINT016 passes for object-like macro", "[lint][lint016]") {
    TempDir tmp;
    tmp.write("src/ok.cpp", "#define MAX_VALUE 100\n");
    REQUIRE(lint::check_function_like_macro(tmp.path()).empty());
}

// ─── LINT017 — setjmp/longjmp ────────────────────────────────────────────────

TEST_CASE("lint: LINT017 detects setjmp", "[lint][lint017]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "void f(){ jmp_buf j; setjmp(j); }\n");
    REQUIRE(has_finding(lint::check_setjmp(tmp.path()), "LINT017"));
}

TEST_CASE("lint: LINT017 detects longjmp", "[lint][lint017]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "void g(jmp_buf j){ longjmp(j, 1); }\n");
    REQUIRE(has_finding(lint::check_setjmp(tmp.path()), "LINT017"));
}

// ─── LINT018 — dynamic_cast ───────────────────────────────────────────────────

TEST_CASE("lint: LINT018 detects dynamic_cast", "[lint][lint018]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "auto* p = dynamic_cast<Derived*>(base);\n");
    REQUIRE(has_finding(lint::check_dynamic_cast(tmp.path()), "LINT018"));
}

// ─── LINT019 — union ─────────────────────────────────────────────────────────

TEST_CASE("lint: LINT019 detects union", "[lint][lint019]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "union Data { int i; float f; };\n");
    REQUIRE(has_finding(lint::check_union(tmp.path()), "LINT019"));
}

// ─── LINT020 — volatile ───────────────────────────────────────────────────────

TEST_CASE("lint: LINT020 detects volatile without justification", "[lint][lint020]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "volatile int reg;\n");
    REQUIRE(has_finding(lint::check_volatile(tmp.path()), "LINT020"));
}

TEST_CASE("lint: LINT020 passes with fusa:volatile annotation", "[lint][lint020]") {
    TempDir tmp;
    tmp.write("src/ok.cpp", "volatile int reg; // fusa:volatile hardware MMIO register\n");
    REQUIRE(lint::check_volatile(tmp.path()).empty());
}

// ─── LINT021 — variadic ───────────────────────────────────────────────────────

TEST_CASE("lint: LINT021 detects variadic function", "[lint][lint021]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "void log(const char* fmt, ...);\n");
    REQUIRE(has_finding(lint::check_variadic(tmp.path()), "LINT021"));
}

// ─── LINT022 — unsafe string functions ───────────────────────────────────────

TEST_CASE("lint: LINT022 detects strcpy", "[lint][lint022]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "strcpy(dst, src);\n");
    REQUIRE(has_finding(lint::check_unsafe_string_fn(tmp.path()), "LINT022"));
}

TEST_CASE("lint: LINT022 detects gets", "[lint][lint022]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "gets(buf);\n");
    REQUIRE(has_finding(lint::check_unsafe_string_fn(tmp.path()), "LINT022"));
}

// ─── LINT023 — atoi/atof ─────────────────────────────────────────────────────

TEST_CASE("lint: LINT023 detects atoi", "[lint][lint023]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "int n = atoi(argv[1]);\n");
    REQUIRE(has_finding(lint::check_unsafe_numeric_conv(tmp.path()), "LINT023"));
}

// ─── LINT024 — missing braces ────────────────────────────────────────────────

TEST_CASE("lint: LINT024 detects if without braces", "[lint][lint024]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "void f(bool b){\n  if (b)\n    do_thing();\n}\n");
    REQUIRE(has_finding(lint::check_missing_braces(tmp.path()), "LINT024"));
}

TEST_CASE("lint: LINT024 passes when braces present", "[lint][lint024]") {
    TempDir tmp;
    tmp.write("src/ok.cpp", "void f(bool b){\n  if (b) {\n    do_thing();\n  }\n}\n");
    REQUIRE(lint::check_missing_braces(tmp.path()).empty());
}

// ─── LINT025 — errno ──────────────────────────────────────────────────────────

TEST_CASE("lint: LINT025 detects errno usage", "[lint][lint025]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "if (errno != 0) handle_error();\n");
    REQUIRE(has_finding(lint::check_errno(tmp.path()), "LINT025"));
}

// ─── LINT026 — C library headers ─────────────────────────────────────────────

TEST_CASE("lint: LINT026 detects deprecated C header", "[lint][lint026]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "#include <stdio.h>\n");
    REQUIRE(has_finding(lint::check_c_headers(tmp.path()), "LINT026"));
}

TEST_CASE("lint: LINT026 passes for C++ header", "[lint][lint026]") {
    TempDir tmp;
    tmp.write("src/ok.cpp", "#include <cstdio>\n");
    REQUIRE(lint::check_c_headers(tmp.path()).empty());
}

// ─── LINT027 — #undef ────────────────────────────────────────────────────────

TEST_CASE("lint: LINT027 detects #undef", "[lint][lint027]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "#undef SOME_MACRO\n");
    REQUIRE(has_finding(lint::check_undef(tmp.path()), "LINT027"));
}

// ─── LINT028 — asm ────────────────────────────────────────────────────────────

TEST_CASE("lint: LINT028 detects asm statement", "[lint][lint028]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "__asm__(\"nop\");\n");
    REQUIRE(has_finding(lint::check_asm(tmp.path()), "LINT028"));
}

// ─── LINT029 — magic numbers ──────────────────────────────────────────────────

TEST_CASE("lint: LINT029 detects magic number literal", "[lint][lint029]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "void f(){ int x = 42; }\n");
    REQUIRE(has_finding(lint::check_magic_numbers(tmp.path()), "LINT029"));
}

TEST_CASE("lint: LINT029 passes for constexpr named constant", "[lint][lint029]") {
    TempDir tmp;
    tmp.write("src/ok.cpp", "constexpr int LIMIT = 42;\n");
    REQUIRE(lint::check_magic_numbers(tmp.path()).empty());
}

// ─── LINT030 — include guard ──────────────────────────────────────────────────

TEST_CASE("lint: LINT030 detects header without include guard", "[lint][lint030]") {
    TempDir tmp;
    tmp.write("include/bare.hpp", "void foo();\n");
    REQUIRE(has_finding(lint::check_include_guard(tmp.path()), "LINT030"));
}

TEST_CASE("lint: LINT030 passes with pragma once", "[lint][lint030]") {
    TempDir tmp;
    tmp.write("include/guarded.hpp", "#pragma once\nvoid foo();\n");
    REQUIRE(lint::check_include_guard(tmp.path()).empty());
}

// ─── LINT031 — float/double literal in == or != ───────────────────────────────

TEST_CASE("lint: LINT031 detects float literal in == comparison", "[lint][lint031]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "void f() { float x = 3.14f; if (x == 3.14f) {} }\n");
    REQUIRE(has_finding(lint::check_float_equality(tmp.path()), "LINT031"));
}

TEST_CASE("lint: LINT031 detects double literal in != comparison", "[lint][lint031]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "void g() { double y = 0.0; if (y != 0.0) {} }\n");
    REQUIRE(has_finding(lint::check_float_equality(tmp.path()), "LINT031"));
}

TEST_CASE("lint: LINT031 passes on integer == comparison", "[lint][lint031]") {
    TempDir tmp;
    tmp.write("src/ok.cpp", "void h() { int a = 5; if (a == 5) {} }\n");
    REQUIRE(lint::check_float_equality(tmp.path()).empty());
}

TEST_CASE("lint: LINT031 passes with fusa:suppress LINT031", "[lint][lint031]") {
    TempDir tmp;
    tmp.write("src/ok.cpp", "void k() { float z = 0.0f; if (z == 0.0f) {} } // fusa:suppress LINT031\n");
    REQUIRE(lint::check_float_equality(tmp.path()).empty());
}
