//fusa:test REQ-LINT001 REQ-LINT002 REQ-LINT003 REQ-LINT004 REQ-LINT005 REQ-LINT006 REQ-LINT007 REQ-LINT008 REQ-LINT009 REQ-LINT010
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
