//fusa:test REQ-COMP001
#include <catch2/catch_all.hpp>
#include "comp/comp.hpp"
#include "testutil/testutil.hpp"
#include <nlohmann/json.hpp>
#include <fstream>

using namespace cpfusa::comp;
using namespace cpfusa::testutil;

TEST_CASE("comp: empty dir produces zero functions", "[comp]") {
    TempDir tmp;
    auto r = analyse(tmp.path(), "test");
    REQUIRE(r.total_functions == 0);
    REQUIRE(r.violations == 0);
}

TEST_CASE("comp: simple function has complexity 1", "[comp]") {
    TempDir tmp;
    tmp.write("simple.cpp", "int foo() {\n  return 42;\n}\n");
    auto r = analyse(tmp.path(), "test");
    REQUIRE(r.total_functions >= 1);
    bool found = false;
    for (const auto& fn : r.results)
        if (fn.name == "foo" && fn.complexity == 1) found = true;
    REQUIRE(found);
}

TEST_CASE("comp: if branch increases complexity", "[comp]") {
    TempDir tmp;
    tmp.write("branch.cpp",
        "int bar(int x) {\n"
        "  if (x > 0) return 1;\n"
        "  return 0;\n"
        "}\n");
    auto r = analyse(tmp.path(), "test");
    bool found = false;
    for (const auto& fn : r.results)
        if (fn.name == "bar" && fn.complexity >= 2) found = true;
    REQUIRE(found);
}

TEST_CASE("comp: threshold violation is flagged", "[comp]") {
    TempDir tmp;
    // Build a function with many branches (> 10)
    std::string src = "int complex_func(int x) {\n";
    for (int i = 0; i < 12; ++i)
        src += "  if (x == " + std::to_string(i) + ") return " + std::to_string(i) + ";\n";
    src += "  return -1;\n}\n";
    tmp.write("complex.cpp", src);
    auto r = analyse(tmp.path(), "test", 10);
    REQUIRE(r.violations >= 1);
}

TEST_CASE("comp: write_json creates comp-report.json", "[comp]") {
    TempDir tmp;
    auto r = analyse(tmp.path(), "test");
    auto out = tmp.path() / COMP_REPORT_FILE;
    REQUIRE_NOTHROW(write_json(out, r));
    REQUIRE(std::filesystem::exists(out));
}

TEST_CASE("comp: JSON report has required fields", "[comp]") {
    TempDir tmp;
    auto r = analyse(tmp.path(), "test");
    auto out = tmp.path() / COMP_REPORT_FILE;
    write_json(out, r);
    std::ifstream f(out);
    nlohmann::json j;
    f >> j;
    REQUIRE(j.contains("violations"));
    REQUIRE(j.contains("threshold"));
    REQUIRE(j.contains("totalFunctions"));
    REQUIRE(j.contains("generatedAt"));
}

TEST_CASE("comp: threshold constants are sensible", "[comp]") {
    REQUIRE(THRESHOLD_DAL_A < THRESHOLD_DAL_B);
    REQUIRE(THRESHOLD_DAL_B < THRESHOLD_DAL_C);
    REQUIRE(THRESHOLD_DAL_C < THRESHOLD_DAL_D);
}

TEST_CASE("comp: violations count matches results", "[comp]") {
    TempDir tmp;
    std::string src = "int big_fn(int x) {\n";
    for (int i = 0; i < 15; ++i)
        src += "  if (x == " + std::to_string(i) + ") return " + std::to_string(i) + ";\n";
    src += "  return -1;\n}\n";
    tmp.write("big.cpp", src);
    auto r = analyse(tmp.path(), "test", 5);
    int counted = 0;
    for (const auto& fn : r.results)
        if (fn.exceeds_threshold) ++counted;
    REQUIRE(counted == r.violations);
}
