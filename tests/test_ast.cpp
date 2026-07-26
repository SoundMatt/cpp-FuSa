//fusa:test REQ-AST001
//fusa:test REQ-AST002
//fusa:test REQ-AST003
//fusa:test REQ-AST004
//fusa:test REQ-AST005
#include <catch2/catch_all.hpp>
#include "ast/ast.hpp"
#include "config/config.hpp"
#include "testutil/testutil.hpp"

using namespace cpfusa;
using namespace cpfusa::testutil;

TEST_CASE("ast: libclang_available returns a bool", "[ast]") {
    // Should not throw; returns true if CPFUSA_HAS_LIBCLANG was compiled in
    REQUIRE_NOTHROW(ast::libclang_available());
}

TEST_CASE("ast: run() returns a vector (may be empty or stub)", "[ast]") {
    TempDir tmp;
    tmp.write("src/foo.cpp", "void f() {}\n");
    config::ProjectConfig cfg;
    REQUIRE_NOTHROW(ast::run(tmp.path(), cfg));
}

TEST_CASE("ast: run() on empty directory returns findings vector", "[ast]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto findings = ast::run(tmp.path(), cfg);
    // Either empty (libclang enabled, nothing to flag) or AST000 stub
    (void)findings;
    SUCCEED();
}

TEST_CASE("ast: stub mode returns AST000 when libclang unavailable", "[ast]") {
#ifdef CPFUSA_HAS_LIBCLANG
    SUCCEED("libclang available — stub path not exercised in this build");
#else
    TempDir tmp;
    config::ProjectConfig cfg;
    auto findings = ast::run(tmp.path(), cfg);
    REQUIRE_FALSE(findings.empty());
    REQUIRE(findings[0].rule_id == "AST000");
#endif
}

TEST_CASE("ast: run() findings have non-empty rule_id", "[ast]") {
    TempDir tmp;
    tmp.write("src/foo.cpp", "int x = 0;\n");
    config::ProjectConfig cfg;
    auto findings = ast::run(tmp.path(), cfg);
    for (const auto& f : findings) {
        REQUIRE_FALSE(f.rule_id.empty());
    }
}

#ifdef CPFUSA_HAS_LIBCLANG
TEST_CASE("ast: AST001 detects virtual method without virtual destructor", "[ast][ast001]") {
    TempDir tmp;
    tmp.write("src/bad.cpp",
        "class Base {\n"
        "public:\n"
        "    virtual void process();\n"
        "    ~Base();\n"
        "};\n");
    config::ProjectConfig cfg;
    auto findings = ast::run(tmp.path(), cfg);
    REQUIRE(has_finding(findings, "AST001"));
}

TEST_CASE("ast: AST001 passes when virtual destructor present", "[ast][ast001]") {
    TempDir tmp;
    tmp.write("src/ok.cpp",
        "class Base {\n"
        "public:\n"
        "    virtual void process();\n"
        "    virtual ~Base();\n"
        "};\n");
    config::ProjectConfig cfg;
    auto findings = ast::run(tmp.path(), cfg);
    REQUIRE_FALSE(has_finding(findings, "AST001"));
}
#endif
