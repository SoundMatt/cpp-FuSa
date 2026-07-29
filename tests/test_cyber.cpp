//fusa:test REQ-CYBER001
//fusa:test REQ-CYBER002
//fusa:test REQ-CYBER003
//fusa:test REQ-CYBER004
//fusa:test REQ-CYBER005
//fusa:test REQ-CYBER006
//fusa:test REQ-CYBER007
//fusa:test REQ-CYBER008
//fusa:test REQ-CYBER009
//fusa:test REQ-CYBER010
//fusa:test REQ-CFG006
#include <catch2/catch_all.hpp>
#include "cyber/cyber.hpp"
#include "testutil/testutil.hpp"

using namespace cpfusa;
using namespace cpfusa::testutil;

static bool has_cyber(const std::vector<cyber::CyberFinding>& f, const std::string& rule) {
    for (auto& x : f) if (x.rule_id == rule) return true;
    return false;
}

// ─── CYBER001 – weak crypto hash ─────────────────────────────────────────────

TEST_CASE("cyber: CYBER001 detects MD5 usage", "[cyber][cyber001]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "#include <openssl/md5.h>\nvoid f() { MD5_CTX ctx; }\n");
    config::ProjectConfig cfg;
    auto r = cyber::run(tmp.path(), cfg);
    REQUIRE(has_cyber(r.findings, "CYBER001"));
}

TEST_CASE("cyber: CYBER001 detects SHA1 usage", "[cyber][cyber001]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "void f() { SHA1_Init(&ctx); }\n");
    config::ProjectConfig cfg;
    auto r = cyber::run(tmp.path(), cfg);
    REQUIRE(has_cyber(r.findings, "CYBER001"));
}

// ─── CYBER002 – weak cipher ───────────────────────────────────────────────────

TEST_CASE("cyber: CYBER002 detects DES usage", "[cyber][cyber002]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "void f() { DES_key_schedule ks; }\n");
    config::ProjectConfig cfg;
    auto r = cyber::run(tmp.path(), cfg);
    REQUIRE(has_cyber(r.findings, "CYBER002"));
}

// ─── CYBER003 – insecure random ───────────────────────────────────────────────

TEST_CASE("cyber: CYBER003 detects rand() usage", "[cyber][cyber003]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "#include <cstdlib>\nvoid f() { int x = rand(); }\n");
    config::ProjectConfig cfg;
    auto r = cyber::run(tmp.path(), cfg);
    REQUIRE(has_cyber(r.findings, "CYBER003"));
}

TEST_CASE("cyber: CYBER003 detects srand() usage", "[cyber][cyber003]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "#include <cstdlib>\nvoid f() { srand(42); }\n");
    config::ProjectConfig cfg;
    auto r = cyber::run(tmp.path(), cfg);
    REQUIRE(has_cyber(r.findings, "CYBER003"));
}

// ─── CYBER004 – unsafe reinterpret_cast ──────────────────────────────────────

TEST_CASE("cyber: CYBER004 detects reinterpret_cast", "[cyber][cyber004]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "void f(void* p) { int* x = reinterpret_cast<int*>(p); }\n");
    config::ProjectConfig cfg;
    auto r = cyber::run(tmp.path(), cfg);
    REQUIRE(has_cyber(r.findings, "CYBER004"));
}

// ─── CYBER008 – unbounded input ───────────────────────────────────────────────

TEST_CASE("cyber: CYBER008 detects gets() usage", "[cyber][cyber008]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "#include <cstdio>\nvoid f() { char buf[64]; gets(buf); }\n");
    config::ProjectConfig cfg;
    auto r = cyber::run(tmp.path(), cfg);
    REQUIRE(has_cyber(r.findings, "CYBER008"));
}

// ─── CYBER011 – unsafe string ops ─────────────────────────────────────────────

TEST_CASE("cyber: CYBER011 detects strcpy usage", "[cyber][cyber011]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "#include <cstring>\nvoid f() { char a[8]; strcpy(a, \"hi\"); }\n");
    config::ProjectConfig cfg;
    auto r = cyber::run(tmp.path(), cfg);
    REQUIRE(has_cyber(r.findings, "CYBER011"));
}

// ─── CYBER018 – format string vuln ────────────────────────────────────────────

TEST_CASE("cyber: CYBER018 detects printf(var) format string", "[cyber][cyber018]") {
    TempDir tmp;
    tmp.write("src/bad.cpp", "void f(const char* s) { printf(s); }\n"); // fusa:suppress LINT009
    config::ProjectConfig cfg;
    auto r = cyber::run(tmp.path(), cfg);
    REQUIRE(has_cyber(r.findings, "CYBER018"));
}

// ─── clean project has no findings ────────────────────────────────────────────

TEST_CASE("cyber: clean project produces no cyber findings", "[cyber]") {
    TempDir tmp;
    tmp.write("src/main.cpp", "#include <string>\nint main() { std::string s = \"ok\"; return 0; }\n");
    config::ProjectConfig cfg;
    auto r = cyber::run(tmp.path(), cfg);
    REQUIRE(r.findings.empty());
}

// ─── report fields ────────────────────────────────────────────────────────────

TEST_CASE("cyber: run() sets project and version from config", "[cyber]") {
    TempDir tmp;
    tmp.write("src/main.cpp", "int main() {}\n");
    config::ProjectConfig cfg;
    cfg.project = "TestProject";
    cfg.version = "1.2.3";
    auto r = cyber::run(tmp.path(), cfg);
    REQUIRE(r.project == "TestProject");
    REQUIRE(r.version == "1.2.3");
}

TEST_CASE("cyber: run() sets generated_at timestamp", "[cyber]") {
    TempDir tmp;
    tmp.write("src/main.cpp", "int main() {}\n");
    config::ProjectConfig cfg;
    auto r = cyber::run(tmp.path(), cfg);
    REQUIRE_FALSE(r.generated_at.empty());
}

// §1.2.1 MUST: sourceDirs must be honoured, not just excludePatterns —
// regression test for cyber scanning a stray build directory outside every
// configured source dir.
TEST_CASE("cyber: files outside every configured sourceDirs are never scanned",
          "[cyber][cfg006]") {
    TempDir tmp;
    tmp.write("src/main.cpp", "int main() { std::string s = \"ok\"; return 0; }\n");
    // Outside sourceDirs and not matched by excludePatterns — must still be skipped.
    tmp.write("build-audit/probe.cpp", "int f() { return rand(); }\n");

    config::ProjectConfig cfg;
    cfg.source_dirs      = {"src"};
    cfg.exclude_patterns = {"build/"};
    auto r = cyber::run(tmp.path(), cfg);
    REQUIRE(r.findings.empty());
    REQUIRE(r.total_files == 1);
}
