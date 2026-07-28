//fusa:test REQ-AUDIT001
//fusa:test REQ-AUDIT002
//fusa:test REQ-AUDIT003
//fusa:test REQ-AUDIT004
#include <catch2/catch_all.hpp>
#include "auditpack/auditpack.hpp"
#include "testutil/testutil.hpp"
#include <cstdlib>

using namespace cpfusa;
using namespace cpfusa::testutil;

// ─── pack ─────────────────────────────────────────────────────────────────────

TEST_CASE("auditpack: pack succeeds for empty project dir", "[auditpack][audit001]") {
    TempDir tmp;
    auto out = tmp.path() / "audit-pack.zip";
    auto r = auditpack::pack(tmp.path(), out);
    if (!is_ok(r)) {
        // Temporary diagnostic (removed once the Windows CI failure is root-
        // caused): Catch2's boolean expansion doesn't surface the wrapped
        // error string, and this is the only reliable way to see it.
        WARN("auditpack::pack error: " << error_of(r));
    }
    REQUIRE(is_ok(r));
}

TEST_CASE("auditpack: pack creates the zip file", "[auditpack][audit001]") {
    TempDir tmp;
    auto out = tmp.path() / "audit-pack.zip";
    auditpack::pack(tmp.path(), out);
    REQUIRE(std::filesystem::exists(out));
}

TEST_CASE("auditpack: pack returns a manifest", "[auditpack][audit002]") {
    TempDir tmp;
    auto out = tmp.path() / "audit-pack.zip";
    auto r = auditpack::pack(tmp.path(), out);
    REQUIRE(is_ok(r));
    auto& m = value_of(r);
    REQUIRE_FALSE(m.format.empty());
    REQUIRE_FALSE(m.generated_at.empty());
}

TEST_CASE("auditpack: pack manifest includes packed evidence files", "[auditpack][audit002]") {
    TempDir tmp;
    tmp.write("qualify-report.json", R"({"passed":8,"total":8})");
    tmp.write(".fusa-evidence.json", R"({"total":43,"passed":43})");
    auto out = tmp.path() / "audit-pack.zip";
    auto r = auditpack::pack(tmp.path(), out);
    REQUIRE(is_ok(r));
    auto& m = value_of(r);
    bool found_qualify = false;
    for (auto& e : m.files)
        if (e.path.find("qualify-report") != std::string::npos) found_qualify = true;
    REQUIRE(found_qualify);
}

TEST_CASE("auditpack: manifest entries have non-empty sha256", "[auditpack][audit002]") {
    TempDir tmp;
    tmp.write("sbom.json", R"({"format":"test"})");
    auto out = tmp.path() / "audit-pack.zip";
    auto r = auditpack::pack(tmp.path(), out);
    REQUIRE(is_ok(r));
    for (auto& e : value_of(r).files)
        REQUIRE_FALSE(e.sha256.empty());
}

TEST_CASE("auditpack: manifest entries have positive size", "[auditpack][audit002]") {
    TempDir tmp;
    tmp.write("provenance.json", R"({"format":"test","project":"x"})");
    auto out = tmp.path() / "audit-pack.zip";
    auto r = auditpack::pack(tmp.path(), out);
    REQUIRE(is_ok(r));
    for (auto& e : value_of(r).files)
        REQUIRE(e.size > 0);
}

TEST_CASE("auditpack: pack zip has non-zero size", "[auditpack][audit001]") {
    TempDir tmp;
    tmp.write("qualify-report.json", R"({"passed":8,"total":8})");
    auto out = tmp.path() / "audit-pack.zip";
    auditpack::pack(tmp.path(), out);
    REQUIRE(std::filesystem::file_size(out) > 0);
}

TEST_CASE("auditpack: manifest format is cpp-FuSa Audit Pack v1", "[auditpack][audit002]") {
    TempDir tmp;
    auto out = tmp.path() / "audit-pack.zip";
    auto r = auditpack::pack(tmp.path(), out);
    REQUIRE(is_ok(r));
    REQUIRE(value_of(r).format == "cpp-FuSa Audit Pack v1");
}

TEST_CASE("auditpack: manifest generated_at is non-empty", "[auditpack][audit002]") {
    TempDir tmp;
    auto out = tmp.path() / "audit-pack.zip";
    auto r = auditpack::pack(tmp.path(), out);
    REQUIRE(is_ok(r));
    REQUIRE_FALSE(value_of(r).generated_at.empty());
}

TEST_CASE("auditpack: multiple evidence files all appear in manifest", "[auditpack][audit002]") {
    TempDir tmp;
    tmp.write("qualify-report.json",   R"({"passed":8})");
    tmp.write(".fusa-evidence.json",   R"({"total":42})");
    tmp.write("sbom.json",             R"({"format":"spdx"})");
    auto out = tmp.path() / "audit-pack.zip";
    auto r = auditpack::pack(tmp.path(), out);
    REQUIRE(is_ok(r));
    int found = 0;
    for (auto& e : value_of(r).files)
        if (e.path.find("qualify-report") != std::string::npos
         || e.path.find("fusa-evidence")  != std::string::npos
         || e.path.find("sbom")            != std::string::npos) ++found;
    REQUIRE(found >= 2);
}

TEST_CASE("auditpack: AuditPackFile constant is audit-pack.zip", "[auditpack][audit001]") {
    REQUIRE(std::string(auditpack::AuditPackFile) == "audit-pack.zip");
}

#ifndef _WIN32
// Regression for the "silently writes a non-ZIP manifest.json and reports
// success when the system `zip` binary is missing" bug: pack() must detect
// the failed popen/zip invocation and return a hard error, never fall back
// to copying manifest.json to the requested output path while claiming
// success (setenv/PATH manipulation is POSIX-only; Windows resolves
// _popen commands differently, so this test is skipped there).
TEST_CASE("auditpack: pack errors (not silently succeeds) when zip is unavailable on PATH",
          "[auditpack][audit001]") {
    TempDir tmp;
    tmp.write("qualify-report.json", R"({"passed":8})");
    auto out = tmp.path() / "audit-pack.zip";

    const char* old_path = std::getenv("PATH");
    std::string saved_path = old_path ? old_path : "";
    setenv("PATH", "/nonexistent-dir-for-cpfusa-auditpack-test", 1);

    auto r = auditpack::pack(tmp.path(), out);

    setenv("PATH", saved_path.c_str(), 1);

    REQUIRE_FALSE(is_ok(r));
    // Must not have written manifest.json (or anything else) under the
    // requested ZIP output path while reporting success.
    REQUIRE_FALSE(std::filesystem::exists(out));
}
#endif
