//fusa:test REQ-AUDIT001 REQ-AUDIT002 REQ-AUDIT003 REQ-AUDIT004
#include <catch2/catch_all.hpp>
#include "auditpack/auditpack.hpp"
#include "testutil/testutil.hpp"

using namespace cpfusa;
using namespace cpfusa::testutil;

// ─── pack ─────────────────────────────────────────────────────────────────────

TEST_CASE("auditpack: pack succeeds for empty project dir", "[auditpack][audit001]") {
    TempDir tmp;
    auto out = tmp.path() / "audit-pack.zip";
    auto r = auditpack::pack(tmp.path(), out);
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
