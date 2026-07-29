//fusa:test REQ-AUDIT001
//fusa:test REQ-AUDIT002
//fusa:test REQ-AUDIT003
//fusa:test REQ-AUDIT004
#include <catch2/catch_all.hpp>
#include "auditpack/auditpack.hpp"
#include "testutil/testutil.hpp"
#include <array>
#include <cstdio>
#include <cstdlib>
#ifdef _WIN32
#  define popen  _popen
#  define pclose _pclose
#endif

using namespace cpfusa;
using namespace cpfusa::testutil;

namespace {
// zip's own "-sf" (show files) option lists archive contents without a
// separate `unzip` dependency — `zip` is already a hard prerequisite for
// every pack() call in these tests.
std::string zip_list(const std::filesystem::path& archive) {
    std::string out;
    std::array<char, 256> buf{};
    std::string cmd = "zip -sf \"" + archive.string() + "\" 2>&1";
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return out;
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe)) out += buf.data();
    pclose(pipe);
    return out;
}
} // namespace

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

// Regression: pack() zips evidence files via `cd "<project_root>" && zip ...`
// then separately adds manifest.json via `cd "<system temp dir>" && zip ...`
// — two DIFFERENT `cd` targets. A still-relative `output_path` embedded
// verbatim in both commands resolves against whichever directory the shell
// most recently `cd`-ed into, so the manifest silently lands in a stray zip
// under the temp dir instead of the real archive, while pack() still
// reports success (the first zip, without the manifest, really did land at
// the right path). This is exactly the shape of the CLI's own default
// invocation (`cpfusa audit-pack --dir .` → a relative `./audit-pack.zip`).
TEST_CASE("auditpack: pack with a relative output path still adds manifest.json "
          "to the real archive (not a stray copy elsewhere)",
          "[auditpack][audit001]") {
    TempDir tmp;
    tmp.write("qualify-report.json", R"({"passed":8})");

    std::filesystem::path rel_out = "cpfusa-audit-pack-relative-test.zip";
    std::filesystem::path expected_abs = std::filesystem::absolute(rel_out);
    std::error_code ec;
    std::filesystem::remove(expected_abs, ec); // clean slate
    struct Cleanup {
        std::filesystem::path p;
        ~Cleanup() { std::error_code e; std::filesystem::remove(p, e); }
    } cleanup{expected_abs};

    auto r = auditpack::pack(tmp.path(), rel_out);
    REQUIRE(is_ok(r));
    REQUIRE(std::filesystem::exists(expected_abs));

    auto listing = zip_list(expected_abs);
    REQUIRE(listing.find("manifest.json") != std::string::npos);
    REQUIRE(listing.find("qualify-report.json") != std::string::npos);
}

// ─── §8 MUST: full §1.2/§1.3 evidence set, not a hardcoded subset ───────────

TEST_CASE("auditpack: manifest includes .fusa-hara.json, .fusa-dispositions.json, "
          ".fusa-problems.json when present",
          "[auditpack][audit002]") {
    TempDir tmp;
    tmp.write(".fusa-hara.json",          R"({"hazards":[]})");
    tmp.write(".fusa-dispositions.json",  R"({"dispositions":[]})");
    tmp.write(".fusa-problems.json",      R"({"problems":[]})");
    auto out = tmp.path() / "audit-pack.zip";
    auto r = auditpack::pack(tmp.path(), out);
    REQUIRE(is_ok(r));
    auto& m = value_of(r);
    bool found_hara = false, found_disp = false, found_prob = false;
    for (auto& e : m.files) {
        if (e.path == ".fusa-hara.json")         found_hara = true;
        if (e.path == ".fusa-dispositions.json") found_disp = true;
        if (e.path == ".fusa-problems.json")     found_prob = true;
    }
    REQUIRE(found_hara);
    REQUIRE(found_disp);
    REQUIRE(found_prob);
}

TEST_CASE("auditpack: manifest includes every <standard>-gap-report.json present",
          "[auditpack][audit002]") {
    TempDir tmp;
    tmp.write("iso26262-gap-report.json",  R"({"gaps":[]})");
    tmp.write("iec61508-gap-report.json",  R"({"gaps":[]})");
    tmp.write("do178-gap-report.json",     R"({"gaps":[]})");
    auto out = tmp.path() / "audit-pack.zip";
    auto r = auditpack::pack(tmp.path(), out);
    REQUIRE(is_ok(r));
    auto& m = value_of(r);
    bool found_iso26262 = false, found_iec61508 = false, found_do178 = false;
    for (auto& e : m.files) {
        if (e.path == "iso26262-gap-report.json") found_iso26262 = true;
        if (e.path == "iec61508-gap-report.json") found_iec61508 = true;
        if (e.path == "do178-gap-report.json")    found_do178 = true;
    }
    REQUIRE(found_iso26262);
    REQUIRE(found_iec61508);
    REQUIRE(found_do178);
}

TEST_CASE("auditpack: does not pack audit-pack.zip itself even though it matches no "
          "evidence pattern", "[auditpack][audit002]") {
    TempDir tmp;
    tmp.write("qualify-report.json", R"({"passed":8})");
    auto out = tmp.path() / "audit-pack.zip";
    // A stale audit-pack.zip already exists before this run.
    tmp.write("audit-pack.zip", "stale");
    auto r = auditpack::pack(tmp.path(), out);
    REQUIRE(is_ok(r));
    for (auto& e : value_of(r).files)
        REQUIRE(e.path != "audit-pack.zip");
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
