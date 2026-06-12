//fusa:test REQ-RELEASE001 REQ-RELEASE002 REQ-RELEASE003 REQ-RELEASE004 REQ-RELEASE005 REQ-RELEASE006 REQ-RELEASE007 REQ-RELEASE008
#include <catch2/catch_all.hpp>
#include "release/release.hpp"
#include "testutil/testutil.hpp"
#include <nlohmann/json.hpp>
#include <fstream>

using namespace cpfusa;
using namespace cpfusa::testutil;
using json = nlohmann::json;

// ─── build_sbom ──────────────────────────────────────────────────────────────

TEST_CASE("release: build_sbom returns a result", "[release][release003]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    cfg.project = "TestProject";
    cfg.version = "1.0.0";
    auto r = release::build_sbom(tmp.path(), cfg);
    REQUIRE(is_ok(r));
}

TEST_CASE("release: build_sbom format is set", "[release][release003]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto r = release::build_sbom(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    REQUIRE_FALSE(value_of(r).format.empty());
}

TEST_CASE("release: build_sbom project matches config", "[release][release003]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    cfg.project = "MyLib";
    auto r = release::build_sbom(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    REQUIRE(value_of(r).project == "MyLib");
}

TEST_CASE("release: build_sbom has cpp_version from config language", "[release][release003]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    cfg.language = "cpp17";
    auto r = release::build_sbom(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    REQUIRE(value_of(r).cpp_version == "cpp17");
}

// ─── build_provenance ─────────────────────────────────────────────────────────

TEST_CASE("release: build_provenance returns a result", "[release][release005]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto r = release::build_provenance(tmp.path(), cfg);
    REQUIRE(is_ok(r));
}

TEST_CASE("release: build_provenance format is set", "[release][release005]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto r = release::build_provenance(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    REQUIRE_FALSE(value_of(r).format.empty());
}

TEST_CASE("release: build_provenance sets generated_at", "[release][release005]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto r = release::build_provenance(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    REQUIRE_FALSE(value_of(r).generated_at.empty());
}

TEST_CASE("release: build_provenance platform is set", "[release][release005]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto r = release::build_provenance(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    REQUIRE_FALSE(value_of(r).platform.empty());
}

// ─── hash_artifacts ───────────────────────────────────────────────────────────

TEST_CASE("release: hash_artifacts returns empty manifest for empty dir", "[release][release006]") {
    TempDir tmp;
    auto m = release::hash_artifacts(tmp.path());
    REQUIRE(m.artifacts.empty());
}

TEST_CASE("release: hash_artifacts finds evidence files in dir", "[release][release006]") {
    TempDir tmp;
    tmp.write("qualify-report.json", R"({"passed":8})");
    auto m = release::hash_artifacts(tmp.path());
    bool found = false;
    for (auto& a : m.artifacts)
        if (a.path.find("qualify-report") != std::string::npos) found = true;
    REQUIRE(found);
}

TEST_CASE("release: hash_artifacts entries have non-empty sha256", "[release][release006]") {
    TempDir tmp;
    tmp.write(".fusa-evidence.json", R"({"total":10,"passed":10})");
    auto m = release::hash_artifacts(tmp.path());
    for (auto& a : m.artifacts)
        REQUIRE_FALSE(a.sha256.empty());
}

TEST_CASE("release: hash_artifacts sha256 is 64 chars", "[release][release006]") {
    TempDir tmp;
    tmp.write("sbom.json", R"({"format":"cpp-FuSa SBOM v1"})");
    auto m = release::hash_artifacts(tmp.path());
    for (auto& a : m.artifacts)
        REQUIRE(a.sha256.size() == 64);
}

// ─── write_all round-trip ─────────────────────────────────────────────────────

TEST_CASE("release: write_all creates sbom.json, provenance.json, artifact-manifest.json", "[release]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    cfg.project = "TestProj";
    auto sbom = value_of(release::build_sbom(tmp.path(), cfg));
    auto prov = value_of(release::build_provenance(tmp.path(), cfg));
    auto manifest = release::hash_artifacts(tmp.path());
    auto w = release::write_all(tmp.path(), sbom, prov, manifest);
    REQUIRE(is_ok(w));
    REQUIRE(std::filesystem::exists(tmp.path() / release::SBOMFile));
    REQUIRE(std::filesystem::exists(tmp.path() / release::ProvenanceFile));
    REQUIRE(std::filesystem::exists(tmp.path() / release::ManifestFile));
}

TEST_CASE("release: sbom.json conforms to x-FuSa spec-7 format", "[release]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    auto sbom = value_of(release::build_sbom(tmp.path(), cfg));
    auto prov = value_of(release::build_provenance(tmp.path(), cfg));
    auto manifest = release::hash_artifacts(tmp.path());
    release::write_all(tmp.path(), sbom, prov, manifest);
    std::ifstream f(tmp.path() / release::SBOMFile);
    json j;
    REQUIRE_NOTHROW(f >> j);
    // §3.1 common header
    REQUIRE(j.contains("schemaVersion"));
    REQUIRE(j["kind"] == "sbom");
    REQUIRE(j["tool"] == "cpp-FuSa");
    // §7 SBOM fields
    REQUIRE(j["format"] == "x-FuSa SBOM v1");
    REQUIRE(j.contains("module"));
    REQUIRE(j.contains("components"));
}

// ─── write_sbom SPDX 2.x format ──────────────────────────────────────────────

TEST_CASE("release: SPDX 2.3 sbom has spdxVersion field", "[release]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    cfg.project = "TestProj";
    auto sbom_r = release::build_sbom(tmp.path(), cfg);
    REQUIRE(is_ok(sbom_r));
    auto out = tmp.path() / "sbom-spdx23.json";
    release::write_sbom(out, value_of(sbom_r), release::SpdxVersion::V2_3);
    REQUIRE(std::filesystem::exists(out));
    std::ifstream f(out);
    json j;
    REQUIRE_NOTHROW(f >> j);
    REQUIRE(j["spdxVersion"] == "SPDX-2.3");
    REQUIRE(j.contains("packages"));
}

TEST_CASE("release: SPDX 2.2 sbom has dataLicense field", "[release]") {
    TempDir tmp;
    config::ProjectConfig cfg;
    cfg.project = "TestProj22";
    auto sbom_r = release::build_sbom(tmp.path(), cfg);
    REQUIRE(is_ok(sbom_r));
    auto out = tmp.path() / "sbom-spdx22.json";
    release::write_sbom(out, value_of(sbom_r), release::SpdxVersion::V2_2);
    REQUIRE(std::filesystem::exists(out));
    std::ifstream f(out);
    json j;
    REQUIRE_NOTHROW(f >> j);
    REQUIRE(j["spdxVersion"] == "SPDX-2.2");
    REQUIRE(j["dataLicense"] == "CC0-1.0");
}

TEST_CASE("release: parse_spdx_version parses 2.2, 2.3 and defaults", "[release]") {
    REQUIRE(release::parse_spdx_version("2.2") == release::SpdxVersion::V2_2);
    REQUIRE(release::parse_spdx_version("2.3") == release::SpdxVersion::V2_3);
    REQUIRE(release::parse_spdx_version("3.0.1") == release::SpdxVersion::V3_0_1);
    REQUIRE(release::parse_spdx_version("unknown") == release::SpdxVersion::V3_0_1);
}
