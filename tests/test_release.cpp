//fusa:test REQ-RELEASE001
//fusa:test REQ-RELEASE002
//fusa:test REQ-RELEASE003
//fusa:test REQ-RELEASE004
//fusa:test REQ-RELEASE005
//fusa:test REQ-RELEASE006
//fusa:test REQ-RELEASE007
//fusa:test REQ-RELEASE008
//fusa:test REQ-RELEASE009
#include <catch2/catch_all.hpp>
#include "release/release.hpp"
#include "testutil/testutil.hpp"
#include <nlohmann/json.hpp>
#include <algorithm>
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

// ─── list_present_evidence_files (§8 MUST, feeds hash_artifacts + audit-pack) ─

TEST_CASE("release: list_present_evidence_files finds .fusa-hara.json/.fusa-dispositions.json/"
          ".fusa-problems.json when present",
          "[release][release006]") {
    TempDir tmp;
    tmp.write(".fusa-hara.json", "{}");
    tmp.write(".fusa-dispositions.json", "{}");
    tmp.write(".fusa-problems.json", "{}");
    auto found = release::list_present_evidence_files(tmp.path());
    auto has = [&](const std::string& n) {
        return std::find(found.begin(), found.end(), n) != found.end();
    };
    REQUIRE(has(".fusa-hara.json"));
    REQUIRE(has(".fusa-dispositions.json"));
    REQUIRE(has(".fusa-problems.json"));
}

TEST_CASE("release: list_present_evidence_files matches the open-ended "
          "<standard>-gap-report.json family", "[release][release006]") {
    TempDir tmp;
    tmp.write("iso26262-gap-report.json", "{}");
    tmp.write("iec61508-gap-report.json", "{}");
    tmp.write("misra-cpp-gap-report.json", "{}");
    tmp.write("not-a-gap-report.txt", "irrelevant"); // wrong extension, must not match
    auto found = release::list_present_evidence_files(tmp.path());
    auto has = [&](const std::string& n) {
        return std::find(found.begin(), found.end(), n) != found.end();
    };
    REQUIRE(has("iso26262-gap-report.json"));
    REQUIRE(has("iec61508-gap-report.json"));
    REQUIRE(has("misra-cpp-gap-report.json"));
    REQUIRE_FALSE(has("not-a-gap-report.txt"));
}

TEST_CASE("release: list_present_evidence_files never includes audit-pack.zip",
          "[release][release006]") {
    TempDir tmp;
    tmp.write("audit-pack.zip", "not really a zip");
    auto found = release::list_present_evidence_files(tmp.path());
    REQUIRE(std::find(found.begin(), found.end(), "audit-pack.zip") == found.end());
}

TEST_CASE("release: hash_artifacts picks up .fusa-hara.json and gap-report files too",
          "[release][release006]") {
    TempDir tmp;
    tmp.write(".fusa-hara.json", "{}");
    tmp.write("iso26262-gap-report.json", "{}");
    auto m = release::hash_artifacts(tmp.path());
    bool found_hara = false, found_gap = false;
    for (auto& a : m.artifacts) {
        if (a.path == ".fusa-hara.json") found_hara = true;
        if (a.path == "iso26262-gap-report.json") found_gap = true;
    }
    REQUIRE(found_hara);
    REQUIRE(found_gap);
}

// ─── §7 components[].hash MUST be "<algo>:<value>", never "" ────────────────

TEST_CASE("release: FetchContent component with no fetched source tree has no hash field",
          "[release][release003]") {
    TempDir tmp;
    tmp.write("CMakeLists.txt",
              "FetchContent_Declare(\n"
              "    nlohmann_json\n"
              "    GIT_REPOSITORY https://github.com/nlohmann/json.git\n"
              "    GIT_TAG        v3.11.3\n"
              ")\n");
    config::ProjectConfig cfg;
    cfg.project = "TestProj";
    auto sbom_r = release::build_sbom(tmp.path(), cfg);
    REQUIRE(is_ok(sbom_r));
    auto& sbom = value_of(sbom_r);
    REQUIRE_FALSE(sbom.components.empty());
    // No _deps/<name>-src tree exists anywhere under tmp — no real hash is
    // computable, so Component.hash MUST be left empty (never fabricated).
    for (auto& c : sbom.components) REQUIRE(c.hash.empty());

    auto prov = value_of(release::build_provenance(tmp.path(), cfg));
    auto manifest = release::hash_artifacts(tmp.path());
    release::write_all(tmp.path(), sbom, prov, manifest);
    std::ifstream f(tmp.path() / release::SBOMFile);
    json j;
    REQUIRE_NOTHROW(f >> j);
    for (auto& cj : j["components"]) {
        // §7: "A bare hash with no algo: prefix is non-conformant" — and an
        // empty string is not a valid algo:value pair either, so the key
        // must be omitted entirely rather than emitted as "".
        REQUIRE_FALSE(cj.contains("hash"));
    }
}

TEST_CASE("release: FetchContent component with a fetched source tree gets a real sha256: hash",
          "[release][release003]") {
    TempDir tmp;
    tmp.write("CMakeLists.txt",
              "FetchContent_Declare(\n"
              "    nlohmann_json\n"
              "    GIT_REPOSITORY https://github.com/nlohmann/json.git\n"
              "    GIT_TAG        v3.11.3\n"
              ")\n");
    // Simulate a prior CMake configure having fetched the dependency source
    // under build/_deps/nlohmann_json-src (CMake lowercases the dep name).
    tmp.write("build/_deps/nlohmann_json-src/include/json.hpp", "// fake header content\n");
    tmp.write("build/_deps/nlohmann_json-src/README.md", "# nlohmann/json\n");

    config::ProjectConfig cfg;
    cfg.project = "TestProj";
    auto sbom_r = release::build_sbom(tmp.path(), cfg);
    REQUIRE(is_ok(sbom_r));
    auto& sbom = value_of(sbom_r);
    REQUIRE_FALSE(sbom.components.empty());
    REQUIRE_FALSE(sbom.components[0].hash.empty());
    REQUIRE(sbom.components[0].hash.size() == 64); // bare hex internally

    // Deterministic: re-running build_sbom against the same tree must
    // produce the identical hash.
    auto sbom_r2 = release::build_sbom(tmp.path(), cfg);
    REQUIRE(value_of(sbom_r2).components[0].hash == sbom.components[0].hash);

    auto prov = value_of(release::build_provenance(tmp.path(), cfg));
    auto manifest = release::hash_artifacts(tmp.path());
    release::write_all(tmp.path(), sbom, prov, manifest);
    std::ifstream f(tmp.path() / release::SBOMFile);
    json j;
    REQUIRE_NOTHROW(f >> j);
    REQUIRE_FALSE(j["components"].empty());
    std::string h = j["components"][0]["hash"].get<std::string>();
    REQUIRE(h.rfind("sha256:", 0) == 0);
    REQUIRE(h.size() == 7 + 64);
}
