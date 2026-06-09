//fusa:test REQ-VULN001 REQ-VULN002 REQ-VULN003 REQ-VULN004
#include <catch2/catch_all.hpp>
#include "vuln/vuln.hpp"
#include "testutil/testutil.hpp"
#include <nlohmann/json.hpp>
#include <fstream>

using namespace cpfusa;
using namespace cpfusa::testutil;
using json = nlohmann::json;

// ─── parse_deps ───────────────────────────────────────────────────────────────

TEST_CASE("vuln: parse_deps finds no deps in empty project", "[vuln][vuln001]") {
    TempDir tmp;
    auto deps = vuln::parse_deps(tmp.path());
    REQUIRE(deps.empty());
}

TEST_CASE("vuln: parse_deps extracts FetchContent declarations from CMakeLists.txt", "[vuln][vuln001]") {
    TempDir tmp;
    tmp.write("CMakeLists.txt",
        "cmake_minimum_required(VERSION 3.20)\n"
        "FetchContent_Declare(\n"
        "  nlohmann_json\n"
        "  GIT_TAG 3.10.5\n"
        ")\n");
    auto deps = vuln::parse_deps(tmp.path());
    REQUIRE(deps.size() == 1);
    REQUIRE(deps[0].name == "nlohmann_json");
    REQUIRE(deps[0].version == "3.10.5");
}

TEST_CASE("vuln: parse_deps extracts multiple dependencies", "[vuln][vuln001]") {
    TempDir tmp;
    tmp.write("CMakeLists.txt",
        "FetchContent_Declare(nlohmann_json GIT_TAG 3.11.3)\n"
        "FetchContent_Declare(catch2 GIT_TAG 3.4.0)\n");
    auto deps = vuln::parse_deps(tmp.path());
    REQUIRE(deps.size() == 2);
}

// ─── scan ─────────────────────────────────────────────────────────────────────

TEST_CASE("vuln: scan on empty project returns zero scanned", "[vuln][vuln001]") {
    TempDir tmp;
    auto r = vuln::scan(tmp.path());
    REQUIRE(r.scanned == 0);
    REQUIRE(r.findings.empty());
}

TEST_CASE("vuln: scan sets generated_at timestamp", "[vuln][vuln002]") {
    TempDir tmp;
    auto r = vuln::scan(tmp.path());
    REQUIRE_FALSE(r.generated_at.empty());
    REQUIRE(r.generated_at.find('T') != std::string::npos);
}

TEST_CASE("vuln: scan clean dependency produces no findings", "[vuln][vuln003]") {
    TempDir tmp;
    // nlohmann_json 3.11.3 is beyond all advisory max_versions
    tmp.write("CMakeLists.txt",
        "FetchContent_Declare(nlohmann_json GIT_TAG 3.11.3)\n");
    auto r = vuln::scan(tmp.path());
    REQUIRE(r.findings.empty());
}

TEST_CASE("vuln: scan affected dependency produces findings", "[vuln][vuln004]") {
    TempDir tmp;
    // nlohmann_json 3.10.4 is below the advisory max 3.10.5
    tmp.write("CMakeLists.txt",
        "FetchContent_Declare(nlohmann_json GIT_TAG 3.10.4)\n");
    auto r = vuln::scan(tmp.path());
    REQUIRE_FALSE(r.findings.empty());
}

TEST_CASE("vuln: finding includes CVE id and severity", "[vuln][vuln004]") {
    TempDir tmp;
    tmp.write("CMakeLists.txt",
        "FetchContent_Declare(nlohmann_json GIT_TAG 3.10.4)\n");
    auto r = vuln::scan(tmp.path());
    REQUIRE_FALSE(r.findings.empty());
    REQUIRE_FALSE(r.findings[0].cve_id.empty());
    REQUIRE_FALSE(r.findings[0].severity.empty());
}

// ─── write_json ───────────────────────────────────────────────────────────────

TEST_CASE("vuln: write_json creates valid JSON file", "[vuln][vuln002]") {
    TempDir tmp;
    vuln::VulnReport r;
    r.generated_at = "2026-06-09T00:00:00Z";
    r.project = "test";
    r.scanned = 0;
    auto out = tmp.path() / "vuln.json";
    REQUIRE_NOTHROW(vuln::write_json(out, r));
    std::ifstream f(out);
    json j;
    REQUIRE_NOTHROW(f >> j);
    REQUIRE(j.contains("findings"));
}

TEST_CASE("vuln: write_json includes findings entries", "[vuln][vuln002]") {
    TempDir tmp;
    vuln::VulnReport r;
    r.generated_at = "2026-06-09T00:00:00Z";
    r.project = "test";
    r.findings.push_back({"pkg", "1.0.0", "CVE-2024-9999", "HIGH", "desc", "ref"});
    auto out = tmp.path() / "vuln.json";
    vuln::write_json(out, r);
    std::ifstream f(out);
    json j;
    f >> j;
    REQUIRE(j["findings"].size() == 1);
    REQUIRE(j["findings"][0]["cveId"].get<std::string>() == "CVE-2024-9999");
}
