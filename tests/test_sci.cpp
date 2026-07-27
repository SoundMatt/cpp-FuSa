//fusa:test REQ-SCI001
//fusa:test REQ-SCI002
#include <catch2/catch_all.hpp>
#include "sci/sci.hpp"
#include "testutil/testutil.hpp"
#include <nlohmann/json.hpp>
#include <fstream>

using namespace cpfusa;
using namespace cpfusa::testutil;
using json = nlohmann::json;

// ─── build ────────────────────────────────────────────────────────────────────

TEST_CASE("sci: build returns non-empty SCI", "[sci][sci001]") {
    TempDir tmp;
    auto s = sci::build(tmp.path(), "proj", "1.0");
    REQUIRE_FALSE(s.items.empty());
}

TEST_CASE("sci: build sets project and version", "[sci][sci001]") {
    TempDir tmp;
    auto s = sci::build(tmp.path(), "my-proj", "2.0");
    REQUIRE(s.project == "my-proj");
    REQUIRE(s.version == "2.0");
}

TEST_CASE("sci: build generated_at is non-empty", "[sci][sci001]") {
    TempDir tmp;
    auto s = sci::build(tmp.path(), "p", "1.0");
    REQUIRE_FALSE(s.generated_at.empty());
}

TEST_CASE("sci: lifecycle items have non-empty category", "[sci][sci001]") {
    TempDir tmp;
    auto s = sci::build(tmp.path(), "p", "1.0");
    for (auto& item : s.items)
        REQUIRE_FALSE(item.category.empty());
}

TEST_CASE("sci: lifecycle items have non-empty artifact names", "[sci][sci001]") {
    TempDir tmp;
    auto s = sci::build(tmp.path(), "p", "1.0");
    for (auto& item : s.items)
        REQUIRE_FALSE(item.artifact.empty());
}

// ─── write_json ───────────────────────────────────────────────────────────────

TEST_CASE("sci: write_json creates valid JSON", "[sci][sci002]") {
    TempDir tmp;
    auto s = sci::build(tmp.path(), "proj", "1.0");
    auto out = tmp.path() / sci::SCI_FILE;
    REQUIRE_NOTHROW(sci::write_json(out, s));
    std::ifstream f(out);
    json j;
    REQUIRE_NOTHROW(f >> j);
    REQUIRE(j.contains("items"));
    REQUIRE(j.contains("project"));
}

TEST_CASE("sci: JSON items array matches items count", "[sci][sci002]") {
    TempDir tmp;
    auto s = sci::build(tmp.path(), "p", "1.0");
    sci::write_json(tmp.path() / sci::SCI_FILE, s);
    std::ifstream f(tmp.path() / sci::SCI_FILE);
    json j; f >> j;
    REQUIRE(j["items"].size() == s.items.size());
}

TEST_CASE("sci: JSON items have category field", "[sci][sci002]") {
    TempDir tmp;
    auto s = sci::build(tmp.path(), "p", "1.0");
    sci::write_json(tmp.path() / sci::SCI_FILE, s);
    std::ifstream f(tmp.path() / sci::SCI_FILE);
    json j; f >> j;
    for (auto& item : j["items"])
        REQUIRE(item.contains("category"));
}

TEST_CASE("sci: JSON items have present field", "[sci][sci002]") {
    TempDir tmp;
    auto s = sci::build(tmp.path(), "p", "1.0");
    sci::write_json(tmp.path() / sci::SCI_FILE, s);
    std::ifstream f(tmp.path() / sci::SCI_FILE);
    json j; f >> j;
    for (auto& item : j["items"])
        REQUIRE(item.contains("present"));
}

TEST_CASE("sci: JSON has generatedAt field", "[sci][sci002]") {
    TempDir tmp;
    auto s = sci::build(tmp.path(), "p", "1.0");
    sci::write_json(tmp.path() / sci::SCI_FILE, s);
    std::ifstream f(tmp.path() / sci::SCI_FILE);
    json j; f >> j;
    REQUIRE(j.contains("generatedAt"));
    REQUIRE_FALSE(j["generatedAt"].get<std::string>().empty());
}

TEST_CASE("sci: JSON items have artifact field", "[sci][sci002]") {
    TempDir tmp;
    auto s = sci::build(tmp.path(), "p", "1.0");
    sci::write_json(tmp.path() / sci::SCI_FILE, s);
    std::ifstream f(tmp.path() / sci::SCI_FILE);
    json j; f >> j;
    for (auto& item : j["items"])
        REQUIRE(item.contains("artifact"));
}

TEST_CASE("sci: JSON items have sha256 field", "[sci][sci002]") {
    TempDir tmp;
    auto s = sci::build(tmp.path(), "p", "1.0");
    sci::write_json(tmp.path() / sci::SCI_FILE, s);
    std::ifstream f(tmp.path() / sci::SCI_FILE);
    json j; f >> j;
    for (auto& item : j["items"])
        REQUIRE(item.contains("sha256"));
}

TEST_CASE("sci: JSON has version field", "[sci][sci001]") {
    TempDir tmp;
    auto s = sci::build(tmp.path(), "p", "3.0");
    sci::write_json(tmp.path() / sci::SCI_FILE, s);
    std::ifstream f(tmp.path() / sci::SCI_FILE);
    json j; f >> j;
    REQUIRE(j["version"].get<std::string>() == "3.0");
}

// ─── build with existing artifacts (exercises sha256_file) ────────────────────

TEST_CASE("sci: build sets present=true for existing artifact", "[sci][sci001]") {
    TempDir tmp;
    // Write one of the known lifecycle artifact files
    tmp.write(".fusa.json", R"({"project":"p","version":"1.0"})");
    auto s = sci::build(tmp.path(), "p", "1.0");
    bool found = false;
    for (const auto& item : s.items) {
        if (item.artifact == ".fusa.json") {
            REQUIRE(item.present == true);
            found = true;
            break;
        }
    }
    REQUIRE(found);
}

TEST_CASE("sci: build computes non-empty sha256 for existing artifact", "[sci][sci002]") {
    TempDir tmp;
    tmp.write(".fusa.json", R"({"project":"p","version":"1.0"})");
    auto s = sci::build(tmp.path(), "p", "1.0");
    for (const auto& item : s.items) {
        if (item.artifact == ".fusa.json") {
            REQUIRE_FALSE(item.sha256.empty());
            // sha256 should look like a 64-char hex string
            REQUIRE(item.sha256.size() == 64);
        }
    }
}

TEST_CASE("sci: build sha256 changes when file content changes", "[sci][sci002]") {
    TempDir tmp;
    tmp.write("fmea.json", R"({"version":"1.0"})");
    auto s1 = sci::build(tmp.path(), "p", "1.0");
    tmp.write("fmea.json", R"({"version":"2.0","extra":"data"})");
    auto s2 = sci::build(tmp.path(), "p", "1.0");
    std::string hash1, hash2;
    for (const auto& item : s1.items)
        if (item.artifact == "fmea.json") hash1 = item.sha256;
    for (const auto& item : s2.items)
        if (item.artifact == "fmea.json") hash2 = item.sha256;
    REQUIRE_FALSE(hash1.empty());
    REQUIRE_FALSE(hash2.empty());
    REQUIRE(hash1 != hash2);
}

TEST_CASE("sci: build sha256 is stable across calls with same content", "[sci][sci002]") {
    TempDir tmp;
    tmp.write(".fusa-reqs.json", R"({"requirements":[]})");
    auto s1 = sci::build(tmp.path(), "p", "1.0");
    auto s2 = sci::build(tmp.path(), "p", "1.0");
    std::string h1, h2;
    for (const auto& item : s1.items)
        if (item.artifact == ".fusa-reqs.json") h1 = item.sha256;
    for (const auto& item : s2.items)
        if (item.artifact == ".fusa-reqs.json") h2 = item.sha256;
    REQUIRE(h1 == h2);
}

TEST_CASE("sci: build sets present=false for missing artifact", "[sci][sci001]") {
    TempDir tmp;
    auto s = sci::build(tmp.path(), "p", "1.0");
    for (const auto& item : s.items) {
        if (item.artifact == ".fusa.json") {
            REQUIRE(item.present == false);
            REQUIRE(item.sha256.empty());
        }
    }
}
