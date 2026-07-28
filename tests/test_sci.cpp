//fusa:test REQ-SCI001
//fusa:test REQ-SCI002
//fusa:test REQ-SCI003
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
    REQUIRE_FALSE(s.artifacts.empty());
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

TEST_CASE("sci: artifacts have non-empty category", "[sci][sci001]") {
    TempDir tmp;
    auto s = sci::build(tmp.path(), "p", "1.0");
    for (auto& item : s.artifacts)
        REQUIRE_FALSE(item.category.empty());
}

TEST_CASE("sci: artifacts have non-empty file names", "[sci][sci001]") {
    TempDir tmp;
    auto s = sci::build(tmp.path(), "p", "1.0");
    for (auto& item : s.artifacts)
        REQUIRE_FALSE(item.file.empty());
}

// ─── to_json / write_json ─────────────────────────────────────────────────────

TEST_CASE("sci: write_json creates valid JSON with artifacts[] (canonical key)", "[sci][sci003]") {
    TempDir tmp;
    auto s = sci::build(tmp.path(), "proj", "1.0");
    auto out = tmp.path() / sci::SCI_FILE;
    REQUIRE_NOTHROW(sci::write_json(out, s, tmp.path().string()));
    std::ifstream f(out);
    json j;
    REQUIRE_NOTHROW(f >> j);
    REQUIRE(j.contains("artifacts"));
    REQUIRE(j.contains("project"));
    REQUIRE(j["kind"] == "sci");
}

TEST_CASE("sci: JSON artifacts array matches artifacts count", "[sci][sci003]") {
    TempDir tmp;
    auto s = sci::build(tmp.path(), "p", "1.0");
    sci::write_json(tmp.path() / sci::SCI_FILE, s, tmp.path().string());
    std::ifstream f(tmp.path() / sci::SCI_FILE);
    json j; f >> j;
    REQUIRE(j["artifacts"].size() == s.artifacts.size());
}

TEST_CASE("sci: JSON artifacts have category field", "[sci][sci003]") {
    TempDir tmp;
    auto s = sci::build(tmp.path(), "p", "1.0");
    sci::write_json(tmp.path() / sci::SCI_FILE, s, tmp.path().string());
    std::ifstream f(tmp.path() / sci::SCI_FILE);
    json j; f >> j;
    for (auto& item : j["artifacts"])
        REQUIRE(item.contains("category"));
}

TEST_CASE("sci: JSON artifacts have present field", "[sci][sci003]") {
    TempDir tmp;
    auto s = sci::build(tmp.path(), "p", "1.0");
    sci::write_json(tmp.path() / sci::SCI_FILE, s, tmp.path().string());
    std::ifstream f(tmp.path() / sci::SCI_FILE);
    json j; f >> j;
    for (auto& item : j["artifacts"])
        REQUIRE(item.contains("present"));
}

TEST_CASE("sci: JSON has generatedAt field", "[sci][sci003]") {
    TempDir tmp;
    auto s = sci::build(tmp.path(), "p", "1.0");
    sci::write_json(tmp.path() / sci::SCI_FILE, s, tmp.path().string());
    std::ifstream f(tmp.path() / sci::SCI_FILE);
    json j; f >> j;
    REQUIRE(j.contains("generatedAt"));
    REQUIRE_FALSE(j["generatedAt"].get<std::string>().empty());
}

TEST_CASE("sci: JSON artifacts have file field", "[sci][sci003]") {
    TempDir tmp;
    auto s = sci::build(tmp.path(), "p", "1.0");
    sci::write_json(tmp.path() / sci::SCI_FILE, s, tmp.path().string());
    std::ifstream f(tmp.path() / sci::SCI_FILE);
    json j; f >> j;
    for (auto& item : j["artifacts"])
        REQUIRE(item.contains("file"));
}

TEST_CASE("sci: JSON has version field", "[sci][sci001]") {
    TempDir tmp;
    auto s = sci::build(tmp.path(), "p", "3.0");
    sci::write_json(tmp.path() / sci::SCI_FILE, s, tmp.path().string());
    std::ifstream f(tmp.path() / sci::SCI_FILE);
    json j; f >> j;
    REQUIRE(j["version"].get<std::string>() == "3.0");
}

// ─── §2.7 hash convention: "hash" field MUST carry the sha256: prefix ────────

TEST_CASE("sci: present artifacts' hash field is sha256:-prefixed", "[sci][sci003]") {
    TempDir tmp;
    tmp.write(".fusa.json", R"({"project":"p","version":"1.0"})");
    auto s = sci::build(tmp.path(), "p", "1.0");
    sci::write_json(tmp.path() / sci::SCI_FILE, s, tmp.path().string());
    std::ifstream f(tmp.path() / sci::SCI_FILE);
    json j; f >> j;
    bool found = false;
    for (auto& item : j["artifacts"]) {
        if (item["file"] == ".fusa.json") {
            REQUIRE(item.contains("hash"));
            REQUIRE(item["hash"].get<std::string>().rfind("sha256:", 0) == 0);
            found = true;
        }
    }
    REQUIRE(found);
}

TEST_CASE("sci: absent artifacts have no hash field", "[sci][sci003]") {
    TempDir tmp;
    auto s = sci::build(tmp.path(), "p", "1.0");
    sci::write_json(tmp.path() / sci::SCI_FILE, s, tmp.path().string());
    std::ifstream f(tmp.path() / sci::SCI_FILE);
    json j; f >> j;
    for (auto& item : j["artifacts"]) {
        if (item["file"] == ".fusa.json") {
            REQUIRE(item["present"] == false);
            REQUIRE_FALSE(item.contains("hash"));
        }
    }
}

// ─── build with existing artifacts (exercises file hashing) ──────────────────

TEST_CASE("sci: build sets present=true for existing artifact", "[sci][sci001]") {
    TempDir tmp;
    tmp.write(".fusa.json", R"({"project":"p","version":"1.0"})");
    auto s = sci::build(tmp.path(), "p", "1.0");
    bool found = false;
    for (const auto& item : s.artifacts) {
        if (item.file == ".fusa.json") {
            REQUIRE(item.present == true);
            found = true;
            break;
        }
    }
    REQUIRE(found);
}

TEST_CASE("sci: build computes a sha256:-prefixed hash for existing artifact", "[sci][sci002]") {
    TempDir tmp;
    tmp.write(".fusa.json", R"({"project":"p","version":"1.0"})");
    auto s = sci::build(tmp.path(), "p", "1.0");
    for (const auto& item : s.artifacts) {
        if (item.file == ".fusa.json") {
            REQUIRE_FALSE(item.hash.empty());
            REQUIRE(item.hash.rfind("sha256:", 0) == 0);
            REQUIRE(item.hash.size() == 7 + 64);
        }
    }
}

TEST_CASE("sci: build hash changes when file content changes", "[sci][sci002]") {
    TempDir tmp;
    tmp.write("fmea.json", R"({"version":"1.0"})");
    auto s1 = sci::build(tmp.path(), "p", "1.0");
    tmp.write("fmea.json", R"({"version":"2.0","extra":"data"})");
    auto s2 = sci::build(tmp.path(), "p", "1.0");
    std::string hash1, hash2;
    for (const auto& item : s1.artifacts)
        if (item.file == "fmea.json") hash1 = item.hash;
    for (const auto& item : s2.artifacts)
        if (item.file == "fmea.json") hash2 = item.hash;
    REQUIRE_FALSE(hash1.empty());
    REQUIRE_FALSE(hash2.empty());
    REQUIRE(hash1 != hash2);
}

TEST_CASE("sci: build hash is stable across calls with same content", "[sci][sci002]") {
    TempDir tmp;
    tmp.write(".fusa-reqs.json", R"({"requirements":[]})");
    auto s1 = sci::build(tmp.path(), "p", "1.0");
    auto s2 = sci::build(tmp.path(), "p", "1.0");
    std::string h1, h2;
    for (const auto& item : s1.artifacts)
        if (item.file == ".fusa-reqs.json") h1 = item.hash;
    for (const auto& item : s2.artifacts)
        if (item.file == ".fusa-reqs.json") h2 = item.hash;
    REQUIRE(h1 == h2);
}

TEST_CASE("sci: build sets present=false for missing artifact", "[sci][sci001]") {
    TempDir tmp;
    auto s = sci::build(tmp.path(), "p", "1.0");
    for (const auto& item : s.artifacts) {
        if (item.file == ".fusa.json") {
            REQUIRE(item.present == false);
            REQUIRE(item.hash.empty());
        }
    }
}
