//fusa:test REQ-SCI001 REQ-SCI002
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
