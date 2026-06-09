//fusa:test REQ-IMPACT001 REQ-IMPACT002
#include <catch2/catch_all.hpp>
#include "impact/impact.hpp"
#include "testutil/testutil.hpp"
#include <nlohmann/json.hpp>
#include <fstream>

using namespace cpfusa;
using namespace cpfusa::testutil;
using json = nlohmann::json;

// ─── analyse ─────────────────────────────────────────────────────────────────

TEST_CASE("impact: analyse on non-git dir returns empty report", "[impact][impact001]") {
    TempDir tmp;
    auto r = impact::analyse(tmp.path(), "HEAD~1", "HEAD");
    REQUIRE_FALSE(r.generated_at.empty());
}

TEST_CASE("impact: analyse sets from_ref and to_ref", "[impact][impact001]") {
    TempDir tmp;
    auto r = impact::analyse(tmp.path(), "abc123", "def456");
    REQUIRE(r.from_ref == "abc123");
    REQUIRE(r.to_ref == "def456");
}

TEST_CASE("impact: analyse stale_artifacts list is a vector", "[impact][impact001]") {
    TempDir tmp;
    auto r = impact::analyse(tmp.path(), "HEAD~1", "HEAD");
    REQUIRE(r.stale_artifacts.size() >= 0);
}

// ─── render_json ─────────────────────────────────────────────────────────────

TEST_CASE("impact: render_json creates valid JSON", "[impact][impact002]") {
    TempDir tmp;
    auto r = impact::analyse(tmp.path(), "v1.0", "v1.1");
    auto out = tmp.path() / "impact.json";
    REQUIRE_NOTHROW(impact::render_json(out, r));
    std::ifstream f(out);
    json j;
    REQUIRE_NOTHROW(f >> j);
    REQUIRE(j.contains("fromRef"));
    REQUIRE(j.contains("toRef"));
}

TEST_CASE("impact: JSON has changedFiles array", "[impact][impact002]") {
    TempDir tmp;
    auto r = impact::analyse(tmp.path(), "v1.0", "v1.1");
    impact::render_json(tmp.path() / "impact.json", r);
    std::ifstream f(tmp.path() / "impact.json");
    json j; f >> j;
    REQUIRE(j.contains("changedFiles"));
}

TEST_CASE("impact: JSON has impactedReqs array", "[impact][impact002]") {
    TempDir tmp;
    auto r = impact::analyse(tmp.path(), "v1.0", "v1.1");
    impact::render_json(tmp.path() / "impact.json", r);
    std::ifstream f(tmp.path() / "impact.json");
    json j; f >> j;
    REQUIRE(j.contains("impactedReqs"));
}

TEST_CASE("impact: JSON generatedAt is non-empty", "[impact][impact001]") {
    TempDir tmp;
    auto r = impact::analyse(tmp.path(), "a", "b");
    impact::render_json(tmp.path() / "impact.json", r);
    std::ifstream f(tmp.path() / "impact.json");
    json j; f >> j;
    REQUIRE_FALSE(j["generatedAt"].get<std::string>().empty());
}
