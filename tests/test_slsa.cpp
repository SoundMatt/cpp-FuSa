//fusa:test REQ-SLSA001
//fusa:test REQ-SLSA002
//fusa:test REQ-SLSA003
#include <catch2/catch_all.hpp>
#include "slsa/slsa.hpp"
#include "testutil/testutil.hpp"
#include <nlohmann/json.hpp>
#include <fstream>

using namespace cpfusa;
using namespace cpfusa::testutil;
using json = nlohmann::json;

// ─── parse_level / level_str ─────────────────────────────────────────────────

TEST_CASE("slsa: parse_level L1", "[slsa][slsa001]") {
    REQUIRE(slsa::parse_level("L1") == slsa::Level::L1);
    REQUIRE(slsa::parse_level("1")  == slsa::Level::L1);
}

TEST_CASE("slsa: level_str roundtrip", "[slsa][slsa001]") {
    REQUIRE(slsa::level_str(slsa::parse_level("L2")) == "SLSA-L2");
    REQUIRE(slsa::level_str(slsa::parse_level("L4")) == "SLSA-L4");
}

TEST_CASE("slsa: status_str met", "[slsa][slsa001]") {
    REQUIRE(slsa::status_str(slsa::Status::Met) == "satisfied");
}

TEST_CASE("slsa: status_str gap", "[slsa][slsa001]") {
    REQUIRE(slsa::status_str(slsa::Status::Gap) == "gap");
}

// ─── assess ───────────────────────────────────────────────────────────────────

TEST_CASE("slsa: assess returns non-empty report for L1", "[slsa][slsa002]") {
    TempDir tmp;
    auto r = slsa::assess(tmp.path(), "proj", slsa::Level::L1);
    REQUIRE(r.total > 0);
}

TEST_CASE("slsa: assess sets project and level", "[slsa][slsa002]") {
    TempDir tmp;
    auto r = slsa::assess(tmp.path(), "my-proj", slsa::Level::L2);
    REQUIRE(r.project == "my-proj");
    REQUIRE(r.level == "SLSA-L2");
}

TEST_CASE("slsa: assess counts are consistent", "[slsa][slsa002]") {
    TempDir tmp;
    auto r = slsa::assess(tmp.path(), "p", slsa::Level::L1);
    REQUIRE(r.satisfied + r.gap == r.total);
}

TEST_CASE("slsa: higher level has >= requirements than lower", "[slsa][slsa002]") {
    TempDir tmp;
    auto r1 = slsa::assess(tmp.path(), "p", slsa::Level::L1);
    auto r3 = slsa::assess(tmp.path(), "p", slsa::Level::L3);
    REQUIRE(r3.total >= r1.total);
}

TEST_CASE("slsa: CMakeLists presence satisfies SLSA-1.1", "[slsa][slsa002]") {
    TempDir tmp;
    tmp.write("CMakeLists.txt", "cmake_minimum_required(VERSION 3.21)\n");
    auto r = slsa::assess(tmp.path(), "p", slsa::Level::L1);
    bool found = false;
    for (auto& req : r.requirements)
        if (req.id == "SLSA-1.1" && req.status == slsa::Status::Met) found = true;
    REQUIRE(found);
}

TEST_CASE("slsa: generated_at is non-empty", "[slsa][slsa001]") {
    TempDir tmp;
    auto r = slsa::assess(tmp.path(), "p", slsa::Level::L1);
    REQUIRE_FALSE(r.generated_at.empty());
}

// ─── write_json ───────────────────────────────────────────────────────────────

TEST_CASE("slsa: write_json creates valid JSON", "[slsa][slsa003]") {
    TempDir tmp;
    auto r = slsa::assess(tmp.path(), "p", slsa::Level::L2);
    auto out = tmp.path() / slsa::SLSA_REPORT_FILE;
    REQUIRE_NOTHROW(slsa::write_json(out, r));
    std::ifstream f(out);
    json j;
    REQUIRE_NOTHROW(f >> j);
    REQUIRE(j.contains("objectives"));
    REQUIRE(j.contains("summary"));
}

TEST_CASE("slsa: JSON summary total matches report", "[slsa][slsa003]") {
    TempDir tmp;
    auto r = slsa::assess(tmp.path(), "p", slsa::Level::L1);
    slsa::write_json(tmp.path() / slsa::SLSA_REPORT_FILE, r);
    std::ifstream f(tmp.path() / slsa::SLSA_REPORT_FILE);
    json j; f >> j;
    REQUIRE(j["summary"]["total"].get<int>() == r.total);
}

TEST_CASE("slsa: JSON objectives have id field", "[slsa][slsa003]") {
    TempDir tmp;
    auto r = slsa::assess(tmp.path(), "p", slsa::Level::L2);
    slsa::write_json(tmp.path() / slsa::SLSA_REPORT_FILE, r);
    std::ifstream f(tmp.path() / slsa::SLSA_REPORT_FILE);
    json j; f >> j;
    for (auto& req : j["objectives"])
        REQUIRE(req.contains("id"));
}

TEST_CASE("slsa: JSON summary has spec 9.3 keys satisfied and gaps", "[slsa][slsa003]") {
    TempDir tmp;
    auto r = slsa::assess(tmp.path(), "p", slsa::Level::L1);
    slsa::write_json(tmp.path() / slsa::SLSA_REPORT_FILE, r);
    std::ifstream f(tmp.path() / slsa::SLSA_REPORT_FILE);
    json j; f >> j;
    REQUIRE(j["summary"].contains("satisfied"));
    REQUIRE(j["summary"].contains("gaps"));
    REQUIRE_FALSE(j["summary"].contains("met"));
    REQUIRE_FALSE(j["summary"].contains("gap"));
}

TEST_CASE("slsa: objective status values are spec-conformant", "[slsa][slsa003]") {
    TempDir tmp;
    auto r = slsa::assess(tmp.path(), "p", slsa::Level::L1);
    slsa::write_json(tmp.path() / slsa::SLSA_REPORT_FILE, r);
    std::ifstream f(tmp.path() / slsa::SLSA_REPORT_FILE);
    json j; f >> j;
    for (auto& req : j["objectives"]) {
        auto s = req["status"].get<std::string>();
        REQUIRE((s == "satisfied" || s == "partial" || s == "gap"));
    }
}
