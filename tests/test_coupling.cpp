//fusa:test REQ-COUPLING001
//fusa:test REQ-COUPLING002
//fusa:test REQ-COUPLING003
#include <catch2/catch_all.hpp>
#include "coupling/coupling.hpp"
#include "testutil/testutil.hpp"
#include <nlohmann/json.hpp>
#include <fstream>

using namespace cpfusa;
using namespace cpfusa::testutil;
using json = nlohmann::json;

// ─── analyse ─────────────────────────────────────────────────────────────────

TEST_CASE("coupling: analyse on empty project returns empty report", "[coupling][coupling001]") {
    TempDir tmp;
    auto r = coupling::analyse(tmp.path());
    REQUIRE(r.data_count == 0);
    REQUIRE(r.control_count == 0);
    REQUIRE(r.data_edges.empty());
    REQUIRE(r.control_edges.empty());
}

TEST_CASE("coupling: analyse sets generated_at timestamp", "[coupling][coupling001]") {
    TempDir tmp;
    auto r = coupling::analyse(tmp.path());
    REQUIRE_FALSE(r.generated_at.empty());
    REQUIRE(r.generated_at.find('T') != std::string::npos);
}

TEST_CASE("coupling: analyse sets project name from dir", "[coupling][coupling001]") {
    TempDir tmp;
    auto r = coupling::analyse(tmp.path());
    REQUIRE_FALSE(r.project.empty());
}

TEST_CASE("coupling: analyse detects data coupling via includes", "[coupling][coupling002]") {
    TempDir tmp;
    tmp.write("src/engine/engine.cpp",
        "#include \"config/config.hpp\"\nvoid f(){}\n");
    auto r = coupling::analyse(tmp.path());
    REQUIRE(r.data_count > 0);
}

TEST_CASE("coupling: data_count matches data_edges size", "[coupling][coupling002]") {
    TempDir tmp;
    tmp.write("src/engine/engine.cpp",
        "#include \"config/config.hpp\"\nvoid f(){}\n");
    auto r = coupling::analyse(tmp.path());
    REQUIRE(r.data_count == static_cast<int>(r.data_edges.size()));
}

TEST_CASE("coupling: control_count matches control_edges size", "[coupling][coupling003]") {
    TempDir tmp;
    tmp.write("src/engine/engine.cpp",
        "void f() { config::load(\".\"); }\n");
    auto r = coupling::analyse(tmp.path());
    REQUIRE(r.control_count == static_cast<int>(r.control_edges.size()));
}

TEST_CASE("coupling: detects control coupling via namespace::call", "[coupling][coupling003]") {
    TempDir tmp;
    tmp.write("src/engine/engine.cpp",
        "namespace cpfusa { void f() { config::load(\".\"); } }\n");
    auto r = coupling::analyse(tmp.path());
    REQUIRE(r.control_count > 0);
}

TEST_CASE("coupling: data edges have non-empty from and to", "[coupling][coupling002]") {
    TempDir tmp;
    tmp.write("src/engine/engine.cpp",
        "#include \"config/config.hpp\"\nvoid f(){}\n");
    auto r = coupling::analyse(tmp.path());
    for (auto& e : r.data_edges) {
        REQUIRE_FALSE(e.from_file.empty());
        REQUIRE_FALSE(e.to_file.empty());
    }
}

// ─── write_json ───────────────────────────────────────────────────────────────

TEST_CASE("coupling: write_json creates valid JSON", "[coupling][coupling001]") {
    TempDir tmp;
    auto r = coupling::analyse(tmp.path());
    auto out = tmp.path() / coupling::COUPLING_FILE;
    REQUIRE_NOTHROW(coupling::write_json(out, r));
    std::ifstream f(out);
    json j;
    REQUIRE_NOTHROW(f >> j);
    REQUIRE(j.contains("dataEdges"));
    REQUIRE(j.contains("controlEdges"));
}

TEST_CASE("coupling: JSON report has generatedAt field", "[coupling][coupling001]") {
    TempDir tmp;
    auto r = coupling::analyse(tmp.path());
    coupling::write_json(tmp.path() / coupling::COUPLING_FILE, r);
    std::ifstream f(tmp.path() / coupling::COUPLING_FILE);
    json j; f >> j;
    REQUIRE(j.contains("generatedAt"));
    REQUIRE_FALSE(j["generatedAt"].get<std::string>().empty());
}

TEST_CASE("coupling: JSON report data and control counts are non-negative", "[coupling][coupling001]") {
    TempDir tmp;
    auto r = coupling::analyse(tmp.path());
    coupling::write_json(tmp.path() / coupling::COUPLING_FILE, r);
    std::ifstream f(tmp.path() / coupling::COUPLING_FILE);
    json j; f >> j;
    REQUIRE(j["dataCount"].get<int>() >= 0);
    REQUIRE(j["controlCount"].get<int>() >= 0);
}
