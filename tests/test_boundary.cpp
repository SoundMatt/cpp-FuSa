//fusa:test REQ-BOUNDARY001
//fusa:test REQ-BOUNDARY002
//fusa:test REQ-BOUNDARY003
#include <catch2/catch_all.hpp>
#include "boundary/boundary.hpp"
#include "testutil/testutil.hpp"
#include <fstream>
#include <string>

using namespace cpfusa;
using namespace cpfusa::testutil;

// ─── scan ─────────────────────────────────────────────────────────────────────

TEST_CASE("boundary: scan on empty project returns empty diagram", "[boundary][boundary001]") {
    TempDir tmp;
    auto d = boundary::scan(tmp.path());
    REQUIRE(d.nodes.empty());
    REQUIRE(d.edges.empty());
}

TEST_CASE("boundary: scan finds components from src/ subdirectories", "[boundary][boundary001]") {
    TempDir tmp;
    tmp.write("src/engine/engine.cpp", "#include \"engine.hpp\"\nvoid f(){}\n");
    tmp.write("src/config/config.cpp", "#include \"config.hpp\"\nvoid g(){}\n");
    auto d = boundary::scan(tmp.path());
    bool found_engine = false, found_config = false;
    for (auto& n : d.nodes) {
        if (n.id == "engine") found_engine = true;
        if (n.id == "config") found_config = true;
    }
    REQUIRE(found_engine);
    REQUIRE(found_config);
}

TEST_CASE("boundary: scan marks std::filesystem as external", "[boundary][boundary003]") {
    TempDir tmp;
    tmp.write("src/release/release.cpp",
        "#include <filesystem>\nvoid f(){}\n");
    auto d = boundary::scan(tmp.path());
    bool found_external = false;
    for (auto& n : d.nodes)
        if (n.id == "std::filesystem" && n.is_external) found_external = true;
    REQUIRE(found_external);
}

TEST_CASE("boundary: scan internal components are not external", "[boundary][boundary003]") {
    TempDir tmp;
    tmp.write("src/engine/engine.cpp", "#include \"engine.hpp\"\nvoid f(){}\n");
    auto d = boundary::scan(tmp.path());
    for (auto& n : d.nodes)
        if (n.id == "engine")
            REQUIRE_FALSE(n.is_external);
}

// ─── write_mermaid ────────────────────────────────────────────────────────────

TEST_CASE("boundary: write_mermaid creates a .mermaid file", "[boundary][boundary001]") {
    TempDir tmp;
    boundary::Diagram d;
    d.nodes.push_back({"engine", "engine", false});
    d.nodes.push_back({"nlohmann_json", "nlohmann_json", true});
    d.edges.push_back({"engine", "nlohmann_json", "uses"});
    auto out = tmp.path() / "boundary.mermaid";
    REQUIRE_NOTHROW(boundary::write_mermaid(out, d));
    REQUIRE(std::filesystem::exists(out));
}

TEST_CASE("boundary: mermaid output contains graph TD directive", "[boundary][boundary001]") {
    TempDir tmp;
    boundary::Diagram d;
    d.nodes.push_back({"engine", "engine", false});
    auto out = tmp.path() / "boundary.mermaid";
    boundary::write_mermaid(out, d);
    std::ifstream f(out);
    std::string content((std::istreambuf_iterator<char>(f)), {});
    REQUIRE(content.find("graph") != std::string::npos);
}

// ─── write_dot ────────────────────────────────────────────────────────────────

TEST_CASE("boundary: write_dot creates a .dot file", "[boundary][boundary002]") {
    TempDir tmp;
    boundary::Diagram d;
    d.nodes.push_back({"engine", "engine", false});
    auto out = tmp.path() / "boundary.dot";
    REQUIRE_NOTHROW(boundary::write_dot(out, d));
    REQUIRE(std::filesystem::exists(out));
}

TEST_CASE("boundary: dot output contains digraph keyword", "[boundary][boundary002]") {
    TempDir tmp;
    boundary::Diagram d;
    d.nodes.push_back({"config", "config", false});
    d.nodes.push_back({"nlohmann_json", "nlohmann_json", true});
    d.edges.push_back({"config", "nlohmann_json", "uses"});
    auto out = tmp.path() / "boundary.dot";
    boundary::write_dot(out, d);
    std::ifstream f(out);
    std::string content((std::istreambuf_iterator<char>(f)), {});
    REQUIRE(content.find("digraph") != std::string::npos);
}

TEST_CASE("boundary: dot output marks external nodes as dashed", "[boundary][boundary002]") {
    TempDir tmp;
    boundary::Diagram d;
    d.nodes.push_back({"nlohmann_json", "nlohmann_json", true});
    auto out = tmp.path() / "boundary.dot";
    boundary::write_dot(out, d);
    std::ifstream f(out);
    std::string content((std::istreambuf_iterator<char>(f)), {});
    REQUIRE(content.find("dashed") != std::string::npos);
}
