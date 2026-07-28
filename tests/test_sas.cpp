//fusa:test REQ-SAS001
//fusa:test REQ-SAS002
//fusa:test REQ-SAS003
//fusa:test REQ-SAS004
//fusa:test REQ-SAS005
//fusa:test REQ-SAS006
#include <catch2/catch_all.hpp>
#include "sas/sas.hpp"
#include "testutil/testutil.hpp"
#include <nlohmann/json.hpp>
#include <fstream>

using namespace cpfusa;
using namespace cpfusa::testutil;
using json = nlohmann::json;

// ─── build ────────────────────────────────────────────────────────────────────

TEST_CASE("sas: build returns non-empty SAS", "[sas][sas001]") {
    TempDir tmp;
    auto s = sas::build(tmp.path(), "proj", "1.0", "DAL-B");
    REQUIRE(s.total > 0);
}

TEST_CASE("sas: build sets project and version", "[sas][sas001]") {
    TempDir tmp;
    auto s = sas::build(tmp.path(), "my-proj", "2.0", "DAL-C");
    REQUIRE(s.project == "my-proj");
    REQUIRE(s.version == "2.0");
}

TEST_CASE("sas: build sets dal", "[sas][sas001]") {
    TempDir tmp;
    auto s = sas::build(tmp.path(), "p", "1.0", "DAL-A");
    REQUIRE(s.dal == "DAL-A");
}

TEST_CASE("sas: build present <= total", "[sas][sas001]") {
    TempDir tmp;
    auto s = sas::build(tmp.path(), "p", "1.0", "DAL-B");
    REQUIRE(s.present <= s.total);
}

TEST_CASE("sas: build generated_at is non-empty", "[sas][sas001]") {
    TempDir tmp;
    auto s = sas::build(tmp.path(), "p", "1.0", "DAL-C");
    REQUIRE_FALSE(s.generated_at.empty());
}

TEST_CASE("sas: checklist items have non-empty item names and clauses", "[sas][sas002]") {
    TempDir tmp;
    auto s = sas::build(tmp.path(), "p", "1.0", "DAL-B");
    for (auto& item : s.checklist) {
        REQUIRE_FALSE(item.item.empty());
        REQUIRE_FALSE(item.clause.empty());
    }
}

TEST_CASE("sas: build sets present=true for an existing artifact", "[sas][sas001]") {
    TempDir tmp;
    tmp.write(".fusa.json", R"({"project":"p"})");
    auto s = sas::build(tmp.path(), "p", "1.0", "DAL-B");
    bool found = false;
    for (auto& item : s.checklist) {
        if (item.artifact == ".fusa.json") { REQUIRE(item.present); found = true; }
    }
    REQUIRE(found);
}

// ─── write_json ───────────────────────────────────────────────────────────────

TEST_CASE("sas: write_json creates valid spec 9.3 JSON", "[sas][sas005]") {
    TempDir tmp;
    auto s = sas::build(tmp.path(), "p", "1.0", "DAL-B");
    auto out = tmp.path() / sas::SAS_JSON_FILE;
    REQUIRE_NOTHROW(sas::write_json(out, s, tmp.path().string()));
    std::ifstream f(out);
    json j;
    REQUIRE_NOTHROW(f >> j);
    REQUIRE(j.contains("checklist"));
    REQUIRE(j.contains("summary"));
    REQUIRE(j["kind"] == "sas");
}

TEST_CASE("sas: JSON summary total matches", "[sas][sas005]") {
    TempDir tmp;
    auto s = sas::build(tmp.path(), "p", "1.0", "DAL-A");
    sas::write_json(tmp.path() / sas::SAS_JSON_FILE, s, tmp.path().string());
    std::ifstream f(tmp.path() / sas::SAS_JSON_FILE);
    json j; f >> j;
    REQUIRE(j["summary"]["total"].get<int>() == s.total);
}

TEST_CASE("sas: JSON summary present matches", "[sas][sas005]") {
    TempDir tmp;
    auto s = sas::build(tmp.path(), "p", "1.0", "DAL-B");
    sas::write_json(tmp.path() / sas::SAS_JSON_FILE, s, tmp.path().string());
    std::ifstream f(tmp.path() / sas::SAS_JSON_FILE);
    json j; f >> j;
    REQUIRE(j["summary"]["present"].get<int>() == s.present);
}

TEST_CASE("sas: JSON checklist items have item/clause/present fields", "[sas][sas005]") {
    TempDir tmp;
    auto s = sas::build(tmp.path(), "p", "1.0", "DAL-A");
    sas::write_json(tmp.path() / sas::SAS_JSON_FILE, s, tmp.path().string());
    std::ifstream f(tmp.path() / sas::SAS_JSON_FILE);
    json j; f >> j;
    for (auto& item : j["checklist"]) {
        REQUIRE(item.contains("item"));
        REQUIRE(item.contains("clause"));
        REQUIRE(item.contains("present"));
    }
}

TEST_CASE("sas: JSON checklist array size matches struct", "[sas][sas005]") {
    TempDir tmp;
    auto s = sas::build(tmp.path(), "p", "1.0", "DAL-B");
    sas::write_json(tmp.path() / sas::SAS_JSON_FILE, s, tmp.path().string());
    std::ifstream f(tmp.path() / sas::SAS_JSON_FILE);
    json j; f >> j;
    REQUIRE(j["checklist"].size() == s.checklist.size());
}

// ─── write_markdown ───────────────────────────────────────────────────────────

TEST_CASE("sas: write_markdown creates a file", "[sas][sas003]") {
    TempDir tmp;
    auto s = sas::build(tmp.path(), "p", "1.0", "DAL-C");
    auto out = tmp.path() / sas::SAS_MD_FILE;
    REQUIRE_NOTHROW(sas::write_markdown(out, s));
    REQUIRE(std::filesystem::exists(out));
    REQUIRE(std::filesystem::file_size(out) > 0);
}

TEST_CASE("sas: markdown contains Checklist section", "[sas][sas003]") {
    TempDir tmp;
    auto s = sas::build(tmp.path(), "MyProj", "1.0", "DAL-B");
    sas::write_markdown(tmp.path() / sas::SAS_MD_FILE, s);
    std::ifstream f(tmp.path() / sas::SAS_MD_FILE);
    std::string content((std::istreambuf_iterator<char>(f)), {});
    REQUIRE(content.find("Checklist") != std::string::npos);
}

TEST_CASE("sas: markdown contains project name", "[sas][sas003]") {
    TempDir tmp;
    auto s = sas::build(tmp.path(), "MyProjectName", "1.0", "DAL-C");
    sas::write_markdown(tmp.path() / sas::SAS_MD_FILE, s);
    std::ifstream f(tmp.path() / sas::SAS_MD_FILE);
    std::string content((std::istreambuf_iterator<char>(f)), {});
    REQUIRE(content.find("MyProjectName") != std::string::npos);
}

// ─── §1.6.1 quality scan wiring ───────────────────────────────────────────────

TEST_CASE("sas: scan_quality flags a placeholder checklist item", "[sas][sas006]") {
    sas::SAS s;
    s.checklist.push_back({"[fill in item name]", "11.1", "x.json", false});
    auto findings = sas::scan_quality(s);
    bool found = false;
    for (auto& f : findings) if (f.rule_id == "FUSA-STUB001") found = true;
    REQUIRE(found);
}

TEST_CASE("sas: scan_quality is clean for the real baseline checklist", "[sas][sas006]") {
    TempDir tmp;
    auto s = sas::build(tmp.path(), "p", "1.0", "DAL-B");
    auto findings = sas::scan_quality(s);
    for (auto& f : findings) REQUIRE(f.rule_id != "FUSA-STUB001");
}
