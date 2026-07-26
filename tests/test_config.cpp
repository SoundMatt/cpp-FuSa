//fusa:test REQ-CFG001
//fusa:test REQ-CFG002
//fusa:test REQ-CFG003
//fusa:test REQ-CFG004
//fusa:test REQ-CFG005
//fusa:test REQ-CFG006
#include <catch2/catch_all.hpp>
#include "config/config.hpp"
#include "testutil/testutil.hpp"
#include <nlohmann/json.hpp>
#include <fstream>

using namespace cpfusa;
using namespace cpfusa::testutil;
using json = nlohmann::json;

// ─── defaults ────────────────────────────────────────────────────────────────

TEST_CASE("config: defaults populate reasonable values", "[config][cfg001]") {
    TempDir tmp;
    auto cfg = config::defaults(tmp.path());
    REQUIRE_FALSE(cfg.project.empty());
    REQUIRE(cfg.version == "0.1.0");
    REQUIRE(cfg.standard == "iso26262");
}

TEST_CASE("config: defaults language is canonical cpp", "[config][cfg001]") {
    TempDir tmp;
    auto cfg = config::defaults(tmp.path());
    REQUIRE(cfg.language == "cpp");
}

TEST_CASE("config: defaults asil is ASIL-B", "[config][cfg001]") {
    TempDir tmp;
    auto cfg = config::defaults(tmp.path());
    REQUIRE(cfg.asil == "ASIL-B");
}

TEST_CASE("config: defaults set project_root to absolute path", "[config][cfg001]") {
    TempDir tmp;
    auto cfg = config::defaults(tmp.path());
    REQUIRE_FALSE(cfg.project_root.empty());
    // Accept both POSIX '/' and Windows '\' path separators.
    const bool has_sep = cfg.project_root.find('/') != std::string::npos
                      || cfg.project_root.find('\\') != std::string::npos;
    REQUIRE(has_sep);
}

// ─── save / load round-trip ───────────────────────────────────────────────────

TEST_CASE("config: save and load round-trip", "[config][cfg002]") {
    TempDir tmp;
    auto cfg = config::defaults(tmp.path());
    cfg.project  = "MyProject";
    cfg.version  = "1.2.3";
    cfg.standard = "iec61508";
    cfg.asil     = "SIL-3";
    REQUIRE(is_ok(config::save(tmp.path(), cfg)));
    auto load_r = config::load(tmp.path());
    REQUIRE(is_ok(load_r));
    const auto& loaded = value_of(load_r);
    REQUIRE(loaded.project  == "MyProject");
    REQUIRE(loaded.version  == "1.2.3");
    REQUIRE(loaded.standard == "iec61508");
    REQUIRE(loaded.asil     == "SIL-3");
}

TEST_CASE("config: save writes configVersion 1.0", "[config][cfg002]") {
    TempDir tmp;
    auto cfg = config::defaults(tmp.path());
    REQUIRE(is_ok(config::save(tmp.path(), cfg)));
    std::ifstream f(tmp.path() / ".fusa.json");
    json j; f >> j;
    REQUIRE(j["configVersion"] == "1.0");
}

TEST_CASE("config: save writes nested project object", "[config][cfg002]") {
    TempDir tmp;
    auto cfg = config::defaults(tmp.path());
    cfg.project = "NestTest";
    cfg.version = "2.0.0";
    REQUIRE(is_ok(config::save(tmp.path(), cfg)));
    std::ifstream f(tmp.path() / ".fusa.json");
    json j; f >> j;
    REQUIRE(j["project"].is_object());
    REQUIRE(j["project"]["name"]    == "NestTest");
    REQUIRE(j["project"]["version"] == "2.0.0");
}

TEST_CASE("config: save writes camelCase sourceDirs", "[config][cfg002]") {
    TempDir tmp;
    auto cfg = config::defaults(tmp.path());
    cfg.source_dirs = {"src", "lib"};
    REQUIRE(is_ok(config::save(tmp.path(), cfg)));
    std::ifstream f(tmp.path() / ".fusa.json");
    json j; f >> j;
    REQUIRE(j.contains("sourceDirs"));
    REQUIRE_FALSE(j.contains("source_dirs"));
}

TEST_CASE("config: save writes camelCase excludePatterns", "[config][cfg002]") {
    TempDir tmp;
    auto cfg = config::defaults(tmp.path());
    cfg.exclude_patterns = {"build/", "_deps/"};
    REQUIRE(is_ok(config::save(tmp.path(), cfg)));
    std::ifstream f(tmp.path() / ".fusa.json");
    json j; f >> j;
    REQUIRE(j.contains("excludePatterns"));
    REQUIRE_FALSE(j.contains("exclude_patterns"));
}

TEST_CASE("config: SIL prefix saves under sil key", "[config][cfg003]") {
    TempDir tmp;
    auto cfg = config::defaults(tmp.path());
    cfg.standard = "iec61508";
    cfg.asil     = "SIL-2";
    REQUIRE(is_ok(config::save(tmp.path(), cfg)));
    std::ifstream f(tmp.path() / ".fusa.json");
    json j; f >> j;
    REQUIRE(j.contains("sil"));
    REQUIRE_FALSE(j.contains("asil"));
    REQUIRE_FALSE(j.contains("dal"));
    REQUIRE(j["sil"] == "SIL-2");
}

TEST_CASE("config: DAL prefix saves under dal key", "[config][cfg003]") {
    TempDir tmp;
    auto cfg = config::defaults(tmp.path());
    cfg.standard = "do178c";
    cfg.asil     = "DAL-B";
    REQUIRE(is_ok(config::save(tmp.path(), cfg)));
    std::ifstream f(tmp.path() / ".fusa.json");
    json j; f >> j;
    REQUIRE(j.contains("dal"));
    REQUIRE_FALSE(j.contains("asil"));
    REQUIRE(j["dal"] == "DAL-B");
}

TEST_CASE("config: ASIL prefix saves under asil key", "[config][cfg003]") {
    TempDir tmp;
    auto cfg = config::defaults(tmp.path());
    cfg.standard = "iso26262";
    cfg.asil     = "ASIL-C";
    REQUIRE(is_ok(config::save(tmp.path(), cfg)));
    std::ifstream f(tmp.path() / ".fusa.json");
    json j; f >> j;
    REQUIRE(j.contains("asil"));
    REQUIRE(j["asil"] == "ASIL-C");
}

TEST_CASE("config: load reads sil key into asil field", "[config][cfg004]") {
    TempDir tmp;
    tmp.write(".fusa.json", R"({
      "configVersion":"1.0",
      "project":{"name":"P","version":"1.0"},
      "standard":"iec61508",
      "sil":"SIL-3",
      "sourceDirs":["src"]
    })");
    auto r = config::load(tmp.path());
    REQUIRE(is_ok(r));
    REQUIRE(value_of(r).asil == "SIL-3");
}

TEST_CASE("config: load reads dal key into asil field", "[config][cfg004]") {
    TempDir tmp;
    tmp.write(".fusa.json", R"({
      "configVersion":"1.0",
      "project":{"name":"P","version":"1.0"},
      "standard":"do178c",
      "dal":"DAL-A",
      "sourceDirs":["src"]
    })");
    auto r = config::load(tmp.path());
    REQUIRE(is_ok(r));
    REQUIRE(value_of(r).asil == "DAL-A");
}

TEST_CASE("config: load accepts legacy flat project string", "[config][cfg005]") {
    TempDir tmp;
    tmp.write(".fusa.json", R"({
      "project":"LegacyName",
      "version":"3.0.0",
      "standard":"iso26262",
      "asil":"B"
    })");
    auto r = config::load(tmp.path());
    REQUIRE(is_ok(r));
    REQUIRE(value_of(r).project == "LegacyName");
    REQUIRE(value_of(r).version == "3.0.0");
}

TEST_CASE("config: load accepts legacy snake_case source_dirs", "[config][cfg005]") {
    TempDir tmp;
    tmp.write(".fusa.json", R"({
      "project":"P",
      "version":"1.0",
      "standard":"iso26262",
      "asil":"B",
      "source_dirs":["src","include"]
    })");
    auto r = config::load(tmp.path());
    REQUIRE(is_ok(r));
    REQUIRE(value_of(r).source_dirs.size() == 2);
}

TEST_CASE("config: load sets project_root to absolute path", "[config][cfg005]") {
    TempDir tmp;
    auto cfg = config::defaults(tmp.path());
    REQUIRE(is_ok(config::save(tmp.path(), cfg)));
    auto r = config::load(tmp.path());
    REQUIRE(is_ok(r));
    REQUIRE_FALSE(value_of(r).project_root.empty());
}

// ─── exists / missing ─────────────────────────────────────────────────────────

TEST_CASE("config: missing file returns ErrNoConfig", "[config][cfg006]") {
    TempDir tmp;
    auto r = config::load(tmp.path());
    REQUIRE_FALSE(is_ok(r));
    REQUIRE(error_of(r) == std::string(ErrNoConfig));
}

TEST_CASE("config: exists() correctly reports presence", "[config][cfg006]") {
    TempDir tmp;
    REQUIRE_FALSE(config::exists(tmp.path()));
    REQUIRE(is_ok(config::save(tmp.path(), config::defaults(tmp.path()))));
    REQUIRE(config::exists(tmp.path()));
}
