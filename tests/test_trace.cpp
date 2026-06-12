//fusa:test REQ-TRACE001 REQ-TRACE002 REQ-TRACE003 REQ-TRACE004 REQ-TRACE005 REQ-TRACE006 REQ-TRACE007 REQ-TRACE008 REQ-TRACE010 REQ-TRACE011 REQ-TRACE012 REQ-TRACE013 REQ-TRACE014 REQ-TRACE015
#include <catch2/catch_all.hpp>
#include "trace/trace.hpp"
#include "testutil/testutil.hpp"
#include <nlohmann/json.hpp>

using json = nlohmann::json;

using namespace cpfusa;
using namespace cpfusa::testutil;

// ─── scan_annotations ────────────────────────────────────────────────────────

TEST_CASE("trace: scan_annotations finds fusa:req", "[trace][trace001]") {
    TempDir tmp;
    tmp.write("src/foo.cpp",
              "// fusa:req REQ-001\n"
              "void safety_fn() {}\n");
    auto anns = trace::scan_annotations(tmp.path());
    REQUIRE(anns.size() == 1);
    REQUIRE(anns[0].req_id == "REQ-001");
    REQUIRE_FALSE(anns[0].is_test);
}

TEST_CASE("trace: scan_annotations finds fusa:test", "[trace][trace001]") {
    TempDir tmp;
    tmp.write("tests/test_foo.cpp",
              "// fusa:test REQ-001\n"
              "TEST_CASE(\"test\") {}\n");
    auto anns = trace::scan_annotations(tmp.path());
    REQUIRE(anns.size() == 1);
    REQUIRE(anns[0].req_id == "REQ-001");
    REQUIRE(anns[0].is_test);
}

TEST_CASE("trace: scan_annotations finds multiple reqs in one file", "[trace][trace001]") {
    TempDir tmp;
    tmp.write("src/foo.cpp",
              "// fusa:req REQ-001\n"
              "void fn1() {}\n"
              "// fusa:req REQ-002\n"
              "void fn2() {}\n");
    auto anns = trace::scan_annotations(tmp.path());
    REQUIRE(anns.size() == 2);
}

TEST_CASE("trace: scan_annotations empty dir yields empty list", "[trace][trace001]") {
    TempDir tmp;
    REQUIRE(trace::scan_annotations(tmp.path()).empty());
}

TEST_CASE("trace: scan_annotations finds annotations in both src and tests", "[trace][trace002]") {
    TempDir tmp;
    tmp.write("src/a.cpp",  "// fusa:req REQ-001\nvoid a() {}\n");
    tmp.write("tests/t.cpp","// fusa:test REQ-001\nTEST_CASE(\"t\"){}\n");
    auto anns = trace::scan_annotations(tmp.path());
    bool found_req = false, found_test = false;
    for (const auto& a : anns) {
        if (!a.is_test) found_req  = true;
        else            found_test = true;
    }
    REQUIRE(found_req);
    REQUIRE(found_test);
}

// ─── load_requirements ────────────────────────────────────────────────────────

TEST_CASE("trace: load_requirements returns empty when file absent", "[trace][trace003]") {
    TempDir tmp;
    auto r = trace::load_requirements(tmp.path());
    REQUIRE(is_ok(r));
    REQUIRE(value_of(r).empty());
}

TEST_CASE("trace: load_requirements parses flat JSON array", "[trace][trace003]") {
    TempDir tmp;
    // load_requirements expects a flat JSON array (not wrapped in {"requirements":[...]})
    tmp.write(".fusa-reqs.json", R"([
      {"id":"REQ-001","title":"Config must exist","severity":"safety"},
      {"id":"REQ-002","title":"Version must be set","severity":"safety"}
    ])");
    auto r = trace::load_requirements(tmp.path());
    REQUIRE(is_ok(r));
    REQUIRE(value_of(r).size() == 2);
    REQUIRE(value_of(r)[0].id == "REQ-001");
    REQUIRE(value_of(r)[1].id == "REQ-002");
}

TEST_CASE("trace: load_requirements reads title field", "[trace][trace003]") {
    TempDir tmp;
    tmp.write(".fusa-reqs.json", R"([{"id":"REQ-001","title":"Safety config","severity":"safety"}])");
    auto reqs = value_of(trace::load_requirements(tmp.path()));
    REQUIRE(reqs[0].title == "Safety config");
}

// ─── run ─────────────────────────────────────────────────────────────────────

TEST_CASE("trace: run with no requirements file succeeds", "[trace][trace004]") {
    TempDir tmp;
    config::ProjectConfig cfg; cfg.project = "test"; cfg.version = "1.0.0";
    auto r = trace::run(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    REQUIRE(value_of(r).total == 0);
}

TEST_CASE("trace: run counts annotation coverage", "[trace][trace004]") {
    TempDir tmp;
    tmp.write(".fusa-reqs.json", R"([{"id":"REQ-001","title":"T","severity":"safety"}])");
    tmp.write("src/a.cpp", "//fusa:req REQ-001\nvoid f(){}\n");
    config::ProjectConfig cfg; cfg.project = "p"; cfg.version = "1.0.0";
    auto r = trace::run(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    REQUIRE(value_of(r).total == 1);
}

TEST_CASE("trace: coverage gate does not fail when total is 0", "[trace][trace005]") {
    TempDir tmp;
    config::ProjectConfig cfg; cfg.project = "test"; cfg.version = "1.0.0";
    trace::TraceOptions opts; opts.min_test_pct = 80;
    REQUIRE(is_ok(trace::run(tmp.path(), cfg, opts)));
}

// ─── render_matrix ────────────────────────────────────────────────────────────

TEST_CASE("trace: render_matrix handles no requirements gracefully", "[trace][trace006]") {
    trace::TraceResult res; trace::TraceOptions opts;
    REQUIRE_FALSE(trace::render_matrix(res, opts).empty());
}

TEST_CASE("trace: render_matrix contains req IDs when present", "[trace][trace006]") {
    TempDir tmp;
    tmp.write(".fusa-reqs.json", R"([{"id":"REQ-001","title":"T","severity":"safety"}])");
    config::ProjectConfig cfg; cfg.project = "p"; cfg.version = "1.0.0";
    auto res = value_of(trace::run(tmp.path(), cfg));
    auto txt = trace::render_matrix(res, {});
    REQUIRE(txt.find("REQ-001") != std::string::npos);
}

// ─── render_json (§5 trace-matrix) ───────────────────────────────────────────

TEST_CASE("trace: render_json produces valid JSON", "[trace][trace006]") {
    TempDir tmp;
    config::ProjectConfig cfg; cfg.project = "p"; cfg.version = "1.0.0";
    auto res = value_of(trace::run(tmp.path(), cfg));
    REQUIRE_NOTHROW(json::parse(trace::render_json(res, cfg)));
}

TEST_CASE("trace: render_json has spec v1.10 envelope", "[trace][trace006]") {
    TempDir tmp;
    config::ProjectConfig cfg; cfg.project = "TestProj"; cfg.version = "1.0.0";
    auto res = value_of(trace::run(tmp.path(), cfg));
    auto j = json::parse(trace::render_json(res, cfg));
    REQUIRE(j["schemaVersion"] == "1.10");
    REQUIRE(j["kind"] == "trace-matrix");
    REQUIRE(j["tool"] == "cpp-FuSa");
    REQUIRE(j["language"] == "cpp");
    REQUIRE(j["project"] == "TestProj");
    REQUIRE_FALSE(j["generatedAt"].get<std::string>().empty());
}

TEST_CASE("trace: render_json requirements array contains req IDs", "[trace][trace006]") {
    TempDir tmp;
    tmp.write(".fusa-reqs.json", R"([{"id":"REQ-001","title":"T","severity":"safety"}])");
    config::ProjectConfig cfg; cfg.project = "p"; cfg.version = "1.0.0";
    auto res = value_of(trace::run(tmp.path(), cfg));
    auto j = json::parse(trace::render_json(res, cfg));
    REQUIRE(j["requirements"].is_array());
    REQUIRE(j["requirements"].size() == 1);
    REQUIRE(j["requirements"][0]["id"] == "REQ-001");
}

TEST_CASE("trace: render_json requirements use canonical standard key not standardRef", "[trace][trace006]") {
    //fusa:test REQ-TRACE013
    TempDir tmp;
    tmp.write(".fusa-reqs.json",
        R"([{"id":"REQ-001","title":"T","severity":"safety","standard_ref":"iso26262"}])");
    config::ProjectConfig cfg; cfg.project = "p"; cfg.version = "1.0.0";
    auto res = value_of(trace::run(tmp.path(), cfg));
    auto j = json::parse(trace::render_json(res, cfg));
    REQUIRE(j["requirements"].size() == 1);
    REQUIRE(j["requirements"][0].contains("standard"));
    REQUIRE_FALSE(j["requirements"][0].contains("standardRef"));
    REQUIRE(j["requirements"][0]["standard"] == "iso26262");
}

TEST_CASE("trace: render_json tags is top-level flat array with impl and test kinds", "[trace][trace006]") {
    TempDir tmp;
    tmp.write(".fusa-reqs.json", R"([{"id":"REQ-001","title":"T","severity":"safety"}])");
    tmp.write("src/a.cpp",   "//fusa:req REQ-001\nvoid f(){}\n");
    tmp.write("tests/t.cpp", "//fusa:test REQ-001\nvoid t(){}\n");
    config::ProjectConfig cfg; cfg.project = "p"; cfg.version = "1.0.0";
    auto res = value_of(trace::run(tmp.path(), cfg));
    auto j = json::parse(trace::render_json(res, cfg));
    // §5: top-level flat tags[] — not nested inside requirements
    REQUIRE(j["tags"].is_array());
    REQUIRE(j["tags"].size() == 2);
    bool has_impl = false, has_test = false;
    for (const auto& tag : j["tags"]) {
        REQUIRE(tag["requirementId"] == "REQ-001");
        REQUIRE_FALSE(tag["file"].get<std::string>().empty());
        REQUIRE(tag["line"].is_number());
        std::string k = tag["kind"].get<std::string>();
        if (k == "impl") has_impl = true;
        if (k == "test") has_test = true;
    }
    REQUIRE(has_impl);
    REQUIRE(has_test);
    // requirements[] must NOT have nested tags
    REQUIRE_FALSE(j["requirements"][0].contains("tags"));
}

TEST_CASE("trace: render_json coverage block has spec-canonical fields", "[trace][trace006]") {
    TempDir tmp;
    config::ProjectConfig cfg; cfg.project = "p"; cfg.version = "1.0.0";
    auto res = value_of(trace::run(tmp.path(), cfg));
    auto j = json::parse(trace::render_json(res, cfg));
    REQUIRE(j["coverage"].contains("totalRequirements"));
    REQUIRE(j["coverage"].contains("tracedRequirements"));
    REQUIRE(j["coverage"].contains("testedRequirements"));
    REQUIRE(j["coverage"].contains("secTestedRequirements"));
    REQUIRE_FALSE(j.contains("summary"));
}

TEST_CASE("trace: render_json coverage secTestedRequirements is present", "[trace][trace006]") {
    TempDir tmp;
    config::ProjectConfig cfg; cfg.project = "p"; cfg.version = "1.0.0";
    auto res = value_of(trace::run(tmp.path(), cfg));
    auto j = json::parse(trace::render_json(res, cfg));
    REQUIRE(j["coverage"].contains("secTestedRequirements"));
}

TEST_CASE("trace: secTestedRequirements counts cybersecurity reqs with test annotations", "[trace][trace008]") {
    TempDir tmp;
    tmp.write(".fusa-reqs.json",
        R"([{"id":"REQ-S01","title":"T","severity":"safety"},{"id":"REQ-C01","title":"C","severity":"cybersecurity"}])");
    tmp.write("src/a.cpp",   "//fusa:req REQ-S01\n//fusa:req REQ-C01\nvoid f(){}\n");
    tmp.write("tests/t.cpp", "//fusa:test REQ-S01\n//fusa:test REQ-C01\nvoid t(){}\n");
    config::ProjectConfig cfg; cfg.project = "p"; cfg.version = "1.0.0";
    auto res = value_of(trace::run(tmp.path(), cfg));
    auto j = json::parse(trace::render_json(res, cfg));
    REQUIRE(j["coverage"]["secTestedRequirements"] == 1);
}

TEST_CASE("trace: render_json sec-test kind for cybersecurity requirement", "[trace][trace008]") {
    TempDir tmp;
    tmp.write(".fusa-reqs.json",
        R"([{"id":"REQ-C01","title":"C","severity":"cybersecurity"}])");
    tmp.write("tests/t.cpp", "//fusa:test REQ-C01\nvoid t(){}\n");
    config::ProjectConfig cfg; cfg.project = "p"; cfg.version = "1.0.0";
    auto res = value_of(trace::run(tmp.path(), cfg));
    auto j = json::parse(trace::render_json(res, cfg));
    bool found_sec_test = false;
    for (const auto& tag : j["tags"]) {
        if (tag["kind"] == "sec-test") { found_sec_test = true; break; }
    }
    REQUIRE(found_sec_test);
}

// ─── render_req ──────────────────────────────────────────────────────────────

TEST_CASE("trace: render_req includes req ID in output", "[trace][trace007]") {
    trace::Requirement req;
    req.id    = "REQ-042";
    req.title = "Something important";
    auto anns = trace::scan_annotations(TempDir{}.path());
    REQUIRE(trace::render_req(req, anns).find("REQ-042") != std::string::npos);
}

// ─── asil field round-trip ───────────────────────────────────────────────────

TEST_CASE("trace: requirement asil field round-trips through save and load", "[trace]") {
    TempDir tmp;
    trace::Requirement r;
    r.id       = "REQ-ASIL-001";
    r.title    = "ASIL test requirement";
    r.severity = "safety";
    r.asil     = "ASIL-B";
    std::vector<trace::Requirement> reqs{r};
    REQUIRE(trace::save_requirements(tmp.path(), reqs));
    auto result = trace::load_requirements(tmp.path());
    REQUIRE(is_ok(result));
    const auto& loaded = value_of(result);
    REQUIRE(loaded.size() == 1);
    REQUIRE(loaded[0].asil == "ASIL-B");
}

TEST_CASE("trace: export csv includes asil column", "[trace]") {
    trace::Requirement r;
    r.id       = "REQ-001";
    r.title    = "Test req";
    r.severity = "safety";
    r.asil     = "ASIL-B";
    std::vector<trace::Requirement> reqs{r};
    std::string csv = trace::export_csv(reqs);
    REQUIRE(csv.find("asil") != std::string::npos);
    REQUIRE(csv.find("ASIL-B") != std::string::npos);
}

// ─── DOORS ReqIF import/export ───────────────────────────────────────────────

TEST_CASE("trace: import doors reads SPEC-OBJECT elements", "[trace]") {
    TempDir tmp;
    tmp.write("reqs.reqif", R"(<?xml version="1.0"?>
<REQ-IF>
  <CORE-CONTENT>
    <SPEC-OBJECTS>
      <SPEC-OBJECT>
        <VALUES>
          <ATTRIBUTE-VALUE-STRING THE-VALUE="REQ-DOORS-001"/>
          <ATTRIBUTE-VALUE-STRING THE-VALUE="Doors requirement one"/>
        </VALUES>
      </SPEC-OBJECT>
      <SPEC-OBJECT>
        <VALUES>
          <ATTRIBUTE-VALUE-STRING THE-VALUE="REQ-DOORS-002"/>
          <ATTRIBUTE-VALUE-STRING THE-VALUE="Doors requirement two"/>
        </VALUES>
      </SPEC-OBJECT>
    </SPEC-OBJECTS>
  </CORE-CONTENT>
</REQ-IF>
)");
    std::vector<trace::Requirement> reqs;
    auto result = trace::import_doors(tmp.path() / "reqs.reqif", reqs);
    REQUIRE(is_ok(result));
    REQUIRE(value_of(result) == 2);
    REQUIRE(reqs.size() == 2);
    REQUIRE(reqs[0].id == "REQ-DOORS-001");
    REQUIRE(reqs[0].title == "Doors requirement one");
}

TEST_CASE("trace: import doors skips duplicates", "[trace]") {
    TempDir tmp;
    tmp.write("reqs.reqif", R"(<?xml version="1.0"?>
<REQ-IF>
  <CORE-CONTENT>
    <SPEC-OBJECTS>
      <SPEC-OBJECT>
        <VALUES>
          <ATTRIBUTE-VALUE-STRING THE-VALUE="REQ-001"/>
          <ATTRIBUTE-VALUE-STRING THE-VALUE="Already exists"/>
        </VALUES>
      </SPEC-OBJECT>
    </SPEC-OBJECTS>
  </CORE-CONTENT>
</REQ-IF>
)");
    trace::Requirement existing;
    existing.id = "REQ-001";
    std::vector<trace::Requirement> reqs{existing};
    auto result = trace::import_doors(tmp.path() / "reqs.reqif", reqs);
    REQUIRE(is_ok(result));
    REQUIRE(value_of(result) == 0);
    REQUIRE(reqs.size() == 1);
}

TEST_CASE("trace: export doors produces valid XML", "[trace]") {
    trace::Requirement r;
    r.id    = "REQ-001";
    r.title = "Safety boot check";
    r.asil  = "ASIL-B";
    std::vector<trace::Requirement> reqs{r};
    std::string xml = trace::export_doors(reqs);
    REQUIRE(xml.find("REQ-IF") != std::string::npos);
    REQUIRE(xml.find("REQ-001") != std::string::npos);
    REQUIRE(xml.find("Safety boot check") != std::string::npos);
}

// ─── Polarion XML import/export ──────────────────────────────────────────────

TEST_CASE("trace: import polarion reads workItem elements", "[trace]") {
    TempDir tmp;
    tmp.write("polarion.xml", R"(<?xml version="1.0"?>
<workItems>
  <workItem id="REQ-POL-001">
    <title>Polarion requirement one</title>
  </workItem>
  <workItem id="REQ-POL-002">
    <title>Polarion requirement two</title>
  </workItem>
</workItems>
)");
    std::vector<trace::Requirement> reqs;
    auto result = trace::import_polarion(tmp.path() / "polarion.xml", reqs);
    REQUIRE(is_ok(result));
    REQUIRE(value_of(result) == 2);
    REQUIRE(reqs.size() == 2);
    REQUIRE(reqs[0].id == "REQ-POL-001");
    REQUIRE(reqs[0].title == "Polarion requirement one");
}

TEST_CASE("trace: export polarion produces XML with workItem elements", "[trace]") {
    trace::Requirement r;
    r.id    = "REQ-001";
    r.title = "Safety requirement";
    r.asil  = "ASIL-C";
    std::vector<trace::Requirement> reqs{r};
    std::string xml = trace::export_polarion(reqs);
    REQUIRE(xml.find("workItem") != std::string::npos);
    REQUIRE(xml.find("REQ-001") != std::string::npos);
    REQUIRE(xml.find("Safety requirement") != std::string::npos);
    REQUIRE(xml.find("ASIL-C") != std::string::npos);
}
