//fusa:test REQ-TRACE001
//fusa:test REQ-TRACE002
//fusa:test REQ-TRACE003
//fusa:test REQ-TRACE004
//fusa:test REQ-TRACE005
//fusa:test REQ-TRACE006
//fusa:test REQ-TRACE007
//fusa:test REQ-TRACE008
//fusa:test REQ-TRACE009
//fusa:test REQ-TRACE010
//fusa:test REQ-TRACE011
//fusa:test REQ-TRACE012
//fusa:test REQ-TRACE013
//fusa:test REQ-TRACE014
//fusa:test REQ-TRACE015
//fusa:test REQ-TRACE016
//fusa:test REQ-TRACE017
//fusa:test REQ-TRACE018
//fusa:test REQ-TRACE019
//fusa:test REQ-TRACE020
//fusa:test REQ-HLR001
//fusa:test REQ-HLR002
//fusa:test REQ-HLR003
//fusa:test REQ-HLR004
//fusa:test REQ-HLR005
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

TEST_CASE("trace: render_json has spec v1.10.12 envelope", "[trace][trace006]") {
    TempDir tmp;
    config::ProjectConfig cfg; cfg.project = "TestProj"; cfg.version = "1.0.0";
    auto res = value_of(trace::run(tmp.path(), cfg));
    auto j = json::parse(trace::render_json(res, cfg));
    REQUIRE(j["schemaVersion"] == "1.10.12");
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

// ─── HLR/LLR Decomposition (REQ-HLR001..REQ-HLR005) ──────────────────────────

TEST_CASE("trace: parent_id round-trips through save and load", "[trace][hlr]") {
    //fusa:test REQ-HLR001
    TempDir tmp;
    trace::Requirement hlr;
    hlr.id       = "REQ-HLR-001";
    hlr.title    = "HLR safety requirement";
    hlr.severity = "safety";

    trace::Requirement llr;
    llr.id        = "REQ-LLR-001";
    llr.title     = "LLR sub-requirement";
    llr.severity  = "safety";
    llr.parent_id = "REQ-HLR-001";

    std::vector<trace::Requirement> reqs{hlr, llr};
    REQUIRE(trace::save_requirements(tmp.path(), reqs));

    auto result = trace::load_requirements(tmp.path());
    REQUIRE(is_ok(result));
    const auto& loaded = value_of(result);
    REQUIRE(loaded.size() == 2);
    REQUIRE(loaded[0].parent_id.empty());  // HLR has no parent
    REQUIRE(loaded[1].parent_id == "REQ-HLR-001");
}

TEST_CASE("trace: run counts hlr_count and llr_count", "[trace][hlr]") {
    //fusa:test REQ-HLR001
    TempDir tmp;
    tmp.write(".fusa-reqs.json", R"([
      {"id":"REQ-HLR-001","title":"HLR","severity":"safety"},
      {"id":"REQ-LLR-001","title":"LLR","severity":"safety","parent_id":"REQ-HLR-001"}
    ])");
    config::ProjectConfig cfg; cfg.project = "p"; cfg.version = "1.0.0";
    auto r = trace::run(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    REQUIRE(value_of(r).hlr_count == 1);
    REQUIRE(value_of(r).llr_count == 1);
}

TEST_CASE("trace: run hlr_covered counts HLRs with at least one LLR child", "[trace][hlr]") {
    //fusa:test REQ-HLR002
    TempDir tmp;
    tmp.write(".fusa-reqs.json", R"([
      {"id":"REQ-HLR-001","title":"HLR covered","severity":"safety"},
      {"id":"REQ-HLR-002","title":"HLR orphan","severity":"safety"},
      {"id":"REQ-LLR-001","title":"LLR","severity":"safety","parent_id":"REQ-HLR-001"}
    ])");
    config::ProjectConfig cfg; cfg.project = "p"; cfg.version = "1.0.0";
    auto r = trace::run(tmp.path(), cfg);
    REQUIRE(is_ok(r));
    REQUIRE(value_of(r).hlr_covered == 1);
    // REQ-HLR-002 has no children — expect a violation (warn level)
    REQUIRE_FALSE(value_of(r).hlr_violations.empty());
}

TEST_CASE("trace: run reports violation when LLR references unknown HLR", "[trace][hlr]") {
    //fusa:test REQ-HLR003
    TempDir tmp;
    tmp.write(".fusa-reqs.json", R"([
      {"id":"REQ-LLR-001","title":"Orphan LLR","severity":"safety","parent_id":"REQ-HLR-NONEXISTENT"}
    ])");
    config::ProjectConfig cfg; cfg.project = "p"; cfg.version = "1.0.0";
    auto r = trace::run(tmp.path(), cfg);
    // No ASIL-C/D, no strict flag → warn not error
    REQUIRE(is_ok(r));
    REQUIRE_FALSE(value_of(r).hlr_violations.empty());
    bool found_llr_viol = false;
    for (const auto& v : value_of(r).hlr_violations)
        if (!v.llr_id.empty()) { found_llr_viol = true; break; }
    REQUIRE(found_llr_viol);
}

TEST_CASE("trace: strict_hlr_llr flag errors on violations", "[trace][hlr]") {
    //fusa:test REQ-HLR004
    TempDir tmp;
    tmp.write(".fusa-reqs.json", R"([
      {"id":"REQ-HLR-001","title":"HLR no children","severity":"safety"}
    ])");
    config::ProjectConfig cfg; cfg.project = "p"; cfg.version = "1.0.0";
    trace::TraceOptions opts;
    opts.strict_hlr_llr = true;
    auto r = trace::run(tmp.path(), cfg, opts);
    // strict mode → should return error
    REQUIRE_FALSE(is_ok(r));
}

TEST_CASE("trace: ASIL-D HLR violation causes error without strict flag", "[trace][hlr]") {
    //fusa:test REQ-HLR004
    TempDir tmp;
    tmp.write(".fusa-reqs.json", R"([
      {"id":"REQ-HLR-001","title":"HLR no children","severity":"safety","asil":"ASIL-D"}
    ])");
    config::ProjectConfig cfg; cfg.project = "p"; cfg.version = "1.0.0"; cfg.asil = "ASIL-D";
    auto r = trace::run(tmp.path(), cfg);
    // ASIL-D project → gate is error (REQ-HLR004)
    REQUIRE_FALSE(is_ok(r));
}

TEST_CASE("trace: ASIL-C HLR violation causes error without strict flag", "[trace][hlr]") {
    //fusa:test REQ-HLR004
    TempDir tmp;
    tmp.write(".fusa-reqs.json", R"([
      {"id":"REQ-HLR-001","title":"HLR no children ASIL-C","severity":"safety","asil":"ASIL-C"}
    ])");
    config::ProjectConfig cfg; cfg.project = "p"; cfg.version = "1.0.0"; cfg.asil = "ASIL-C";
    auto r = trace::run(tmp.path(), cfg);
    // ASIL-C project → gate is error (REQ-HLR004), same as ASIL-D
    REQUIRE_FALSE(is_ok(r));
}

TEST_CASE("trace: ASIL-B HLR violation is warn not error without strict flag", "[trace][hlr]") {
    //fusa:test REQ-HLR005
    TempDir tmp;
    tmp.write(".fusa-reqs.json", R"([
      {"id":"REQ-HLR-001","title":"HLR no children","severity":"safety","asil":"ASIL-B"}
    ])");
    config::ProjectConfig cfg; cfg.project = "p"; cfg.version = "1.0.0";
    auto r = trace::run(tmp.path(), cfg);
    // ASIL-B → should succeed with violations recorded
    REQUIRE(is_ok(r));
    REQUIRE_FALSE(value_of(r).hlr_violations.empty());
}

TEST_CASE("trace: render_matrix shows HLR/LLR summary", "[trace][hlr]") {
    //fusa:test REQ-HLR001
    TempDir tmp;
    tmp.write(".fusa-reqs.json", R"([
      {"id":"REQ-HLR-001","title":"HLR","severity":"safety"},
      {"id":"REQ-LLR-001","title":"LLR","severity":"safety","parent_id":"REQ-HLR-001"}
    ])");
    config::ProjectConfig cfg; cfg.project = "p"; cfg.version = "1.0.0";
    auto res = value_of(trace::run(tmp.path(), cfg));
    auto txt = trace::render_matrix(res, {});
    REQUIRE(txt.find("HLR") != std::string::npos);
}

TEST_CASE("trace: render_json includes parentId for LLR requirements", "[trace][hlr]") {
    //fusa:test REQ-HLR001
    TempDir tmp;
    tmp.write(".fusa-reqs.json", R"([
      {"id":"REQ-HLR-001","title":"HLR","severity":"safety"},
      {"id":"REQ-LLR-001","title":"LLR","severity":"safety","parent_id":"REQ-HLR-001"}
    ])");
    config::ProjectConfig cfg; cfg.project = "p"; cfg.version = "1.0.0";
    auto res = value_of(trace::run(tmp.path(), cfg));
    auto j = json::parse(trace::render_json(res, cfg));
    bool found_parent = false;
    for (const auto& r : j["requirements"]) {
        if (r.contains("parentId") && r["parentId"] == "REQ-HLR-001") {
            found_parent = true; break;
        }
    }
    REQUIRE(found_parent);
}

TEST_CASE("trace: render_json includes hierarchy block", "[trace][hlr]") {
    //fusa:test REQ-HLR002
    TempDir tmp;
    tmp.write(".fusa-reqs.json", R"([
      {"id":"REQ-HLR-001","title":"HLR","severity":"safety"},
      {"id":"REQ-LLR-001","title":"LLR","severity":"safety","parent_id":"REQ-HLR-001"}
    ])");
    config::ProjectConfig cfg; cfg.project = "p"; cfg.version = "1.0.0";
    auto res = value_of(trace::run(tmp.path(), cfg));
    auto j = json::parse(trace::render_json(res, cfg));
    REQUIRE(j.contains("hierarchy"));
    REQUIRE(j["hierarchy"]["hlrCount"] == 1);
    REQUIRE(j["hierarchy"]["llrCount"] == 1);
    REQUIRE(j["hierarchy"]["hlrCovered"] == 1);
}

TEST_CASE("trace: export_csv includes parent_id column", "[trace][hlr]") {
    //fusa:test REQ-HLR001
    trace::Requirement r;
    r.id        = "REQ-LLR-001";
    r.title     = "LLR req";
    r.severity  = "safety";
    r.parent_id = "REQ-HLR-001";
    std::vector<trace::Requirement> reqs{r};
    std::string csv = trace::export_csv(reqs);
    REQUIRE(csv.find("parent_id") != std::string::npos);
    REQUIRE(csv.find("REQ-HLR-001") != std::string::npos);
}

// ─── §1.4.1 / §5 --func-coverage ─────────────────────────────────────────────

TEST_CASE("trace: is_func_exempt recognises trivial converters and serialisers", "[trace][trace018]") {
    //fusa:test REQ-TRACE018
    REQUIRE(trace::is_func_exempt("render_text"));
    REQUIRE(trace::is_func_exempt("render_json"));
    REQUIRE(trace::is_func_exempt("render_matrix"));
    REQUIRE(trace::is_func_exempt("write_json"));
    REQUIRE(trace::is_func_exempt("export_csv"));
    REQUIRE(trace::is_func_exempt("parse_asil"));
    REQUIRE(trace::is_func_exempt("dal_str"));
    REQUIRE(trace::is_func_exempt("asil_str"));
    REQUIRE(trace::is_func_exempt("to_string"));
}

TEST_CASE("trace: is_func_exempt does not exempt ordinary functions", "[trace][trace018]") {
    //fusa:test REQ-TRACE018
    REQUIRE_FALSE(trace::is_func_exempt("assess"));
    REQUIRE_FALSE(trace::is_func_exempt("load"));
    REQUIRE_FALSE(trace::is_func_exempt("save"));
    REQUIRE_FALSE(trace::is_func_exempt("run"));
}

TEST_CASE("trace: scan_func_coverage counts a tagged function as covered", "[trace][trace018]") {
    //fusa:test REQ-TRACE018
    TempDir tmp;
    tmp.write("src/widget/widget.hpp",
              "#pragma once\n"
              "namespace cpfusa::widget {\n"
              "[[nodiscard]] int assess(int x);\n"
              "} // namespace\n");
    tmp.write("src/widget/widget.cpp",
              "#include \"widget.hpp\"\n"
              "namespace cpfusa::widget {\n"
              "//fusa:req REQ-WIDGET-001\n"
              "int assess(int x) { return x; }\n"
              "} // namespace\n");
    auto fc = trace::scan_func_coverage(tmp.path());
    REQUIRE(fc.total == 1);
    REQUIRE(fc.covered == 1);
    REQUIRE(fc.uncovered.empty());
}

TEST_CASE("trace: scan_func_coverage counts an untagged function as uncovered", "[trace][trace018]") {
    //fusa:test REQ-TRACE018
    TempDir tmp;
    tmp.write("src/widget/widget.hpp",
              "#pragma once\n"
              "namespace cpfusa::widget {\n"
              "[[nodiscard]] int assess(int x);\n"
              "} // namespace\n");
    tmp.write("src/widget/widget.cpp",
              "#include \"widget.hpp\"\n"
              "namespace cpfusa::widget {\n"
              "int assess(int x) { return x; }\n"
              "} // namespace\n");
    auto fc = trace::scan_func_coverage(tmp.path());
    REQUIRE(fc.total == 1);
    REQUIRE(fc.covered == 0);
    REQUIRE(fc.uncovered.size() == 1);
    REQUIRE(fc.uncovered[0].find("assess") != std::string::npos);
}

TEST_CASE("trace: scan_func_coverage excludes trivial converters and serialisers", "[trace][trace018]") {
    //fusa:test REQ-TRACE018
    TempDir tmp;
    tmp.write("src/widget/widget.hpp",
              "#pragma once\n"
              "namespace cpfusa::widget {\n"
              "enum class Kind { A, B };\n"
              "std::string kind_str(Kind k);\n"
              "Kind parse_kind(const std::string& s);\n"
              "void render_text(Kind k);\n"
              "void write_json(Kind k);\n"
              "} // namespace\n");
    tmp.write("src/widget/widget.cpp",
              "#include \"widget.hpp\"\n"
              "namespace cpfusa::widget {\n"
              "std::string kind_str(Kind k) { return \"\"; }\n"
              "Kind parse_kind(const std::string& s) { return Kind::A; }\n"
              "void render_text(Kind k) {}\n"
              "void write_json(Kind k) {}\n"
              "} // namespace\n");
    auto fc = trace::scan_func_coverage(tmp.path());
    REQUIRE(fc.total == 0); // every declared function is exempt
}

TEST_CASE("trace: scan_func_coverage ignores fully inline header functions", "[trace][trace018]") {
    //fusa:test REQ-TRACE018
    TempDir tmp;
    tmp.write("src/widget/widget.hpp",
              "#pragma once\n"
              "namespace cpfusa::widget {\n"
              "class Thing {\n"
              "public:\n"
              "    int inline_accessor() const { return 0; }\n"
              "    int declared_only() const;\n"
              "};\n"
              "} // namespace\n");
    tmp.write("src/widget/widget.cpp",
              "#include \"widget.hpp\"\n"
              "namespace cpfusa::widget {\n"
              "int Thing::declared_only() const { return 0; }\n"
              "} // namespace\n");
    auto fc = trace::scan_func_coverage(tmp.path());
    // inline_accessor has no separate .cpp definition and is excluded entirely;
    // declared_only is the sole counted (uncovered) function.
    REQUIRE(fc.total == 1);
    REQUIRE(fc.covered == 0);
    REQUIRE(fc.uncovered[0].find("declared_only") != std::string::npos);
}

TEST_CASE("trace: scan_func_coverage skips headers with no matching .cpp", "[trace][trace018]") {
    //fusa:test REQ-TRACE018
    TempDir tmp;
    tmp.write("src/widget/widget.hpp",
              "#pragma once\n"
              "namespace cpfusa::widget {\n"
              "int assess(int x);\n"
              "} // namespace\n");
    auto fc = trace::scan_func_coverage(tmp.path());
    REQUIRE(fc.total == 0);
}

TEST_CASE("trace: run reports func_coverage in the result", "[trace][trace018]") {
    //fusa:test REQ-TRACE018
    TempDir tmp;
    tmp.write("src/widget/widget.hpp",
              "#pragma once\n"
              "namespace cpfusa::widget { int assess(int x); }\n");
    tmp.write("src/widget/widget.cpp",
              "#include \"widget.hpp\"\n"
              "namespace cpfusa::widget { int assess(int x) { return x; } }\n");
    config::ProjectConfig cfg; cfg.project = "p"; cfg.version = "1.0.0";
    auto res = value_of(trace::run(tmp.path(), cfg));
    REQUIRE(res.func_coverage.total == 1);
    REQUIRE(res.func_coverage.covered == 0);
    REQUIRE(res.func_coverage.pct == Catch::Approx(0.0));
}

TEST_CASE("trace: --func-coverage N fails the run when below threshold", "[trace][trace018]") {
    //fusa:test REQ-TRACE018
    TempDir tmp;
    tmp.write("src/widget/widget.hpp",
              "#pragma once\n"
              "namespace cpfusa::widget { int assess(int x); }\n");
    tmp.write("src/widget/widget.cpp",
              "#include \"widget.hpp\"\n"
              "namespace cpfusa::widget { int assess(int x) { return x; } }\n");
    config::ProjectConfig cfg; cfg.project = "p"; cfg.version = "1.0.0";
    trace::TraceOptions opts;
    opts.min_func_pct = 50;
    auto res = trace::run(tmp.path(), cfg, opts);
    REQUIRE_FALSE(is_ok(res));
    REQUIRE(error_of(res).find("function coverage") != std::string::npos);
}

TEST_CASE("trace: --func-coverage 0 disables the gate", "[trace][trace018]") {
    //fusa:test REQ-TRACE018
    TempDir tmp;
    tmp.write("src/widget/widget.hpp",
              "#pragma once\n"
              "namespace cpfusa::widget { int assess(int x); }\n");
    tmp.write("src/widget/widget.cpp",
              "#include \"widget.hpp\"\n"
              "namespace cpfusa::widget { int assess(int x) { return x; } }\n");
    config::ProjectConfig cfg; cfg.project = "p"; cfg.version = "1.0.0";
    trace::TraceOptions opts;
    opts.min_func_pct = 0;
    auto res = trace::run(tmp.path(), cfg, opts);
    REQUIRE(is_ok(res));
}

TEST_CASE("trace: render_json reports funcCoverage in coverage block", "[trace][trace018]") {
    //fusa:test REQ-TRACE018
    TempDir tmp;
    config::ProjectConfig cfg; cfg.project = "p"; cfg.version = "1.0.0";
    auto res = value_of(trace::run(tmp.path(), cfg));
    auto j = json::parse(trace::render_json(res, cfg));
    REQUIRE(j["coverage"].contains("funcCoverage"));
    REQUIRE(j["coverage"]["funcCoverage"].contains("total"));
    REQUIRE(j["coverage"]["funcCoverage"].contains("covered"));
    REQUIRE(j["coverage"]["funcCoverage"].contains("pct"));
}

// ─── §1.4.1 item 3 — dangling //fusa:test references ────────────────────────

TEST_CASE("trace: run detects a dangling //fusa:test reference", "[trace][trace019]") {
    //fusa:test REQ-TRACE019
    TempDir tmp;
    tmp.write(".fusa-reqs.json", R"([{"id":"REQ-001","title":"T","severity":"safety"}])");
    tmp.write("tests/test_foo.cpp", "//fusa:test REQ-999\nTEST_CASE(\"t\"){}\n");
    config::ProjectConfig cfg; cfg.project = "p"; cfg.version = "1.0.0";
    auto res = value_of(trace::run(tmp.path(), cfg));
    REQUIRE(res.dangling_tags.size() == 1);
    REQUIRE(res.dangling_tags[0].req_id == "REQ-999");
    REQUIRE(res.dangling_tags[0].message.find("dangling") != std::string::npos);
}

TEST_CASE("trace: run does not flag a //fusa:test reference that exists", "[trace][trace019]") {
    //fusa:test REQ-TRACE019
    TempDir tmp;
    tmp.write(".fusa-reqs.json", R"([{"id":"REQ-001","title":"T","severity":"safety"}])");
    tmp.write("tests/test_foo.cpp", "//fusa:test REQ-001\nTEST_CASE(\"t\"){}\n");
    config::ProjectConfig cfg; cfg.project = "p"; cfg.version = "1.0.0";
    auto res = value_of(trace::run(tmp.path(), cfg));
    REQUIRE(res.dangling_tags.empty());
}

TEST_CASE("trace: run does not flag a dangling //fusa:req reference (test-tag only)", "[trace][trace019]") {
    //fusa:test REQ-TRACE019
    TempDir tmp;
    tmp.write(".fusa-reqs.json", "[]");
    tmp.write("src/foo.cpp", "//fusa:req REQ-999\nvoid f() {}\n");
    config::ProjectConfig cfg; cfg.project = "p"; cfg.version = "1.0.0";
    auto res = value_of(trace::run(tmp.path(), cfg));
    REQUIRE(res.dangling_tags.empty());
}

TEST_CASE("trace: render_matrix reports dangling test-tag references as WARN", "[trace][trace019]") {
    //fusa:test REQ-TRACE019
    TempDir tmp;
    tmp.write(".fusa-reqs.json", R"([{"id":"REQ-001","title":"T","severity":"safety"}])");
    tmp.write("tests/test_foo.cpp", "//fusa:test REQ-999\nTEST_CASE(\"t\"){}\n");
    config::ProjectConfig cfg; cfg.project = "p"; cfg.version = "1.0.0";
    auto res = value_of(trace::run(tmp.path(), cfg));
    std::string out = trace::render_matrix(res, {});
    REQUIRE(out.find("WARN") != std::string::npos);
    REQUIRE(out.find("REQ-999") != std::string::npos);
}

TEST_CASE("trace: render_json includes danglingTags array", "[trace][trace019]") {
    //fusa:test REQ-TRACE019
    TempDir tmp;
    tmp.write(".fusa-reqs.json", R"([{"id":"REQ-001","title":"T","severity":"safety"}])");
    tmp.write("tests/test_foo.cpp", "//fusa:test REQ-999\nTEST_CASE(\"t\"){}\n");
    config::ProjectConfig cfg; cfg.project = "p"; cfg.version = "1.0.0";
    auto res = value_of(trace::run(tmp.path(), cfg));
    auto j = json::parse(trace::render_json(res, cfg));
    REQUIRE(j.contains("danglingTags"));
    REQUIRE(j["danglingTags"].size() == 1);
    REQUIRE(j["danglingTags"][0]["requirementId"] == "REQ-999");
}
