//fusa:test REQ-TMPL001
//fusa:test REQ-TMPL002
//fusa:test REQ-TMPL003
#include <catch2/catch_all.hpp>
#include "template/template_gen.hpp"
#include "config/config.hpp"
#include "testutil/testutil.hpp"
#include <filesystem>

using namespace cpfusa;
using namespace cpfusa::testutil;
namespace fs = std::filesystem;

static config::ProjectConfig make_cfg() {
    config::ProjectConfig cfg;
    cfg.project = "test-proj";
    cfg.version = "1.0";
    cfg.standard = "iso26262";
    cfg.asil = "B";
    cfg.language = "cpp17";
    return cfg;
}

// ─── content generators ───────────────────────────────────────────────────────

TEST_CASE("template: safety_plan_content is non-empty", "[template][tmpl001]") {
    auto cfg = make_cfg();
    REQUIRE_FALSE(tmpl::safety_plan_content(cfg).empty());
}

TEST_CASE("template: safety_plan_content mentions project name", "[template][tmpl001]") {
    auto cfg = make_cfg();
    auto s = tmpl::safety_plan_content(cfg);
    REQUIRE(s.find("test-proj") != std::string::npos);
}

TEST_CASE("template: test_evidence_content is non-empty", "[template][tmpl001]") {
    auto cfg = make_cfg();
    REQUIRE_FALSE(tmpl::test_evidence_content(cfg).empty());
}

TEST_CASE("template: hara_content is non-empty", "[template][tmpl001]") {
    auto cfg = make_cfg();
    REQUIRE_FALSE(tmpl::hara_content(cfg).empty());
}

TEST_CASE("template: svp_content is non-empty", "[template][tmpl002]") {
    auto cfg = make_cfg();
    REQUIRE_FALSE(tmpl::svp_content(cfg).empty());
}

TEST_CASE("template: scmp_content is non-empty", "[template][tmpl002]") {
    auto cfg = make_cfg();
    REQUIRE_FALSE(tmpl::scmp_content(cfg).empty());
}

TEST_CASE("template: sqap_content is non-empty", "[template][tmpl002]") {
    auto cfg = make_cfg();
    REQUIRE_FALSE(tmpl::sqap_content(cfg).empty());
}

// ─── generate ─────────────────────────────────────────────────────────────────

TEST_CASE("template: generate SAFETY_PLAN creates file", "[template][tmpl003]") {
    TempDir tmp;
    auto cfg = make_cfg();
    auto res = tmpl::generate(tmp.path(), cfg, tmpl::TemplateType::SAFETY_PLAN);
    REQUIRE(is_ok(res));
    REQUIRE(fs::exists(tmp.path() / "SAFETY_PLAN.md"));
}

TEST_CASE("template: generate HARA creates file", "[template][tmpl003]") {
    TempDir tmp;
    auto cfg = make_cfg();
    auto res = tmpl::generate(tmp.path(), cfg, tmpl::TemplateType::HARA);
    REQUIRE(is_ok(res));
    REQUIRE(fs::exists(tmp.path() / "HARA.md"));
}

TEST_CASE("template: generate ALL creates multiple files", "[template][tmpl003]") {
    TempDir tmp;
    auto cfg = make_cfg();
    auto res = tmpl::generate(tmp.path(), cfg, tmpl::TemplateType::ALL);
    REQUIRE(is_ok(res));
    REQUIRE(fs::exists(tmp.path() / "SAFETY_PLAN.md"));
    REQUIRE(fs::exists(tmp.path() / "HARA.md"));
}

TEST_CASE("template: generate SVP creates file", "[template][tmpl003]") {
    TempDir tmp;
    auto cfg = make_cfg();
    auto res = tmpl::generate(tmp.path(), cfg, tmpl::TemplateType::SVP);
    REQUIRE(is_ok(res));
    REQUIRE(fs::exists(tmp.path() / "SVP.md"));
}
