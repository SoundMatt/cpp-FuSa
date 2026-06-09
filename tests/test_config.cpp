#include <catch2/catch_all.hpp>
#include "config/config.hpp"
#include "testutil/testutil.hpp"

using namespace cpfusa;
using namespace cpfusa::testutil;

TEST_CASE("config: defaults populate reasonable values", "[config]") {
    TempDir tmp;
    auto cfg = config::defaults(tmp.path());
    REQUIRE_FALSE(cfg.project.empty());
    REQUIRE(cfg.version == "0.1.0");
    REQUIRE(cfg.standard == "iso26262");
}

TEST_CASE("config: save and load round-trip", "[config]") {
    TempDir tmp;
    auto cfg = config::defaults(tmp.path());
    cfg.project  = "MyProject";
    cfg.version  = "1.2.3";
    cfg.standard = "iec61508";
    cfg.asil     = "SIL-3";

    auto save_r = config::save(tmp.path(), cfg);
    REQUIRE(is_ok(save_r));
    REQUIRE(config::exists(tmp.path()));

    auto load_r = config::load(tmp.path());
    REQUIRE(is_ok(load_r));
    const auto& loaded = value_of(load_r);
    REQUIRE(loaded.project  == "MyProject");
    REQUIRE(loaded.version  == "1.2.3");
    REQUIRE(loaded.standard == "iec61508");
    REQUIRE(loaded.asil     == "SIL-3");
}

TEST_CASE("config: missing file returns ErrNoConfig", "[config]") {
    TempDir tmp;
    auto r = config::load(tmp.path());
    REQUIRE_FALSE(is_ok(r));
    REQUIRE(error_of(r) == std::string(ErrNoConfig));
}

TEST_CASE("config: exists() correctly reports presence", "[config]") {
    TempDir tmp;
    REQUIRE_FALSE(config::exists(tmp.path()));
    auto cfg = config::defaults(tmp.path());
    config::save(tmp.path(), cfg);
    REQUIRE(config::exists(tmp.path()));
}
