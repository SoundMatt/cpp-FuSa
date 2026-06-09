//fusa:test REQ-HARA001 REQ-HARA002 REQ-HARA003
#include <catch2/catch_all.hpp>
#include "hara/hara.hpp"
#include "testutil/testutil.hpp"
#include <fstream>

using namespace cpfusa;
using namespace cpfusa::testutil;

// ─── determine_asil ──────────────────────────────────────────────────────────

TEST_CASE("hara: S3 E4 C3 = ASIL-D", "[hara][hara001]") {
    REQUIRE(hara::determine_asil(hara::Severity::S3, hara::Exposure::E4, hara::Controllability::C3) == "ASIL-D");
}

TEST_CASE("hara: S0 any = QM", "[hara][hara001]") {
    REQUIRE(hara::determine_asil(hara::Severity::S0, hara::Exposure::E4, hara::Controllability::C3) == "QM");
}

TEST_CASE("hara: S1 E1 C1 = QM", "[hara][hara001]") {
    REQUIRE(hara::determine_asil(hara::Severity::S1, hara::Exposure::E1, hara::Controllability::C1) == "QM");
}

TEST_CASE("hara: parse_severity S2", "[hara][hara001]") {
    REQUIRE(hara::parse_severity("S2") == hara::Severity::S2);
}

TEST_CASE("hara: parse_exposure E3", "[hara][hara001]") {
    REQUIRE(hara::parse_exposure("E3") == hara::Exposure::E3);
}

TEST_CASE("hara: parse_controllability C2", "[hara][hara001]") {
    REQUIRE(hara::parse_controllability("C2") == hara::Controllability::C2);
}

// ─── init / load / save ───────────────────────────────────────────────────────

TEST_CASE("hara: init creates HARA file", "[hara][hara002]") {
    TempDir tmp;
    std::string err;
    REQUIRE(hara::init(tmp.path(), "test-proj", "ISO 26262", err));
    REQUIRE(std::filesystem::exists(tmp.path() / hara::HARA_FILE));
}

TEST_CASE("hara: load after init succeeds", "[hara][hara002]") {
    TempDir tmp;
    std::string err;
    REQUIRE(hara::init(tmp.path(), "proj", "ISO 26262", err));
    hara::HARA h;
    REQUIRE(hara::load(tmp.path(), h, err));
    REQUIRE(h.project == "proj");
}

TEST_CASE("hara: load returns false when file missing", "[hara][hara002]") {
    TempDir tmp;
    hara::HARA h;
    std::string err;
    REQUIRE_FALSE(hara::load(tmp.path(), h, err));
    REQUIRE_FALSE(err.empty());
}

TEST_CASE("hara: save and load roundtrip preserves hazard count", "[hara][hara003]") {
    TempDir tmp;
    hara::HARA h;
    h.project  = "roundtrip-proj";
    h.standard = "ISO 26262";
    hara::Hazard hz;
    hz.id = "H-001";
    hz.description = "Test hazard";
    h.hazards.push_back(hz);
    std::string err;
    REQUIRE(hara::save(tmp.path() / hara::HARA_FILE, h, err));
    hara::HARA loaded;
    REQUIRE(hara::load(tmp.path(), loaded, err));
    REQUIRE(loaded.hazards.size() == 1);
    REQUIRE(loaded.hazards[0].id == "H-001");
}

TEST_CASE("hara: save fails on bad path", "[hara][hara002]") {
    hara::HARA h;
    std::string err;
    REQUIRE_FALSE(hara::save("/no/such/dir/hara.json", h, err));
}
