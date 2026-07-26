//fusa:test REQ-BADGE001
//fusa:test REQ-BADGE002
//fusa:test REQ-BADGE003
#include <catch2/catch_all.hpp>
#include "badge/badge.hpp"

using namespace cpfusa;

// ─── from_findings ────────────────────────────────────────────────────────────

TEST_CASE("badge: from_findings PASS when no errors or warnings", "[badge][badge001]") {
    auto b = badge::from_findings(0, 0, "0.6.0");
    REQUIRE(b.status == badge::Status::PASS);
}

TEST_CASE("badge: from_findings WARN when only warnings", "[badge][badge001]") {
    auto b = badge::from_findings(0, 3, "0.6.0");
    REQUIRE(b.status == badge::Status::WARN);
}

TEST_CASE("badge: from_findings FAIL when errors present", "[badge][badge001]") {
    auto b = badge::from_findings(1, 0, "0.6.0");
    REQUIRE(b.status == badge::Status::FAIL);
}

TEST_CASE("badge: from_findings FAIL when both errors and warnings", "[badge][badge001]") {
    auto b = badge::from_findings(2, 5, "0.6.0");
    REQUIRE(b.status == badge::Status::FAIL);
}

TEST_CASE("badge: from_findings sets counts", "[badge][badge001]") {
    auto b = badge::from_findings(3, 7, "1.0.0");
    REQUIRE(b.errors == 3);
    REQUIRE(b.warnings == 7);
    REQUIRE(b.version == "1.0.0");
}

// ─── render ───────────────────────────────────────────────────────────────────

TEST_CASE("badge: render produces SVG element", "[badge][badge002]") {
    auto b = badge::from_findings(0, 0, "0.6.0");
    auto svg = badge::render(b);
    REQUIRE(svg.find("<svg") != std::string::npos);
}

TEST_CASE("badge: render PASS badge contains passing text", "[badge][badge002]") {
    auto b = badge::from_findings(0, 0, "0.6.0");
    auto svg = badge::render(b);
    REQUIRE(svg.find("passing") != std::string::npos);
}

TEST_CASE("badge: render FAIL badge contains failing text", "[badge][badge002]") {
    auto b = badge::from_findings(1, 0, "0.6.0");
    auto svg = badge::render(b);
    REQUIRE(svg.find("failing") != std::string::npos);
}

TEST_CASE("badge: render WARN badge contains warnings text", "[badge][badge002]") {
    auto b = badge::from_findings(0, 5, "0.6.0");
    auto svg = badge::render(b);
    REQUIRE(svg.find("warnings") != std::string::npos);
}

TEST_CASE("badge: render SVG is well-formed (has closing tag)", "[badge][badge002]") {
    auto b = badge::from_findings(0, 0, "0.6.0");
    auto svg = badge::render(b);
    REQUIRE(svg.find("</svg>") != std::string::npos);
}
