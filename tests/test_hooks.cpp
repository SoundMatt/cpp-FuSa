//fusa:test REQ-HOOKS001 REQ-HOOKS002 REQ-HOOKS003
#include <catch2/catch_all.hpp>
#include "hooks/hooks.hpp"
#include "testutil/testutil.hpp"
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;
using namespace cpfusa;
using namespace cpfusa::testutil;

// ─── show ─────────────────────────────────────────────────────────────────────

TEST_CASE("hooks: show returns non-empty script", "[hooks]") {
    auto script = hooks::show();
    REQUIRE_FALSE(script.empty());
}

TEST_CASE("hooks: show script contains cpfusa invocation", "[hooks]") {
    auto script = hooks::show();
    REQUIRE(script.find("cpfusa") != std::string::npos);
}

TEST_CASE("hooks: show script has shebang line", "[hooks]") {
    auto script = hooks::show();
    REQUIRE(script.substr(0, 2) == "#!");
}

// ─── install ─────────────────────────────────────────────────────────────────

TEST_CASE("hooks: install creates pre-commit hook", "[hooks][hooks001]") {
    TempDir tmp;
    // Create a minimal .git/hooks directory
    fs::create_directories(tmp.path() / ".git" / "hooks");
    auto r = hooks::install(tmp.path());
    REQUIRE(is_ok(r));
    REQUIRE(fs::exists(tmp.path() / ".git" / "hooks" / "pre-commit"));
}

TEST_CASE("hooks: installed hook contains cpfusa invocation", "[hooks][hooks001]") {
    TempDir tmp;
    fs::create_directories(tmp.path() / ".git" / "hooks");
    hooks::install(tmp.path());
    std::ifstream f(tmp.path() / ".git" / "hooks" / "pre-commit");
    std::string content((std::istreambuf_iterator<char>(f)), {});
    REQUIRE(content.find("cpfusa") != std::string::npos);
}

TEST_CASE("hooks: install returns error when .git/hooks is missing", "[hooks][hooks001]") {
    TempDir tmp;
    // No .git directory — not a git repo
    auto r = hooks::install(tmp.path());
    REQUIRE_FALSE(is_ok(r));
}

// ─── remove ───────────────────────────────────────────────────────────────────

TEST_CASE("hooks: remove deletes installed hook", "[hooks]") {
    TempDir tmp;
    fs::create_directories(tmp.path() / ".git" / "hooks");
    hooks::install(tmp.path());
    REQUIRE(fs::exists(tmp.path() / ".git" / "hooks" / "pre-commit"));
    auto r = hooks::remove(tmp.path());
    REQUIRE(is_ok(r));
    REQUIRE_FALSE(fs::exists(tmp.path() / ".git" / "hooks" / "pre-commit"));
}

TEST_CASE("hooks: remove succeeds when hook does not exist", "[hooks]") {
    TempDir tmp;
    fs::create_directories(tmp.path() / ".git" / "hooks");
    auto r = hooks::remove(tmp.path());
    REQUIRE(is_ok(r));
}
