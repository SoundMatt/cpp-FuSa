//fusa:test REQ-SIGN001 REQ-SIGN002 REQ-SIGN003 REQ-SIGN004 REQ-SIGN005
#include <catch2/catch_all.hpp>
#include "sign/sign.hpp"
#include "testutil/testutil.hpp"
#include <fstream>

using namespace cpfusa;
using namespace cpfusa::testutil;

// ─── keygen ───────────────────────────────────────────────────────────────────

TEST_CASE("sign: keygen writes a key file", "[sign][sign001]") {
    TempDir tmp;
    auto key_path = tmp.path() / "fusa.key";
    auto r = sign::keygen(key_path);
    REQUIRE(is_ok(r));
    REQUIRE(std::filesystem::exists(key_path));
}

TEST_CASE("sign: keygen produces 64-char hex key", "[sign][sign001]") {
    TempDir tmp;
    auto key_path = tmp.path() / "fusa.key";
    sign::keygen(key_path);
    std::ifstream f(key_path);
    std::string key;
    f >> key;
    REQUIRE(key.size() == 64);
}

TEST_CASE("sign: keygen produces different keys on successive calls", "[sign][sign001]") {
    TempDir tmp;
    auto k1 = tmp.path() / "key1.key";
    auto k2 = tmp.path() / "key2.key";
    sign::keygen(k1);
    sign::keygen(k2);
    std::ifstream f1(k1), f2(k2);
    std::string s1, s2;
    f1 >> s1; f2 >> s2;
    REQUIRE(s1 != s2);
}

TEST_CASE("sign: keygen key contains only hex chars", "[sign][sign001]") {
    TempDir tmp;
    auto key_path = tmp.path() / "fusa.key";
    sign::keygen(key_path);
    std::ifstream f(key_path);
    std::string key;
    f >> key;
    for (char c : key)
        REQUIRE(std::isxdigit(static_cast<unsigned char>(c)));
}

// ─── sign_file ────────────────────────────────────────────────────────────────

TEST_CASE("sign: sign_file creates .sig file", "[sign][sign002]") {
    TempDir tmp;
    auto key_path = tmp.path() / "fusa.key";
    auto target   = tmp.path() / "artifact.json";
    sign::keygen(key_path);
    std::ofstream(target) << R"({"test":"data"})";
    auto r = sign::sign_file(target, key_path);
    REQUIRE(is_ok(r));
    REQUIRE(std::filesystem::exists(tmp.path() / "artifact.json.sig"));
}

TEST_CASE("sign: sign_file returns error for missing target", "[sign][sign002]") {
    TempDir tmp;
    auto key_path = tmp.path() / "fusa.key";
    sign::keygen(key_path);
    auto r = sign::sign_file(tmp.path() / "missing.json", key_path);
    REQUIRE_FALSE(is_ok(r));
}

TEST_CASE("sign: sign_file returns error for missing key", "[sign][sign002]") {
    TempDir tmp;
    auto target = tmp.path() / "artifact.json";
    std::ofstream(target) << "data";
    auto r = sign::sign_file(target, tmp.path() / "missing.key");
    REQUIRE_FALSE(is_ok(r));
}

// ─── verify_file ──────────────────────────────────────────────────────────────

TEST_CASE("sign: verify_file returns true for valid signature", "[sign][sign003]") {
    TempDir tmp;
    auto key_path = tmp.path() / "fusa.key";
    auto target   = tmp.path() / "artifact.json";
    sign::keygen(key_path);
    std::ofstream(target) << R"({"result":"pass"})";
    sign::sign_file(target, key_path);
    auto r = sign::verify_file(target, key_path);
    REQUIRE(is_ok(r));
    REQUIRE(value_of(r) == true);
}

TEST_CASE("sign: verify_file returns false for tampered file", "[sign][sign003]") {
    TempDir tmp;
    auto key_path = tmp.path() / "fusa.key";
    auto target   = tmp.path() / "artifact.json";
    sign::keygen(key_path);
    std::ofstream(target) << R"({"original":"data"})";
    sign::sign_file(target, key_path);
    // Tamper with the file
    std::ofstream(target) << R"({"tampered":"data"})";
    auto r = sign::verify_file(target, key_path);
    REQUIRE(is_ok(r));
    REQUIRE(value_of(r) == false);
}

TEST_CASE("sign: verify_file returns error when sig file missing", "[sign][sign003]") {
    TempDir tmp;
    auto key_path = tmp.path() / "fusa.key";
    auto target   = tmp.path() / "artifact.json";
    sign::keygen(key_path);
    std::ofstream(target) << "data";
    // No sign_file call — .sig doesn't exist
    auto r = sign::verify_file(target, key_path);
    REQUIRE_FALSE(is_ok(r));
}

TEST_CASE("sign: signature with wrong key fails verification", "[sign][sign003]") {
    TempDir tmp;
    auto k1 = tmp.path() / "key1.key";
    auto k2 = tmp.path() / "key2.key";
    auto target = tmp.path() / "artifact.json";
    sign::keygen(k1);
    sign::keygen(k2);
    std::ofstream(target) << "data";
    sign::sign_file(target, k1);
    auto r = sign::verify_file(target, k2);
    REQUIRE(is_ok(r));
    REQUIRE(value_of(r) == false);
}
