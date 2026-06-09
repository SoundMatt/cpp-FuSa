#pragma once
// sign provides HMAC-SHA256 artifact signing and verification.
// Key format: 64 hex chars (32 bytes). Signature written to <file>.sig
#include "cpfusa/fusa.hpp"
#include <filesystem>
#include <string>

namespace cpfusa::sign {

// keygen generates a 32-byte random key and writes it as 64-char hex to path.
//
//fusa:req REQ-SIGN001
Result<std::monostate> keygen(const std::filesystem::path& key_path);

// sign_file creates an HMAC-SHA256 signature of target and writes it to target + ".sig".
//
//fusa:req REQ-SIGN002
Result<std::monostate> sign_file(const std::filesystem::path& target,
                                 const std::filesystem::path& key_path);

// verify_file verifies the signature at target + ".sig" against target.
//
//fusa:req REQ-SIGN003
Result<bool> verify_file(const std::filesystem::path& target,
                         const std::filesystem::path& key_path);

} // namespace cpfusa::sign
