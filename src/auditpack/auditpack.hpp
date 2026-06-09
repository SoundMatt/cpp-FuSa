#pragma once
// auditpack bundles all cpp-FuSa evidence artifacts into a single ZIP archive.
// Output filename matches go-FuSa: audit-pack.zip with AUDIT-MANIFEST.json inside.
#include "cpfusa/fusa.hpp"
#include <filesystem>
#include <string>
#include <vector>

namespace cpfusa::auditpack {

constexpr std::string_view AuditPackFile = "audit-pack.zip";

struct ManifestEntry {
    std::string path;
    std::string sha256;
    long long   size{0};
};

struct AuditManifest {
    std::string                format;       // "cpp-FuSa Audit Pack v1"
    std::string                generated_at;
    std::string                project;
    std::vector<ManifestEntry> files;
};

// pack collects evidence files from project_root, writes audit-pack.zip to output_path,
// and returns the AuditManifest describing what was packed.
//
//fusa:req REQ-AUDIT001
//fusa:req REQ-AUDIT002
Result<AuditManifest> pack(const std::filesystem::path& project_root,
                           const std::filesystem::path& output_path);

} // namespace cpfusa::auditpack
