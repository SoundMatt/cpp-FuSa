#pragma once
// release generates SBOM, provenance, and artifact manifest for cpp-FuSa projects.
// Artifact filenames match go-FuSa exactly: sbom.json, provenance.json, artifact-manifest.json
#include "cpfusa/fusa.hpp"
#include "../config/config.hpp"
#include <filesystem>
#include <string>
#include <vector>

namespace cpfusa::release {

constexpr std::string_view SBOMFile       = "sbom.json";
constexpr std::string_view ProvenanceFile = "provenance.json";
constexpr std::string_view ManifestFile   = "artifact-manifest.json";

enum class SpdxVersion { V3_0_1, V2_3, V2_2 };
SpdxVersion parse_spdx_version(const std::string& s); // "2.2" -> V2_2, "2.3" -> V2_3, else V3_0_1

struct Component {
    std::string name;
    std::string version;
    std::string hash;  // SHA-256 of CMakeLists.txt dependency block or empty
};

struct SBOM {
    std::string              format;       // "cpp-FuSa SBOM v1"
    std::string              generated_at;
    std::string              project;
    std::string              cpp_version;
    std::string              cmake_version;
    std::vector<Component>   components;
};

struct Provenance {
    std::string format;
    std::string generated_at;
    std::string project;
    std::string cpp_version;
    std::string platform;
    std::string vcs_revision;
    bool        vcs_modified{false};
};

struct Artifact {
    std::string path;
    std::string sha256;
};

struct Manifest {
    std::string            format;
    std::string            generated_at;
    std::vector<Artifact>  artifacts;
};

// build_sbom parses CMakeLists.txt / cmake/FetchDeps.cmake for dependencies.
//
//fusa:req REQ-RELEASE003
Result<SBOM> build_sbom(const std::filesystem::path& project_root,
                        const config::ProjectConfig& cfg);

// build_provenance records the current build environment.
//
//fusa:req REQ-RELEASE005
Result<Provenance> build_provenance(const std::filesystem::path& project_root,
                                    const config::ProjectConfig& cfg);

// hash_artifacts computes SHA-256 checksums for evidence files present in dir.
//
//fusa:req REQ-RELEASE006
Manifest hash_artifacts(const std::filesystem::path& dir);

// write_sbom serialises an SBOM to a file in the given SPDX format.
void write_sbom(const std::filesystem::path& out, const SBOM& sbom,
                SpdxVersion ver = SpdxVersion::V3_0_1);

// write_all serialises SBOM, Provenance, and Manifest to dir.
Result<std::monostate> write_all(const std::filesystem::path& dir,
                                 const SBOM& sbom,
                                 const Provenance& prov,
                                 const Manifest& manifest);

// The fixed §1.2 input-file / §1.3 generated-evidence filenames collected by
// hash_artifacts / audit-pack. Does NOT include the open-ended
// `<standard>-gap-report.json` family (§1.3) — see list_present_evidence_files.
extern const std::vector<std::string> EvidenceFiles;

// list_present_evidence_files scans `dir` (project root, non-recursive) for
// every EvidenceFiles name that exists, plus every `<standard>-gap-report.json`
// file present (§1.3's glob pattern — the standard-id set is open-ended, so it
// can't be a fixed list). Returns matches sorted, so hash_artifacts and
// audit-pack both pick up any generated evidence file at the project root
// rather than only a hardcoded subset (§8 MUST).
//
//fusa:req REQ-RELEASE006 REQ-AUDIT001
std::vector<std::string> list_present_evidence_files(const std::filesystem::path& dir);

} // namespace cpfusa::release
