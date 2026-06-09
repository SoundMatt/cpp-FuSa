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

// write_all serialises SBOM, Provenance, and Manifest to dir.
Result<std::monostate> write_all(const std::filesystem::path& dir,
                                 const SBOM& sbom,
                                 const Provenance& prov,
                                 const Manifest& manifest);

// The evidence files collected by hash_artifacts / audit-pack.
extern const std::vector<std::string> EvidenceFiles;

} // namespace cpfusa::release
