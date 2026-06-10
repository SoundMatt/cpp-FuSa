# Release Process

This document describes how cpp-FuSa versions are released. It is part of the
tool's own change management evidence for ISO 26262-8 / IEC 61508-6 qualification.

## Prerequisites

Before tagging a release, verify on `main`:

1. All CI jobs pass — `build-and-test` (5 matrix jobs), `self-check`, `docker-build`
2. `cpfusa qualify` shows 8/8 passed
3. `cpfusa trace` shows ≥ 80% annotated requirements
4. `CHANGELOG.md` has an entry for the new version
5. Version constant in `include/cpfusa/fusa.hpp` has been bumped
6. `CMakeLists.txt` `project(VERSION ...)` matches
7. `.fusa.json` `version` field matches

## Steps

### 1. Pull latest main

```bash
git checkout main && git pull origin main
```

### 2. Bump version

Edit three locations to the new version `x.y.z`:

```bash
# include/cpfusa/fusa.hpp
constexpr std::string_view Version = "x.y.z";

# CMakeLists.txt
project(cpfusa VERSION x.y.z ...)

# .fusa.json
{ "version": "x.y.z" }
```

### 3. Update CHANGELOG.md

Add a `## [x.y.z] — YYYY-MM-DD` section with the release notes.

### 4. Regenerate evidence

```bash
cmake --build build --parallel
ctest --test-dir build --output-on-failure -j1
cpfusa verify
cpfusa qualify
cpfusa release
cpfusa sci
cpfusa sas
cpfusa audit-pack
```

### 5. Commit

```bash
git add include/cpfusa/fusa.hpp CMakeLists.txt .fusa.json CHANGELOG.md \
        qualify-report.json .fusa-evidence.json sbom.json provenance.json \
        sci.json sas.json sas.md audit-pack.zip
git commit -F - <<'COMMIT'
chore(release): prepare vx.y.z

Signed-off-by: Matt Jones <matt@jellybaby.com>
COMMIT
git push origin main
```

Wait for CI to go green.

### 6. Tag and push

```bash
git tag -a vx.y.z -m "Release vx.y.z"
git push origin vx.y.z
```

The `docker-publish` workflow triggers automatically on tag push and publishes
`ghcr.io/soundmatt/cpp-fusa:x.y.z` and `:latest`.

### 7. GitHub release

Create a GitHub release from the tag. Title: `vx.y.z`. Body: the `CHANGELOG.md`
entry for this version.

Attach the following files as release assets (the tool qualification evidence package):

| File | Description |
|---|---|
| `qualify-report.json` | Qualification suite results (8 cases, SHA-256 hashed) |
| `.fusa-evidence.json` | CTest evidence bundle |
| `sbom.json` | SPDX 3.0.1 Software Bill of Materials |
| `provenance.json` | Build provenance record |
| `sci.json` | Software Configuration Index |
| `sas.md` | Software Accomplishment Summary |
| `audit-pack.zip` | Complete evidence bundle ZIP |

### 8. Post-release smoke test

```bash
docker pull ghcr.io/soundmatt/cpp-fusa:x.y.z
docker run --rm ghcr.io/soundmatt/cpp-fusa:x.y.z --version
docker run --rm -v "$(pwd)":/project ghcr.io/soundmatt/cpp-fusa:x.y.z qualify
```

## Versioning policy

cpp-FuSa follows [Semantic Versioning](https://semver.org/):

| Change type | Version bump |
|---|---|
| Bug fixes, documentation, test additions | Patch (0.x.Z) |
| New commands, new rules, backward-compatible changes | Minor (0.X.0) |
| Breaking changes to `.fusa.json` schema, CLI, or artifact format | Major (X.0.0) |

Pre-1.0: minor bumps may include breaking changes; these are called out explicitly
in `CHANGELOG.md`.

## Release authority

Releases are authorised by the repository owner (Matt Jones). No automated release
tagging is configured — every release requires a manual `git tag`. This ensures a
qualified engineer has reviewed all evidence before any version is declared released.

## Evidence retention

The evidence files attached to each GitHub release constitute the **tool qualification
evidence package** for that version. Auditors qualifying cpp-FuSa for use in a
regulated project should:

1. Download the evidence package for the specific version in use
2. Verify `qualify-report.json` hash (see `docs/qualification.md`)
3. Record the `cpfusa` binary SHA-256 hash in the project safety plan
4. Re-run `cpfusa qualify` in their own CI to confirm reproducibility
