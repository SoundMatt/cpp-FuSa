# Changelog

## [0.6.0] — 2026-06-09

### Added
- v0.6 — Gap assessment, evidence lifecycle, and Docker
  - `cpfusa hara` — HARA management with ASIL determination (ISO 26262-3:2018 Table 4)
  - `cpfusa iso26262` — ISO 26262 Part 6 gap report (19 objectives, ASIL-A/B/C/D)
  - `cpfusa iec61508` — IEC 61508 Parts 1-3 gap report (17 objectives, SIL-1/2/3/4)
  - `cpfusa do178` — DO-178C Annex A gap report (21 objectives, DAL-A/B/C/D)
  - `cpfusa boundary` — Component boundary diagrams (Mermaid + DOT)
  - `cpfusa metrics` — Safety metrics time series (record/show)
  - `cpfusa vuln` — Dependency vulnerability scan (offline CVE advisory database)
  - `cpfusa coverage` — LCOV structural coverage parser (DO-178C MC/DC + decision)
  - `cpfusa disposition` — Finding disposition lifecycle (add/list/show)
  - `cpfusa impact` — Change impact analysis (git diff → impacted requirements)
  - `cpfusa sas` — Software Accomplishment Summary (DO-178C §11.20)
  - `cpfusa sci` — Software Configuration Index with SHA-256 checksums (DO-178C §11.16)
  - `cpfusa pr` — Problem Report log (add/list)
  - `cpfusa fix` — Fix guidance catalog (14 rules, before/after code)
  - Docker multi-stage image: `ghcr.io/soundmatt/cpp-fusa`
  - `docker-compose.yml` for zero-install pipeline
  - CI: docker-build job, self-check for all 36 commands
  - `docs/qualification.md`, `docs/tool-safety-manual.md`, `docs/release-process.md`
  - `INCIDENT-RESPONSE.md`
  - `//fusa:req` annotations on all LINT001–010 and ANAL001–002 implementations
  - `//fusa:test` annotations across all 6 test files (100% test file coverage)

### Fixed
- `impact.cpp`: command injection (CYBER005 CWE-78) — git refs now allowlist-validated
- `impact.cpp`: `goto next_req` (LINT002) — replaced with `matched` flag + `break`
- SHA-256 `reinterpret_cast` sites annotated with `// fusa:unsafe` (sign, release, qualify, auditpack)
- `safety-case` command now produces a third artifact: `safety-case.md` (Markdown GSN table)

## [0.5.0] — 2026-06-09

### Added
- v0.5 — Cybersecurity, qualification, and advanced analysis
  - `cpfusa cyber` — 20 CWE-mapped cybersecurity rules (CYBER001–020, ISO 21434)
  - `cpfusa verify` — CTest integration, produces `.fusa-evidence.json`
  - `cpfusa qualify` — Full qualification suite (8 built-in positive/negative test cases, SHA-256 hashed report)
  - `cpfusa release` — SBOM (SPDX 3.0.1 JSON-LD), build provenance, artifact manifest
  - `cpfusa audit-pack` — ZIP evidence bundle with SHA-256 manifest
  - `cpfusa tara` — TARA workbook (ISO 21434 threat analysis)
  - `cpfusa fmea` — dFMEA generation from source declarations
  - `cpfusa safety-case` — GSN safety case assembly (JSON + Mermaid)
  - `cpfusa badge` — SVG status badge
  - `cpfusa diff` — Report regression diff
  - `cpfusa sign` — HMAC-SHA256 artifact signing and verification
  - `cpfusa hooks` — git pre-commit hook installation

## [0.4.0] — 2026-06-09

### Added
- v0.4 — Requirements traceability engine
  - `cpfusa trace` — full requirements ↔ source ↔ tests coverage matrix
  - `cpfusa req <REQ-ID>` — show single requirement with annotation locations
  - `--gaps` flag to show only untested/unannotated requirements
  - `--req-coverage N` and `--sec-tested N` CI gates
  - `.fusa-reqs.json` requirement registry format

## [0.3.0] — 2026-06-09

### Added
- v0.3 — Static analysis
  - `cpfusa analyze` — clang-tidy integration, cppcheck integration, own passes
  - ANAL003: unguarded global write detection
  - ANAL004: raw pointer arithmetic detection
  - ANAL005: unbounded loop detection
  - ANAL006: large stack allocation detection
  - ANAL007: memcpy/memset on possibly non-trivial types

## [0.2.0] — 2026-06-09

### Added
- v0.2 — MISRA/AUTOSAR lint rules
  - `cpfusa lint` — 10 rules: LINT001–LINT010
  - LINT001: no raw new/delete (MISRA A18-5-2)
  - LINT002: no goto (MISRA A6-6-1)
  - LINT003: reinterpret_cast justification (MISRA A5-2-4)
  - LINT004: safe-state before abort/exit (MISRA A15-5-3)
  - LINT005: global mutable annotation (AUTOSAR A3-3-2)
  - LINT006: #define → constexpr (MISRA A2-13-1)
  - LINT007: C-style cast → named cast (MISRA A5-2-2)
  - LINT008: recursive function guard (JSF++ 119)
  - LINT009: printf/scanf → type-safe I/O
  - LINT010: exception specification

## [0.1.0] — 2026-06-09

### Added
- Initial release — v0.1 Foundation
  - `cpfusa init` — project configuration initialisation
  - `cpfusa check` — FUSA001–005 built-in rule engine
  - `cpfusa report` — text, JSON, HTML, SARIF report renderers
  - `cpfusa template` — SAFETY_PLAN.md, HARA.md, SVP.md, SCMP.md, SQAP.md generators
  - `cpfusa verify` — test evidence bundle (ctest integration)
  - `cpfusa qualify` — tool qualification stub
  - Runtime safety patterns: `Watchdog`, `SafeStateGuard`, `Heartbeat`
  - GitHub Actions CI matrix: Ubuntu (clang/gcc) × C++17/20, macOS, Windows
  - Self-hosting: repo carries `.fusa.json`, `.fusa-reqs.json`, `//fusa:req` annotations
