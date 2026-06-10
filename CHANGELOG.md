# Changelog

## [0.7.0] — 2026-06-10

### Added
- Homebrew formula (`Formula/cpp-fusa.rb`) — builds `cpfusa` from source via GitHub archive; `brew install` and `brew test` supported
- GitHub Actions composite action (`.github/action.yml`) — `uses: SoundMatt/cpp-FuSa@v0.7.0` mounts the project into the Docker image and runs any `cpfusa` subcommand; exposes `exit-code` output
- CPack packaging in `CMakeLists.txt` — NSIS (Windows installer with PATH modification), WiX (Windows MSI), DEB (Debian/Ubuntu), RPM (Fedora/RHEL); build with `cmake --build build --target package`
- ROADMAP.md updated to reflect reality: v0.7 (IEC 62443, SLSA) and v0.8 (distribution) marked complete

## [0.6.1] — 2026-06-10

### Added
- x-FuSa spec v1.8 conformance
  - All JSON documents carry §3.1 common header: `schemaVersion`, `kind`, `tool`, `toolVersion`, `language`, `generatedAt`
  - Finding schema §4: `ruleId` (camelCase), nested `location:{file,line,column}`, `remediation` (was `fix`), `category`, `standard`, `clause`, `fingerprint`
  - Exit codes §2.3: 0=success, 1=gate failure, 2=usage error, 3=runtime error
  - `cpfusa capabilities` — §10 capabilities endpoint: `{commands, formats, standards, specVersion}` for FuSaOps discovery
  - `cpfusa version --format json` — returns `{tool,version,specVersion}` machine-readable version
  - `.fusa.json` v1.8 schema: `configVersion`, nested `project:{name,version}`, camelCase `sourceDirs`/`excludePatterns`
- Expanded test suite: 454 tests covering all modules
  - test_report.cpp: 27 tests for spec v1.8 JSON envelope and finding schema
  - test_config.cpp: 19 tests including legacy round-trip, SIL/DAL/ASIL key routing
  - test_engine.cpp: 20 tests including per-finding category assertions
  - test_trace.cpp: 15 tests including flat-array requirements loading
  - test_verify.cpp: 10 tests for evidence bundle JSON structure
  - test_impact.cpp: 12 tests including ref round-trip and text render
- 153-requirement `.fusa-reqs.json` covering all modules (CFG, ENG, FUSA, LINT, ANAL, CYBER, RPT, TRACE, VERIFY, QUALIFY, RELEASE, AUDIT, TARA, FMEA, SAFETYCASE, BADGE, DIFF, SIGN, HOOKS, RT, VULN, BOUNDARY, NF)

### Fixed
- `cpfusa init` writes `.fusa-reqs.json` as flat JSON array `[]` (compatible with `trace::load_requirements`)
- `cpfusa version` subcommand matches §9.1 format `^(\S+) (\d+\.\d+\.\d+)$`
- `--no-color` propagated to all `ReportOptions` objects; colour suppressed when non-TTY or `NO_COLOR` env set
- `std::gmtime` (CWE-676 thread-unsafe) replaced with `gmtime_r`/`gmtime_s` platform conditional in `capabilities` command
- SARIF renderer: `locations` array always emitted; `uri` defaults to `"."` for project-level findings

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

### Added (CI/CD hardening)
- 17 new test files: 395 tests total covering all modules added in v0.5–0.6
- `.github/workflows/codeql.yml` — CodeQL `security-extended` weekly scan
- `.github/workflows/dco.yml` — DCO Signed-off-by enforcement on every PR commit
- `.github/workflows/release.yml` — tag-triggered release pipeline; builds linux/macos/windows binaries with SHA-256 checksums
- `.github/CODEOWNERS`, `.github/PULL_REQUEST_TEMPLATE.md`, `.github/ISSUE_TEMPLATE/` — community files
- CI: coverage (LCOV), SARIF upload to GitHub Security tab, Docker smoke-test job
- `Dockerfile` committed; Alpine runtime includes `libstdc++` for dynamic linking

### Fixed
- `impact.cpp`: command injection (CYBER005 CWE-78) — git refs now allowlist-validated
- `impact.cpp`: `goto next_req` (LINT002) — replaced with `matched` flag + `break`
- SHA-256 `reinterpret_cast` sites annotated with `// fusa:unsafe` (sign, release, qualify, auditpack)
- `safety-case` command now produces a third artifact: `safety-case.md` (Markdown GSN table)
- `hooks::remove`: ifstream now scoped so handle closes before `fs::remove`; fixes Windows file-lock error
- Windows/MSVC: `popen`/`pclose` → `_popen`/`_pclose` in 5 files; `/wd4996` for `gmtime`; `/wd4100` for unused params
- SARIF renderer: always emits `locations` array (GitHub Code Scanning requirement); fallback uri `"."` for project-level findings
- `TempDir`: atomic counter suffix prevents path collisions across test instances; destructor uses `error_code` overload (noexcept-safe)
- Watchdog test timing: 500 ms / 100 ms kick interval is robust on slow CI runners
- CI: switched clang-16 → clang-14 (only version present on ubuntu-22.04 runners)
- CI: lcov `--ignore-errors mismatch` removed (lcov 1.x on ubuntu-22.04 doesn't support it)
- CI coverage gate: corrected flag from `--lcov`/`--threshold` to `--profile`

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
