# cpp-FuSa Roadmap

## Vision

cpp-FuSa is the functional safety enablement layer for C++-based systems.
It provides MISRA/AUTOSAR coding standards enforcement, static analysis,
requirements traceability, evidence generation, runtime safety patterns,
and compliance tooling to help organizations build safety cases for ISO 26262,
IEC 61508, ISO 21434, DO-178C, and related standards.

It is **NOT** a certification product.
It is an engineering accelerator that reduces the cost of producing
functional safety evidence throughout the SDLC.

---

## v0.1 — Foundation ✅

**Goal:** Core architecture — CLI, rule engine, config, report.

- CLI framework (`cpfusa`)
- Project configuration (`.fusa.json`)
- Built-in rules: FUSA001–FUSA005
- Text / JSON / HTML / SARIF report renderers
- GitHub Actions CI (Ubuntu × clang/gcc, macOS, Windows, C++17/20)

Deliverables: `cpfusa init`, `cpfusa check`, `cpfusa report`

---

## v0.2 — Coding Standard ✅

**Goal:** MISRA C++:2023 and AUTOSAR C++14 lint rules.

- LINT001: No raw new/delete (MISRA A18-5-2)
- LINT002: No goto (MISRA A6-6-1)
- LINT003: reinterpret_cast justification (MISRA A5-2-4)
- LINT004: safe-state before abort/exit (MISRA A15-5-3)
- LINT005: Global mutable annotation (AUTOSAR A3-3-2)
- LINT006: #define → constexpr (MISRA A2-13-1)
- LINT007: C-style cast → named cast (MISRA A5-2-2)
- LINT008: Recursive function guard (JSF++ 119)
- LINT009: printf/scanf → type-safe I/O
- LINT010: Exception specification

Deliverables: `cpfusa lint`

---

## v0.3 — Static Analysis ✅

**Goal:** External tool integration + own analysis passes.

- clang-tidy integration (compile_commands.json → JSON output)
- cppcheck integration (XML output)
- ANAL003: Unguarded global write
- ANAL004: Raw pointer arithmetic
- ANAL005: Unbounded loop detection
- ANAL006: Large stack allocation
- ANAL007: memcpy on non-trivial types

Deliverables: `cpfusa analyze`

---

## v0.4 — Traceability ✅

**Goal:** Requirements → Code → Tests coverage matrix.

- `.fusa-reqs.json` requirement registry
- `//fusa:req` / `//fusa:test` annotation scanner
- Coverage matrix with %annotated and %tested
- CI gates: `--req-coverage N`, `--sec-tested N`
- `cpfusa req <REQ-ID>` — show single requirement

Deliverables: `cpfusa trace`, `cpfusa req`

---

## v0.5 — Full Feature Parity with go-FuSa ✅

**Goal:** Achieve parity with go-FuSa across all major artifact categories.

- `cpfusa verify` — CTest integration, `.fusa-evidence.json`
- `cpfusa qualify` — 8 built-in test cases, `qualify-report.json` with SHA-256 hash
- `cpfusa cyber` — 20 CWE-mapped rules (CYBER001–020), `cyber-report.json`
- `cpfusa tara` — ISO 21434 Ch.9 threat scenarios, `tara.json` + `tara.md`
- `cpfusa fmea` — dFMEA from declarations, `fmea.json` + `fmea.csv` with RPN
- `cpfusa safety-case` — GSN argument, `safety-case.json` + `safety-case.mermaid` + `safety-case.md`
- `cpfusa release` — SPDX 3.0.1 SBOM, `sbom.json` + `provenance.json` + `artifact-manifest.json`
- `cpfusa audit-pack` — ZIP bundle with `AUDIT-MANIFEST.json`
- `cpfusa badge` — Shields.io SVG, `fusa-badge.svg`
- `cpfusa diff` — introduced/resolved/unchanged report comparison
- `cpfusa sign` — HMAC-SHA256 artifact signing + verification
- `cpfusa hooks` — git pre-commit hook installer/remover

---

## v0.6 — Full Go-FuSa v0.21 Parity ✅

**Goal:** Feature parity with go-FuSa v0.21 across all major categories.

- `cpfusa hara` — HARA management (show/init/asil), ISO 26262-3 Table 4 ASIL determination
- `cpfusa iso26262` — ISO 26262 Part 6 gap assessment, summary keys `satisfied`/`gaps` (§9.3)
- `cpfusa iec61508` — IEC 61508 Parts 1-3 gap assessment
- `cpfusa boundary` — Component boundary diagram → `boundary.mermaid` + `boundary.dot`
- `cpfusa metrics` — Safety metrics time series → `.fusa-metrics.json`
- `cpfusa vuln` — CMake dependency vulnerability scan → `vuln.json`
- `cpfusa coverage` — LCOV structural coverage (DO-178C) → `coverage-report.json`
- `cpfusa disposition` — Finding disposition lifecycle → `.fusa-dispositions.json`
- `cpfusa impact` — git diff + req mapping impact analysis
- `cpfusa do178` — DO-178C Annex A objectives (41 checks, Tables A-1–A-11) → `do178-gap-report.json`
- `cpfusa sas` — Software Accomplishment Summary → `sas.json` + `sas.md`
- `cpfusa sci` — Software Configuration Index with SHA-256 → `sci.json`
- `cpfusa pr` — Problem Report log → `.fusa-problems.json`
- `cpfusa fix` — Fix guidance catalog with before/after code examples
- Docker image + `docker-compose.yml` + `docker-publish.yml` workflow
- x-FuSa spec v1.8 conformance: §3.1 envelope, §4 finding schema, §5 trace JSON, §9.3 summary keys, §2.3 exit codes, §10 capabilities
- 463 tests, 129 requirements at 100% annotated and tested coverage

---

## v0.7 — Industrial Security + Supply Chain ✅

**Goal:** IEC 62443 industrial security and SLSA supply-chain provenance.

- `cpfusa iec62443` — IEC 62443 Security Level compliance checks → `iec62443-report.json`
- `cpfusa slsa` — SLSA L2/L3 supply-chain provenance checks → `slsa-report.json`

---

## v0.8 — Distribution ✅ *(tagged v0.7.0)*

**Goal:** Zero-install and package manager distribution.

- ✅ Docker image (`ghcr.io/soundmatt/cpp-fusa`) — shipped in v0.6
- ✅ GitHub Actions release pipeline (tag-triggered, linux/macOS/Windows binaries) — shipped in v0.6
- ✅ Homebrew formula (`Formula/cpp-fusa.rb`) — builds from source via GitHub archive
- ✅ GitHub Actions composite action (`.github/action.yml`) — `uses: SoundMatt/cpp-FuSa@v0.7.0`
- ✅ CPack packaging — NSIS (Windows installer) + DEB/RPM (Linux packages)

---

## v0.9 — AST Analysis + Full MISRA C++:2023 ✅

**Goal:** libclang AST integration and complete MISRA C++:2023 rule set.

- ✅ libclang optional integration (`src/ast/ast.cpp`, `cmake/FindLibClang.cmake`) — AST001-003
- ✅ Stub mode when libclang unavailable (AST000 INFO finding)
- ✅ `cpfusa ast` CLI subcommand with `--format text|json --output`
- ✅ LINT011–030: full MISRA C++:2023 + AUTOSAR extended rules
  - M4-10-2 NULL, A10-3-2 override, M6-4-6 switch default, M15-3-4 empty catch, M15-5-1 dtor throw
  - A16-0-1 function-like macro, A15-1-2 setjmp, A5-2-3 dynamic_cast, A9-5-1 union, A2-11-1 volatile
  - A8-4-1 variadic, A27-0-1 unsafe string fn, A27-0-2 atoi, M6-3-1 missing braces, A19-3-1 errno
  - M17-0-5 C headers, M16-0-3 #undef, A7-4-1 asm, A2-13-4 magic numbers, M16-2-1 include guard
- ✅ 179 requirements, 500 tests

---

## v0.10 — ISO 21434 + UNECE + Req Import/Export ✅

**Goal:** Full automotive cybersecurity standard coverage and requirements lifecycle management.

- ✅ `cpfusa iso21434` — ISO 21434:2021 CAL-scoped gap assessment (21 objectives, CAL-1 to CAL-4)
- ✅ `cpfusa unece` — UNECE R155 (9 threat categories) + R156 (6 SUMS requirements) gap reports
- ✅ `cpfusa req show|import|export` — requirements lifecycle: CSV import/export with duplicate skip, canonical `{"requirements":[]}` save
- ✅ Spec §9.3 objective status fix: `iso26262`, `iec61508`, `do178` now emit `"satisfied"` (not `"addressed"`)
- ✅ 167 requirements, 545 tests (v0.10.0 context: before go-FuSa parity additions)

---

## v0.11 — go-FuSa Parity Gaps ✅

**Goal:** Close all remaining feature gaps vs go-FuSa v0.22/v0.23.

- ✅ `cpfusa comp` — cyclomatic complexity (COMP001, DAL-A/B/C/D thresholds), `comp-report.json`
- ✅ COUP003 engine rule — missing `coupling-report.json` on DO-178C projects
- ✅ HARA005 engine rule — hazard ASIL exceeds project ASIL
- ✅ ISO26262002/003 engine rules — missing `asil` field on reqs / qualify failures
- ✅ `asil` field on requirements — optional ASIL field in `.fusa-reqs.json`, CSV, and trace JSON
- ✅ SPDX 2.2 / 2.3 SBOM formats — `cpfusa release --spdx-version 2.2|2.3|3.0.1`
- ✅ DOORS ReqIF XML import/export — `cpfusa trace import/export --format doors`
- ✅ Polarion work-item XML import/export — `cpfusa trace import/export --format polarion`
- ✅ Gap-assessment objective upgrades: iso26262 +2 objs, iec61508 +1 obj + 2 improved, do178 +3 improved
- ✅ **175 requirements, 603 tests**

---

## v0.12 — rust-FuSa Parity ✅

**Goal:** Close all static analysis gaps identified vs rust-FuSa v0.2.0.

- ✅ ANAL008 — Function body > 60 lines (WARNING, DO-178C §6.3.4 / MISRA C++:2023 Rule 6-3-1)
- ✅ ANAL009 — Nesting depth > 5 within a function body (WARNING)
- ✅ ANAL010 — Function parameter count > 7 (WARNING, MISRA C++:2023 Rule 8-4-2 / JSF++ Rule 122)
- ✅ ANAL011 — Narrowing integer cast to 8-/16-bit types (WARNING, MISRA C++:2023 Rule 5-0-8)
- ✅ ANAL012 — More than 3 explicit return points per function (INFO, MISRA C++:2023 Rule 6-6-5)
- ✅ **180 requirements, 614 tests**

---

## Future

- QNX / FreeRTOS / Zephyr RTOS integration
- AUTOSAR Adaptive Platform compliance checks
- Homebrew tap (`homebrew-soundmatt`) for binary distribution
- MISRA C++:2023 remaining rules (rule count >100)
