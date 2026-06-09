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

- `cpfusa verify` — CTest integration, `.fusa-evidence.json` with generatedAt/cppVersion/results/summary
- `cpfusa qualify` — 8 built-in test cases, `qualify-report.json` with SHA-256 integrity hash
- `cpfusa cyber` — 20 CWE-mapped rules (CYBER001–020), `cyber-report.json`
- `cpfusa tara` — ISO 21434 Ch.9 threat scenarios, `tara.json` + `tara.md`
- `cpfusa fmea` — dFMEA from declarations, `fmea.json` + `fmea.csv` with RPN
- `cpfusa safety-case` — GSN argument, `safety-case.json` + `safety-case.mermaid`
- `cpfusa release` — SPDX 3.0.1 SBOM, `sbom.json` + `provenance.json` + `artifact-manifest.json`
- `cpfusa audit-pack` — ZIP bundle with `AUDIT-MANIFEST.json`
- `cpfusa badge` — Shields.io SVG, `fusa-badge.svg`
- `cpfusa diff` — introduced/resolved/unchanged report comparison
- `cpfusa sign` — HMAC-SHA256 artifact signing + verification
- `cpfusa hooks` — git pre-commit hook installer/remover

Artifacts match go-FuSa filenames exactly.

---

## v0.6 — Extended Coverage

**Goal:** Deeper analysis and coverage tooling.

- LCOV/gcov structural coverage parser (statement, branch, MC/DC)
- `cpfusa coverage` — DO-178C §6.4.4 coverage report
- `cpfusa vuln` — OSV API + CMake dependency vulnerability scan
- `cpfusa boundary` — Component boundary diagram (Mermaid + DOT)
- `cpfusa fix` — Auto-fix guidance with code patterns

Deliverables: `cpfusa coverage`, `cpfusa vuln`, `cpfusa boundary`, `cpfusa fix`

---

## v0.7 — DO-178C + SAS + SCI

**Goal:** Complete DO-178C process support.

- Annex A gap report (38 objectives, Tables A-1 to A-11)
- Software Accomplishment Summary (SAS) — 20 evidence items
- Software Configuration Index (SCI) — SHA-256 lifecycle data
- Problem Report log (CRUD + PR001 engine rule)

Deliverables: `cpfusa do178`, `cpfusa sas`, `cpfusa sci`, `cpfusa pr`

---

## v0.8 — IEC 62443 + SLSA

**Goal:** Industrial and supply-chain security.

- IEC 62443 Security Level compliance checks
- SLSA L2/L3 supply-chain provenance checks

Deliverables: `cpfusa iec62443`, `cpfusa slsa`

---

## v1.0 — Docker + Distribution

**Goal:** Zero-install workflow.

- Docker image (ghcr.io/soundmatt/cpp-fusa)
- GitHub Actions composite action
- Homebrew formula
- Windows installer (NSIS/WiX)

---

## Future

- libclang integration for deeper AST analysis
- MISRA C++:2023 full rule set (300+ rules)
- QNX / FreeRTOS / Zephyr RTOS integration
- AUTOSAR Adaptive Platform AUTOSAR-AP compliance checks
