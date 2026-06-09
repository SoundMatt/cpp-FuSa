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

## v0.5 — Test Evidence

**Goal:** Verification evidence generation.

- CTest integration for evidence capture
- `.fusa-evidence.json` bundle with run metadata
- LCOV/gcov structural coverage parser (statement, branch, MC/DC)
- `cpfusa coverage` — DO-178C §6.4.4 coverage report

Deliverables: `cpfusa verify`, `cpfusa coverage`

---

## v0.6 — Tool Qualification

**Goal:** Self-qualification suite.

- Engine self-tests against known-good/bad synthetic projects
- SHA-256 hashed `qualify-report.json`
- Qualification guidance for ISO 26262-8 / DO-178C TQL evidence

Deliverables: `cpfusa qualify`

---

## v0.7 — Release Evidence

**Goal:** SBOM, build provenance, artifact signing.

- SPDX 3.0.1 SBOM from CMake/Conan/vcpkg manifests
- Build provenance (compiler, flags, git SHA, timestamp)
- HMAC-SHA256 artifact signing (`cpfusa sign`)
- Artifact manifest JSON

Deliverables: `cpfusa release`, `cpfusa sign`

---

## v0.8 — Safety Case

**Goal:** Safety case assembly and evidence bundling.

- GSN diagram (Mermaid)
- Compliance mapping (standard ↔ evidence items)
- `cpfusa safety-case` — assemble from collected evidence
- `cpfusa audit-pack` — ZIP bundle for auditors

Deliverables: `cpfusa safety-case`, `cpfusa audit-pack`

---

## v0.9 — FMEA + Boundary

**Goal:** Design-level safety artefacts.

- dFMEA from class/function declarations (header parsing)
- Component boundary diagram (Mermaid + DOT)
- JSON + CSV FMEA export

Deliverables: `cpfusa fmea`, `cpfusa boundary`

---

## v0.10 — Cybersecurity

**Goal:** ISO 21434 cybersecurity analysis.

- CWE-mapped MISRA/CERT-C++ rules for cybersecurity
- TARA generation (STRIDE threat model, risk matrix, Markdown export)
- IEC 62443 Security Level compliance checks
- SLSA L2/L3 supply-chain checks

Deliverables: `cpfusa cyber`, `cpfusa tara`, `cpfusa iec62443`, `cpfusa slsa`

---

## v0.11 — Vulnerability Scanning

**Goal:** Dependency vulnerability management.

- OSV API integration for Conan/vcpkg/CMake deps
- `cpfusa vuln` — vulnerability report

Deliverables: `cpfusa vuln`

---

## v0.12 — DO-178C Toolset

**Goal:** Complete DO-178C process support.

- Annex A gap report (38 objectives, Tables A-1 to A-11)
- Software Accomplishment Summary (20 evidence items)
- Software Configuration Index (SHA-256 lifecycle data)
- Problem Report log (CRUD + PR001 engine rule)

Deliverables: `cpfusa do178`, `cpfusa sas`, `cpfusa sci`, `cpfusa pr`

---

## v0.13 — Report Tooling

**Goal:** Diff, badge, and enhanced reporting.

- Report diff engine (introduced/resolved/unchanged findings)
- SVG badge generator (Shields.io-style)
- Enhanced HTML report with charts
- Fix suggestions (`cpfusa fix`)

Deliverables: `cpfusa diff`, `cpfusa badge`, `cpfusa fix`

---

## v1.0 — Docker + Distribution

**Goal:** Zero-install workflow.

- Docker image (ghcr.io/soundmatt/cpp-fusa)
- GitHub Actions composite action
- Homebrew formula
- Windows installer (NSIS/WiX)

---

## Future

- `cpfusa hooks` — git pre-commit hook installer
- libclang integration for deeper AST analysis
- MISRA C++:2023 full rule set (300+ rules)
- QNX / FreeRTOS / Zephyr RTOS integration
- AUTOSAR Adaptive Platform AUTOSAR-AP compliance checks
