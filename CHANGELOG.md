# Changelog

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
