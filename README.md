# cpp-FuSa

A functional safety enablement toolkit for C++ projects. cpp-FuSa provides MISRA/AUTOSAR lint
rules, static analysis passes, requirements traceability, CI evidence bundles, runtime safety
patterns, and compliance gap reports to help teams build safety cases for ISO 26262, IEC 61508,
ISO 21434, and DO-178C.

[![CI](https://github.com/SoundMatt/cpp-FuSa/actions/workflows/ci.yml/badge.svg)](https://github.com/SoundMatt/cpp-FuSa/actions/workflows/ci.yml)

> **Not a certification product.** cpp-FuSa is an engineering accelerator that reduces
> the cost of producing functional safety evidence throughout the SDLC.

## Docker quick start

Zero-install: mount your C++ project at `/project`.

```bash
# Pull the latest image
docker pull ghcr.io/soundmatt/cpp-fusa:latest

# Run a single command
docker run --rm -v "$(pwd)":/project ghcr.io/soundmatt/cpp-fusa check
docker run --rm -v "$(pwd)":/project ghcr.io/soundmatt/cpp-fusa lint
docker run --rm -v "$(pwd)":/project ghcr.io/soundmatt/cpp-fusa trace
docker run --rm -v "$(pwd)":/project ghcr.io/soundmatt/cpp-fusa release

# Or run the full evidence-generation pipeline via Compose
docker compose run --rm pipeline
```

## Build from source

Requires: CMake ≥ 3.21, C++17 compiler, Ninja (optional). Dependencies fetched automatically via `FetchContent`.

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release -G Ninja
cmake --build build --parallel
ctest --test-dir build --output-on-failure -j1
```

## Install

```bash
cmake --install build --prefix /usr/local
# → /usr/local/bin/cpfusa
```

## Quick start

```bash
# Initialise a project
cpfusa init

# Run all safety checks (exits 1 on ERROR; --strict exits 1 on WARNING too)
cpfusa check
cpfusa check --strict

# Run MISRA/AUTOSAR lint rules
cpfusa lint

# Run static analysis (clang-tidy + cppcheck + own passes)
cpfusa analyze

# Cybersecurity analysis — 20 CWE-mapped rules (ISO 21434)
cpfusa cyber
cpfusa cyber --write --strict

# Requirements traceability matrix
cpfusa trace
cpfusa trace --gaps
cpfusa trace --req-coverage 80   # CI gate: fail if < 80% annotated

# Hazard Analysis and Risk Assessment
cpfusa hara init
cpfusa hara show
cpfusa hara asil -s S2 -e E3 -c C2   # → ASIL-C

# Standards gap reports
cpfusa iso26262 --asil ASIL-B --output iso26262-gap-report.json
cpfusa iec61508 --sil SIL-2   --output iec61508-gap-report.json
cpfusa do178    --dal DAL-B   --output do178-gap-report.json

# Safety analysis artifacts
cpfusa tara          # TARA per ISO 21434 Ch. 9 → tara.json + tara.md
cpfusa fmea          # dFMEA from declarations  → fmea.json + fmea.csv
cpfusa safety-case   # GSN safety case          → safety-case.{json,mermaid,md}

# Test evidence and tool qualification
cpfusa verify        # run ctest → .fusa-evidence.json
cpfusa qualify       # tool qualification suite → qualify-report.json

# Release artifacts
cpfusa release       # SPDX 3.0.1 SBOM → sbom.json + provenance.json + artifact-manifest.json
cpfusa audit-pack    # ZIP evidence bundle → audit-pack.zip
cpfusa badge         # Shields.io SVG → fusa-badge.svg

# Software process artifacts (DO-178C)
cpfusa sas           # Software Accomplishment Summary → sas.json + sas.md
cpfusa sci           # Software Configuration Index   → sci.json

# Impact and change management
cpfusa impact                            # git diff + req mapping
cpfusa diff baseline.json current.json   # regression gating (exit 1 on new findings)
cpfusa disposition add --rule LINT001 --reviewer alice --rationale "test only"
cpfusa pr add --title "Stack overflow in parser" --severity major
cpfusa metrics record                    # snapshot errors/reqs/coverage trend

# Security
cpfusa vuln                    # scan CMake deps for known CVEs → vuln.json
cpfusa sign --key key.hex file # HMAC-SHA256 artifact signing
cpfusa sign --keygen key.hex   # generate signing key
cpfusa hooks install           # git pre-commit hook

# Visualisation
cpfusa boundary    # component diagram → boundary.mermaid + boundary.dot
cpfusa coverage --profile coverage.info --dal DAL-B   # LCOV → DO-178C report

# Fix guidance
cpfusa fix         # list all rules with fix guidance
cpfusa fix LINT001 # show before/after fix for a specific rule

# Full compliance report
cpfusa report
cpfusa report --format json  --output report.json
cpfusa report --format html  --output report.html
cpfusa report --format sarif --output results.sarif

# Safety document templates
cpfusa template --type all    # SAFETY_PLAN.md, HARA.md, SVP.md, SCMP.md, SQAP.md

# Requirement lookup, import, and export
cpfusa req show               # show all requirements and their annotations
cpfusa req show REQ-FO-001    # show a single requirement
cpfusa req import --file reqs.csv
cpfusa req export --output reqs.csv

# ISO 21434 CAL gap report
cpfusa iso21434 --cal CAL-2 --output iso21434-gap-report.json

# UNECE R155/R156 gap report
cpfusa unece --regulation r155 --output unece-r155-gap-report.json
cpfusa unece --regulation both

# MISRA C++:2023 rule mapping
cpfusa misra
cpfusa misra --gaps   # manually-reviewed rules only

# Data and control coupling analysis (DO-178C §6.4.4.3)
cpfusa coupling --output coupling-report.json

# Deep AST-based safety analysis (requires libclang)
cpfusa ast --format json --output ast-report.json

# Version and machine-readable capabilities
cpfusa version
cpfusa capabilities
```

## Modules

| Module | Description |
|---|---|
| `include/cpfusa/` | Core types — `Finding`, `Severity`, `Result<T>`, `Version` |
| `src/config/` | Project configuration (`.fusa.json`) |
| `src/engine/` | Rule engine + FUSA001–005 built-in checks |
| `src/report/` | Text, JSON, HTML, SARIF compliance report renderers |
| `src/lint/` | MISRA/AUTOSAR coding rules — LINT001–010 |
| `src/analyze/` | Static analysis — clang-tidy + cppcheck + own passes |
| `src/trace/` | Requirements traceability — `//fusa:req` / `//fusa:test` |
| `src/template/` | Safety document generators (SAFETY_PLAN, SVP, HARA, SCMP, SQAP) |
| `src/runtime/` | RAII safety patterns — `Watchdog`, `SafeStateGuard`, `Heartbeat` |
| `src/cyber/` | 20 CWE-mapped cybersecurity rules (ISO 21434) |
| `src/hara/` | HARA management — ASIL determination (ISO 26262-3 Table 4) |
| `src/iso26262/` | ISO 26262 Part 6 gap assessment |
| `src/iec61508/` | IEC 61508 Parts 1-3 gap assessment |
| `src/do178/` | DO-178C Annex A objectives gap report |
| `src/tara/` | TARA — ISO 21434 Ch. 9 threat scenarios |
| `src/fmea/` | dFMEA from source declarations with RPN scoring |
| `src/safety_case/` | GSN safety case (JSON + Mermaid + Markdown) |
| `src/verify/` | CTest integration → `.fusa-evidence.json` |
| `src/qualify/` | Tool qualification suite → `qualify-report.json` (SHA-256) |
| `src/release/` | SPDX 3.0.1 SBOM, provenance, artifact manifest |
| `src/auditpack/` | ZIP audit evidence bundle |
| `src/badge/` | Shields.io-style SVG badge |
| `src/diff/` | Report diff for regression gating |
| `src/sign/` | HMAC-SHA256 artifact signing |
| `src/hooks/` | git pre-commit hook installer |
| `src/boundary/` | Component boundary diagram (Mermaid + DOT) |
| `src/metrics/` | Safety metrics time series |
| `src/vuln/` | CMake dependency vulnerability scan |
| `src/coverage/` | LCOV structural coverage report (DO-178C) |
| `src/disposition/` | Finding disposition lifecycle management |
| `src/impact/` | Change impact analysis (git diff + req mapping) |
| `src/sas/` | Software Accomplishment Summary (DO-178C §11.20) |
| `src/sci/` | Software Configuration Index with SHA-256 (DO-178C §11.16) |
| `src/pr/` | Problem Report log (DO-178C §11.17) |
| `src/fix/` | Fix guidance catalog with before/after code examples |
| `src/testutil/` | Test harness helpers (`TempDir`, `has_finding`) |
| `src/ast/` | Deep AST-based safety analysis (requires libclang) |
| `src/coupling/` | Data and control coupling analysis (DO-178C §6.4.4.3) |
| `src/iso21434/` | ISO 21434 CAL gap assessment |
| `src/unece/` | UNECE R155/R156 gap assessment |
| `src/misra/` | MISRA C++:2023 → cpfusa rule mapping |

## Standards coverage

| Standard | Scope | Gap report |
|---|---|---|
| ISO 26262 | Automotive functional safety (ASIL A–D) | `cpfusa iso26262` |
| IEC 61508 | General functional safety (SIL 1–4) | `cpfusa iec61508` |
| ISO 21434 | Automotive cybersecurity | `cpfusa tara`, `cpfusa cyber`, `cpfusa iso21434` (CAL gap report) |
| UNECE R155/R156 | Cybersecurity/software update management | `cpfusa unece` |
| DO-178C | Aerospace software (DAL A–D) | `cpfusa do178`, `cpfusa coverage` |
| MISRA C++:2023 | C++ coding standard | `cpfusa lint` (LINT001–010), `cpfusa misra` |
| AUTOSAR C++14 | AUTOSAR coding guidelines | `cpfusa lint` (LINT005) |
| JSF++ | Joint Strike Fighter C++ | `cpfusa lint` (LINT008) |

## Tool qualification

cpp-FuSa includes a built-in tool qualification suite per ISO 26262 Part 8 §11 and DO-178C §12.
Run `cpfusa qualify` to execute 8 built-in positive/negative test cases and generate
`qualify-report.json` with an SHA-256 integrity hash.

## Lint rules (MISRA/AUTOSAR/JSF++)

| Rule | Standard | Description |
|---|---|---|
| LINT001 | MISRA A18-5-2 | No raw `new`/`delete` — use smart pointers |
| LINT002 | MISRA A6-6-1 | No `goto` statement |
| LINT003 | MISRA A5-2-4 | `reinterpret_cast` requires `// fusa:unsafe` annotation |
| LINT004 | MISRA A15-5-3 | `abort()`/`exit()` requires preceding `// fusa:safe-state` |
| LINT005 | AUTOSAR A3-3-2 | Global mutable variable requires `// fusa:shared` annotation |
| LINT006 | MISRA A2-13-1 | `#define` for constants — use `constexpr` |
| LINT007 | MISRA A5-2-2 | C-style cast — use named casts |
| LINT008 | JSF++ 119 | Recursive function — add `// fusa:recursive <max-depth>` |
| LINT009 | — | `printf`/`scanf` family — prefer type-safe I/O |
| LINT010 | — | Function with `throw` missing `noexcept` specification |

## Runtime safety patterns (header-only)

```cpp
#include "runtime/watchdog.hpp"
#include "runtime/safe_state.hpp"
#include "runtime/heartbeat.hpp"

// Watchdog — kicks must arrive within 100 ms or handler fires.
cpfusa::runtime::Watchdog wd(100ms, [] { engage_safe_state(); });
while (running) { wd.kick(); process(); }

// Safe-state guard — fires handler unless commit() is called.
cpfusa::runtime::SafeStateGuard guard([] { engage_safe_state(); });
do_critical_work();
guard.commit(); // disarm

// Heartbeat — on_missed() fires if beat() not called within period.
cpfusa::runtime::Heartbeat hb(1s, [] { log("alive"); }, [] { raise_alarm(); });
// In task loop: hb.beat();
```

## Annotation syntax

```cpp
// fusa:req REQ-001            — marks implementation of a requirement
// fusa:test REQ-001           — marks a test for a requirement
// fusa:unsafe <justification> — justifies reinterpret_cast or other unsafe use
// fusa:safe-state             — marks a safe-state transition before abort/exit
// fusa:shared                 — marks a global variable as intentionally shared
// fusa:recursive <max-depth>  — justifies a recursive function
// fusa:bounded <max-iter>     — justifies an infinite-style loop
// fusa:suppress LINT001       — suppresses a specific lint rule on this line
```

## License

Mozilla Public License v2.0. See [LICENSE](LICENSE).
