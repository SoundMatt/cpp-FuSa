# cpp-FuSa

A functional safety enablement toolkit for C++ projects. cpp-FuSa provides MISRA/AUTOSAR lint
rules, static analysis passes, requirements traceability, CI evidence bundles, and runtime safety
patterns to help teams build safety cases for ISO 26262, IEC 61508, ISO 21434, and DO-178C.

[![CI](https://github.com/SoundMatt/cpp-FuSa/actions/workflows/ci.yml/badge.svg)](https://github.com/SoundMatt/cpp-FuSa/actions/workflows/ci.yml)

> **Not a certification product.** cpp-FuSa is an engineering accelerator that reduces
> the cost of producing functional safety evidence throughout the SDLC.

## Modules

| Module | Description |
|---|---|
| `include/cpfusa/` | Core types — `Finding`, `Severity`, `Result<T>`, `Version` |
| `src/config/` | Project configuration (`.fusa.json`) |
| `src/engine/` | Rule engine + FUSA001–005 built-in checks |
| `src/report/` | Text, JSON, HTML, SARIF compliance report renderers |
| `src/lint/` | MISRA/AUTOSAR coding rules — LINT001–010 |
| `src/analyze/` | Static analysis — clang-tidy + cppcheck wrappers + own passes |
| `src/trace/` | Requirements traceability engine — `//fusa:req` / `//fusa:test` |
| `src/template/` | Safety plan, SVP, HARA, SCMP, SQAP document generators |
| `src/runtime/` | RAII safety patterns — `Watchdog`, `SafeStateGuard`, `Heartbeat` |
| `src/testutil/` | Test harness helpers (`TempDir`, `has_finding`) |

## Build

Requires: CMake ≥ 3.21, C++17 compiler, Ninja (optional). Dependencies fetched automatically.

```bash
# Configure and build
cmake -B build -DCMAKE_BUILD_TYPE=Release -G Ninja
cmake --build build --parallel

# Or with Make wrapper
make build
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

# Run MISRA/AUTOSAR lint rules only
cpfusa lint

# Run static analysis (clang-tidy + cppcheck + own passes)
cpfusa analyze

# Show requirements traceability matrix
cpfusa trace

# Show only unannotated/untested requirements
cpfusa trace --gaps

# CI gate: fail if annotation coverage < 80%
cpfusa trace --req-coverage 80

# Show a specific requirement
cpfusa req REQ-RT001

# Generate safety document templates
cpfusa template --type all         # SAFETY_PLAN.md, HARA.md, SVP.md, SCMP.md, SQAP.md
cpfusa template --type safety-plan

# Generate full compliance report
cpfusa report
cpfusa report --format json --output report.json
cpfusa report --format html --output report.html
cpfusa report --format sarif --output results.sarif

# Collect test evidence bundle (runs ctest)
cpfusa verify

# Run tool qualification suite
cpfusa qualify
```

## Lint rules (v0.2 — MISRA/AUTOSAR)

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

## Static analysis passes (v0.3)

| Pass | Description |
|---|---|
| ANAL000 | Tool availability check (clang-tidy, cppcheck) |
| ANAL001 | clang-tidy findings (integrated) |
| ANAL002 | cppcheck findings (integrated) |
| ANAL003 | Unguarded write to global/shared variable |
| ANAL004 | Raw pointer arithmetic |
| ANAL005 | Potentially unbounded loop |
| ANAL006 | Large stack allocation (> 4 KiB) |
| ANAL007 | `memcpy`/`memset` on possibly non-trivial types |

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

## Standards coverage

| Standard | Scope |
|---|---|
| ISO 26262 | Automotive functional safety (ASIL A–D) |
| IEC 61508 | General functional safety (SIL 1–4) |
| ISO 21434 | Automotive cybersecurity |
| DO-178C | Aerospace software (process alignment) |
| MISRA C++:2023 | C++ coding standard |
| AUTOSAR C++14 | AUTOSAR adaptive platform coding guidelines |
| JSF++ | Joint Strike Fighter C++ coding standards |

## Requirements traceability

Annotate source with `//fusa:req` and tests with `//fusa:test`, define requirements in
`.fusa-reqs.json`, then run `cpfusa trace` to get a full coverage matrix.

## License

Mozilla Public License v2.0. See [LICENSE](LICENSE).
