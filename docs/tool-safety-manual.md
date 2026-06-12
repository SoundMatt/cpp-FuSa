# cpp-FuSa Tool Safety Manual

**Version:** 0.12.3  
**Binary:** `cpfusa`  
**Repository:** `github.com/SoundMatt/cpp-FuSa`  
**License:** Mozilla Public License 2.0  
**Standards addressed:** ISO 26262, IEC 61508, ISO 21434, UNECE R155/R156, DO-178C  
**Spec conformance:** x-FuSa specification v1.9

---

## 1. Purpose

This document is the Tool Safety Manual for cpp-FuSa. It is intended for:

- Engineering teams qualifying cpp-FuSa for use in safety-critical C++ projects
- Auditors assessing compliance with ISO 26262-8 (software tools), IEC 61508-3, or equivalent standards
- CI architects integrating cpp-FuSa into a regulated software development lifecycle

## 2. Tool Overview

cpp-FuSa is a functional safety enablement toolkit for C++ projects. It is **not** a
certification product — it is an engineering accelerator that reduces the cost of
producing functional safety evidence throughout the SDLC.

Capabilities:

| Capability | Rules | Command |
|---|---|---|
| Project structure checks | FUSA001–005 | `cpfusa check` |
| MISRA/AUTOSAR/JSF++ coding standard analysis | LINT001–031 | `cpfusa lint` |
| Static analysis (clang-tidy, cppcheck, own passes) | ANAL001–012 | `cpfusa analyze` |
| Requirements traceability and coverage | — | `cpfusa trace` |
| Requirements import/export (CSV, DOORS ReqIF, Polarion XML) | — | `cpfusa req import|export` |
| Cyclomatic complexity analysis (DO-178C §6.3.4) | COMP001 | `cpfusa comp` |
| SPDX 2.2 / 2.3 / 3.0.1 SBOM, provenance, artifact manifest | — | `cpfusa release [--spdx-version 2.2|2.3|3.0.1]` |
| Test evidence collection (CTest) | — | `cpfusa verify` |
| Cybersecurity analysis — 20 CWE-mapped rules | CYBER001–020 | `cpfusa cyber` |
| Hazard Analysis and Risk Assessment | HARA001–005, engine rules HARA002–005 | `cpfusa hara` |
| ISO 26262 Part 6 gap assessment | — | `cpfusa iso26262` |
| IEC 61508 Parts 1-3 gap assessment | — | `cpfusa iec61508` |
| DO-178C Annex A gap assessment | — | `cpfusa do178` |
| ISO 21434:2021 CAL-scoped gap assessment | — | `cpfusa iso21434` |
| UNECE R155 threat category gap assessment | — | `cpfusa unece --regulation r155` |
| UNECE R156 SUMS gap assessment | — | `cpfusa unece --regulation r156` |
| Threat Analysis and Risk Assessment (ISO 21434) | — | `cpfusa tara` |
| dFMEA generation from source declarations (with optional `--cyber` enrichment) | — | `cpfusa fmea [--cyber]` |
| GSN Safety case assembly | — | `cpfusa safety-case` |
| SBOM (SPDX 2.2/2.3/3.0.1), provenance, artifact manifest | — | `cpfusa release` |
| Tool qualification suite | — | `cpfusa qualify` |
| ZIP audit evidence bundle | — | `cpfusa audit-pack` |
| Dependency vulnerability scan | — | `cpfusa vuln` |
| Component boundary diagrams | — | `cpfusa boundary` |
| LCOV structural coverage (DO-178C) | — | `cpfusa coverage` |
| Software Accomplishment Summary | — | `cpfusa sas` |
| Software Configuration Index | — | `cpfusa sci` |
| Problem Report log | — | `cpfusa pr` |
| Finding disposition lifecycle | — | `cpfusa disposition` |
| Change impact analysis | — | `cpfusa impact` |
| Safety metrics time series | — | `cpfusa metrics` |
| Fix guidance catalog | — | `cpfusa fix` |
| SVG status badge | — | `cpfusa badge` |
| Report regression diff | — | `cpfusa diff` |
| HMAC-SHA256 artifact signing | — | `cpfusa sign` |
| git pre-commit hook | — | `cpfusa hooks` |
| Tool capabilities discovery (FuSaOps) | — | `cpfusa capabilities` |

## 3. Tool Classification

### ISO 26262-8 / IEC 61508-3 Assessment

cpp-FuSa is a **software development support tool**. Its potential impact on the
software under development:

- **Indirect** — it reports findings but does not modify, compile, or link the target software
- **No direct output** is incorporated into the safety-critical binary

| Criterion | Assessment |
|---|---|
| Tool output directly in safety-critical code? | No |
| Tool failure could cause an undetected error in the target? | Possible (false negative) |
| Recommended TCL (ISO 26262-8 Table 4) | **TCL2** |

### TCL Guidance

| TCL | When applicable | Required evidence |
|---|---|---|
| TCL1 | Informational use only; all findings reviewed by a qualified engineer | Usage record |
| TCL2 | Recommended for most regulated projects | This manual + `qualify-report.json` |
| TCL3 | Mandated only if the project safety plan requires it | Full validation package |

## 4. Installation

### Prerequisites

- CMake ≥ 3.21
- C++17 compiler (GCC ≥ 10, Clang ≥ 12, MSVC 2022)
- Ninja (recommended) or Make
- Internet access for FetchContent (nlohmann/json, CLI11, Catch2 — fetched once, cached)

### Build from source

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release -G Ninja
cmake --build build --parallel
cmake --install build --prefix /usr/local   # → /usr/local/bin/cpfusa
```

### Docker (zero-install)

```bash
docker pull ghcr.io/soundmatt/cpp-fusa:latest
docker run --rm -v "$(pwd)":/project ghcr.io/soundmatt/cpp-fusa check
```

### Verify

```bash
cpfusa version
```

## 5. Configuration Reference

cpp-FuSa is configured by a `.fusa.json` file in the project root, created by
`cpfusa init`.

| Field | Type | Default | Description |
|---|---|---|---|
| `project` | string | directory name | Project display name |
| `version` | string | `"0.0.0"` | Project version |
| `standard` | string | `"iso26262"` | Safety standard: `iso26262`, `iec61508`, `iso21434`, `do178c` |
| `asil` | string | `"B"` | ASIL / SIL / DAL level |
| `language` | string | `"cpp17"` | Language version |
| `strict` | bool | `false` | Treat warnings as errors |
| `sourceDirs` | []string | `["src","include"]` | Source directories to scan |
| `excludePatterns` | []string | `["build/","_deps/"]` | Path substrings to exclude from analysis |

### Example (.fusa.json — x-FuSa spec v1.8)

```json
{
  "configVersion": "1.0",
  "project": {"name": "my-safety-project", "version": "1.0.0"},
  "standard": "iso26262",
  "asil": "ASIL-B",
  "strict": false,
  "sourceDirs": ["src", "include"],
  "excludePatterns": ["build/", "_deps/", "vendor/"]
}
```

## 6. CLI Command Reference

### `cpfusa check`
```
cpfusa check [--dir <path>] [--format text|json|html|sarif] [--output <file>] [--strict]
```
Runs FUSA001–005 structural checks. Exit 0 = no ERRORs. Exit 1 = one or more ERRORs.

### `cpfusa lint`
```
cpfusa lint [--dir <path>] [--strict]
```
Runs LINT001–010 MISRA/AUTOSAR/JSF++ coding standard rules across all C++ source files.

### `cpfusa analyze`
```
cpfusa analyze [--dir <path>] [--no-clang-tidy] [--no-cppcheck]
```
Runs clang-tidy, cppcheck, and own analysis passes (ANAL003–007).

### `cpfusa trace`
```
cpfusa trace [--dir <path>] [--gaps] [--req-coverage N] [--sec-tested N]
             [--format text|json] [--output <file>]
```
Scans `//fusa:req` (implementation) and `//fusa:test` (test) annotations.
CI gates: `--req-coverage 80` fails if fewer than 80% of requirements are annotated.
`--format json` writes `trace-report.json` to the project directory (x-FuSa §5 schema);
use `--output <file>` to redirect to a custom path.

### `cpfusa verify`
```
cpfusa verify [--dir <path>]
```
Runs CTest and writes `.fusa-evidence.json`.

### `cpfusa qualify`
```
cpfusa qualify [--dir <path>]
```
Runs 8 built-in positive/negative test cases and writes an SHA-256 integrity-hashed
`qualify-report.json`.

### `cpfusa hara`
```
cpfusa hara [--dir <path>] <show|init|asil>
cpfusa hara init [--project <name>] [--standard <std>]
cpfusa hara asil -s <S0-S3> -e <E0-E4> -c <C0-C3>
```
Manages `.fusa-hara.json`. `asil` derives ASIL from ISO 26262-3:2018 Table 4.

### `cpfusa iso26262`
```
cpfusa iso26262 [--dir <path>] [--asil ASIL-A|B|C|D] [--output <file>]
```
ISO 26262 Part 6 gap assessment. Writes `iso26262-gap-report.json`.

### `cpfusa iec61508`
```
cpfusa iec61508 [--dir <path>] [--sil SIL-1|2|3|4] [--output <file>]
```
IEC 61508 Parts 1-3 gap assessment. Writes `iec61508-gap-report.json`.

### `cpfusa do178`
```
cpfusa do178 [--dir <path>] [--dal DAL-A|B|C|D] [--output <file>]
```
DO-178C Annex A objectives gap report. Writes `do178-gap-report.json`.

### `cpfusa release`
```
cpfusa release [--dir <path>] [--full]
```
Generates `sbom.json` (SPDX 3.0.1 JSON-LD), `provenance.json`, `artifact-manifest.json`.

### `cpfusa audit-pack`
```
cpfusa audit-pack [--dir <path>] [--output <path>]
```
Bundles all evidence files into `audit-pack.zip` with SHA-256 manifest.

### `cpfusa sas`
```
cpfusa sas [--dir <path>] [--dal <level>]
```
Software Accomplishment Summary (DO-178C §11.20). Writes `sas.json` + `sas.md`.

### `cpfusa sci`
```
cpfusa sci [--dir <path>]
```
Software Configuration Index with SHA-256 checksums (DO-178C §11.16). Writes `sci.json`.

### `cpfusa disposition`
```
cpfusa disposition [--dir <path>] <add|list|show>
cpfusa disposition add --rule <ID> --reviewer <name> --rationale "<text>" [--action accept|fix]
```
Maintains `.fusa-dispositions.json`. Documents decisions for findings.

### `cpfusa fix`
```
cpfusa fix [<rule-id>]
```
Shows fix guidance with before/after code for a rule. No args = list all.

## 7. Rule Reference

### Severity levels

| Severity | Meaning | Default response |
|---|---|---|
| **ERROR** | Baseline safety requirement not met | Fail pipeline (`cpfusa check` exits 1) |
| **WARNING** | Potential safety concern; engineering judgement required | Review and document rationale |
| **INFO** | Observation relevant to completeness | Review; document acceptance if relevant |

### FUSA — Project Structure Rules

| Rule | Severity | Trigger | Remediation |
|---|---|---|---|
| FUSA001 | ERROR | `.fusa.json` not found | `cpfusa init` |
| FUSA002 | WARNING | No `//fusa:req` annotation found anywhere in source | Add `//fusa:req REQ-XXX` annotation |
| FUSA003 | WARNING | `project.version` empty or `0.0.0` | Set `version` in `.fusa.json` |
| FUSA004 | WARNING | `.fusa-evidence.json` not found | `cpfusa verify` |
| FUSA005 | INFO | `CHANGELOG.md` missing or empty | Add `CHANGELOG.md` |

### LINT — MISRA/AUTOSAR/JSF++ Coding Standard Rules

| Rule | Standard | Severity | Trigger | Remediation |
|---|---|---|---|---|
| LINT001 | MISRA A18-5-2 | WARNING | Raw `new`/`delete` | Replace with `std::make_unique`/`std::make_shared` |
| LINT002 | MISRA A6-6-1 | ERROR | `goto` statement | Refactor with structured control flow |
| LINT003 | MISRA A5-2-4 | WARNING | `reinterpret_cast` without `// fusa:unsafe` | Add justification comment |
| LINT004 | MISRA A15-5-3 | ERROR | `abort()`/`exit()` without `// fusa:safe-state` | Add safe-state transition |
| LINT005 | AUTOSAR A3-3-2 | WARNING | Global mutable variable without `// fusa:shared` | Annotate or make `const`/`constexpr` |
| LINT006 | MISRA A2-13-1 | WARNING | `#define` for numeric/string constant | Replace with `constexpr` |
| LINT007 | MISRA A5-2-2 | WARNING | C-style cast | Replace with named cast |
| LINT008 | JSF++ 119 | WARNING | Recursive function call without `// fusa:recursive` | Add depth-bound annotation |
| LINT009 | — | INFO | `printf`/`scanf` family | Replace with `std::ostream`/`std::format` |
| LINT010 | — | INFO | Function with `throw` without `noexcept` | Mark non-throwing functions `noexcept` |

### ANAL — Static Analysis Rules

| Rule | Severity | Trigger | Remediation |
|---|---|---|---|
| ANAL003 | WARNING | Unguarded write to global/shared variable | Add mutex or `// fusa:shared` |
| ANAL004 | WARNING | Raw pointer arithmetic | Replace with iterator or span |
| ANAL005 | WARNING | Potentially unbounded loop | Add `// fusa:bounded <max>` annotation |
| ANAL006 | WARNING | Stack allocation > 4 KiB | Move to heap or static storage |
| ANAL007 | WARNING | `memcpy`/`memset` on possibly non-trivial type | Use copy construction/assignment |

### CYBER — CWE-Mapped Cybersecurity Rules (ISO 21434)

CYBER001–020 cover: buffer overflows (CWE-120, -121, -122), format strings (CWE-134),
integer overflow (CWE-190), null dereference (CWE-476), command injection (CWE-78),
`reinterpret_cast` (CWE-242), unsafe C functions (CWE-676), use-after-free (CWE-416),
and more. See `cpfusa cyber --help` for the full list.

## 8. CI Pipeline Integration

Recommended GitHub Actions integration:

```yaml
name: Safety
on: [push, pull_request]

jobs:
  safety:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install tools
        run: sudo apt-get install -y cmake ninja-build zip
      - name: Build cpfusa
        run: |
          cmake -B build -DCMAKE_BUILD_TYPE=Release -G Ninja
          cmake --build build --parallel
      - run: ./build/cpfusa check
      - run: ./build/cpfusa trace
      - run: ./build/cpfusa verify
      - run: ./build/cpfusa qualify
      - run: ./build/cpfusa release
      - uses: actions/upload-artifact@v4
        with:
          name: safety-evidence
          path: |
            .fusa-evidence.json
            qualify-report.json
            sbom.json
            provenance.json
```

## 9. Rule Exclusions

Findings are suppressed per-line with:
```cpp
int* p = new int(42); // fusa:suppress LINT001
```

Or project-wide via `exclude_patterns` in `.fusa.json` for path-based exclusion.

**Safety plan obligation:** Every suppression must be justified in the project
safety plan before release acceptance. Acceptable justifications:

- Rule inapplicable to this file type (e.g. LINT001 in Catch2 test fixture)
- Compensating control exists (e.g. LINT003 with `// fusa:unsafe <justification>`)

## 10. Known Limitations

1. **LINT008** uses a name-matching heuristic for recursion detection. It may fire
   on overloaded functions where one overload calls another with the same base name.
   Supplement with `--no-recurse` compiler flags and manual review.

2. **LINT001** detects `new`/`delete` keywords. It does not detect raw heap allocation
   via `malloc`/`free`. Enable CYBER001 (`cpfusa cyber`) for C heap function detection.

3. **LINT003** requires `// fusa:unsafe` on the same line or the line immediately above
   `reinterpret_cast`. A comment two lines above is not recognised.

4. **Exclusion patterns** suppress by path substring. A pattern of `build/` will also
   match `rebuild/` if that directory exists.

5. **ANAL001/ANAL002** (clang-tidy/cppcheck) require those tools to be installed.
   `cpfusa analyze` skips them gracefully and reports `ANAL000` if unavailable.

6. `cpfusa verify` runs `ctest` in the first build directory found containing
   `CTestTestfile.cmake`. Projects with multiple build trees must specify `--dir`.

7. `cpfusa coverage` parses LCOV format (`.info` files). Generate with:
   `lcov --capture --directory build --output-file coverage.info`

8. cpp-FuSa performs static and structural analysis only. It does not replace:
   - Dynamic testing and coverage measurement at target hardware level
   - Formal verification
   - Manual code review by a qualified safety engineer

## 11. Assumptions of Use

| # | Assumption |
|---|---|
| AoU-1 | The tool is applied to the **complete** C++ source tree. Selective analysis may produce incomplete findings. |
| AoU-2 | Findings are reviewed by a **qualified safety engineer** before use in a safety case. cpp-FuSa automates detection; it does not replace engineering judgement. |
| AoU-3 | The tool binary is built from a verified tag and its version is recorded in the project safety plan. |
| AoU-4 | `qualify-report.json` is **regenerated** whenever the tool version changes. |
| AoU-5 | `exclude_patterns` and `// fusa:suppress` annotations are reviewed and justified in the safety plan before each release. |
| AoU-6 | `cpfusa verify` is run against the **same test suite** executed during integration testing. |

## 12. Tool Qualification Evidence Summary

| Evidence Item | Location | Generated By |
|---|---|---|
| Rule specification | `src/engine/rules.cpp`, `src/lint/lint.cpp`, etc. | Source code |
| Test specification | `tests/test_*.cpp` (454 tests) | Source code |
| Test results | `.fusa-evidence.json` | `cpfusa verify` |
| Qualification report | `qualify-report.json` | `cpfusa qualify` |
| SBOM | `sbom.json` | `cpfusa release` |
| Build provenance | `provenance.json` | `cpfusa release` |
| Software Configuration Index | `sci.json` | `cpfusa sci` |
| Software Accomplishment Summary | `sas.json`, `sas.md` | `cpfusa sas` |
| Traceability matrix | stdout of `cpfusa trace` | `cpfusa trace` |
| This document | `docs/tool-safety-manual.md` | Manual |

### Assembling a qualification package

1. `cpfusa qualify` — verify all cases pass
2. `cpfusa verify` — verify all tests pass
3. `cpfusa release` — generate SBOM and provenance
4. `cpfusa sci` — generate Software Configuration Index
5. `cpfusa sas` — generate Software Accomplishment Summary
6. `cpfusa audit-pack` — ZIP all evidence
7. Archive this document alongside `audit-pack.zip`
8. Record the tool version and SHA-256 of the `cpfusa` binary in the project safety plan

---

*cpp-FuSa is open source under the Mozilla Public License 2.0. The MPL 2.0 permits
use in commercial and regulated products. See `LICENSE` for terms.*
