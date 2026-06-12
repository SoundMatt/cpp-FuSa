# Tool Qualification Guide

## Overview

ISO 26262 Part 8 §11 and IEC 61508-3 §7.4.4 require that software tools used in
safety-related development processes be qualified. Tool qualification establishes
confidence that a tool performs its intended function correctly — it does not certify
the tool, but provides documented evidence to support a safety assessor's judgement.

cpp-FuSa provides a built-in qualification suite (`cpfusa qualify`) that generates
machine-readable evidence conforming to these requirements.

## Running the qualification suite

```bash
cpfusa qualify
```

This command:

1. Runs 8 built-in test cases covering FUSA001–005 (positive and negative per rule).
2. Verifies that each rule detects the pattern it claims to detect (positive case).
3. Verifies that each rule does not produce false positives on clean code (negative case).
4. Writes `qualify-report.json` with a SHA-256 integrity hash.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | All cases passed |
| 1 | One or more cases failed, or report could not be written |

## Report structure

`qualify-report.json` contains:

```json
{
  "generatedAt": "2026-01-01T12:00:00Z",
  "cppVersion":  "C++17",
  "module":      "cpfusa",
  "total":       8,
  "passed":      8,
  "failed":      0,
  "results": [
    {
      "case": {
        "name":          "FUSA001-pos: missing .fusa.json",
        "ruleId":        "FUSA001",
        "description":   "Project without .fusa.json must produce a FUSA001 finding.",
        "expectFinding": true
      },
      "passed": true,
      "error":  ""
    }
  ],
  "hash": "a3f2...e8b1"
}
```

The `hash` field is an SHA-256 of the report contents (excluding the hash field itself),
providing tamper evidence.

## Verifying the integrity hash

```bash
# Recompute and compare manually (Python):
python3 -c "
import json, hashlib
with open('qualify-report.json') as f:
    j = json.load(f)
stored = j.pop('hash', '')
digest = hashlib.sha256(json.dumps(j, sort_keys=True, separators=(',',':')).encode()).hexdigest()
print('stored: ', stored)
print('computed:', digest)
print('MATCH' if stored == digest else 'MISMATCH')
"
```

## What is tested

The suite covers the core engine rules (FUSA001–005):

| Case | Rule | What is tested |
|---|---|---|
| FUSA001-pos | FUSA001 | Missing `.fusa.json` → finding produced |
| FUSA001-neg | FUSA001 | `.fusa.json` present → no finding |
| FUSA002-pos | FUSA002 | No `//fusa:req` annotation → finding produced |
| FUSA002-neg | FUSA002 | `//fusa:req` annotation present → no finding |
| FUSA003-pos | FUSA003 | Empty version in config → finding produced |
| FUSA003-neg | FUSA003 | Valid version in config → no finding |
| FUSA004-pos | FUSA004 | No `.fusa-evidence.json` → finding produced |
| FUSA004-neg | FUSA004 | `.fusa-evidence.json` present → no finding |

The LINT001–031 and ANAL003–012 rules are indirectly qualified through the
Catch2 unit test suite (633 tests). Run `cpfusa verify` to capture those results.

## Tool Confidence Level

Under IEC 61508-3, tools are assigned a Tool Confidence Level (TCL) based on:

- **TC1** — No tool confidence measures needed (tool output does not influence safety).
- **TC2** — Tool validated by other means (version control, known inputs, review).
- **TC3** — Full tool qualification documentation required.

cpp-FuSa is primarily a **TC2** tool: its output (findings and reports) influences
the safety process but does not directly generate executable safety-critical code.
The qualification suite supports TC2 validation by providing documented evidence
that the tool's analysis rules behave as specified.

For organisations requiring TC3, the qualification suite provides:

- Version-stamped, hashed reports (tamper evidence via SHA-256).
- Complete test case specifications (inputs, expected outputs, pass/fail).
- Machine-readable results for audit trail integration.
- An SCI (`cpfusa sci`) with SHA-256 checksums of all lifecycle artifacts.

## Integration into a safety case

Include the qualification report in your project's safety case package alongside:

- `sbom.json` — Software Bill of Materials (SPDX 3.0.1 JSON-LD).
- `provenance.json` — Build provenance record.
- `.fusa-evidence.json` — Test evidence bundle.
- `sci.json` — Software Configuration Index.
- `sas.json` / `sas.md` — Software Accomplishment Summary.

The complete artefact set provides evidence for:

- §8.4.4 of ISO 26262-8 (tool use qualification).
- §7.4.4.10 of IEC 61508-3 (software tool qualification).
- §12.3 of DO-178C (tool qualification).

## Regenerating the report

The qualification report must be regenerated:

- On every release of cpp-FuSa used in the project.
- When the C++ toolchain or CMake version changes.
- As part of the CI pipeline (add `cpfusa qualify` as a CI step).

Example GitHub Actions step:

```yaml
- name: cpfusa qualify
  run: cpfusa qualify

- name: Upload qualification report
  uses: actions/upload-artifact@v4
  with:
    name: qualify-report
    path: qualify-report.json
```

## Full evidence assembly procedure

```bash
# 1. Run tool qualification
cpfusa qualify

# 2. Run test suite and collect evidence
ctest --test-dir build --output-on-failure -j1
cpfusa verify

# 3. Generate release artifacts
cpfusa release

# 4. Generate lifecycle index
cpfusa sci
cpfusa sas

# 5. Bundle everything
cpfusa audit-pack

# 6. Record binary hash in safety plan
sha256sum build/cpfusa
```
