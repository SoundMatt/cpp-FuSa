# Changelog

## [Unreleased]

### Added
- `docker-publish.yml` now notifies `SoundMatt/FuSaOps` via `repository_dispatch`
  (`xfusa-released`) after a successful image push, so FuSaOps rebuilds its
  bundled image promptly instead of waiting for its weekly cron. Requires a
  `FUSAOPS_DISPATCH_TOKEN` secret in this repo; falls back silently
  (`continue-on-error`) to the weekly rebuild if it's not set.

## [0.14.5] — 2026-07-27

### Fixed
- **FUSA004 `location.file` was empty** (issue #35): `make_fusa004()` in
  `src/engine/rules.cpp` hardcoded `""` for the missing `.fusa-evidence.json`
  finding's `location.file` instead of the target filename, unlike the
  sibling FUSA003/FUSA005 rules. Now emits `.fusa-evidence.json`, a valid
  spec §4 project-relative path.
- **`trace --format json` emitted no output on HLR/LLR gate failure**
  (issue #36): on ASIL-C/D projects (or with `--strict-hlr-llr`), `trace::run()`
  returned a plain error string on an HLR/LLR violation, and the CLI exited
  before ever rendering — discarding the JSON/text artefact entirely, even
  though the `hierarchy` block was already built. `trace::run()` now always
  returns the populated `TraceResult` (with a new `hlr_gate_failed` flag);
  the CLI renders the requested output first and exits `1` afterward, per
  spec §2.3 (a gate failure MUST NOT suppress the artefact).
- **`qualify` had no `--output` flag** (issue #37): passing `--output <file>`
  was a CLI11 parse error — the flag was never registered, and the report
  path was hardcoded to `<dir>/qualify-report.json`. `qualify --output <file>`
  now works per spec §2.2/§6.
- **`release` had no `--output-dir` flag** (issue #38): passing
  `--output-dir <dir>` was a CLI11 parse error; `sbom.json`/`provenance.json`/
  `artifact-manifest.json` were always written to the project root.
  `release --output-dir <dir>` now works per spec §2.2/§7, creating the
  directory if it doesn't exist.
- **`audit-pack` silently wrote a non-ZIP `manifest.json` and reported
  success when the system `zip` binary was missing** (issue #39): the
  `popen("zip ...")` calls in `src/auditpack/auditpack.cpp` never checked
  their exit status; when `zip` was unavailable (e.g. the FuSaOps bundled
  image before it added `zip`), the code fell back to copying
  `manifest.json` to the requested `--output` path and still exited `0`.
  `pack()` now checks each `zip` invocation's exit code and returns a hard
  error (exit `1`, no fallback file) instead of masquerading a corrupt
  evidence bundle as a success.

### Requirements
- Closed 27 orphan requirement tags surfaced by `trace --gaps` / `--format
  json` self-audit: `REQ-COUPLING001..003`, `REQ-METRICS001..003`,
  `REQ-FIX001..002`, `REQ-SLSA001..003`, `REQ-MISRA001..003`,
  `REQ-COV001..003`, `REQ-IMPACT001..002`, `REQ-TMPL001..002`,
  `REQ-IEC62443-001..003`, and `REQ-SAS001..003` had real `//fusa:req`/
  `//fusa:test` annotations but no entry in `.fusa-reqs.json`; all are now
  registered with titles/descriptions drawn from the tagged code. The
  duplicate `REQ-TMPL003` test-only tag (same `generate()` behaviour already
  covered by the registered `REQ-TMPL004`) was removed rather than
  registered. Zero orphan tags and zero untested requirements remain.

### CI
- `windows-2022` matrix job now installs `zip` via Chocolatey. The runner
  image doesn't ship one by default (unlike the ubuntu/macos jobs), which
  the `audit-pack` zip-missing hard error above now correctly surfaces as a
  test failure instead of silently degrading.

## [0.14.4] — 2026-07-27

### Fixed (issue #30)
- **`fusa.hpp` internal version inconsistency**: `VersionPatch` was `"2"` while `Version` was
  `"0.14.3"` — a stale sub-constant not caught by the repo's 3-file version-sync process
  (`fusa.hpp`/`CMakeLists.txt`/`.fusa.json`). `VersionPatch` now agrees with `Version` (both `0.14.4`).
- **Stale Dockerfile OCI labels**: `org.opencontainers.image.version` (`0.12.5`, ~9 releases behind)
  and `io.x-fusa.spec-version` (`1.10`, actual `1.10.12`) were hardcoded and baked into every published
  image. Both are now `ARG`s (`VERSION`, `SPEC_VERSION`) with local-build defaults, injected at CI build
  time via `--build-arg` in `.github/workflows/docker-publish.yml` (derived from the pushed tag and
  `fusa.hpp`'s `SpecVersion` constant), so published images always track the actual release.
- **`docs/tool-safety-manual.md`** stale `**Version:** 0.12.3` header updated to `0.14.4`.
- **`docs/qualification.md`** stale "Catch2 unit test suite (633 tests)" updated to the actual current
  count (757 tests, per the v0.14.3 CHANGELOG entry).

### Added (issue #31)
- README Quick Start now documents `req`, `iso21434`, `unece`, `misra`, `coupling`, `ast`, `version`,
  and `capabilities` — real, shipped subcommands that were previously undocumented (`iso21434` and
  `unece` since v0.9.0).
- README Modules table gains rows for `src/ast/`, `src/coupling/`, `src/iso21434/`, `src/unece/`, and
  `src/misra/`.
- README Standards coverage table gains a UNECE R155/R156 row and cross-references `cpfusa iso21434`/
  `cpfusa misra` on their respective standard rows.

### Changed
- Backfilled missing `CHANGELOG.md` entries for `v0.12.5`, `v0.12.4`, and `v0.6.2` (each a single-commit
  release that had been omitted, reconstructed from their tagged commits).

## [0.14.3] — 2026-07-27

### Retrofit (§1.4.1 function-level tag completeness, continued)
Further closed `--func-coverage` gaps surfaced by v0.14.2's new gate, focusing on genuinely
behavioural functions and leaving trivial/serialisation helpers (`save`/`write_*` JSON
builders, `*_content` template strings, `write_mermaid`/`write_dot`/`write_markdown`
renderers, one-line accessors) untagged, consistent with the metric's existing
`render_*`/`write_json`/`export_*`/`parse_*`/`*_str` exemption:
- `metrics::load()`, `lint::run()`, `trace::scan_annotations()`, `unece::assess_r155()/assess_r156()`,
  `config::load()/save()`, `tmpl::generate()`, `comp::analyse()`, `sas::build()`, `fix::show()`,
  `ast::run()` (both libclang and stub definitions), `analyze::check_large_stack_alloc()/check_memcpy_on_class()`,
  `report::write_report()/exit_code()`, `Engine::run()/run_ids()/make_default_engine()`, and
  `badge::write_badge()` now carry a direct `//fusa:req` tag above their definition.
- Registered 17 new requirements: `REQ-ANAL006/007` (filling a pre-existing ANAL006/ANAL007
  rule-id gap), `REQ-METRICS004`, `REQ-LINT032`, `REQ-TRACE020`, `REQ-UNECE-006/007`,
  `REQ-CFG007/008`, `REQ-TMPL004`, `REQ-SAS004`, `REQ-FIX003`, `REQ-AST006`, `REQ-RPT007/008`,
  `REQ-ENG005/006`. `REQ-COMP001`, `REQ-ENG004`, and `REQ-BADGE003` were reused where an existing
  requirement already described the now-tagged function.
- Every new requirement is backed by a genuine `//fusa:test` — mostly existing `TEST_CASE`s that
  already exercised the function (verified before tagging, per this repo's convention); `badge::write_badge()`
  had no existing caller, so two new tests were added (`fusa-badge.svg` is written, and its content matches `render()`).
- cpp-FuSa's own `--func-coverage` density rose from 74.8% (116/155) to **87.7% (136/155)**.
  The remaining 19 uncovered declarations are pure serialisation/rendering helpers judged
  out of scope for req-tagging (e.g. `metrics::save()`, `qualify::save()`, `cyber::write_report()`,
  `trace::save_requirements()`, `boundary::write_mermaid()/write_dot()`, the six `tmpl::*_content()`
  template-string functions, `release::write_all()`, `sas::write_markdown()`, `hooks::show()`,
  `fix::list_all()`, `config::exists()`, `ast::libclang_available()`, `metrics::append()`).

### Tests
- 2 new tests (`badge::write_badge()`); total: **757 tests** (up from 755)

### Version
- `Version` constant in `include/cpfusa/fusa.hpp` bumped to `0.14.3`

## [0.14.2] — 2026-07-27

### Added
- **`--func-coverage N`** (x-FuSa spec §1.4.1 / §5, closes part of the tag-completeness tracking issue): `trace` gains a `--func-coverage N` flag mirroring `--req-coverage`. It reports the percentage of header-declared public functions (`src/*/*.hpp` with a matching `.cpp` definition) that carry a `//fusa:req` tag directly above their definition, and exits `1` when the percentage is below `N` (`N=0` disables the gate). Trivial enum/string converters and pure serialisation helpers (`render_*`, `write_json`, `export_*`, `parse_*`, `*_str`) are exempt, per this repo's existing tagging convention. New `trace::scan_func_coverage()` / `trace::is_func_exempt()` (REQ-TRACE018); `TraceResult::func_coverage` surfaces in both `render_matrix` text output and the `render_json` `coverage.funcCoverage` block.
- **Dangling `//fusa:test` reference detection** (x-FuSa spec §1.4.1 item 3): a `//fusa:test <ID>` tag whose `<ID>` does not exist in `.fusa-reqs.json` is now surfaced as a WARNING (`TraceResult::dangling_tags`), the same treatment a malformed annotation gets, never silently accepted. Shown in `render_matrix` text output and as a `danglingTags[]` array in `render_json` (REQ-TRACE019).

### Retrofit (§1.4.1 function-level tag completeness)
Running the new `--func-coverage` gate against cpp-FuSa's own source surfaced several core per-standard assessment entry points with zero `//fusa:req` tags anywhere in their file, and several referenced-but-unregistered requirement IDs. Fixed:
- `do178::assess()`, `iso26262::assess()`, `iec61508::assess()`, `iso21434::assess()` now carry a direct req tag above their definition. Registered `REQ-DO178-001/-002/-003`, `REQ-ISO26262-001/-002/-003`, `REQ-IEC61508-001/-002/-003` in `.fusa-reqs.json` (previously referenced by these files and their tests but never registered — a pre-existing dangling-reference gap the new detector would have caught).
- `hara::load()/save()/init()`, `disposition::save()/add()/find_by_rule()`, `pr::save()/add()`, `sci::build()`, `analyze::run_clang_tidy()/run_cppcheck()/run_own_passes()` now carry req tags. Registered `REQ-HARA001/006/007/008`, `REQ-DISP001/002/003`, `REQ-PR001/002/003`, `REQ-SCI001/002`, `REQ-ANAL014/015/016`.
- Added missing `//fusa:test` gap-report coverage for `REQ-TRACE009` (Polarion import/export — tests already existed, just untagged), `REQ-RELEASE009` (SPDX 2.2/2.3 — ditto), `REQ-TRACE016`/`REQ-TRACE017` (trace JSON `kind` field / canonical `standard` key).
- cpp-FuSa's own `--func-coverage` density rose from 63.2% (98/155, measured before the retrofit) to 74.8% (116/155). Remaining gaps are in modules outside this pass's scope and are now visible via `trace --func-coverage`/`--gaps` for future work.

### Tests
- 16 new tests (11 for `--func-coverage`, 5 for dangling-tag detection); total: **755 tests** (up from 739)

### Version
- `Version` constant in `include/cpfusa/fusa.hpp` bumped to `0.14.2`

## [0.14.1] — 2026-07-27

### Fixed
- **SpecVersion** (P0): Updated `SpecVersion` constant in `include/cpfusa/fusa.hpp` from `"1.10.4"` to `"1.10.12"`, aligning cpp-FuSa with the current x-FuSa spec. Updated four test cases (test_report.cpp, test_iso21434.cpp, test_unece.cpp, test_trace.cpp) that hard-coded the old value.

### Coverage
- **verify**: Added 5 new tests exercising `run_ctest` with a real build directory stub, `write_evidence` `project_root` field, `elapsedSeconds` field, and skipped-count round-trip.
- **metrics**: Added 12 new tests covering `collect()` branches (check-report.json findings, .fusa-reqs.json requirements and coverage_pct, cyber-report.json), malformed-JSON graceful handling, `render_text` with empty and non-empty series, and full snapshot round-trip.
- **sci**: Added 5 new tests covering `sha256_file` via `build()` with existing artifact files — present/absent flags, sha256 stability, and hash change on content change.
- **diff**: Added 7 new tests covering nested `location`-object format in `load_findings`, snake_case `rule_id` key, empty `findings` key, `render_json` output shape, and key-only equality semantics in `compare`.
- **impact**: Added 6 new tests covering `render_text` with populated changed files, impacted requirements, and stale artifacts; `staleArtifacts` JSON field; empty-ref defaults.
- **analyze**: Added 10 new tests covering `run_clang_tidy` and `run_cppcheck` tool-not-found paths, `run()` dispatch with each option combination, and ANAL006 large-stack-allocation detection.
- **fix**: Added 6 new tests covering `show()` for known rule, unknown rule, empty rule ID, and all catalog entries; `list_all()`; every catalog entry has non-empty before/after.
- **report**: Added 12 new tests covering SIL/DAL/empty integrity-level key emission, `write_report` for all four formats (JSON, HTML, SARIF, TEXT) and the error path, `render_html` with findings.
- **engine**: Added 6 new tests covering `run_ids()` with single rule, empty list, unknown ID, and multiple rules; `rules()` accessor and non-empty rule IDs.

### Tests
- 72 new tests; total: **739 tests** (up from 667)

### Version
- `Version` constant in `include/cpfusa/fusa.hpp` bumped to `0.14.1`

## [0.14.0] — 2026-07-26

### Fixed
- **CMakeLists.txt version** (P0): `VERSION` in `project()` call corrected from `0.12.3` to `0.13.0`; header and cmake build banner are now in sync. Bumped to `0.14.0` for this release.
- **Annotation convention** (P1): All 47 multi-ID `//fusa:test` header annotation lines across every test file have been split into individual single-ID lines, matching the go-FuSa authoritative model (one requirement ID per annotation line).
- **ASIL-C HLR gate test** (P1): Added `trace: ASIL-C HLR violation causes error without strict flag` test case in `tests/test_trace.cpp`, providing full coverage of both sides of the `ASIL-C || ASIL-D` gate condition (REQ-HLR004).
- **Compiler warning** (P2): `test_req.cpp` aggregate initialisers now include an explicit empty `parent_id` field, eliminating `-Wmissing-field-initializers` on the REQ-RT1 and REQ-RT2 lines.
- **Dogfooding** (P2): `.fusa.json` project version updated to `0.14.0`; `strict: false` (already present) combined with `asil: ASIL-B` suppresses the HLR/LLR gate error until full HLR/LLR decomposition is applied to `.fusa-reqs.json` incrementally.

### Version
- `Version` constant in `include/cpfusa/fusa.hpp` bumped to `0.14.0`

## [0.13.0] — 2026-07-26

### Added
- **HLR/LLR Decomposition** (Feature 1, closes #19): `Requirement` struct gains `parent_id` field; empty = HLR, non-empty = LLR. `trace run` validates hierarchy: LLRs must reference known HLRs; HLRs must have at least one LLR child. Gate: warn for ASIL-A/B, error for ASIL-C/D; `--strict-hlr-llr` forces error at any level. `render_matrix` and `render_json` show hierarchy metrics and a `hierarchy` block.
- **Tool Qualification Display** (Feature 2, closes #20): `QualifyReport` gains `qualification_method` ("self" | "independent"), `qualification_record_uri`, and `qualifier_identity` fields. `qualify` command gains `--qualification-method`, `--qualifier`, `--record-uri` flags. JSON output includes badge: "independently-qualified" | "self-qualified" | "unqualified".
- **MC/DC Coverage** (Feature 3, closes #21): `coverage.hpp` gains `MCDCCondition`, `MCDCRecord` structs and `apply_mcdc()` function. Parses LLVM MC/DC JSON (`mcdc_records[]`). A condition is covered when `covered_true_count > 0 AND covered_false_count > 0`. Hard gate: `meets_mcdc` fails if any condition is uncovered (at threshold). `write_json` emits structured `mcdc` block. CLI adds `--mcdc`, `--mcdc-file`, `--mcdc-threshold` to `coverage` subcommand.
- **V&V Independence** (Feature 4, closes #22): `QualifyReport` gains `implementation_author`, `independent_reviewer`, `independent_test_executor`, `achievable_asil` fields. `independence_status()` returns "independent" when reviewer differs from author, "self" when same, "unqualified" when empty. CLI adds `--implementation-author`, `--independent-reviewer`, `--independent-test-executor`, `--achievable-asil` flags.

### Requirements
- 13 new requirements: REQ-HLR001..REQ-HLR005, REQ-QUALIFY005..REQ-QUALIFY010, REQ-COV004..REQ-COV005 — total: **209 requirements**

### Tests
- 35 new tests across test_trace.cpp, test_qualify.cpp, test_coverage.cpp
- Total: **670 tests**

## [0.12.6] — 2026-07-25

### Fixed
- `SpecVersion` constant updated from `"1.10"` to `"1.10.4"` (x-FuSa spec alignment)
- MSVC C2338 compile error in `test_analyze.cpp`: wrap compound `REQUIRE` expression in parentheses

## [0.12.5] — 2026-06-12

### Fixed
- **Project-relative finding paths** (issue #27, mirrors go-FuSa v0.30.0): `analyze::for_each_source()` now
  passes `fs::relative(entry.path(), dir)` to each own-pass lambda, so ANAL003–012 findings all carry portable
  project-relative paths instead of absolute ones; `run_clang_tidy()` likewise relativizes the path parsed
  from clang-tidy diagnostic output. Required per x-FuSa spec §4 MUST so fingerprints, SARIF
  `artifactLocation`s, and cross-environment diff baselines are stable regardless of checkout location.
  New REQ-ANAL013 test asserts an ANAL003 finding's file does not start with `/`.

## [0.12.4] — 2026-06-12

### Fixed
- **Trace JSON canonical keys** (closes #11, #12): `trace --format json` emitted `kind: "trace-report"`
  where x-FuSa spec §3.1 requires `"trace-matrix"`, and `requirements[]` entries used `"standardRef"`
  where spec §5 requires `"standard"`. Both corrected; adds REQ-TRACE016/REQ-TRACE017 and a test
  asserting `"standard"` is present and `"standardRef"` is absent.

## [0.12.3] — 2026-06-12

### Fixed
- **Gap-report `objectives` key** (issues #7): `iec62443` JSON now emits `"objectives"` (was `"checks"`) with `"title"` (was `"requirement"`); `slsa` JSON now emits `"objectives"` (was `"requirements"`). All six gap-report commands (`iso26262`, `iec61508`, `do178`, `iec62443`, `slsa`) now emit `"title"` for the human-readable objective name (was `"description"`). Fixes FuSaOps rollup decoding.
- **Capabilities `standards` array** (issue #8): `cpfusa capabilities --format json` now includes `"slsa"` in the `standards[]` array.
- **Dockerfile OCI label** (issue #9): `io.x-fusa.spec-version` updated from `"1.9"` to `"1.10"` to match current spec.

## [0.12.2] — 2026-06-12

### Fixed
- `trace --format json` now emits a spec §5 **top-level flat** `tags[]` array (not nested inside each requirement entry). `kind` values are now `impl`, `test`, or `sec-test`; `sec-test` is used for test annotations on cybersecurity requirements and counts toward both `testedRequirements` and `secTestedRequirements`.
- `trace --format json` coverage block renamed from `summary` to `coverage`; field names updated to `totalRequirements`, `tracedRequirements`, `testedRequirements`, `secTestedRequirements` (spec §5 canonical names).
- `schemaVersion` updated from `"1.9"` to `"1.10"` across all JSON outputs to reflect the current x-FuSa spec.
- Findings JSON `location` object now emits `endLine`/`endColumn` when present (spec §4 MAY); SARIF `region` likewise emits `endLine`/`endColumn`. Fields are omitted (not emitted as `0`) when only a point location is known.

### Requirements
- 4 new requirements: REQ-TRACE013, REQ-TRACE014, REQ-TRACE015, REQ-RPT006 — total: **193 requirements**

### Tests
- 3 new tests for top-level `tags[]`, `coverage` block field names, `sec-test` kind detection
- 3 new tests for `endLine`/`endColumn` in JSON and SARIF
- Total: **633 tests** (was 630)

## [0.12.1] — 2026-06-12

### Fixed
- `trace --format json` now emits spec §5 flat `tags[]` array with `{requirementId, file, line, kind}` per annotation instead of split `implementedBy[]`/`testedBy[]` arrays.
- `trace --format json` now writes to stdout by default (§2.2); `--output` writes to a named file.
- `trace --format json` summary block now includes `secTestedRequirements` (count of cybersecurity requirements with at least one `//fusa:test` annotation, §5).
- `cpfusa slsa` JSON output now includes §3.1 common header: `schemaVersion`, `kind: "gap-report"`, `standard: "slsa"`, `tool`, `toolVersion`, `language`.
- `cpfusa iec62443` JSON output now includes §3.1 common header: `schemaVersion`, `kind: "gap-report"`, `standard: "iec62443"`, `tool`, `toolVersion`, `language`.

### Requirements
- 3 new requirements: REQ-TRACE010 (tags[] schema), REQ-TRACE011 (trace stdout default), REQ-TRACE012 (secTestedRequirements) — total: **189 requirements**

### Tests
- 2 new tests for `secTestedRequirements` counting and summary field presence
- Total: **630 tests** (was 628)

## [0.12.0] — 2026-06-12

### Added
- LINT031 — Float/double literal in `==` or `!=` comparison (WARNING, MISRA C++:2023 Rule 6-2-2). Flags direct equality checks on floating-point literals; suppressed with `// fusa:suppress LINT031`.
- HARA002 engine rule — fires WARNING when a hazard in `.fusa-hara.json` is missing `severity`, `exposure`, or `controllability` in its `risk` object (ISO 26262-3 §7).
- HARA003 engine rule — fires WARNING when a hazard has an empty `safetyGoals` list (not linked to any safety goal, ISO 26262-3 §8).
- HARA004 engine rule — fires WARNING when a safety goal in `.fusa-hara.json` has no `asil` field (ISO 26262-3 §8).
- VERIFY002 engine rule — fires ERROR when `.fusa-evidence.json` reports `summary.failed > 0` (tests not green before release).
- `cpfusa fmea --cyber` — cross-references `cyber-report.json` and appends matching CYBER rule IDs to FMEA entry actions for files with cybersecurity findings (ISO 21434 §9).
- 6 new requirements: REQ-LINT031, REQ-HARA002, REQ-HARA003, REQ-HARA004, REQ-VERIFY006, REQ-FMEA007 (total: **186 requirements**)

### Engine
- Default engine now has 13 built-in rules (was 9).

### Tests
- 14 new tests covering all 6 new capabilities
- Total: **628 tests** (was 614)

## [0.11.0] — 2026-06-12

### Added
- ANAL008 — Function body > 60 lines (WARNING). Enforces single-responsibility per DO-178C §6.3.4 and MISRA C++:2023 Rule 6-3-1.
- ANAL009 — Nesting depth > 5 within a function (WARNING). Flags deep conditional nesting that increases complexity and reduces test coverage tractability.
- ANAL010 — Function parameter count > 7 (WARNING). Excessive parameters indicate poor interface design; matches MISRA C++:2023 Rule 8-4-2 and JSF++ Rule 122.
- ANAL011 — Narrowing integer cast to `uint8_t`, `int8_t`, `uint16_t`, `int16_t`, `unsigned char`, `short` (WARNING). C-style truncating casts silently discard high bits; suppressed with `// fusa:unsafe`.
- ANAL012 — More than 3 explicit `return` points per function (INFO). Multiple exit points obscure control flow; matches MISRA C++:2023 Rule 6-6-5 and JSF++ Rule 113.
- 5 new requirements: REQ-ANAL008–REQ-ANAL012 (total: **180 requirements**)

### Tests
- 11 new tests covering detection and suppression for all five rules
- Total: **614 tests** (was 603)

## [0.10.0] — 2026-06-12

### Added
- `cpfusa comp` — cyclomatic complexity analysis (DO-178C §6.3.4): COMP001 flags functions
  exceeding the DAL-level threshold (DAL-A ≤4, DAL-B ≤10, DAL-C ≤15, DAL-D ≤20).
  Writes `comp-report.json`. CLI: `cpfusa comp [--threshold N] [--output file]`
- COUP003 engine rule — fires INFO when `coupling-report.json` is absent in a DO-178C project
- HARA005 engine rule — fires WARNING when the highest hazard ASIL in `.fusa-hara.json`
  exceeds the project ASIL declared in `.fusa.json`
- ISO26262002 engine rule — fires INFO when any requirement lacks an `asil` field in an ISO 26262 project
- ISO26262003 engine rule — fires WARNING when `qualify-report.json` reports test failures
- `asil` field on `trace::Requirement` — `.fusa-reqs.json` entries accept optional `"asil": "ASIL-B"`;
  round-trips through load/save, CSV export/import, and trace JSON output
- SPDX 2.2 / 2.3 SBOM formats — `cpfusa release --spdx-version 2.2|2.3|3.0.1`
- DOORS ReqIF XML import/export — `cpfusa trace import --format doors` / `export --format doors`
- Polarion work-item XML import/export — `cpfusa trace import --format polarion` / `export --format polarion`
- Gap-assessment objective upgrades:
  - ISO 26262: obj `10.4` (SCI, ASIL-B+) and `11.3` (coupling, ASIL-C/D)
  - IEC 61508: obj `3-B.6` (SCI, SIL-2+); `1-7.2` now checks `.fusa-hara.json`; `3-7.4` checks `fmea.json`
  - DO-178C: A-2.2 detects `level: LLR` in reqs; A-6.2 maps to `check-report.json`; A-6.3 maps to `coupling-report.json`
- 8 new requirements: REQ-COMP001, REQ-COUP003, REQ-HARA005, REQ-ISO26262002, REQ-ISO26262003,
  REQ-TRACE008, REQ-TRACE009, REQ-RELEASE009 (total: **175 requirements**)

### Tests
- 32 new tests across `comp`, `engine`, `trace`, `release` modules
- Total: **603 tests** (was 571)

## [0.9.2] — 2026-06-11

### Fixed
- `Dockerfile` missing all OCI + `io.x-fusa.*` labels added per spec §15:
  `org.opencontainers.image.{title,description,source,licenses,version}` and
  `io.x-fusa.{tool,language,binary,spec-version}`
- `CMakeLists.txt` project `VERSION` bumped to `0.9.2`
- `docs/tool-safety-manual.md` version header updated to `0.9.2`

## [0.9.1] — 2026-06-11

### Fixed
- `cpfusa trace --format json` now writes `trace-report.json` to the project directory
  instead of emitting to stdout only; FuSaOps artifact discovery no longer fails
- `iec62443` and `slsa` JSON summary keys corrected to x-FuSa spec §9.3 canonical form:
  `"met"` → `"satisfied"`, `"gap"` → `"gaps"` (plural); per-objective status string
  updated likewise (`"met"` → `"satisfied"`)
- `qualification.md` test count corrected (549 → 571)

### Tests
- 22 new tests across `auditpack`, `fmea`, `tara`, `sas`, `sci` modules covering
  JSON schema validation, field completeness, multi-artifact bundling, and markdown content
- 4 conformance tests for §9.3 summary keys in `iec62443` and `slsa`
- Total: **571 tests** (was 549)

## [0.9.0] — 2026-06-10

### Added
- `cpfusa iso21434` — ISO 21434:2021 cybersecurity assurance level (CAL) gap assessment
  - 21 objectives across clauses 5–15 and Annex A; CAL-1 to CAL-4 scoping
  - Automatable objectives check evidence files: `.fusa.json`, `tara.json`, `vuln.json`, `cyber-report.json`, `sbom.json`, `provenance.json`, `safety-case.json`, `.fusa-reqs.json`
  - Writes `iso21434-gap-report.json` with spec §3.1 envelope + §9.3 summary keys
  - `--cal CAL-1|CAL-2|CAL-3|CAL-4`, `--output <file>`
- `cpfusa unece` — UNECE R155/R156 automotive cybersecurity compliance gap reports
  - R155: 9 threat categories (TC-1 communication, TC-2 update, TC-3 physical, TC-4 connectivity, TC-5 supply chain, TC-6 storage, TC-7 key mgmt, TC-8 privacy, TC-9 incident)
  - R156: 6 SUMS requirements (SU-1 authorization, SU-2 impact, SU-3 validation, SU-4 rollback, SU-5 supply chain, SU-6 campaign monitoring)
  - Writes `unece-r155-gap-report.json` / `unece-r156-gap-report.json` with spec §3.1 envelope
  - `--regulation r155|r156|both`, `--output <file>`
- `cpfusa req` — full requirement import/export subcommand structure
  - `req show [<REQ-ID>]` — show all requirements or a single one (backward-compatible with old `cpfusa req <ID>` form)
  - `req import --file <csv> --format csv` — import from CSV, skipping duplicate IDs
  - `req export --output <file> --format csv` — export all requirements to CSV
  - CSV format: `id,title,description,standard_ref,severity`; commas in values escaped as semicolons
  - `save_requirements()` writes canonical `{"requirements":[...]}` format per spec §1.2.2
- 13 new requirements in `.fusa-reqs.json`: REQ-ISO21434-001–005, REQ-UNECE-001–005, REQ-REQ001–003 (total: 192)
- 45 new tests in `test_iso21434.cpp`, `test_unece.cpp`, `test_req.cpp` (total: 545)

### Fixed
- `iso26262`, `iec61508`, `do178` objective-level `status` field now emits `"satisfied"` (was `"addressed"`) — spec §9.3 requires `satisfied|partial|gap`

## [0.8.0] — 2026-06-10

### Added
- libclang AST integration (`src/ast/ast.cpp`, `cmake/FindLibClang.cmake`)
  - Optional: links `LibClang::LibClang` when `brew install llvm` / `apt install libclang-dev` is present
  - When available: AST001 (virtual method without virtual dtor), AST002 (variable shadowing), AST003 (raw pointer return without `[[nodiscard]]`)
  - When unavailable: stub mode returns AST000 INFO finding and exits 0
  - `cpfusa ast --format text|json --output <file>` CLI subcommand
- Full MISRA C++:2023 rule set — LINT011–030 (20 new rules)
  - M4-10-2 NULL literal, A10-3-2 missing override, M6-4-6 switch default, M15-3-4 empty catch, M15-5-1 throw in destructor
  - A16-0-1 function-like macro, A15-1-2 setjmp/longjmp, A5-2-3 dynamic_cast, A9-5-1 union, A2-11-1 volatile
  - A8-4-1 variadic, A27-0-1 unsafe string functions, A27-0-2 atoi/atof, M6-3-1 missing braces, A19-3-1 errno
  - M17-0-5 C library headers, M16-0-3 #undef, A7-4-1 inline asm, A2-13-4 magic numbers, M16-2-1 include guard
- 37 new requirements: REQ-LINT011–030 and REQ-AST001–005 added to `.fusa-reqs.json` (total: 179)
- 37 new tests: LINT011–030 positive + negative tests in `test_lint.cpp`; `test_ast.cpp` covering stub and libclang paths
- x-FuSa spec v1.9 conformance
  - `SpecVersion` bumped to "1.9"; all `schemaVersion` fields now emit "1.9"
  - `.fusa-reqs.json` canonical format: `init` now writes `{"requirements":[]}` per §1.2.2; `load_requirements` reads `.requirements` key with flat-array backward-compat
  - `version --format json` and `capabilities` both emit `"specVersion":"1.9"`
  - `category`, `remediation`, `fingerprint` (promoted to MUST in v1.9) were already implemented; now documented as conformant
- Test suite: 500 tests passing

## [0.7.0] — 2026-06-10

### Added
- Homebrew formula (`Formula/cpp-fusa.rb`) — builds `cpfusa` from source via GitHub archive; `brew install` and `brew test` supported
- GitHub Actions composite action (`.github/action.yml`) — `uses: SoundMatt/cpp-FuSa@v0.7.0` mounts the project into the Docker image and runs any `cpfusa` subcommand; exposes `exit-code` output
- CPack packaging in `CMakeLists.txt` — NSIS (Windows installer with PATH modification), WiX (Windows MSI), DEB (Debian/Ubuntu), RPM (Fedora/RHEL); build with `cmake --build build --target package`
- ROADMAP.md updated to reflect reality: v0.7 (IEC 62443, SLSA) and v0.8 (distribution) marked complete

## [0.6.2] — 2026-06-10

### Fixed
- **x-FuSa spec v1.8 MUST gap 1** — `cpfusa trace --format json` (§5): added `render_json()` emitting the
  §5 cross-language traceability schema — §3.1 common envelope (`schemaVersion 1.8`, `kind:"trace-report"`,
  `tool`/`toolVersion`/`language`/`generatedAt`), per-requirement `implementedBy`/`testedBy` location
  arrays, a `covered`/`partial`/`gap` status, and a summary block; paths are project-relative. `trace`
  gains `--format text|json` and `--output`.
- **x-FuSa spec v1.8 MUST gap 2** — gap-report summary keys (§9.3): `iso26262`, `iec61508`, and `do178`
  `write_json()` emitted `"addressed"`/`"gap"` instead of the spec-mandated `"satisfied"`/`"gaps"`; renamed
  across all three modules.
- 9 new tests (6 `trace` `render_json`, 3 gap-report summary-key assertions); 463 total, 100% pass.

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
