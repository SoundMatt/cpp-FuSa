## Summary

<!-- One paragraph describing WHAT changed and WHY. Reference ROADMAP.md items if applicable. -->

## Type of change

- [ ] Bug fix
- [ ] New feature / new rule
- [ ] Refactor (no behaviour change)
- [ ] Documentation
- [ ] Test only
- [ ] CI / toolchain

## Pre-PR checklist

- [ ] `cmake --build build --parallel` — clean build
- [ ] `ctest --test-dir build --output-on-failure -j1` — all tests pass
- [ ] `./build/cpfusa lint --dir .` — no new LINT findings in `src/`
- [ ] `./build/cpfusa trace --dir .` — 100% annotated & tested (if reqs changed)
- [ ] New or changed public API has `[[nodiscard]]` where appropriate
- [ ] No raw `new`/`delete`, `goto`, or C-style casts (without `// fusa:unsafe`)
- [ ] Source annotated with `//fusa:req REQ-XXX` where applicable
- [ ] Tests annotated with `//fusa:test REQ-XXX`
- [ ] Commit messages follow the `type(scope): summary` convention
- [ ] Each commit has `Signed-off-by: Name <email>` (DCO)

## Test plan

<!-- Describe how the change was tested beyond the existing suite. -->

## Evidence / artefacts produced

<!-- List any new `.json` / `.md` evidence files this PR introduces or modifies. -->
