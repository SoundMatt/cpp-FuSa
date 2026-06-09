# cpp-FuSa — Claude session guide

Repo: `github.com/SoundMatt/cpp-FuSa` (owned by Matt Jones).
Local path: `/Users/matt/Documents/Coding/SoundMatt/cpp-FuSa`

## Project overview

cpp-FuSa is a functional safety enablement toolkit for C++ projects. It is **not** a
certification product — it is an engineering accelerator that reduces the cost of producing
functional safety evidence (ISO 26262, IEC 61508, ISO 21434, DO-178C) throughout the SDLC.

The tool is itself written in C++17 to dogfood the patterns it enforces.

| Module | What it is |
|---|---|
| `include/cpfusa/` | Core types — `Finding`, `Severity`, `Result<T>` |
| `src/config/` | `.fusa.json` project config |
| `src/engine/` | Rule engine + FUSA001–005 |
| `src/report/` | text/JSON/HTML/SARIF renderers |
| `src/lint/` | MISRA/AUTOSAR lint rules (LINT001–010) |
| `src/analyze/` | clang-tidy + cppcheck + own passes |
| `src/trace/` | Requirements traceability engine |
| `src/template/` | Safety document generators |
| `src/runtime/` | Watchdog, SafeStateGuard, Heartbeat (header-only) |
| `src/testutil/` | TempDir, has_finding helpers |
| `tests/` | Catch2 unit tests |

## Build and test

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release -G Ninja
cmake --build build --parallel
ctest --test-dir build --output-on-failure

# Self-check
./build/cpfusa check --dir .
./build/cpfusa lint --dir .
```

## Per-PR checklist

1. `git checkout main && git pull origin main`
2. `git checkout -b fix/<scope>-<short>` or `feat/<scope>-<short>`
3. Implement + tests.
4. `cmake --build build --parallel`
5. `ctest --test-dir build --output-on-failure`
6. `./build/cpfusa lint --dir .` (no new LINT findings in src/)
7. Commit (see style below).
8. `git push origin <branch>`, open PR targeting `main`.
9. All CI checks green, then squash-merge.

## Commit message style

```
type(scope): short summary

Body explaining *why*, not what. Reference ROADMAP.md items.

Signed-off-by: Matt Jones <matt@jellybaby.com>
```

Types: `feat`, `fix`, `docs`, `test`, `chore`, `refactor`.
Scopes: `engine`, `lint`, `analyze`, `trace`, `runtime`, `report`, `cli`, `config`.

Use heredoc to avoid zsh expansion:
```bash
git commit -F - <<'COMMIT'
feat(lint): add LINT011 rule
...
Signed-off-by: Matt Jones <matt@jellybaby.com>
COMMIT
```

## C++ conventions

- C++17, `[[nodiscard]]` on all `Result<T>`-returning functions.
- No raw `new`/`delete` — we run our own LINT001.
- No `goto`, no C-style casts, no `reinterpret_cast` without `// fusa:unsafe`.
- `std::optional`, `std::variant`, `std::filesystem` throughout.
- Tests use Catch2 v3 (`TEST_CASE`, `REQUIRE`, `REQUIRE_FALSE`).
- Test helpers in `src/testutil/testutil.hpp` — use `TempDir` and `has_finding`.
- Self-annotate source with `//fusa:req` and tests with `//fusa:test`.

## Autonomous operation

Matt has granted blanket permission for all C++ build operations:
`cmake`, `ctest`, `git`, `gh` CLI for PR management.
No confirmation needed for build, test, or commit operations.
Do NOT ask for permission before running builds or tests.
