# Contributing to cpp-FuSa

Thank you for considering a contribution. All contributions require a DCO sign-off.

## Prerequisites

- CMake ≥ 3.21
- C++17 compiler (clang++ ≥ 14, g++ ≥ 12, or MSVC 2022)
- Ninja (optional but recommended)
- clang-tidy, cppcheck (optional — for `cpfusa analyze`)

## Dev workflow

```bash
# Build and run tests
make test

# Run self-check
make check && make lint

# Run a single test binary
./build/cpfusa_tests "[engine]"
```

## Commit message style

```
type(scope): short summary

Body explaining *why*, not what. Reference ROADMAP.md items.

Signed-off-by: Your Name <you@example.com>
```

Types: `feat`, `fix`, `docs`, `test`, `chore`, `refactor`.
Scopes: `engine`, `lint`, `analyze`, `trace`, `runtime`, `report`, `cli`, `config`.

Use heredoc to avoid shell expansion issues:
```bash
git commit -F - <<'COMMIT'
feat(lint): add LINT011 rule for uninitialized member

Uninitialized members are a common source of undefined behaviour
in safety-critical C++ code.

Signed-off-by: Your Name <you@example.com>
COMMIT
```

## Adding a lint rule

1. Add the rule ID to the table in `README.md` and `ROADMAP.md`.
2. Implement `check_<name>(const fs::path& dir)` in `src/lint/lint.cpp`.
3. Call it from `lint::run()`.
4. Add tests in `tests/test_lint.cpp` — at minimum: one failing case, one passing case.

## Adding an engine rule

1. Add `make_fusaXXX()` declaration to `src/engine/rules.hpp`.
2. Implement it in `src/engine/rules.cpp`.
3. Register it in `engine::make_default_engine()`.
4. Add tests in `tests/test_engine.cpp`.

## Code style (we dogfood our own rules)

- C++17, no raw `new`/`delete` (LINT001)
- No `goto` (LINT002)
- `reinterpret_cast` requires `// fusa:unsafe` (LINT003)
- `abort()`/`exit()` requires `// fusa:safe-state` (LINT004)
- `constexpr` over `#define` (LINT006)
- Named casts over C-style casts (LINT007)
- `[[nodiscard]]` on functions returning `Result<T>` or error codes
- RAII everywhere — no manual resource management

## DCO Sign-off

All commits must include:
```
Signed-off-by: Your Name <you@example.com>
```

By signing off you confirm the contribution is your original work and
you agree to the [DCO](https://developercertificate.org/).
