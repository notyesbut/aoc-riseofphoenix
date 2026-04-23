# Contributing to AoC-RiseOfPhoenix

This is a small private team project.  Rules are intentionally lightweight —
ship working code, keep the tree clean, document what you learn.

---

## Ground rules

1. **This is a private repo.**  Don't fork to public, don't push to
   public remotes, don't share credentials or the `replay_data.bin`
   fixture outside the invited team.  See `LICENSE`.
2. **All RE findings belong in `docs/`.**  If you decompile a client
   function, summarize what it does in a short note under `docs/`.
   Future-you will thank past-you.
3. **Validate with tests.**  Every codec or protocol change must be
   covered by a test in `src/tools/test_*.cpp`.  Bit-level claims
   deserve bit-level proofs.
4. **Prefer portability.**  No hardcoded `C:\Users\<your-name>\...`
   paths.  Use `AOC_REPO_ROOT` (set by CMake) for fixture paths, use
   `%~dp0` in batch scripts, use `Split-Path $PSCommandPath` in
   PowerShell.

---

## Development workflow

### Branching

- `main` — must always build and pass tests.
- Feature branches: `feature/<short-description>`
- RE branches: `re/<function-or-area>`
- Docs-only: `docs/<topic>`

Small fixes can land directly on `main` if they're < 50 LOC and pass all
tests.

### Commits

- Use imperative voice: `Add FStruct codec`, `Fix BDB bit offset`.
- Reference tests: `...  94/94 pass` in the commit body.
- If reverting, explain *why* — not just *what*.

### Pull requests

- Title: what the PR does in one sentence.
- Description: the *why*, any test output, any RE findings worth a
  permanent link.
- A reviewer should be able to understand the change without running
  the code.

---

## Build & test

```powershell
# First-time setup (requires VCPKG_ROOT env var pointing at your vcpkg install):
.\scripts\build.ps1 -Configure

# Subsequent builds:
.\scripts\build.ps1                    # all targets, Release
.\scripts\build.ps1 -Target aoc_server # one target
.\scripts\build.ps1 -Config Debug      # debug build
.\scripts\build.ps1 -Clean             # rebuild from scratch
.\scripts\build.ps1 -Test              # build + run all tests
```

The `-Test` flag runs the three big test suites and fails the build if
any test fails.  Run it before every commit.

### Adding a new test target

1. Add the `.cpp` to `src/tools/`.
2. Register an `add_executable(test_xxx ...)` block in `CMakeLists.txt`
   (copy the pattern from an existing test target).
3. Include the test in the `$testExes` array at the bottom of
   `scripts/build.ps1`.

---

## Coding conventions

### C++

- **C++20.**  Use concepts and `if constexpr` freely.  Avoid exceptions
  in hot paths.
- **`namespace aoc::...::...`** — every file under `src/` should live
  in a nested `aoc::` namespace matching its directory.
- **Doc-comment every public function.**  Include what it does, its
  preconditions, and what it returns on failure.
- **Log with `spdlog`.**  Levels: `info` for milestones, `debug` for
  per-operation detail, `warn` for recoverable anomalies, `error` for
  failures.
- **Prefer `std::string_view` / `std::span` for read-only arguments.**
- **No raw `new`/`delete`.**  Use `std::make_unique` / `std::make_shared`
  or stack allocation.

### Bit-level code

- **Always document the byte layout** in a comment block above the
  function, referencing `docs/wire-format.md`.
- **LSB-first per byte**, matching UE5's `FBitReader`.  Never silently
  switch to MSB-first.
- **Validate with round-trip tests** — if you write `encode_X`, you
  must also have `decode_X`, and `decode(encode(v)) == v` must be in
  the test suite.

### CMake

- **No hardcoded paths.**  Use `${CMAKE_CURRENT_SOURCE_DIR}` or
  `${CMAKE_CURRENT_BINARY_DIR}`.
- **Set `target_compile_features(... PRIVATE cxx_std_20)`** on every
  target.
- **Link only what's needed** — don't drag in `spdlog` for pure-data
  targets.

### Python / IDA scripts

- **Read from `%USERPROFILE%` / `os.path.expanduser("~")`** for output
  paths, not hardcoded directories.
- **Script docstring at the top** explains the input and output of
  the script.

---

## Reverse-engineering protocol

When you decompile a client function, follow this template:

1. **Identify what the function is.**  Look at its callers, the strings
   it references, the vtable slots it calls.
2. **Classify its role.**  Is it serialization (wire bytes)?  State
   tracking (shadow updates)?  Plumbing (class registration)?
3. **Document only what generalises.**  Struct offsets, flag bits, and
   dispatch logic belong in `docs/wire-format.md`.  One-off functions
   that are just UE5 internals don't.
4. **Note what's NOT worth more RE time.**  If you bottomed out without
   learning anything, say so.

### The "value curve"

Not every function is worth decompiling.  If you've done 3 in a row and
each one's been pure UE5 plumbing, stop and reconsider.  Target:
- Per-property dispatch entry points
- NetSerialize overrides for AoC-specific types
- Anti-cheat / handshake gating functions (for M5+ work)

Don't target:
- Lazy-init class registrars (they all look the same)
- String-constant getters
- Virtual-dispatch glue that's obviously UE5 stock

---

## Where to get help

- **Wire format questions** → `docs/wire-format.md`
- **"Why is this weird" questions** → `docs/phase-ii-postmortem.md`
- **"What should I work on" questions** → `docs/phase-iii-roadmap.md`
- **UE5-specific questions** → your local UE5 source clone (set up one
  at `<UE5_SRC>` — see `docs/live-server-implementation-plan.md`)

If none of those answer it, ping the team.  Don't silently guess — wire
protocol bugs are painful to diagnose after the fact.
