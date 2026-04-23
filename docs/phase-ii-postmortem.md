# Phase II Post-mortem — Custom Character Names via Replay Mutation

Written 2026-04-23 after ~two weeks of iteration.  This document exists so
the next engineer on the project doesn't re-try the approach that didn't
work, and understands *why* it didn't.

---

## The goal

Support custom character names (4–20 chars per AoC's UI) at login, so a
player spawned via the captured replay shows as e.g. "MyCharacter" instead
of the hardcoded "RandomChar" from the capture.

## The approach that was tried (and abandoned)

**Mutate the captured packets in memory right before sendto.**

When the replay hit pkt#104 (HUD name bunch) or pkt#79 (Pawn nametag
bunch), we'd:

1. Find the `FString` region containing "RandomChar"
2. Rewrite it with the user's chosen name
3. Shift all subsequent bunch bits by the length delta
4. Update the `BunchDataBits` (BDB) field in the bunch header
5. Send

This is implemented in `src/protocol/emit/replay_mutator.cpp` + validated
by `src/tools/test_replay_mutator.cpp` (40 tests, all pass at the library
level).  The library is **correct in isolation** — bit-shift math verified,
BDB update proven, identity mutation produces byte-identical output.

## Why it failed

### The symptom

- Identity mutation (same length, same content) → client works
- Same-length, different content (e.g. "TestHeroXX" vs "RandomChar") → works
- **Any length change (even 1 byte)** → client gets stuck in a loading
  loop with brief flashes of a "broken world" state (character appears
  underwater / in rocks), never completes login

### The cause

pkt#79 and pkt#104 are **`bPartialInitial=1`** bunches — they're the **first
fragment** of a multi-packet logical bunch that continues across many
subsequent packets (pkt#80, pkt#81, …, up to whichever packet carries
`bPartialFinal=1`).

When we mutate the initial fragment's size, we change the **reassembled
total bit count** of the logical bunch.  Continuation fragments are
unmodified, so the reassembled content is still internally well-formed —
but **something in the client's reassembly pipeline validates an invariant
we can't reach from mutating a single fragment**.

We don't know exactly what that invariant is (a pre-declared total size?
a bit-count hash?  a cross-fragment length reference?).  We do know:

- **Stock UE5 `FInBunch::ReadReceivedBunch()` doesn't obviously do such a
  check** — so this is likely AoC-specific.
- **The `sub_145035420` branch** in Function D (triggered by flag
  `0x200000`) is a candidate for the check, but hasn't been RE'd.
- Capturing the failing UDP traffic via Wireshark would definitively
  show whether the client acks the bunch before breaking, or breaks
  during reassembly, or after delivery to the actor.  Not done yet.

### What we tried to work around it

- ✓ Confirmed our mutator is bit-level correct (unit tests, identity
  self-test, BDB read-back, tail-copy verification).
- ✓ Fixed a 7-bit offset bug (`BDB_BIT=183` → correct `176`).  Did not
  change the failure.
- ✓ Tried every length delta: -72, -56, -9, -8, +8, +24, +48, +80 bits.
  All fail with any non-zero delta.
- ✓ Tried mutating only one site at a time (`--mutate-disable-pkt79` /
  `--mutate-disable-pkt104`).  Both individually fail.
- ✗ Did not try: Wireshark capture of the failing stream to identify
  whether client sends anything abnormal after receiving the mutated
  bunch.

## Why we stopped

Two hard constraints made further work here unproductive:

1. **We don't own the continuation fragments.**  To fix the total-size
   invariant we'd need to also mutate every fragment in the chain.  The
   chain spans many packets and the fragment boundaries aren't clean from
   our side — we'd be chasing a moving target.
2. **Phase III makes this obsolete.**  The real solution is to
   synthesise pkt#79 / pkt#104 from scratch rather than mutate them in
   place.  Full synthesis lets us emit a *non-partial* bunch with just
   the name property, which avoids the partial-bunch invariant entirely.

Time-to-value on Phase III work is much better than continuing to dig
into the invariant.  See [`phase-iii-roadmap.md`](./phase-iii-roadmap.md).

## What we kept

The mutation library and its tests are **intentionally retained in the
tree** even though they're not wired into the live path:

- `src/protocol/emit/replay_mutator.{h,cpp}` — the mutation engine
- `src/tools/test_replay_mutator.cpp` — 40 tests covering bit-shift,
  BDB update, FString round-trip, edge cases
- `src/tools/test_pkt104_round_trip.cpp` — 14 tests covering pkt#104
  FString region round-trip
- `docs/` session notes from the attempts

They're useful as:
- **Reference** for Phase III synthesis (the mutator already solves
  "encode an FString to the exact wire format").
- **Bit-level validators** we can reuse when we need to diff a
  synthesised bunch against a captured fixture.
- **Documentation** of what didn't work, so no one redoes it.

## Lessons for future RE work

1. **"Tests pass at library level" ≠ "works on the wire."**  The tests
   validated every codec in isolation against the captured fixture.  The
   failure only shows up when the mutated bunch participates in the
   larger reassembly chain — which our tests can't see.  Integration
   testing against a real client is irreplaceable.

2. **Partial-bunch invariants propagate across packets you don't touch.**
   If you only mutate fragment `i`, but the client validates something
   that depends on fragments `i..N`, you'll fail even when `i`'s own
   bytes are perfect.  Either own the whole chain or go around it
   (Phase III's approach).

3. **Always inspect bunch partial flags before assuming mutation is safe.**
   The `inspect_bunch_header.py` tool in `src/protocol/tools/` does this
   — run it on any bunch before mutating.  It would have told us day one
   that pkt#79/pkt#104 are partial-Initial and warned us off.

4. **Verify constants against ground truth.**  The `BDB_BIT=183`
   mistake came from the old patcher and was never independently
   verified.  `inspect_bunch_header.py` showed the real value was 176.
   Running the inspector on a new fixture should be step 1 of any
   mutation or synthesis work.

5. **RE "plumbing" functions have diminishing returns.**  We decompiled
   9 functions in one late-night session.  The first 4 were highly
   valuable (Function J, Function D, sub_145056800, FastArraySerializer
   reveal).  The last 5 were low-value plumbing (class registration,
   static init).  Set a value budget before going deep.

## What broke-world "flash" actually is

Our best guess, never verified: when the client's reassembler finishes
the (incorrectly-sized) logical bunch and dispatches its content, the
content is technically well-formed but the client's actor state ends up
in a half-initialised state.  The player pawn spawns at `(0, 0, 0)` —
which is deep below terrain in the captured world region — producing the
"rocks + underwater" appearance.  Then something triggers a state
invalidation (maybe a heartbeat check) and the client kicks back to
loading to retry.  We never confirmed this theory.  If future debugging
needs a starting hypothesis, this is it.
