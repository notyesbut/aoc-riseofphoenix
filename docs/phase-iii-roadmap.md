# Phase III Roadmap — Live Synthesis

> 2026-06-12 update: this document is now historical planning context plus
> still-useful design notes. For the current native-server status, start with
> [`re-plan/PUBLIC-PROGRESS-2026-06-12.md`](re-plan/PUBLIC-PROGRESS-2026-06-12.md)
> and [`PROJECT-OVERVIEW.md`](PROJECT-OVERVIEW.md).
>
> The active blocker is no longer "emit standalone pkt#22". The native path now
> reaches the `ClientAckUpdateLevelVisibility` RPC parameter reader; the next
> task is deriving the exact CALV parameter bit layout from the current retail
> client and replacing the probe matrix with one proven serializer.

Phase III replaces the captured replay with server-synthesised bunches.
The goal is a server that **emits actual per-client actor spawns from
live state**, so things like custom character names work naturally —
no mutation, no bit-shifting, no partial-fragment wrestling.

This document is the plan.  It's a starting point; adjust as the team
learns more.

---

## Premise

The replay plays captured packets verbatim from `fixtures/replay_data.bin`
and renders "RandomChar" no matter what.  To get past that, we stop
replaying and start **building fresh bunches** using our codec layer.

### What we already have (from Phase II)

- **Bunch framing emitter** (`ActorBuilder`) — validated bit-identical to
  a captured pkt#22 for the first 4011 bits of the bunch.
- **Package-map export emitter** — validated.
- **`FIntrepidNetworkGUID` writer** — validated.
- **`SerializeNewActor` block emitter** — validated.
- **Per-property codec layer** (`replayout/`) — FBool, FByte, FInt,
  FInt64, FFloat, FDouble, FObject (as 128-bit GUID), FString
  (ASCII+UCS-2), FStruct (recursive) — 94 tests green.
- **Class catalogs** for AActor / AController / APlayerController /
  APlayerState / APawn / AAoCPlayerController — 6 classes populated.
- **`AuthServerIDReplicated` identified as FIntProperty** (32-bit).

### What's still missing

1. **A server-side authoritative state model** — today `LiveWorld` /
   `ActorRegistry` exists but is mostly stubs.  We need typed actor
   state (name, position, class, etc.) that the emitter reads from.
2. **Per-class phase splits** — we now know (as of 2026-04-24, see
   `docs/wire-format.md` §16) that RepLayout uses a **2-phase model**
   (InitialRepProps vs LifetimeRepProps) with a `0xDEADBEEF` sentinel
   between them.  Our catalogs are flat — we need to split each class's
   properties into InitialOnly vs Lifetime lists to match the wire.
3. **FastArraySerializer NetDelta emit** — for `TArray<FItem>` replicated
   state (abilities list, inventory, etc.).  Flag 0x200000 (now resolved
   to the TArray element serializer `sub_145035420`) handles the simple
   TArray case; FastArraySerializer is a separate path (flag 0x100000).
4. **Handshake-path integration** — the real client initiates connection
   via `StatelessConnect`.  Right now replay bypasses that.  Phase III
   needs a proper handshake at the start.

### What we resolved 2026-04-24 (was blocking M1)

- ✅ **The "cmd_index=0 twice" mystery** — not per-subobject interleaving.
  It's the **phase boundary**: pkt#22 emits InitialRepProps (cmd_index=0..N)
  + `0xDEADBEEF` sentinel + LifetimeRepProps (cmd_index=0..M) + sentinel.
- ✅ **`sub_145035420` dispatch path** — fully RE'd, it's the TArray
  element serializer (uint16 Num + per-element recurse).
- ✅ **Function G / J / diff-checker / shadow-hash** — all mapped (see
  `docs/wire-format.md` §16).
- ✅ **AActor AoC additions** — confirmed 3 properties at the top of the
  AActor FPropertyParams table: AuthServerIDReplicated (FInt),
  bIsInterServerReplicated (FBool), ProxyNetUpdateInterval (FFloat).

---

## Milestones

### M1 — Synthesise a Standalone pkt#22 (**unblocks custom names**)

**Deliverable:** emit the PlayerController ActorOpen bunch from scratch
using `ActorBuilder` + `replayout`, with the chosen name baked in.

**Sub-tasks:**
1. **Split catalogs into phase lists** (`initial_props` + `lifetime_props`
   on each class) — the wire model from `wire-format.md` §16.2.

   **DO NOT try to find `GetLifetimeReplicatedProps` via string XRefs
   in IDA.** It doesn't work: UE5 Shipping builds precompute `FName`
   indices at compile-time, so `DOREPLIFETIME(Class, Property)` emits
   no string literals.  Attempts on 2026-04-24 chased `aGetlifetime`,
   `aAaocplayercont`, `aCondInitialonl` — all landed on unrelated
   Slate UI / physics / math code because those strings are generic
   and reused in dozens of places.

   Approaches that DO work (in order of preference):

   a. **Read FPropertyParams flags directly.**  Each property has a
      64-byte descriptor (e.g. `0x14A77C220` for `AuthServerIDReplicated`)
      containing a `PropertyFlags` field with the CPF_* bits.  Flag
      `CPF_RepNotify` (0x0000000000000100) and CPF conditions encode
      the phase implicitly.  Dump 3 known-type structures and diff to
      find the flags offset.  **This is the preferred path.**

   b. **Heuristic split + round-trip validator.**  Assume:
      - InitialOnly = `AuthServerIDReplicated`, `bIsInterServerReplicated`
        (identity markers, sent once)
      - Lifetime = everything else (stock UE5 replicated AActor props
        are all Lifetime)
      Run `test_pc_spawn_round_trip`.  If bits differ, move properties
      between lists until the round-trip is bit-exact.  Coarse but
      effective — the search space is small (we know there are only
      15 AActor replicated props, 3 AoC additions, etc.).

   c. **Locate `UClass::PropertyLink` table** for AAoCPlayerController.
      UClass+0x130/+0x120 hold the per-phase property lists at runtime
      (per `wire-format.md` §16.1).  Finding the UClass object itself
      (via `AAoCPlayerController::StaticClass`) gives us the split at
      a known offset.  Requires more IDA spelunking but is definitive.
2. Decode the captured pkt#22 via `decode_pc_spawn(bytes)` → typed
   `DecodedPCSpawn`.  Walker expects `[phase_mask][phase body × N]` where
   each phase body is `[(cmd_index, body)*][0xDEADBEEF]`.
3. Round-trip validator: `encode(decode(captured)) == captured` at the
   bit level.  Exact-bit match including the 0xDEADBEEF sentinels.
4. Mutate `DecodedPCSpawn.name = "YourName"` and emit.  Non-partial.
   Send to client.
5. Replace pkt#22 in the replay stream with our synthesised version
   for connecting clients.

**Risks:**
- **Phase-split correctness** — if we mis-classify a property (Initial vs
  Lifetime), the client will see cmd_indices in the wrong list and either
  ignore them or crash.  Round-trip validator catches this early: if
  `encode(decode(captured)) != captured`, our split is wrong.
- **Unclassified property types** — AAoCPlayerController has 19 replicated
  properties but our catalog only types 3-4 of them.  Decode will fail on
  first `FPropertyType::Unknown`.  Mitigation: the RE done via IDA's
  FPropertyParams walker (see `wire-format.md` §16) gives us every
  type — just need to extend the catalog.

**Success criterion:** client logs in, spawns with the custom name
visible in HUD + nametag.

### M2 — Synthesise pkt#78 (Pawn ActorOpen)

Same as M1 but for the Pawn.  Blocks on getting `AAoCPlayerPawn` class
metadata (currently missing — IDA anchor hunt failed, need new strategy
like finding the class descriptor via `ida_dump_aoc_subclasses.idc`).

**Success criterion:** player pawn spawns correctly with custom class
(Fighter vs Mage vs etc.) baked into the emitted class reference.

### M3 — Progressive retirement of the replay stream

As each packet's synthesiser comes online, stop playing the captured
version and emit the synthesised one:

1. pkt#22 (PC) — M1
2. pkt#78 (Pawn) — M2
3. pkt#104 (HUD name update)
4. pkt#79 (Nametag update)
5. World bootstrap packets (pkt#23..#77, various)
6. Property-delta packets (once M4 is done)

Each replacement reduces the replay's surface area.  When everything is
synthesised, delete the replay stream from the emitter.

### M4 — Per-tick delta replication

Server authoritatively tracks actor state; each tick, diff against
last-sent shadow and emit delta packets for what changed.  This is the
RepLayout write path, not just initial spawn.  Requires:

- `shadow_state` per client per actor
- Diff engine
- Relevance / visibility filter (who sees whom)
- Per-connection priority / bandwidth budget

At this point the server is a real live server.  The replay can be
deleted entirely.

### M5 — Client input handling

Receive `ClientMove` RPCs, apply movement physics, send authoritative
position updates back.  Player can actually walk around.

### M6 — Multiplayer

Two clients on the same shard see each other.  Requires M4's visibility
filter to actually function.

---

## First concrete task for whoever picks this up

**Implement `src/protocol/bootstrap/decode_pc_spawn.cpp`** that:

1. Reads `fixtures/captured_pkt_22.bin` (extract via
   `src/protocol/tools/extract_pkt_fixture.py 22 captured_pkt_22`)
2. Parses the outer bunch header (use existing `pc_spawn_parser.cpp`)
3. Walks the package-map export section into a
   `std::vector<ExportEntry>`
4. Parses `SerializeNewActor` block into `{actor_guid, archetype_guid,
   level_guid, transform_flags, transform_body}`
5. Walks the property stream via `[cmd_index: 32 bits][body]*` format,
   dispatching per FProperty type using the catalog.  For each property
   produce a `ReplayoutField{cmd_index, FPropertyType, PropertyValue}`.
6. Returns a `DecodedPCSpawn` struct containing all of the above.

Write a unit test: round-trip the decoded struct through `ActorBuilder`
+ `replayout` encoders and verify bit-identical output vs the fixture.
This closes the validation loop for M1.

Once that round-trip is green, mutate the `ActorState.name` field and
emit to the client as the first live milestone.

---

## What "done" looks like

Phase III is done when:

- **`fixtures/replay_data.bin` is no longer read at runtime.**
  `GameServer::replay_loop` is deleted or becomes a dev-only flag.
- A new player logs in → the server emits a fresh PC/Pawn/PS spawn
  triple from live state with the chosen name and class.
- At least one other connected player can see them, and they can see
  each other, standing at their correct server-authoritative positions.
- No captured packets survive in the live send path.

Beyond Phase III lies "actually making it a game" — gameplay systems,
content, persistence.  That's out of scope for this roadmap.
