# Phase III Roadmap — Live Synthesis

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
2. **The `sub_145035420` (flag `0x200000`) dispatch path** — still
   unknown.  Might affect ~10–20% of replicated properties.
3. **Per-subobject RepLayout framing** — pkt#22 shows two `cmd_index=0`
   entries in its property stream.  We believe this is per-subobject
   interleaving but haven't pinned down the framing marker.
4. **FastArraySerializer NetDelta emit** — for `TArray<FItem>` replicated
   state (abilities list, inventory, etc.).
5. **Handshake-path integration** — the real client initiates connection
   via `StatelessConnect`.  Right now replay bypasses that.  Phase III
   needs a proper handshake at the start.

---

## Milestones

### M1 — Synthesise a Standalone pkt#22 (**unblocks custom names**)

**Deliverable:** emit the PlayerController ActorOpen bunch from scratch
using `ActorBuilder` + `replayout`, with the chosen name baked in.

**Sub-tasks:**
1. Decode the captured pkt#22 via a `decode_pc_spawn` function that uses
   our full codec layer (not the Python decoders — those are for
   exploration).  Output: a typed `ActorState` struct with every
   replicated property in a typed slot.
2. Round-trip validator: `encode(decode(captured)) == captured` at the
   bit level.
3. Mutate `ActorState.name = "YourName"` and emit.  Non-partial.  Send
   to client.
4. Replace pkt#22 in the replay stream with our synthesised version
   for connecting clients.

**Risks:**
- The per-subobject framing unknown (§3 in "missing" list).  Workaround:
  initially synthesise only the actor root, skip subobjects.  Client
  may tolerate it.
- `sub_145035420` path may handle some of AAoCPlayerController's 19
  properties.  Workaround: identify which ones, treat as `Unknown`
  for now and don't emit them.

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
