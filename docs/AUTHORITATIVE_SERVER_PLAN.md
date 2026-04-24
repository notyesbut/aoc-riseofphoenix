# AUTHORITATIVE SERVER PLAN

**Status**: living document  |  **Owner**: Path B  |  **Started**: 2026-04-24

This is the north-star document for the project. It describes how we build a
fully functional private server for an online game whose official servers are
gone, using captured replay data and the shipping client binary as
reverse-engineering **references only** — not as a runtime mechanism. The
final product is an authoritative server that drives gameplay in real time
and faithfully speaks the protocol the original client expects.

---

## 1. Executive Summary

### 1.1 Goal

Revive the game by owning the server side fully:

- **Server = authority**. Holds canonical game state (positions, HP, inventory,
  world content). Validates every client action. Is the source of truth.
- **Client = presentation**. Renders what the server says, submits input,
  runs local prediction for responsiveness. Believes the server.
- **No replay at runtime**. Replay data exists in the repo exclusively for
  RE and regression-testing (byte-identity diff harnesses). The running
  server never reads replay files.

### 1.2 What exists today (inventory)

| Layer | State | Notes |
|---|---|---|
| UDP transport + StatelessConnect | ✅ native, working | Real handshake with real client |
| NMT (Hello/Login/Welcome/NetSpeed/Join) | ✅ native, working | `opcode_dispatcher.cpp` |
| Session management, ACK window | ✅ working | `ClientState` + `replay_loop`'s pacing |
| Wire primitives (bit-packed IO, SIP, SerializeInt) | ✅ 148 tests green | `protocol/wire/` |
| FString / FInt / FFloat / FBool / FObject / FStruct codecs | ✅ round-trip green | `protocol/emit/replayout/encoders/` |
| `ActorBuilder::build_spawn(PC)` | ✅ **byte-identical to captured pkt#22** (4859/4864 bits) | `protocol/emit/actor_builder.cpp` |
| `PropertyUpdateBunchBuilder` | ✅ 17 tests | `protocol/emit/property_update_bunch_builder.cpp` |
| Class catalogs (AActor/AController/APlayerController/AAoCPlayerController/APlayerState/APawn/ACharacter) | ✅ extracted from binary | `catalog.cpp` — 13 + 2 + 2 + 19 + 10 + 4 + 11 replicated |
| `NativeConnectSequencer` | ✅ scaffold + NMT hook + state machine | `net/native_connect_sequencer.cpp` (M1.0) |
| Replay system | ✅ working, used for comparison | `ReplayData::load` — **reference only** post-M1.4 |

### 1.3 What's missing (at the highest level)

- Native world bootstrap (channel-0 control bunches, level references)
- Keep-alive + ACK advancement (prevents timeout once packets start flowing)
- Client→server input parsing (movement, chat, RPC)
- Authoritative simulation tick (positions update, state evolves)
- Persistence (character state across sessions)
- Multi-client broadcast (for multiplayer)

### 1.4 Success criterion

```
$ launch_all_native.bat
[NativeConnectSequencer] client enters world with character "MyHero" in < 10s
[NativeConnectSequencer] client does not disconnect
[NativeConnectSequencer] player walks around; position updates are
                         authoritatively integrated server-side
[NativeConnectSequencer] second client can connect and see the first
```

---

## 2. Architecture

### 2.1 Process topology

```
┌────────────────────────┐   HTTPS :8081   ┌─────────────────────┐
│    launcher.exe        │ ───────────────▶│   auth_server.exe   │
│  (login + char select) │                 │  (account DB)       │
└────────────┬───────────┘                 └─────────────────────┘
             │ launch command
             ▼
┌────────────────────────┐   UDP :7777     ┌─────────────────────┐
│ AOCClient-Shipping.exe │◄───────────────▶│    aoc_server.exe   │
│    (Unreal client)     │                 │  (authoritative)    │
└────────────────────────┘                 └──────────┬──────────┘
             │ UDP :19021                              │
             ▼                                         │
    ┌────────────────────┐                             │
    │ tether_server.exe  │─────── shared session ──────┘
    │  (ARQ transport)   │
    └────────────────────┘
```

### 2.2 aoc_server.exe internal layers (authoritative-mode)

```
┌─────────────────────────────────────────────────────────────────┐
│  Main receive loop (game_server.h::start)                       │
│  • recvfrom → parse PE/packet header → route to dispatcher      │
│  • Routes handshake (StatelessConnect) separately from NMT      │
└─────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────┐
│  OpcodeDispatcher                                               │
│  • Identifies NMT opcode → invokes handler                      │
│  • Parses client-data bunches → routes to InputRouter           │
└─────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────┐
│  NativeConnectSequencer  (one per connected client)             │
│  • State machine: AwaitNmtJoin → SendBootstrap → ... → Maintain │
│  • Drives initial bring-up                                      │
│  • Spawns per-tick work once in Maintain                        │
└─────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────┐
│  Emitter layer                                                  │
│  • ActorBuilder::build_spawn       — pkt#22-style ActorOpen     │
│  • PropertyUpdateBunchBuilder      — property deltas            │
│  • BootstrapEmitter (M1.1 — new)   — channel-0 control flow     │
│  • SubobjectChannelOpener (M2+)    — for components             │
└─────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────┐
│  LiveWorld (simulation)                                         │
│  • ActorRegistry       — all server-side actors                 │
│  • TickLoop            — runs at ~60Hz                          │
│  • MovementIntegrator  — applies client input + physics         │
│  • VisibilityManager   — who sees what                          │
│  • BroadcastManager    — replicate updates to clients           │
└─────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────┐
│  Persistence (M4+)                                              │
│  • SQLite character DB                                          │
│  • World state snapshots                                        │
└─────────────────────────────────────────────────────────────────┘
```

### 2.3 Key modules (existing + new)

| Module | Path | M-status |
|---|---|---|
| `GameServer` | `net/game_server.h` | modified — now branches native vs replay |
| `NativeConnectSequencer` | `net/native_connect_sequencer.{h,cpp}` | M1.0 scaffolded, handlers empty |
| `BootstrapEmitter` | `net/bootstrap_emitter.{h,cpp}` **(NEW M1.1)** | not started |
| `HeartbeatEmitter` | `net/heartbeat_emitter.{h,cpp}` **(NEW M1.3)** | not started |
| `InputRouter` | `net/input_router.{h,cpp}` **(NEW M1.4)** | not started |
| `LiveWorld::TickLoop` | `net/live_world.cpp` | stub — M1.4+ will flesh |
| `ActorRegistry` | `world/simulation/actor_registry.*` | stub — M2 |
| `BroadcastManager` | `world/replication/broadcast_manager.*` | stub — M2 |

---

## 3. Milestones

Each milestone has a **DONE criterion** — an observable behavior that
validates the milestone is complete. We do not advance without hitting it.

### M1.0 — Scaffolding  ✅ DONE (2026-04-24)

- `--native` flag gates replay vs native
- Post-NMT hook starts `NativeConnectSequencer`
- State machine walks all states with stub handlers
- **Done**: logs in `emu-20260424-105808.log` show full state progression

### M1.1 — Native World Bootstrap  (16-30 h)

**Goal**: replace the first ~30 captured packets with native emission so the
client receives a valid world reference and starts loading the level.

**Work**:
1. **RE pass** on replay packets 0–30 using existing tools:
   - `phase1_parser.py` — bunch decomposition per packet
   - `find_actor_opens.py` — identify opens by class
   - Cross-reference with `docs/world-bootstrap-findings.md` and
     `docs/aoc-packagemap-xrefs.md`
   - Document each packet's purpose in new file
     `docs/native-bootstrap-sequence.md`
2. **Decode** the semantic intent:
   - Channel 0 control bunches announce game class, level, session info
   - NetGUID exports establish the `PackageMap` client-side (level class,
     game-mode class, AoCGlobalCommands asset, etc.)
   - `/Game/Levels/Verra_World_Master/Verra_World_Master` is the level
     archetype (seen in captured pkt#22 export chain)
3. **Build** `BootstrapEmitter`:
   - `emit_game_info(channel_0_bunch)` — announces game class
   - `emit_level_ref(channel_N_bunch)` — opens level channel
   - `emit_package_map_preload(exports)` — pre-populates NetGUID cache
4. **Validate** with a new test `test_bootstrap_emit_diff.cpp` that diffs
   bytes against captured replay (target: byte-identical for the first 30
   packets, or bit-identical within alignment-padding tolerance).

**Done**: client accepts our bootstrap, loading screen appears, stays on
loading screen (no timeout yet because we still don't send PC). Server log
shows `[BootstrapEmitter] sent <N> bunches, <M> bytes total`.

### M1.2 — Native PlayerController + PlayerState  (8-16 h)

**Goal**: character appears in world; name shows whatever `--custom-name`
supplies. No movement yet.

**Work**:
1. **Reuse** `ActorBuilder::build_spawn(pc_schema, rt, ctx)` — already
   byte-identical for pkt#22. Supply `rt.custom_name = config.custom_name`.
2. **Add** `PlayerState` emission via `ActorBuilder` (stock UE5 schema,
   10 replicated properties including `PlayerNamePrivate` which is the
   name the HUD reads).
3. **Wire** in `NativeConnectSequencer::do_send_pc_open()` and
   `do_send_pc_props()`.
4. **Investigate** which property the HUD actually reads from (our three
   failed injection tests suggested it's not `AAoCPlayerController.Name`
   alone — also need `APlayerState.PlayerNamePrivate`).

**Done**: running `launch_all_native.bat` with `--custom-name "MyHero"`
shows a character named MyHero in-world. HP/MP/stamina may be zero
(fixed in M1.4), but the character is visible with the right name.

### M1.3 — Keep-alive + ACK handling  (8-16 h)

**Goal**: connection stays alive indefinitely even if server sends no
gameplay packets. Prevents the "timeout after 20s" failure mode.

**Work**:
1. **HeartbeatEmitter**: send an empty data packet every 200 ms while
   in `Maintain` state (same pattern as `replay_loop`'s post-replay keepalive).
2. **ACK tracking**: parse client-sent packet-ack history, advance
   `cs.out_ack_seq`, prune the sent window.
3. **Reliability**: if a reliable bunch isn't ACK'd within N ms, resend.
   (UE5's `FInBunch`/reliability layer — reference `docs/re-aoc-client.md`.)

**Done**: client stays connected for > 5 minutes in `--native` mode with
no input. Log shows `cs.out_ack_seq` advancing.

### M1.4 — Movement input  (12-24 h)

**Goal**: player can walk around. Server is authoritative — it integrates
client input, corrects the client if it predicts wrongly.

**Work**:
1. **RE** the `ServerMove` / `ServerMovePackedCompressed` / `ClientAdjustPosition`
   wire format from IDA (these are UE5 stock; reference
   `docs/ue5-actor-replication-wire-format.md`).
2. **InputRouter**: parses incoming bunches on the PlayerController channel
   (ch=3 in our capture), dispatches to `LiveWorld::apply_client_move`.
3. **MovementIntegrator**: server-side physics (simplified — capsule +
   gravity + clamped velocity). Runs at 60 Hz inside `LiveWorld::tick`.
4. **ClientAdjustPosition**: if server position diverges from client's
   predicted position beyond a threshold, emit a correction bunch. Client
   snaps to it.
5. **Replicated movement broadcast**: emit `ReplicatedMovement` property
   update bunches periodically so other clients (future M2) see the moves.

**Done**: character walks smoothly. Jumping + gravity work. Server-side
log shows position ticking. If you teleport to absurd position client-side,
server snaps you back.

### M2.0 — Second client + broadcast  (20-40 h)

**Goal**: two AoC clients connect to the same server, each sees the other's
character and movement.

**Work**:
1. **BroadcastManager**: maintain per-client visibility sets; when actor A
   changes, broadcast the delta to every client that can see A.
2. **Per-client ActorRegistry view**: each connected client needs its own
   view of the world (different NetGUID namespaces, different property
   version-vectors).
3. **Spawn other player's PC/Pawn** when visibility brings them into range.
4. **Despawn** when they leave range.

**Done**: two clients on the same LAN (or same machine with two game
processes) can see each other walking around.

### M2.1 — Chat  (8-16 h)

**Goal**: `/s hello world` sends a chat message to nearby players.

**Work**:
1. **RE** the `ServerSay` / `ClientMessage` RPC bunches in the client.
2. **ChatRouter**: accept client chat bunches, route by channel (/s /w /p /g),
   broadcast to visible players.
3. **Handle** the `Say` UFunction — look at IDA for the
   `AAoCPlayerController::Say` method to see what params the client sends.

**Done**: two clients can chat. Say-channel is distance-limited to nearby.

### M3.0 — NPCs and interactables  (40-80 h)

**Goal**: one NPC (e.g. Goblin_LanguidGoblin we've seen in replay) appears
in the world and can be interacted with.

This is a substantial phase — requires:
- NPC class schema calibration (similar to pawn_schema but for NPC)
- AI tick loop (simple patrol / idle for start)
- Combat basics (attack, damage, death)
- Loot drop on death

### M4.0 — Persistence  (16-32 h)

**Goal**: character name, position, inventory persist across server restarts.

- SQLite schema for `characters`, `inventory_items`, `world_state`
- Save on client disconnect + periodic auto-save
- Load on client reconnect

### M5.0 — Anti-cheat + production hardening (multi-week)

- EAC bypass is a stub today; for production-grade need real analysis
- Input validation (speed hacks, teleport hacks)
- Rate limiting, DoS protection
- Proper TLS, auth token validation

---

## 4. Reverse-Engineering Methodology

### 4.1 The three sources of truth

1. **Captured replay (`replay_data.bin`, 29 010 packets)** — shows what the
   real server sent in a real session. Gold for: packet ordering, bunch
   framing, NetGUID flow, property values.
2. **Shipping client binary (`AOCClient-Win64-Shipping.exe`, 235 MB)** —
   shows what the client EXPECTS to parse. Gold for: exact wire formats,
   class structures, property metadata (FPropertyParams), dispatch logic.
3. **Markdown RE notes (`docs/*.md`, 23+ files)** — the accumulated
   knowledge base. New RE findings land here before they land in code.

### 4.2 Standard workflow per new wire-format question

```
┌─────────────────────────────────────────────────────────┐
│ 1. Find examples in the replay                          │
│    • grep / phase1_parser / custom scanners             │
│    • isolate a fixture (.bin slice of one packet)       │
└─────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│ 2. Cross-reference with IDA / client binary             │
│    • Find the parser function (e.g. ProcessBunch)       │
│    • Read its decompilation; identify fields            │
│    • Look up FPropertyParams tables for structs         │
└─────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│ 3. Write a decoder in Python first                      │
│    • Fast iteration; no C++ build cycle                 │
│    • Validate against multiple fixture examples         │
│    • Output: exact structure definition                 │
└─────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│ 4. Document findings in docs/*.md                       │
│    • Before writing code: write what you learned        │
│    • Future-you (and the team) will need this           │
└─────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│ 5. Write the C++ encoder + decoder                      │
│    • Add a round-trip test against the fixture          │
│    • Byte-identity is the gold standard                 │
└─────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│ 6. Wire into the server                                 │
│    • Only after bytes match is it safe to use live      │
│    • Any discrepancy would manifest as client reject    │
└─────────────────────────────────────────────────────────┘
```

### 4.3 IDA-specific RE patterns we use

Documented in detail in:
- `docs/re-aoc-client.md` — general client RE findings
- `docs/ue5-actor-replication-wire-format.md` — RepLayout internals
- `docs/intrepid-packagemap-re.md` — AoC's NetGUID scheme
- `docs/serialize_new_actor_analysis.md` — pkt#22 structure

Key functions we've RE'd:
- `sub_14504F1A0` (Function G) — `UNetDriver::ReplicateActor` iterator
- `sub_145057C30` (Function J) — per-property dispatcher
- `sub_1450357C0` (Function D) — FProperty type dispatch
- `sub_14141E960` — `ReadFIntrepidNetworkGUID` (AoC's 128-bit GUID)
- `sub_1450360E0` — `WriteFIntrepidNetworkGUID`

When RE'ing a new function:
1. Script its XRefs: where is this called from?
2. Decompile (hex-rays / Ghidra)
3. Identify data structures referenced (FField offsets etc.)
4. Cross-check with UE5 public source (same decompilation patterns)
5. Document in `docs/ida-<function>.md`

### 4.4 Fixtures + regression tests

Every non-trivial RE finding gets a fixture + round-trip test:

```
src/protocol/tools/captured_*.bin     # fixture binary
src/tools/test_<thing>_round_trip.cpp # C++ round-trip test
docs/<thing>-decoded.md               # human-readable findings
```

**Current fixtures**:
- `captured_pc_spawn_reassembled.bin` — pkt#22 reassembled
- `captured_pkt_78.bin` — raw pkt#78
- `captured_pkt_79.bin`, `captured_pkt_80.bin` — raw
- `captured_pkt_104.bin` — Name property update bunch

Tests (all green):
- `test_replayout_codecs` — 94 primitive codec tests
- `test_pkt22_round_trip` — pkt#22 byte-identity
- `test_pkt104_round_trip` — pkt#104 FString region
- `test_pc_spawn_diff` — ActorBuilder output vs captured pkt#22 (99.9% match)
- `test_name_update_bunch` — Name-delta bit-identity (7 tests)
- `test_property_update_bunch_builder` — builder class (17 tests)

**Every new emitter MUST have a corresponding byte-identity test against a
captured fixture** before it ships into `NativeConnectSequencer`.

---

## 5. Data Structures

### 5.1 Coordinates + Transforms

AoC uses UE5-standard coordinate system:
- **X** = forward (red)
- **Y** = right (green)
- **Z** = up (blue)
- Units = **centimeters** (1 UE unit = 1 cm)
- Quaternions LHS (left-hand)

Server data structures:
```cpp
struct Vec3 { double x, y, z; };       // world-space position
struct Rotator { float pitch, yaw, roll; };  // degrees
struct Transform {
    Vec3 location;
    Rotator rotation;
    Vec3 scale = {1,1,1};
    Vec3 velocity;     // for movement prediction
};
```

Wire encoding:
- Location is **quantized** via `SerializePackedVector<100, 24>` (24 bits
  per component, scale 100 → cm precision in a ±83 km range)
- Rotation is 3× optional int16 (yaw/pitch/roll; absent means zero)
- Full RE notes: `docs/ue5-actor-replication-wire-format.md` §transform

### 5.2 Entities

```cpp
enum class ActorClass {
    PlayerController,     // AAoCPlayerController
    PlayerState,          // APlayerState
    Pawn,                 // PlayerPawn_C (Blueprint, parent ACharacter)
    NPC_Humanoid,         // Goblin_LanguidGoblin_C etc.
    StaticMeshActor,      // world geometry
    InteractableActor,
    // ... many more (see replay scan in M3)
};

struct Actor {
    uint64_t net_guid;         // FIntrepidNetworkGUID.ObjectId
    uint32_t server_id;        // FIntrepidNetworkGUID.ServerId
    uint32_t randomizer;       // FIntrepidNetworkGUID.Randomizer
    ActorClass cls;
    Transform transform;
    uint8_t  channel;          // network channel assigned to this actor
    ActorState state;          // per-class data

    // For replication
    uint64_t last_seen_by_client;  // bitmask of clients that got this
    uint32_t property_version;     // bumped when any replicated prop changes
};
```

### 5.3 Items + Inventory

Not needed for M1/M2. Sketch for M3+:

```cpp
struct Item {
    uint64_t item_id;      // globally-unique
    uint32_t asset_id;     // references item-catalog asset (e.g. sword)
    uint32_t stack_count;
    uint32_t quality_tier;
    // ... AoC-specific: socket slots, enchants, durability
};

struct Inventory {
    std::vector<Item> slots;
    static constexpr size_t MAX_SLOTS = 40;  // RE from client
};
```

Wire encoding: **FastArraySerializer NetDelta** path (flag 0x100000 in
FProperty dispatch). Not yet RE'd — blocking work for M3.

### 5.4 World state

```cpp
struct World {
    std::string level_path;   // e.g. "/Game/Levels/Verra_World_Master/Verra_World_Master"
    uint64_t    level_net_guid;
    double      game_time_seconds;
    uint32_t    tick_count;

    ActorRegistry actors;
    SpatialGrid   grid;       // for visibility + broadcast queries
};
```

---

## 6. Client-Server Interaction Model

### 6.1 Trust boundary

```
   ┌────────── CLIENT ──────────┐      ┌────────── SERVER ──────────┐
   │  Renders what server says   │      │  Authoritative state       │
   │  Predicts own motion        │  →   │  Validates input           │
   │  Submits input (ServerMove) │      │  Corrects client (snap)    │
   │  NEVER trusted as authority │  ←   │  Broadcasts to observers   │
   └─────────────────────────────┘      └────────────────────────────┘
```

### 6.2 Typical tick

```
T+0ms:   Client captures input (WASD, mouse look) + predicts movement
         locally. Sends ServerMove{timestamp, input_vec, predicted_pos} to
         server via ch=3 (PC channel).
T+10ms:  Server receives ServerMove, validates:
           - timestamp monotonic?
           - input vector bounded (no super-speed)?
           - predicted_pos within tolerance of server's own integration?
         If valid → update actor's position.
         If divergent → emit ClientAdjustPosition{server_pos} on ch=3.
T+16ms:  Server tick integrates physics for all actors.
T+16ms:  BroadcastManager emits ReplicatedMovement to all clients that
         can see this actor.
T+20ms:  Other clients receive the update, interpolate.
```

### 6.3 What the server NEVER trusts

- Client-reported position → only a hint; server integrates its own
- Client-reported item quantities → derived from server DB
- Client-reported damage done → calculated by server combat engine
- Client-reported location of NPCs → server owns all AI

### 6.4 What the server DOES trust (with validation)

- Client's input vector (within bounds)
- Client's button presses (abilities — gated by cooldowns server-side)
- Client's chat text (length-capped, profanity-filtered)

---

## 7. Validation Strategy

### 7.1 Byte-identity oracle

For every wire-format primitive we emit:
- Capture the original wire bytes (fixture)
- Build our encoder output
- **Bit-level compare** against the fixture
- Target: **100% match** (any divergence = client will reject)

This is the pattern established by `test_pc_spawn_diff.cpp` (pkt#22) and
`test_name_update_bunch.cpp`. Continue for every new emitter.

### 7.2 Incremental replay-diff

As M1.1+ lands, the server's output stream can be compared to the
captured replay:
- Log every S>C packet's hex to `logs/bunches.log` (already implemented
  via `--verbose-bunches`)
- Diff against the replay's expected packet at that index
- Expected drift: 5-bit alignment padding + our own NetGUID values
  (different from captured session) + custom name
- Unexpected drift = bug

### 7.3 Client-behavior assertions

Observable client states that confirm correctness:
- Loading screen completes → bootstrap is valid
- Character appears → PC + PlayerState accepted
- Name visible in HUD → correct property targeting
- Can walk → movement input parsed correctly
- No disconnect after 10 min → keepalive + ACKs working

Each is a **test criterion** for a milestone. We do not advance without
all observed.

### 7.4 Structured logging

Standard format for every subsystem's log lines:
```
[<ts>] [<level>] [<Subsystem>] <event> <key=val ...>
```

Subsystems:
- `[GameServer]` — top-level routing
- `[NativeConnectSequencer]` — connect orchestration
- `[BootstrapEmitter]` — M1.1
- `[ActorBuilder]` — actor open emission
- `[PropertyUpdateBunchBuilder]` — delta emission
- `[HeartbeatEmitter]` — M1.3
- `[InputRouter]` — M1.4
- `[LiveWorld]` — simulation
- `[BroadcastManager]` — replication

---

## 8. Debugging Practices

### 8.1 Log levels

- `debug` — per-bit tracing; only when `--verbose-bunches` set
- `info` — normal operational events (connected, disconnected, tick N)
- `warn` — something unexpected but recoverable (bunch parse mismatch)
- `error` — client-visible bug (disconnect, data corruption)

### 8.2 Packet inspection utilities

Existing tools (keep using):
- `phase1_parser.py` — full packet → bunches decomposition
- `decode_pc_spawn_v2.py` — pkt#22 specific decoder
- `extract_pkt_fixture.py` — slice one packet out of replay
- `find_actor_opens.py` — find all ActorOpen bunches

Add (M1.1+):
- `dump_server_stream.py` — parse `logs/bunches.log` into structured JSON
- `diff_streams.py` — side-by-side replay vs server-output
- `replay_packet_N.py` — re-run the server's emission of packet N offline
  (no client needed) for unit-like RE

### 8.3 Live debugging tricks

- **Freeze the replay at packet N** (`--replay-max-packets N`) — lets us
  isolate which captured bunch first diverges from our understanding
- **Dual-run**: `launch_all.bat` (replay) in one terminal,
  `launch_all_native.bat` (native) in another, same client, diff the
  server output streams
- **Wireshark**: capture `loopback:7777`; Wireshark's UE5 dissector is
  incomplete but raw byte comparison still works
- **Client symbols**: the client is stripped, but IDA pseudo-code is
  rich. Annotate aggressively; save .idb frequently.

---

## 9. Documentation Practices

### 9.1 `docs/` is where knowledge lives

We currently have **23 RE docs**; more will land. Rules:

1. **Write before you code.** If you RE something new, document it first.
   Only then write the encoder/decoder.
2. **One topic per file.** Don't conflate packet formats and dispatch
   logic in the same doc.
3. **Link across files.** Use relative paths; the docs/ tree is a graph.
4. **Date your findings.** Markdown headers with `(RE'd YYYY-MM-DD)`.
5. **Keep obsolete docs but mark them.** Rename to `LEGACY_*.md`; don't
   delete (they capture failed paths — future-you needs the negative
   result too).

### 9.2 Key docs by topic

**Wire format**:
- `aoc-wire-format-decoded.md` — master wire-format reference
- `ue5-actor-replication-wire-format.md` — RepLayout specifics
- `ue5-packet-format-analysis.md` — outer packet framing

**Actor / property**:
- `pc-spawn-handle-catalog.md` — PlayerController property handles
- `serialize_new_actor_analysis.md` — pkt#22 structure
- `world-bootstrap-findings.md` — channel 0 bunch findings

**NetGUID / PackageMap**:
- `intrepid-packagemap-re.md` — AoC's 128-bit GUID scheme
- `ue5-packagemap-internals.md` — UE5 NetGUID lifecycle
- `aoc-packagemap-xrefs.md` — cross-references

**Strategy / roadmap**:
- `path-to-multiplayer.md` — older strategy notes
- `master-plan-multiplayer.md` — earlier plan
- `live-server-implementation-plan.md` — predecessor to this doc
- `session-h-roadmap.md` — session-era milestones

**Post-mortems**:
- `code-audit-2026-04-21.md` — architectural audit
- `phase-ii-postmortem.md` (in repo root docs) — failed mutation approach

### 9.3 New docs M1.1+ will create

- `docs/native-bootstrap-sequence.md` — M1.1 bootstrap RE
- `docs/ue5-heartbeat-ack.md` — M1.3 keepalive + ACK
- `docs/servermove-rpc.md` — M1.4 movement input format
- `docs/broadcast-visibility.md` — M2 replication
- `docs/npc-replication.md` — M3 NPC class schema

---

## 10. Extensibility Principles

### 10.1 Interfaces, not concretes

`NativeConnectSequencer` accesses `GameServer` through the narrow
`IGameServerHost` interface. This keeps the sequencer testable in
isolation (mock the host).

Apply this pattern to everything new:
- `IActorEmitter` — for ActorBuilder & subclass emitters
- `IBroadcastChannel` — for BroadcastManager
- `IInputSink` — for InputRouter's consumers

### 10.2 Event-based flow where possible

Simulation tick → raises `ActorMoved`, `ActorSpawned`, `ActorDestroyed`
events. BroadcastManager subscribes, translates to wire bunches.

This makes it cheap to add new consumers (e.g. a **recorder** that saves
the server's output stream for later debugging).

### 10.3 Config-driven behavior

CLI flags we've defined:
- `--replay <path>` — legacy replay mode
- `--use-embedded-bootstrap` — legacy embedded bootstrap
- `--native` — authoritative mode (new)
- `--custom-name <str>` — character name in native mode

Add per-milestone flags, e.g.:
- `--native-disable-bootstrap` — M1.2 debug: skip bootstrap, just send PC
- `--native-disable-tick` — pause simulation
- `--broadcast-debug` — dump broadcast decisions

---

## 11. Risk Management

### 11.1 Known risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| RE effort on wire formats takes 2-3× estimate | High | Scope creep | Strict DONE criteria per milestone; stop at criterion met, don't polish |
| Client has anti-cheat check we haven't stubbed | Medium | Disconnect | EOSSDK stub addresses known path; Wireshark-diff flags new ones |
| UE5 behavioral change between AoC binary and our references | Medium | Silent corruption | Trust the binary RE, not external UE5 docs |
| FastArraySerializer (inventory) not decodable | Medium | Blocks M3 | Defer inventory to M3+; M1/M2 works with empty arrays |
| Threading bugs in sequencer vs main loop | Medium | Crashes | `client_mu_` mutex protects shared state; no lock-free tricks |

### 11.2 How to handle unknowns

When you hit something you don't understand:
1. **Stop**. Don't guess.
2. **Isolate** the smallest reproducer (one packet, one function).
3. **Document** what you've observed in a new `docs/question-<topic>.md`.
4. **Investigate** with tooling (Python scripts, IDA decomp, fixture RE).
5. **Ask for a second opinion** (the team, the RE community).
6. **Only then** write code.

The previous `custom-name injection` experiment violated this — we
guessed the wire format three times and the client rejected every
attempt. The pivot to Path B is explicitly a commitment to not-guess.

---

## 12. Call-to-action — What's Next

### Immediate (next session): M1.1 RE pass

Before writing ANY code for M1.1, do this RE pass:

1. **Parse first 30 packets** of `replay_data.bin` via `phase1_parser.py`.
   For each, record in `docs/native-bootstrap-sequence.md`:
   - Packet index
   - Original seq
   - Bunches contained (ctrl, ch, open, partial, bdb)
   - Semantic purpose (inferred from `ch_name`, export content, known
     patterns)

2. **Identify the "minimum bootstrap set"** — the subset of packets that
   actually matter for the client to start loading the level. Many of the
   30 packets are NPC spawns we don't need yet.

3. **Decode package-map exports** from the first bootstrap packets —
   what NetGUIDs are declared, to what paths? This is the seed of our
   server-side PackageMap.

4. **Emit a hand-written C++ prototype** of the first 5-10 essential
   bunches (no class yet, just code in a temp file) and verify
   byte-identity against captured. Only after this is clean do we
   write the `BootstrapEmitter` class.

### M1.1 DONE when:

- `docs/native-bootstrap-sequence.md` documents first 30 packets
- `BootstrapEmitter` class emits the essential subset
- `test_bootstrap_emit_diff.cpp` passes byte-identity for that subset
- `launch_all_native.bat` shows client reaches "loading screen" and
  stays there (doesn't time out thanks to M1.3 work done in parallel)

---

## 13. Open Questions / Reminders

- Does the HUD name read from `AAoCPlayerController.Name` or
  `APlayerState.PlayerNamePrivate`? Our injection tests suggested the
  latter. M1.2 will emit BOTH to cover.

- What's the 16-byte prefix (`00 00 00 01 × 3, 00 00 00 6A`) that
  precedes the Name FString in captured pkt#104? Hypothesis: 3× prior
  property values (all int32=1) + cmd_index=0x6A. Test by decoding
  the 1344 bits of pkt#104 bunch payload preceding the Name slot.

- Does AoC's pkt#22 actually use the phase-partitioned RepLayout format
  (`0xDEADBEEF` sentinel + 2 phases) documented in
  `docs/ue5-actor-replication-wire-format.md` §16? pkt#22 shows
  `AuthServerIDReplicated` twice — phase boundary? Our current
  `ActorBuilder` hits byte-identity WITHOUT explicit phase handling,
  so the flat model works for this actor. Revisit for other actors.

- FastArraySerializer (for `MarkedTargets` array in AAoCPlayerController,
  and inventory in M3+) — still not RE'd. Low priority until M3.

---

*This document is alive. Update it as milestones complete and new
findings land.*
