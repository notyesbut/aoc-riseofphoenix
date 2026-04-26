# Master Plan — From Replay to Multiplayer World

**Version 1.0 — 2026-04-21**
**Status:** Canonical roadmap. All future work is judged against this plan.

---

## 0. Executive Summary

### The Vision
Transform the current **single-player replay emulator** into a **live multiplayer server** where N players can click Play on their launcher, authenticate, spawn into the shared world, see each other, move, fight, and interact. **No replay dependency on the hot path.**

### Why this plan exists
Prior sessions made tactical progress (name patching, character persistence, property walker port, RE of the client binary) but weren't anchored to a shared architecture. We've been shipping small wins that sometimes conflict (archetype patch broke HUD; variable-length broke loading). This plan establishes the **canonical sequence** so every future session serves the same target.

### North Star
> When a player clicks Play, they connect to our server. Our server **generates** their bunches (not replays them), assigns unique NetGUIDs, spawns their actor in a shared world state, and broadcasts their presence to other connected players. A second player joining sees the first. No replay is streamed. The world state is server-authoritative.

### Success = minimum viable multiplayer
- Two characters on one map
- Each walks around independently
- Each sees the other's movement
- Chat works (basic text)
- Clean disconnect doesn't orphan state

Everything else (combat, inventory, quests, nodes) is additive after this MVP.

---

## 1. Current State (Evidence-Based)

### What we have that works

| Component | Lines of code | Status |
|---|---|---|
| AuthService (gRPC) | `services/auth/auth_service.h` (464) | ✅ Works — client authenticates |
| LauncherService (gRPC) | `services/launcher/launcher_service.h` (222) | ✅ Returns game server IP/port |
| XClientService (gRPC) | `services/xclient/xclient_service.h` (1,505) | ✅ Character create/list/select, with JSON persistence |
| TetherService | `services/tether/tether_service.h` (902) | ✅ Pre-game auth/token flow |
| UDP game server | `net/game_server.h` (4,492) | ✅ Handshake + NMT + replay |
| Replay embedded data | `protocol/bootstrap/bootstrap_data.h` (2000 packets) | ✅ Plays back to client |
| BootstrapSequence | `protocol/bootstrap/bootstrap_sequence.cpp` | ✅ Orchestrates replay+synthesis |
| PlayerController builder | `protocol/actors/player_controller.cpp` | ⚠️ 96% splice, 4% generated — works but not real |
| NetGuidAllocator | `protocol/net_guid_allocator.h` (150) | ✅ Exists, unused (allocated but not consumed) |
| Phase1 bunch parser | `protocol/tools/phase1_parser.py` (1,449) | ✅ Ported, runs on our capture |
| Phase3 property walker | `protocol/tools/phase3_walker.py` (1,316) | ✅ Parses 58k payloads, 236 channels |
| Character persistence | `services/xclient/xclient_service.h` | ✅ JSON file, survives restart |
| Name patch (10-char fixed) | `game_server.h` | ✅ "RandomChar" → live name on HUD and floating nametag |

### What we know from RE of the client binary

See `docs/re-aoc-client.md` for full details.

**Property names confirmed (via string scan of AOCClient-Win64-Shipping.exe):**
- `CharacterName` (FString, `OnRep_CharacterName` callback)
- `PrimaryArchetype` (int; ≠ ArchetypeId as we wrongly assumed)
- `CharacterRace` (int, `HandleRaceChanged` callback)
- `CharacterGender` (int)
- `CharacterAlignment`, `CharacterLevel`, `CharacterGuildName`, `CharacterCitizenNodeId`

**All live on `CharacterInformationComponent`** — a subobject of the Pawn. NOT on the PlayerController, NOT in CustomDelta.

**Critical implication:** the RepLayout handle-stream walker we already ship can decode these. We were solving the wrong problem (CustomDelta RE) when the solution is a targeted scan of character initial-spawn bunches.

### What's broken / limited

| Issue | Severity | Impact |
|---|---|---|
| Joeva town buildings don't visually render | Medium | Cosmetic — node territory + civic systems work |
| Variable-length names disabled (`kEnableVariableLength=false`) | Low | Names stuck at 10 chars space-padded |
| Archetype patch reverted (broke HUD) | Closed | No longer active |
| Only ONE player can meaningfully connect | **Blocks multiplayer** | Replay-based design |
| Duplicate bootstrap files (`src/data/` vs `src/protocol/bootstrap/`) | Medium | 500-packet stale + 2000-packet current both active |
| `write_sip` implemented 3× | Low | Maintenance hazard |
| Orphan actor metadata headers | Low | 5 unused .h in `protocol/actors/` |
| `replay_data_` is shared across clients | **HIGH for multiplayer** | Patches race when 2 clients simultaneously connect |

---

## 2. Target Architecture

### Request flow — click Play to multiplayer world

```
┌─────────────┐      gRPC        ┌──────────────┐
│   Client    │ ───────────────► │ Auth Server  │  ← authenticate
│  Launcher   │                  │  (we have)   │
└──────┬──────┘ ◄─ access_token  └──────────────┘
       │
       │          gRPC
       ├──────────────────────►  LauncherService  ← get game IP/port
       │                           (we have)
       │
       │          UDP             ┌──────────────┐
       ▼                          │              │
┌─────────────┐                   │              │
│   Client    │ ─── Handshake ──► │ Game Server  │  ◄──── Shared world state
│  (AoC exe)  │                   │              │
│             │ ◄── Bunches ───── │              │
└─────────────┘                   └──┬───────┬───┘
       ▲                             │       │
       │                             │       │
       │                             ▼       ▼
       │                   ┌──────────────────────┐
       │                   │   World Simulation   │
       │                   │  ┌─────────────────┐ │
       │                   │  │ Actor registry  │ │
       │                   │  │ NetGUID alloc   │ │
       │                   │  │ Client list     │ │
       │                   │  │ Per-player PC   │ │
       │                   │  │ Per-player Pawn │ │
       │                   │  │ Per-player PS   │ │
       │                   │  └─────────────────┘ │
       │                   └──────────────────────┘
       │
       │ (other player connects)
       ▼
┌─────────────┐
│  Client B   │
└─────────────┘
```

### Architectural principles

1. **Server-authoritative.** The server owns the canonical world state. Clients see what the server sends; client input is validated before being applied.
2. **Per-player isolation.** Each connected player has their own `ClientSession` with their own PC, Pawn, PlayerState, and per-player NetGUID block. No shared-mutable state across clients.
3. **Broadcast model for visibility.** When player A moves, server computes which other players need to see the update, and multicasts the property delta to each.
4. **Static vs dynamic NetGUIDs.** Shared assets (class BPs, level, plugins) use captured static NetGUIDs. Dynamic actors (players, spawned NPCs) use server-allocated NetGUIDs from `NetGuidAllocator`.
5. **Builders, not splicers.** Actor bunches are generated from code, parameterized by `CharacterProfile`. Only CustomDelta payloads we don't yet understand are spliced from captured data (this will shrink over time).
6. **Replay as a fallback fixture.** The replay stays available as a behavior reference and for debugging, but the MULTIPLAYER hot path doesn't stream it.

### Component ownership (what lives where)

```
src/
├── net/                          ← UDP transport, handshake, packet framing
│   ├── game_server.h             ← currently monolithic, will split
│   └── (future: client_session.h, actor_registry.h, broadcast_manager.h)
│
├── services/                     ← gRPC services (already clean)
│
├── protocol/                     ← UE5 protocol implementation
│   ├── bootstrap/                ← Replay data as fixtures
│   ├── tools/                    ← Python analysis scripts
│   ├── actors/                   ← Actor builders (one .h/.cpp per type)
│   │   ├── player_controller.{h,cpp}
│   │   ├── character_pawn.{h,cpp}          ← TO BUILD
│   │   ├── player_state.{h,cpp}            ← TO BUILD
│   │   └── components/                     ← TO BUILD
│   │       ├── character_information.{h,cpp}
│   │       ├── combat_info.{h,cpp}
│   │       ├── alignment.{h,cpp}
│   │       ├── ability_component.{h,cpp}
│   │       └── stats_component.{h,cpp}
│   ├── bunch_builder.h                     ← existing
│   ├── character_profile.h                 ← existing, needs extension
│   ├── net_guid_allocator.h                ← existing
│   └── (future: world_state.h, actor_spawner.h, property_emitter.h)
```

---

## 3. Phased Implementation Plan

Each phase is a coherent unit of work with a **testable exit criterion**. No phase is considered done until its exit criterion passes.

### Phase 0 — Foundation Cleanup (1 session, low risk)

**Goal:** remove audit-identified friction before building new features.

| Task | Files | Evidence |
|---|---|---|
| 0.1 — Rename `src/data/bootstrap_data.h` → `src/data/handshake_packets.h`; rename namespace `bootstrap` → `handshake_packets` | `src/data/bootstrap_data.h`, `src/net/game_server.h` (6 use sites at lines 2751-2985), `CMakeLists.txt` | [code-audit Finding 1] |
| 0.2 — Consolidate `write_sip` into `src/net/ue5_primitives.h`; delete duplicates in `game_server.h:198`, `bunch_builder.h:67`, remove from `ue5_replication.h:110` | 3 files | [code-audit Finding 2] |
| 0.3 — Remove orphan actor headers from CMake until they have real .cpp | `CMakeLists.txt` lines 112-118 | [code-audit Finding 3] |
| 0.4 — Delete the gated-off variable-length code block OR wrap in `#if 0` with explicit note | `game_server.h:672+` | [code-audit Finding 5] |

**Exit:** All build clean, `replay_inspect` still passes, game loads identically. Codebase has ~8,000 fewer lines and zero duplicates.

---

### Phase 1 — Decode the Real Property Stream (1-2 sessions)

**Goal:** Identify exact RepLayout handles for all identity fields on `CharacterInformationComponent`, plus `bIsGM` on PlayerController.

#### 1.1 — Targeted walker on initial-spawn bunches

Extend `phase3_walker.py` to:
- Isolate the FIRST bunch on each character channel (ch=78, 104, etc.)
- Decode RepLayout handle stream
- Emit `(handle, type_guess, sample_payload_hex)` for each handle

Expected output for ch=104 (bunch containing "RandomChar"):
```
Handle 1  (CharacterName):      118-bit FString "RandomChar"
Handle 2  (PrimaryArchetype):   16-bit u16 = 17748 (Cleric)
Handle 3  (CharacterRace):      8-bit  u8  = 2 (Kaelar)
Handle 4  (CharacterGender):    8-bit  u8  = 1 (Male)
Handle 5  (CharacterAlignment): ...
```

**Evidence citation:** From `docs/re-aoc-client.md` we know all 4 identity fields live on `CharacterInformationComponent` as standard RepLayout (not CustomDelta). The walker just needs to focus on the right content block.

#### 1.2 — Identify `bIsGM` handle on PlayerController (ch=3)

From RE: `bIsGM @ 0xb6beb68`. It's a single bit in PC's RepLayout.

Task: scan all RL-handle payloads on ch=3 for 1-bit entries. One of them is `bIsGM` (currently 0). Bit-flipping it to 1 in the captured bunch = GM menu unlock.

Lower-bound estimate: PC has 411 fields per the export mask (Phase 3.3 finding), maybe 20 are booleans. We need to find which 1-bit handle is bIsGM specifically. Approach: cross-reference with string proximity (`bIsGM` string is at a specific RVA, close to its UProperty definition).

#### 1.3 — Identify `NodeLevel` handle on the node actor

From RE: `SetNodeLevel` exists as a function, `NodeLevel` (50 hits) is a replicated int. The node actor channel hasn't been identified yet in our walker output — need to find which channel is `ANodeActor` and scan its RepLayout.

**Exit criterion:**
- Handle map for `CharacterInformationComponent` fully known (CharacterName, PrimaryArchetype, CharacterRace, CharacterGender, CharacterAlignment minimum)
- Handle for `bIsGM` on PlayerController identified and verified (value 0 in captured, flip to 1 in memory = GM menu appears)
- Handle for `NodeLevel` on node actor identified

---

### Phase 2 — Actor Builders From Scratch (2-3 sessions)

**Goal:** replace the ~96%-splice PC builder with a complete PC + Pawn + PlayerState builder trio that emits all bits from code, parameterized by `CharacterProfile`.

#### 2.1 — Extend `CharacterProfile`

`src/protocol/character_profile.h`:
```cpp
struct CharacterProfile {
    // Existing
    std::string name;
    uint64_t archetype_id;    // = PrimaryArchetype (map to wire enum)
    uint64_t race_id;
    uint64_t gender_id;

    // NEW — NetGUID slots for per-player actors
    uint64_t pawn_netguid          = 0;
    uint64_t player_state_netguid  = 0;
    uint64_t pc_netguid            = 0;
    uint64_t ability_component_ng  = 0;
    uint64_t stats_component_ng    = 0;
    uint64_t alignment_component_ng = 0;
    uint64_t combat_info_ng        = 0;
    uint64_t base_char_info_ng     = 0;
    uint64_t interact_info_ng      = 0;

    // NEW — Initial world state
    float spawn_x = 0.0f, spawn_y = 0.0f, spawn_z = 0.0f;
    float spawn_yaw = 0.0f;
    uint32_t starting_zone_id = 0;
    bool is_gm = false;          // for admin-mode testing

    // NEW — Additional identity
    uint32_t character_level = 1;
    uint32_t character_alignment = 0;
    std::string guild_name;
    uint64_t citizen_node_id = 0;
};
```

Wire these from `NetGuidAllocator::allocate_player_block()` at replay_loop start.

#### 2.2 — Pawn builder (`protocol/actors/character_pawn.cpp`)

Full bunch structure from scratch:
```
Bunch header (variable-length, per phase1_parser's parser)
    ChIndex = dynamic (pawn channel, server-allocated)
    bOpen=0 explicit, but first-bunch-on-channel = implicit open
    bReliable, partial flags
NetGUID exports for subobject path exports
SerializeNewActor:
    Actor NetGUID = profile.pawn_netguid
    Archetype NetGUID = static (captured value, same for all players)
    Level NetGUID = static
    Location (from profile.spawn_x/y/z)
    Rotation (compressed short from profile.spawn_yaw)
    Scale, Velocity
Content blocks for 6 components:
    AlignmentComponent      (netguid = profile.alignment_component_ng)
    CharacterSecondaryInfo  (netguid = profile.interact_info_ng)
    CharacterInformation    (netguid = profile.base_char_info_ng)
        RepLayout stream:
            Handle N: CharacterName FString = profile.name
            Handle M: PrimaryArchetype = profile.archetype_id
            Handle K: CharacterRace = profile.race_id
            Handle L: CharacterGender = profile.gender_id
            ... more ...
    CharacterCombatInfo     (netguid = profile.combat_info_ng)
    AbilityComponent        (netguid = profile.ability_component_ng)
    StatsComponent          (netguid = profile.stats_component_ng)
```

Validate by byte-identity: with default-profile values matching captured RandomChar, the builder should produce the same bytes as the captured Pawn bunch (just like Phase 3.7 did for PC).

#### 2.3 — PlayerState builder (`protocol/actors/player_state.cpp`)

From RE: `AAoCPlayerState`, lots of siege/node-related properties. Smaller than Pawn. Start with minimal set:
- Player name echo
- Score / level
- Ping
- Team / alignment

#### 2.4 — PC builder rewrite (`protocol/actors/player_controller.cpp`)

Currently 96% splice. Rewrite to emit from scratch, parameterized by `profile.pc_netguid` for the Actor NetGUID. Include `bIsGM` handle so `profile.is_gm = true` flips the admin bit.

**Exit criterion:**
- All three builders produce byte-identical output to captured replay when given default profile values
- With custom profile values, builder output produces working in-game spawn (no HUD break, no loading loop)
- `profile.is_gm = true` visibly unlocks GM commands in-game

---

### Phase 3 — Per-Client World State (1-2 sessions)

**Goal:** replace the shared `replay_data_` with per-client actor state, so simultaneous connections don't race.

#### 3.1 — `ClientSession` struct

New file `src/net/client_session.h`:
```cpp
struct ClientSession {
    // Identity
    std::string client_key;
    sockaddr_in addr;
    ClientState state;  // the existing handshake state

    // Assigned resources
    aoc::protocol::PlayerNetGuidBlock netguid_block;
    aoc::protocol::CharacterProfile profile;

    // Per-client generated bunches (replacing shared replay_data_)
    std::vector<ReplayPacketInfo> bunches;

    // Last-sent state for this client (so we don't double-send)
    uint32_t last_seq_sent = 0;
    std::chrono::steady_clock::time_point last_bunch_ts;
};
```

Move all the `patch_*` functions off `ReplayData` and onto `ClientSession` — operating on `session.bunches` instead of shared `replay_data_->packets`.

#### 3.2 — Per-client bunch generation

Replace the replay_loop's "stream all 2000 packets" with:
1. Build packet sequence in memory per-client using the actor builders (Phase 2 output)
2. Include: login response, level load, PC spawn, Pawn spawn, PlayerState spawn, initial state snapshots
3. Stream to client over UDP with proper pacing (reuse existing pacing logic)

#### 3.3 — World actor registry

New `src/net/actor_registry.h`:
```cpp
struct WorldActor {
    uint64_t netguid;
    actor_type_t type;  // PC, Pawn, PlayerState, NPC, etc.
    std::string owner_client_key;  // empty for server-owned (NPCs, world actors)
    // ... property state ...
};

class ActorRegistry {
    std::unordered_map<uint64_t, WorldActor> actors_;
    std::mutex mu_;
public:
    void spawn(WorldActor&&);
    void destroy(uint64_t netguid);
    std::vector<uint64_t> list_visible_to(const ClientSession&);
};
```

**Exit criterion:**
- Two simulated clients can complete login → PC/Pawn/PS spawn without racing
- `replay_data_` is no longer mutated per-client; each client has its own `bunches` vector
- Logout cleans up correctly (NetGUID block released, actor registry entries deleted)

---

### Phase 4 — Multi-Client Broadcast (2-3 sessions)

**Goal:** when player A does something visible (moves, chats, attacks), player B sees it.

#### 4.1 — Property update emitter

For each actor, server tracks property values. When a property changes:
1. Look up all clients who have this actor visible
2. For each client, emit a RepLayout property-update bunch on the actor's channel
3. Deliver via UDP

Data flow:
```
ClientSession A receives NMT_Move → parse → update A's Pawn Location
  ↓
For each ClientSession B != A where B has A's Pawn visible:
    Emit property update bunch (Handle=Location, new value)
    Add to B's outgoing queue
```

#### 4.2 — Visibility management

Start simple: **everyone sees everyone** (flat visibility). Later optimize to proximity-based.

#### 4.3 — Incoming client traffic handling

Currently the server mostly ignores client → server packets (except handshake). Need to parse:
- NMT_Move (position/rotation updates) → apply to actor, broadcast
- NMT_RPC (server function calls) → route to appropriate handler
- Client chat messages → broadcast

**Exit criterion:** Two players on two separate machines can log in, see each other, walk around with synchronized positions.

---

### Phase 5 — Game Simulation (open-ended, many sessions)

**Goal:** actual gameplay mechanics.

**Priorities (ranked by user impact and RE clarity):**
1. **Chat** — trivial to implement, high social value. Broadcast text on a chat channel.
2. **Basic combat** — given `CalculateDamage`, `HateMap`, `DamageDealt`, `DamageTaken` from RE, wire up a damage-apply flow. Start with PvP auto-attack only.
3. **Inventory operations** — `EquipItem`, `UnequipItem`, `UseItem`. Item data sourced from `CacheDB.dbc` (requires decoding that format — deferred unless we decode it).
4. **NPC spawning** — server spawns NPC actors using the same builder pattern (reuse Pawn builder with NPC profile).
5. **Nodes & civic** — `SetNodeLevel` lets us trigger node progression. `CitizenshipDues` already fires from captured replay.
6. **Mounts** — `SummonMount`, vehicle registry. Already mapped.
7. **Gathering / crafting** — `Anvil`, `Forge`, recipes. Specifics in RE doc.

Each of these is effectively its own mini-phase.

---

### Phase 6 — Production Hardening (ongoing)

- Rate limiting / DDoS protection (per-IP packet rate caps)
- Persistent world state (periodic saves to DB)
- Graceful restart / client reconnect
- Observability (metrics, structured logs)
- Anti-cheat basics (movement validation, cooldown enforcement server-side)
- Database schema for characters, inventory, nodes

---

## 4. Critical Path — Click Play to Multiplayer World

This is the MINIMUM sequence of events that must work for MVP multiplayer. Every step must be achievable with the plan above.

```
1. Player launches launcher.exe
2. Launcher auth:
     → POST /api/v1/auth/login → our AuthService → access_token
3. Launcher gets game info:
     → gRPC LauncherService.GetGameClientConnectionInfos → (ip, port)
4. Launcher spawns AOCClient-Win64-Shipping.exe with args:
     → -ip 127.0.0.1 -port 7777 -token <access_token> -username <name>
5. Client opens UDP socket, sends StatelessConnectHandshake
     → Our game_server receives, validates, responds with Challenge
6. Client sends Challenge response
     → Our server promotes ClientState to HANDSHAKE_COMPLETE
7. Client sends NMT_Hello (network version negotiation)
     → We echo back NMT_Welcome with server version
8. Client sends NMT_Login (URL, online ID, player name)
     → We parse, look up CharacterProfile by name via XClientService
     → Allocate NetGuidBlock for this client
     → Populate ClientSession with profile + block
9. Our server generates initial bunches using our actor builders:
     a. GameStateBase bunch (level, gamemode — static, shared)
     b. World subobject bunches (level refs, plugin refs — static)
     c. PlayerController spawn (dynamic NetGUID, replicates player)
     d. Pawn spawn (dynamic NetGUID, with profile.name/race/class/etc.)
     e. PlayerState spawn (dynamic NetGUID)
     f. Visibility bunches for OTHER players already in world
10. Stream bunches to client with pacing (reuse current adaptive pacing logic)
11. Client processes bunches, loads map, spawns actors, renders world
12. Client sends NMT_JoinSuccess or first movement packet
     → Server marks ClientSession as IN_WORLD
     → Server broadcasts this player's Pawn spawn to all other ClientSessions
13. Client sends movement deltas
     → Server validates (no teleporting faster than max speed, etc.)
     → Server broadcasts movement to other clients
14. Client disconnect:
     → Server emits destroy bunches to other clients
     → Release NetGUID block
     → Remove from ActorRegistry
     → Persist final character state
```

Steps 1-4 already work (our existing gRPC services handle them).
Steps 5-7 already work (existing handshake + NMT code).
**Step 8 is partially there** (CharacterProfile exists, persistence exists) — needs to trigger per-session allocation instead of the current replay trigger.
**Steps 9-10 are the crux** — currently we stream captured replay. Must replace with generated bunches. This is Phase 2 + Phase 3 work.
**Steps 11-14 are Phase 4+.**

---

## 5. Completed Fixes (from today's audit)

These are already queued or implemented. They stay in Phase 0's cleanup list:

| Fix | Source doc | Status |
|---|---|---|
| Variable-length name safety gate | code-audit Finding 5 | ✅ Gated off — doesn't ship broken |
| Archetype patch revert | earlier session | ✅ Commented out, documented in doc |
| 2000-packet bootstrap expansion | earlier session | ✅ Shipped, unlocked Citizenship Dues |
| NUL → space pad for names | earlier session | ✅ Shipped |
| Character persistence | earlier session | ✅ Shipped, JSON round-trip verified |
| NetGuidAllocator foundation | earlier session | ✅ Shipped, inactive (awaiting Phase 2 consumers) |
| Stale bootstrap duplication (data/bootstrap_data.h) | code-audit Finding 1 | ⬜ Planned Phase 0.1 |
| `write_sip` triplicate | code-audit Finding 2 | ⬜ Planned Phase 0.2 |
| Orphan actor headers | code-audit Finding 3 | ⬜ Planned Phase 0.3 |
| Dead variable-length code | code-audit Finding 5 | ⬜ Planned Phase 0.4 |
| Per-client race on `replay_data_` | code-audit Finding 9.multiplayer | ⬜ Planned Phase 3.1 |

---

## 6. Risk Register

### Highest-risk items (mitigate before they bite)

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| Builder produces wire output that desyncs client (HUD break pattern we saw with archetype patch) | High, based on prior incidents | High (game unplayable for tester) | **Mandatory byte-identity test for every builder change** before shipping. Python prototype first, C++ port second. |
| Multi-client broadcast has lock contention / throughput issues | Medium | Medium | Design review Phase 4. Use lock-free queue for per-client sends if needed. |
| CacheDB.dbc format never gets decoded, blocking things like item spawning | Medium | Medium (narrow) | Item spawn via captured-bytes splice works for MVP; full decode is optional. |
| UE5 protocol version drift when AoC updates their client | Low in short term, certain long term | High | Pin to current client version; re-RE when they patch. |
| Replay fixture file rots (captured RandomChar's data doesn't match new patch) | Medium | Low (we have tooling) | Regenerate from fresh captures via our proxy when needed. |
| We run out of NetGUIDs for very long sessions (16M max) | Near-zero | Low | Already noted in `net_guid_allocator.h` — add reuse pool in Phase 6 if needed. |
| A player joins while another is mid-spawn → sees partial state | Medium | Low (they'll resync) | Queue visibility updates; emit after target client reaches IN_WORLD. |

### Concerns rooted in what we DON'T know

- The exact **bunch framing for C2S packets** the client sends back to us (movement, RPC). Our current parser handles most but not all (`C>S-PARSE` warnings in logs for channels 5249, 6145 etc.).
- **How dialogue/NPC interaction** triggers activate. Phase 5.4 (NPC) is ahead of any RE on this.
- **How node progression persistence** interacts with player data. `NodeLevel` / `CitizenshipDues` work in replay but authoring the server side is new territory.

---

## 7. Testing Strategy

### Unit-level (builder correctness)
- Every actor builder has a **byte-identity test**: with default-profile values matching captured actor's properties, builder output == captured bunch bytes exactly.
- Python prototype before C++ port for any bit-level work. Python is easier to debug when it's wrong.

### Integration-level (protocol compliance)
- Launch real AoC client → our server → confirm:
  - Client reaches world-spawn state (visible character, renderable environment)
  - No client disconnect / loading-loop / error dialog
  - Character identity fields match profile (name, class icon, race look)

### Multi-client (Phase 3+)
- Two clients simultaneously → both reach world
- Move A → verify B sees A's movement
- Disconnect A → verify B sees A disappear (destroy bunch)
- Reconnect A → verify A can re-enter and see B

### Regression
- Run `replay_inspect` on current captured data → counts must stay stable (sanity that parsing infrastructure isn't drifting)

### Stress (Phase 6)
- Connect 10 synthetic clients via scripting
- Measure server CPU, memory, packet/sec throughput
- Target: 10 clients at 20Hz tick without packet loss

---

## 8. Session Cadence & Success Metrics

### Per-session success criteria

Every session must end with:
- Either a **new capability shipped** (code + test + docs update)
- Or a **documented negative result** (with specific evidence of why the approach doesn't work, so we don't retry it)

No ambiguous outcomes. "I tried some stuff" is not acceptable. "I tried X, here's the data that shows X won't work, proposing Y instead" is.

### Rolling metrics to track

| Metric | Current (2026-04-21) | Phase 3 target | Phase 5 target |
|---|---|---|---|
| Max simultaneous clients in world | 1 | 2 | 10 |
| % of PC bunch bits generated (not spliced) | ~4% | 100% | 100% |
| Byte-identity builder tests passing | 1 | 3 | 10+ |
| Known property handles (by name) | 0 | 5 (identity) | 50+ |
| Open HIGH-severity code-audit findings | 1 | 0 | 0 |
| Replay fixtures used in hot path | 1 (2000 pkt) | 0 | 0 |

---

## 9. What Gets Cut From Scope (Explicitly)

To avoid scope creep, these are NOT in the MVP multiplayer plan:

- Dungeon instancing
- Housing / freehold building
- Node progression (players growing a node to Metropolis)
- Caravan system
- Guilds beyond name display
- Mount riding (summon/dismount mechanics)
- Combat rotation (abilities, skill trees)
- Inventory item effects (equipping a weapon that actually changes stats)
- PvE loot drops
- Localization
- Voice chat

These are Phase 5+ or Phase 6+ work. Each adds months if pursued without the Phase 1-4 foundation.

---

## 10. Concrete "Tomorrow" Starting Point

When next session opens, the single highest-leverage task is:

### Do this first (Phase 0 cleanup — ~30 min, low risk)
1. Rename `src/data/bootstrap_data.h` → `src/data/handshake_packets.h` (and namespace rename)
2. Consolidate `write_sip` to one implementation
3. Remove orphan headers from CMake

This eliminates noise before real work begins. Pure refactor, no behavior change.

### Do this second (Phase 1.1 — the real win)
Write `src/protocol/tools/find_identity_handles.py`:
- Load our `replay_full.jsonl`
- Filter to bunches on ch=104 (we know "RandomChar" is there)
- Run phase3_walker's `decode_handle_stream` on content blocks
- Extract each handle's payload
- Interpret payloads: FString → printable text, u16 → int, u8 → int
- **Output: handle N contains "RandomChar" → that's CharacterName**

Then similar for the PrimaryArchetype value (scan for 17748), CharacterRace (scan for 2), etc.

**Success = a table like:**
```
CharacterInformationComponent RepLayout:
  Handle 1 → CharacterName (FString)
  Handle 2 → PrimaryArchetype (int)
  Handle 3 → CharacterRace (int)
  Handle 4 → CharacterGender (int)
  ...
```

This IS the master key. Once we have this table, Phase 2 builders write themselves.

---

## 11. Principles for the Road Ahead

- **Evidence over hypothesis.** Don't ship code based on guesses. If we can't cite why we think X is true, either gather data or leave it for another day.
- **Python prototype first.** Any bit-level wire-format code gets a Python proof before C++. We learned this the hard way with variable-length.
- **Byte-identity as gospel.** If a builder change can't produce byte-identical output when given known-captured values, it's not trustworthy.
- **One patch → one test → one commit.** No pile-on changes.
- **Docs get updated in the same session they're relevant to.** Stale docs are worse than no docs.
- **The replay is a fixture, not a product.** Don't design around "making the replay nicer." Design around replacing it.

---

## Appendix A — Key Files Reference

| File | Role | Last touched |
|---|---|---|
| `src/net/game_server.h` | UDP server, replay loop, patch functions | today (NetGuidAllocator wiring) |
| `src/protocol/bootstrap/bootstrap_sequence.cpp` | Fill ReplayData from embedded data | today |
| `src/protocol/actors/player_controller.cpp` | PC bunch builder (96% splice) | earlier session |
| `src/protocol/character_profile.h` | Profile struct | today |
| `src/protocol/net_guid_allocator.h` | NEW — per-player NetGUID blocks | today |
| `src/protocol/tools/phase1_parser.py` | UE5 bunch parser (ported) | today |
| `src/protocol/tools/phase3_walker.py` | RepLayout property walker (ported) | today |
| `src/services/xclient/xclient_service.h` | Character CRUD, persistence | earlier session |
| `docs/re-aoc-client.md` | RE findings (Parts 1 + 2) | today |
| `docs/code-audit-2026-04-21.md` | Code quality audit | today |
| `docs/session-save-2026-04-21.md` | Per-session save/resume doc | today |
| `docs/master-plan-multiplayer.md` | **THIS FILE** | today |
| `dist/Release/re_scan_full.txt` | 366-keyword RE scan report | today |
| `dist/Release/re_scan_deep.txt` | 214-keyword targeted RE scan | today |
| `dist/Release/re_admin_regions.txt` | Admin/GM region dumps | today |
| `dist/Release/replay_data.bin` | Captured session (29,010 packets) | unchanged |

## Appendix B — All RE Tools Produced (All in `dist/Release/`)

- `re_scan_exe.py`, `re_scan_full.py`, `re_scan_deep.py` — exe keyword scanners
- `re_dump_region.py`, `re_dump_admin.py` — region-dump tools
- `re_extract_symbols.py` — IDA .nam format exploration
- `walk_pc_bunch.py`, `find_actor_opens.py`, `identify_channels.py` — C++ codebase wire-format analyzers
- `replay_to_jsonl.py` — format converter
- `varlen_name_prototype.py` — Python prototype of variable-length FString rewrite
- `verify_archetype_patch.py`, `verify_pawn_patch.py` — dry-run validators
- `decode_pc_precise.py`, `decode_pc_properties.py`, `decode_pawn.py` — targeted decoders
- Plus the phase1/3 ports: `src/protocol/tools/phase1_parser.py`, `phase3_walker.py`

---

## Appendix C — Glossary

- **Bunch:** UE5's unit of actor state replication. A bunch contains a header + payload (property deltas or full state).
- **CustomDelta:** UE5 mechanism where an actor overrides `NetDeltaSerialize` to encode state with custom logic (bypassing the standard RepLayout).
- **NetGUID:** UE5's wire identifier for an actor/object. Stable (static) for shared assets, dynamic for server-allocated actors.
- **RepLayout:** UE5's standard property replication mechanism — each property has a "handle" (index), and the bunch contains `(handle, value)` pairs.
- **OnRep_Foo:** Client-side callback fired when property `Foo` is updated via replication.
- **UFunction / UProperty:** UE5 reflection metadata — functions and data fields exposed to the engine's scripting system.
- **UIntrepidNetDriver:** AoC's custom UE5 NetDriver subclass (the game's custom network stack).
- **Fixture data:** Captured bunch bytes used as reference — NOT as a live streaming source once builders are complete.

---

*End of master plan. Print, pin, or reference as the canonical source of truth for all multiplayer work going forward.*

---

# Plan Update — 2026-04-22 early morning RE follow-up

**New doc: `docs/re-deep-customdelta-db.md`** with 3 critical breakthroughs:

### 1. CustomDelta demystified
- AoC's FastArraySerializer is `FFastActorLocationArray` (used for position updates)
- Lifecycle hooks confirmed: `PostReplicatedAdd`, `PostReplicatedChange`, `PreReplicatedRemove`
- **Identity fields (CharacterName, PrimaryArchetype, CharacterRace, CharacterGender) DO NOT use CustomDelta** — confirmed standard RepLayout. Our existing walker can decode them.

### 2. Spatial visibility — `UFilteredActorTrackingRegistry`
- 6 named methods documented including `CalculateRelevantTrackersForActorLocation` and `GetLocationUpdatesForServer`
- **This IS the pattern to mirror in our Phase 4 broadcast manager.**
- Source-file path leaked: `C:\P4\rel\AOCUE5\Game\Plugins\GameSystems\Source\GameSystemsPlugin\Private\GameService\ActorTracking\ActorTrackingType.cpp`

### 3. CacheDB.dbc parsed — 571,767 strings extracted
- Custom "IDB" format (not SQLite, though SQLite IS embedded in the client separately)
- All 8 archetype descriptions + traits
- **247 status effects named** (Status_Burning, Status_Bleeding, Status_Stunned, ... full catalog)
- 925 weapon tier references
- 1,769 node/civic refs
- 30,526 BP script paths including the full AI condition/targeting library

### Confidence update (per-phase)
- Phase 1: Medium → **High** (RepLayout confirmed, not CustomDelta)
- Phase 4: Low → **High** (we have the exact pattern to mirror)
- Phase 5: Low-medium → **Medium-high** (all content definitions accessible)

### New action items added to Phase 6
- IDB format parser (8-12 hours) to decode CacheDB.dbc rows
- Extract IoStore pak files via UnrealPak/retoc for structured `UDataTable` assets
- Engage IDA .i64 database for exact struct layouts

See `docs/re-deep-customdelta-db.md` for full evidence.

---

# Plan Update #2 — 2026-04-22 RE review pass

**New doc: `docs/re-review-2026-04-22.md`** — gap-hunting pass that verified the first RE and added:

### CustomDelta re-verification (CONFIRMED first-pass was correct)
- **Only 1 `FFast*Array` type exists** in the binary (`FFastActorLocationArray`). No hidden FastArraySerializer variants we missed.
- **Zero per-class `*::NetSerialize` or `*::NetDeltaSerialize` overrides** in strings. AoC doesn't have custom NetSerialize code we'd need to reverse.
- **276 `OnRep_*` callbacks** catalogued — the complete replicated property list of the game. First 40 include: `OnRep_ActorLocations`, `OnRep_CharacterCustomization`, `OnRep_HateList`, `OnRep_InventoryContents`, `OnRep_EquippedItems`, `OnRep_HotbarSlots`, `OnRep_HealthData`, `OnRep_CombatSkills`, `OnRep_MountedPawn`.

### Major NEW finding: `IntrepidNetReplicationGraph`
- AoC uses UE5's **ReplicationGraph** system (not legacy per-actor relevancy)
- Full `IntrepidNet` plugin module mapped (17 .cpp/.h files)
- **Phase 4 architecture decision:** our `BroadcastManager` mirrors `UReplicationGraph` patterns
- Inter-server replication code present (`IntrepidNetInterServerReplicationDriver`, `InterServerPropertyTracker`, etc.) — AoC has world-sharding, but MVP ignores this

### `GameSystemsPlugin` module fully mapped
32 subsystems documented with exact source paths, including:
- `GameService/ActorTracking/ActorTrackingType.cpp` (where `FFastActorLocationArray` lives)
- `Combat/AoCAbilityComponent.cpp`, `AoCStatsComponent.cpp`, `AoCCombatInfo.cpp`
- `Inventory/ItemMovementSubsystem.cpp`, `ItemStorageComponent.cpp`
- `Node/NodeData.cpp`, `NodeLayoutReplicator.cpp`
- `AI/Controllers/AoCAIController.cpp`
- `Artisanship/CraftingStationBase.cpp`, `GatherableActor.cpp`, `WeaponSmith.cpp`

### Database re-inventory
- **146 GB of game data in 91 `.ucas` IoStore chunks** (`Content/Paks/`) — this is where the real content lives
- `Manifest_UFSFiles_Win64.txt` (22MB) lists every file inside the paks
- 31 `DT_*` + 12 `DataTable*` + 154 `DataAsset*` `.uasset` files for structured game data
- **Node level convention confirmed:** `N3_Village`, `N4_Town` folder naming; race-tagged assets (`HuKaelar/`, `DwDunir/`, `Hu_Aela/`)
- 91 `Livestream_*` (pre-built node building variants)
- **Extraction path:** use `retoc` or `FModel` on the `.utoc/.ucas` pairs to get structured `.uasset` files

### IDB format partial decode
- Header offset 0x28 points to string table at file offset 0x07b08380
- String format is `[u32 length][bytes]`
- Row table at 0x30+ is 16 bytes per entry (format partially understood)
- Full parser = 8-12 hour project, not MVP blocker

### Updated roadmap clarity
- Phase 4 now has specific UE5 classes to mirror (UReplicationGraph, FFastActorLocationArray)
- Phase 6 added: pak extraction via retoc/FModel — gives structured game data without parsing IDB
- **No changes to phase ordering or exit criteria.** The re-verification confirmed the existing plan is sound.
