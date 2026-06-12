# AoC-RiseOfPhoenix — Project Overview

> Consolidated reference. Read this first. For full setup instructions see [README.md](../README.md). For session-by-session journey notes see `docs/archive/`.

---

## 1. What this project is

`AoC-RiseOfPhoenix` is an educational reverse-engineering project targeting the networking layer of *Ashes of Creation* — Intrepid Studios' UE5-based MMO. It impersonates the Intrepid services the retail client expects (auth, launcher, game, tether) on loopback so the unmodified shipping client can talk to a local stack. The stable baseline is still replay-driven; the active development frontier is replacing replay with **live, server-synthesised bunches** built from authoritative state.

---

## 2. Current state

Current public snapshot: [`re-plan/PUBLIC-PROGRESS-2026-06-12.md`](re-plan/PUBLIC-PROGRESS-2026-06-12.md).

### What works today (VERIFIED-FROM-CODE)

- **Replay-driven smoke path.** `scripts\launch_all.bat` remains the regression baseline for the captured S>C flow.
- **Four-process loopback stack:** auth/launcher, `aoc_server` (UDP:443), `tether_server` (UDP:19021), and launcher/client helpers.
- **20 registered tests pass through `scripts\build.ps1 -Test`.** Coverage includes bit-level packet parsing, replayout codecs, packet fixtures, ActorBuilder, dispatcher/session state, LiveWorld, NMT packet builders, PackageMap export, and PC/Pawn spawn diff harnesses.
- **Native NMT replies** (`NMT_Challenge`, `NMT_Welcome`, `NMT_NetGUIDAssign`) emit byte-identical to capture.
- **Native ActorOpen/SNA path has advanced.** The current native path emits package-map exports, `SerializeNewActor`, even-stride dynamic NetGUIDs, and a minimal valid actor-root content tail.
- **Structured SULV → CALV probe path.** The server parses client `ServerUpdateLevelVisibility` payloads, queues `ClientAckUpdateLevelVisibility`, and now reaches the client-side CALV RPC parameter reader.
- **Character persistence** (`data/characters.json`) survives restarts.
- **gRPC services** (auth/launcher/xclient/tether) — character create/list/select all work.

### What does NOT work today

| Gap | Impact | Notes |
|---|---|---|
| **Stable native world streaming** | Native mode is not yet a stable playable server | CALV enters the client's parameter reader but still ends in `Mismatch read`. |
| **Full CALV parameter serialization** | Current blocker | Need exact receiver-side bit-consumption for package name, request id, and boolean within bounded `NumPayloadBits`. |
| **Full ActorOpen property/subobject fidelity** | Native actors are still minimal | The minimal tail is useful for NetGUID registration; complete replicated actor state still needs the exact ClassNetCache/field layout. |
| **Live deltas / HUD values** | No complete live HP/MP/name pipeline | Property/RPC payloads remain probe-gated until the reader path is exact. |
| **Movement input handling** | Player can't actually walk | `ServerMove` RPC parsing not implemented. |
| **Live multiplayer** | Single-client only | Multi-client visibility and broadcast testing are later milestones. |

---

## 3. Architecture

### 3.1 Process topology — what the client sees

```
                       ┌─────────────────┐
                       │   AOC CLIENT    │
                       └────┬────┬───────┘
            HTTPS :8081      │    │  UDP :443
            ┌──────────┐    │    │   ┌──────────────┐
            │   auth   │ ◄──┘    └──►│  aoc_server  │    UDP :19021    ┌─────────────┐
            │  server  │              │  (replay +   │ ◄─loopback─────► │tether_server│
            └──────────┘              │  LiveWorld)  │                  └─────────────┘
                                      │   + xclient  │
                                      │   gRPC      │              ┌─────────────┐
                                      └──────┬───────┘              │  launcher   │
                                             │  (in-mem state)      │ (char select)│
                                             └──────────────────────┘
```

All four run on `127.0.0.1`. The client talks to each in the same order it would Intrepid's production deployment.

### 3.2 The 4-layer model inside `aoc_server`

```
1. SESSION / HANDSHAKE       StatelessConnect → NMT_Hello/Welcome/Join → ClientState
   (net/game_server.h, opcode_dispatcher.cpp, native_connect_sequencer.cpp)

2. OBJECT IDENTITY            FIntrepidNetworkGUID (128-bit) ↔ UObject mapping
   (protocol/emit/intrepid_netguid.h, package_map_exporter.cpp)
   - Stock UE5's 32-bit FNetworkGUID is REPLACED with a 16-byte struct
     (see §4.2). NetGUIDAllocator hands per-client blocks at login.

3. AUTHORITATIVE STATE        WorldState → CharacterState per-client (DESIGN ONLY today)
   (net/live_world.cpp, world/simulation/actor_registry.* — both stubs)
   - Target: position/HP/MP/dirty flags + 10Hz tick → broadcast deltas.

4. REPLICATION OUTPUT         BunchWriter → ActorBuilder → PacketBuilder → sendto
   (protocol/emit/bunch_writer.h, actor_builder.cpp, replayout/encoders/*)
```

### 3.3 Replay vs Synthesis (the two emission paths)

- **Replay (today's default)** — `GameServer::replay_loop` rewrites the outer header (seq/ack/our session's custom field), copies the bunch verbatim from `fixtures/replay_data.bin`, sends. One packet at a time, paced ~15 ms.
- **Synthesis (active development)** — `NativeConnectSequencer` + `WorldBootstrapEmitter` drive post-NMT traffic through `ActorBuilder`, per-class emitters, and probeable property/RPC payload builders. The current focus is deriving the exact CALV parameter layout from the retail client reader path.

---

## 4. Reverse-engineering catalog

### 4.1 Wire format summary (full reference: `docs/wire-format.md`)

```
[Outer packet bits — stock UE5 + AoC's 6-byte client-identity field]
[Bunches, contiguously bit-packed]
[Termination: 1 bit set, then zero pad to byte boundary]

Each Bunch:
  bControl, bControlOpen, bClose, bIsReplicationPaused, bReliable
  ChIndex (SerializeIntPacked, 8-40 bits)
  bHasPackageMapExports, bHasMustBeMappedGUIDs, bPartial
  ChSequence (10 bits if ch=0, 12 bits if ch>0)
  [bPartialInitial, bPartialFinal, optional CustomExportsFinal]
  [ChName block, when present]
  BunchDataBits (13 bits) ← payload size
  Payload (BDB bits)
```

Confidence: **VERIFIED-FROM-CODE** (captured fixture round-trips plus the current 20-test registered suite).

#### Critical AoC deviations from stock UE5

| Field | Stock UE5 | AoC |
|---|---|---|
| `FNetworkGUID` | 32-bit `SerializeIntPacked64` | **128-bit `FIntrepidNetworkGUID`** (4× uint32 LSB-first) |
| Partial-bunch flags | 2 bits (Initial, Final) | **3 bits** (adds `CustomExportsFinal`) on ActorOpen |
| BDB position | varies | bit **176** for typical-sized packets (was wrongly assumed 183 in early code) |
| Field exports | `FNetFieldExport` records (variable) | **411-bit bitmask** (1 bit per pre-registered field — class-knowledge required) |
| Property stream framing | per-stock RepLayout | `[uint32 cmd_index][body]*[0xDEADBEEF]` per phase, see §4.4 |

### 4.2 `FIntrepidNetworkGUID` — AoC's NetGUID replacement

```cpp
struct FIntrepidNetworkGUID {     // 16 bytes, written as 4 contiguous uint32s LSB-first
    uint64_t ObjectId;            // +0..7  primary handle
    uint32_t ServerId;            // +8..11 originating backend server
    uint32_t Randomizer;          // +12..15 collision salt
};
```

Source: `sub_14141E960` (reader) + `sub_1450360E0` (writer); cross-verified by log string `"ObjectId: %llu | ServerId: %u | Randomizer: %u"` in `UIntrepidNetServerPackageMap::InternalLoadObject`.

### 4.3 RE'd functions (navigating IDA)

`AOCClient-Win64-Shipping.exe` (235 MB, MSVC shipping, image base `0x140000000`). All addresses VERIFIED-FROM-CODE via direct decompile.

| Address | Name | Role |
|---|---|---|
| `sub_14141E960` | `ReadFIntrepidNetworkGUID` | 128-bit NetGUID reader (4× uint32) |
| `sub_1450360E0` | `WriteFIntrepidNetworkGUID` | Recursive NetGUID writer with outer chain |
| `sub_1450318A0` | `FGuidCache::GetOrAssignNetGUID` | UObject → NetGUID resolver |
| `sub_1450347B0` | `InternalLoadObject` (Function B) | The 3173-byte beast where `FExportFlags` decoding lives |
| `sub_1450357C0` | **Function D** — per-property dispatcher | 4-branch flag-based routing |
| `sub_145035420` | **Function C / F-body** — TArray element serializer | uint16 Num + per-elem dispatch (RE'd 2026-04-23) |
| `sub_145037460` | Function E — struct sub-field walker | Recursive inner-fields, skip flags |
| `sub_14503E260` | Function F — array writer | TArray flag-detect + dispatch |
| `sub_14504F1A0` | **Function G** — `WriteActorChanges` | Top-level RepLayout iterator: walks phase bitmask, emits `[cmd_idx][body]*[0xDEADBEEF]` per phase |
| `sub_14504F7C0` | Function H — `SerializeObject` | Bidirectional |
| `sub_145057C30` | **Function J** — per-cmd entry | Writes 32-bit cmd_index atomically; runs diff-check, skips unchanged; rewinds if body empty |
| `sub_14502D230` | Diff-checker | 3-level hashtable → `FField::Identical()` comparison |
| `sub_145032980` | Shadow-hash (Bob Jenkins, golden-ratio mix) | FName-based 16-byte content hash → shadow-state slot |

Stripped-shipping wall: `InternalWriteObject`, `bHasPath`, `bNoLoad`, `RTTI for UIntrepidNetServerPackageMap` are all **absent as strings** — only source-path leak `IntrepidNetServerPackageMap.cpp @ 0xae2cac0` survives. IDA interactive is needed for any further RE on the stripped path.

### 4.4 RepLayout property stream — phase model (RE'd 2026-04-24)

`Function G` reads an 8-bit phase bitmask from `context[+0]` and iterates set bits lowest-first. Each phase selects a different property list on the actor's UClass:

| Phase bit | UClass offset | List | Meaning |
|---|---|---|---|
| `0x01` | `+0x130` (304) | `InitialRepProps` | "constant once" — sent at open |
| others | `+0x120` (288) | `LifetimeRepProps` | "change over time" — deltas |

Per-phase wire layout:
```
for each property (cmd_index = 0..N within this phase):
    [uint32 cmd_index]                  ← 32 bits LSB-first, bit-contiguous
    [body]                              ← Function J; default values rolled back to 0 bits
[0xDEADBEEF]                            ← phase terminator (4 bytes LE: DE AD BE EF)
```

This explains why pkt#22 contains `cmd_index=0` twice — it runs **both phases** (InitialRepProps then LifetimeRepProps), each starting at cmd_index 0, separated by the sentinel.

### 4.5 `FRepCmdType` and FProperty wire formats

| FProperty subclass | Body size | Notes |
|---|---|---|
| `FBoolProperty` | 1 bit | LSB of conceptual byte |
| `FByteProperty` | 8 bits | fixed |
| `FIntProperty` | 32 bits | LSB-first |
| `FInt64Property` | 64 bits | LSB-first |
| `FFloatProperty` | 32 bits | IEEE 754 |
| `FDoubleProperty` | 64 bits | IEEE 754 |
| `FNameProperty` | SIP-packed uint32 | indexed via PackageMap |
| `FObjectProperty` | SIP uint32 OR 128-bit `FIntrepidNetworkGUID` | depends on PackageMap resolution |
| `FStrProperty` | `[int32 len][bytes][NUL]` | ASCII (len > 0) or UCS-2 LE (len < 0) |
| `FStructProperty` w/ NetSerialize | per-struct | e.g. `FRepMovement`, `FVector_NetQuantize10`, `FRotator::SerializeCompressedShort` |
| `FStructProperty` w/o NetSerialize | concatenation of inner fields | via `sub_145037460` |
| `FArrayProperty` | `[uint16 Num][element bodies]` (bit-contiguous) | NetDelta path for `FFastArraySerializerItem` derivatives |

`FProperty` struct layout (offsets verified): `+0` vtable, `+8` FFieldClass*, `+24` Next, `+32` Name, `+48` ArrayDim, `+52` ElementSize, `+56` PropertyFlags (CPF_*), `+68` Offset_Internal.

`FPropertyParams` (64-byte descriptor in `.rdata`, RE'd directly via PE parser): `+0x00` NameUTF8*, `+0x08` RepNotifyFunc, `+0x10` PropertyFlags (CPF_Net=`0x20`, CPF_RepNotify=`0x100000000`, AoC-specific CPF_InterServer=`0x8000000000000000`), `+0x32` BitIndex/Offset, `+0x34` OffsetInClass, `+0x38` ExtraPtr.

### 4.6 Class metadata catalog (extracted from binary)

Confidence: **VERIFIED-FROM-CODE** (CPF flags read from `.rdata` `FPropertyParams` tables).

| Class | Replicated count | Status |
|---|---|---|
| `AActor` | 13 (was wrongly 15 — `bIsInterServerReplicated`/`ProxyNetUpdateInterval` use `CPF_InterServer`, not the standard stream) | Catalog: `replayout/catalog.cpp` |
| `AController` | +2 (`PlayerState`, `Pawn` — both `FObjectProperty`) | |
| `APlayerController` | +2 (`TargetViewRotation` FRotator, `SpawnLocation` FVector_NetQuantize10) | |
| `APlayerState` | 10 (Score, Ping, PlayerName, PlayerId, UniqueId, bIsABot, bIsInactive, bOnlySpectator, StartTime, plus AoC: CharacterArchetype, CharacterGuildName, CharacterCitizenNodeId, CharacterGuid, etc. — total ~20) | `re-aocplayerstate.md` |
| `APawn`/`ACharacter`/`PlayerPawn_C` | 10 root + 6 subobject components | `re-apawn-playerpawn-c.md` |
| `UAoCAbilityComponent` | (CustomDelta — needs FastArraySerializer RE) | Stub |
| `UAoCStatsComponent` | HealthData / ManaData / StaminaData (CustomDelta) + Float scalars (CurrentHealth, MaxHealth, etc.) | Stub |
| `AAoCPlayerController` | 19 properties (3 in AActor AoC additions: `AuthServerIDReplicated` FInt, `bIsInterServerReplicated` FBool, `ProxyNetUpdateInterval` FFloat) | Catalog: `aaoc_player_controller_catalog()` |

#### Identity-field location (the most-asked question)

Confirmed via string scan of the shipping binary + `OnRep_*` callbacks (276 catalogued):
- `CharacterName` (FString, OnRep_CharacterName), `PrimaryArchetype` (UInt32), `CharacterRace` (UInt32, HandleRaceChanged), `CharacterGender`, `CharacterAlignment`, `CharacterLevel`, `CharacterCustomization` (sparse `[float][FString name]` morph list, NOT the assumed 16-float array) — **all live on `CharacterInformationComponent`, a subobject of the Pawn** (NOT on PlayerController, NOT in CustomDelta — they go through standard RepLayout).
- `CharacterArchetype` is on `APlayerState` (replicated to all clients), separately.
- Class IDs: Bard=17747, Cleric=17748, Fighter=17749, Mage=17750, Ranger=17751, Rogue=17752, Summoner=17753, Tank=17754. The captured replay character is **a Mage** (per `CreateChar` log, JSON `"class":"Mage"`).
- Race IDs (partial): Kaelar=2, Dunir=7, Empyrean=8 (full set: 9 races).
- `CharacterName` wire location (EMPIRICAL): replay pkt#104 byte 207, format `[var_int cmd_index=0x6A][int32 LE length][ASCII][NUL]` — channel still TBD because pkt#104 is a partial-continuation and our parser can't resolve which channel it's on.

### 4.7 Bootstrap analysis — first 100 packets (~514K bunch bits, 66KB)

| Phase | Pkts | Purpose | Essential? |
|---|---|---|---|
| 1 — Post-NMT echoes | 0, 2 | AoC opcode 3 (unknown, 8-digit string `"50995344"`) + NMT_Welcome re-emit | Maybe + YES |
| 2 — Sentinel fillers | 1, 3-21 | bb=1 keepalives | NO (natural gap in native mode) |
| 3 — PC ActorOpen | 22-23 | Multi-fragment ch=3 ActorOpen (PC + HUD) | YES |
| 4 — Initial GUIDExports | 24-28 | ch=85/2 NetGUID class registrations + ch=30 ActorClose | Maybe |
| 5 — Big PC partial stream | 29-44 | ~75K bits of PC RepLayout tail + subobjects across 16 packets | YES |
| 6 — Other actors | 47-99 | ch=4+ NPC / environment spawns | Optional for character render |

**Historical empirical findings**: <30 pkts → loading-screen loop; 30-50 → loading screen never exits; ~100 → world loads, character visible, HUD frame rendered but values blank; ~150 → first stat updates arrive (pkts #100-115 carry HP/MP/Stamina + the cmd=0x6A Name update at pkt#104). Current native work no longer tries to solve this by blindly extending replay; it targets the specific client readers reached by native traffic.

The full ActorOpen catalog across 2000 captured packets shows **359 unique actor channels** = 359 distinct ActorOpen synthesisers needed to fully replace the replay (3 player actors + ~20-50 world singletons + ~300 NPCs/interactables in relevancy range).

---

## 5. How to build & run

See [README.md](../README.md) for prerequisites (VS 2022, CMake 3.22+, vcpkg, retail AoC client).

```powershell
# Build + test (20 registered tests, all green expected)
.\scripts\build.ps1 -Configure
.\scripts\build.ps1 -Test

# Stub the EOSSDK once; deploys to the game folder
.\scripts\build_eossdk_proxy.bat

# Launch the full stack
.\scripts\launch_all.bat                 # default replay mode
```

Key CLI flags on `aoc_server.exe`:
- `--use-embedded-bootstrap` — skip the file read; uses the compiled-in 2000-packet table
- `--enable-live-world` — spin up the LiveWorld pipeline alongside replay (observer mode)
- `--session-g-send` — actually `sendto()` natively-generated bytes (default OFF for safety)
- `--native` — gates the `NativeConnectSequencer` path (replay vs native)
- `--custom-name <str>` — character name in native mode (broken for length ≠ 10 — see §6)

Login with `test222 / test` or register a new account via the launcher.

---

## 6. Roadmap

### Current phase — Native world-entry stabilization

**Goal**: make the native path stable enough to keep the client in-world without depending on the captured replay loop.

**Status**: outer ActorOpen/content-tail and SULV/CALV routing progressed substantially. The client reaches `ReceivePropertiesForRPC` for `ClientAckUpdateLevelVisibility`; the remaining blocker is the exact CALV parameter payload layout.

Concrete next deliverable: derive the CALV leaf reader from the current retail client, replace probe-ranked payload variants with one proven layout, then restore richer ActorOpen property/subobject payloads behind tests.

### Next phase — Full native replicated actor state

**Goal**: replace minimal content-tail probes with complete property/subobject streams whose ClassNetCache and field counts are verified against the current retail client.

### Later phase — Multiplayer + database

- M2.0: Second client + per-client `ActorRegistry` view + `BroadcastManager` (mirror UE5's `IntrepidNetReplicationGraph` + AoC's `UFilteredActorTrackingRegistry` pattern — names known, source paths leaked).
- M2.1: Chat (`ServerSay`/`ClientMessage`).
- M3.0: NPCs (one Goblin first, then generalise).
- M4.0: SQLite persistence (characters, inventory, world state).
- M5.0: Anti-cheat + production hardening.

### Why Phase II (in-place replay mutation) is dead — see [phase-ii-postmortem.md](phase-ii-postmortem.md)

Mutating pkt#79 / pkt#104 to inject custom names worked at the codec level (40 unit tests green) but **broke the partial-bunch reassembly in the client** for any non-zero length delta. Fixing it requires owning every fragment in the chain (we don't) or an unknown invariant in AoC's reassembler. Phase III synthesis avoids the problem entirely.

---

## 7. Where to find things

### Documentation index

Start in this order:

| File | Why |
|---|---|
| **`PROJECT-OVERVIEW.md`** (this file) | Big picture |
| [`README.md`](../README.md) | Build / run / quickstart |
| [`architecture.md`](architecture.md) | 10000-ft component overview |
| [`wire-format.md`](wire-format.md) | Authoritative wire-format reference (decoder + encoder spec) |
| [`phase-ii-postmortem.md`](phase-ii-postmortem.md) | What didn't work and why (don't redo it) |
| [`phase-iii-roadmap.md`](phase-iii-roadmap.md) | Historical Phase III plan plus current update note |
| [`re-plan/PUBLIC-PROGRESS-2026-06-12.md`](re-plan/PUBLIC-PROGRESS-2026-06-12.md) | Current sanitized native progress snapshot |
| [`AUTHORITATIVE_SERVER_PLAN.md`](AUTHORITATIVE_SERVER_PLAN.md) | Full multi-milestone plan to multiplayer |

Deep-reference data (don't read end-to-end; grep when needed):
- `re-aoc-client.md` — String/symbol catalogue from the shipping binary (276 OnRep_*, 366 keyword scan, 32 GameSystemsPlugin subsystems, GM commands)
- `bootstrap-2000-catalog.md` + `.jsonl` — Per-packet inventory (2000 S>C packets, 5193 bunches, 359 unique actor channels)
- `re-apawn-playerpawn-c.md`, `re-aocplayerstate.md`, `re-aocgamestate.md`, `re-bp-aochud.md` — Per-class replicated property catalogs
- `pc-spawn-handle-catalog.md` — pkt#22 bit-by-bit decode
- `intrepid-packagemap-re.md` — IntrepidNetServerPackageMap function map (10 methods at known VAs)

### Code layout

```
src/
├── main.cpp / launcher_main.cpp / tether_server_main.cpp  ← entry points
├── eossdk_proxy.cpp                       ← stub EOSSDK DLL (replaces real)
├── net/
│   ├── game_server.h                      ← UDP server, replay loop (4500 lines, monolith)
│   ├── live_world.cpp                     ← LiveWorld observer + emitter pipeline
│   ├── native_connect_sequencer.cpp       ← Phase III state machine (M1.0 scaffold)
│   ├── opcode_dispatcher.cpp              ← NMT routing
│   └── (TODO: bootstrap_emitter, heartbeat_emitter, input_router, broadcast_manager)
├── protocol/
│   ├── wire/                              ← Bit primitives (ue5_primitives.h, packet_reader, bunch_types)
│   ├── bootstrap/                         ← Replay loading + pc_spawn_parser
│   │   └── bootstrap_data.h               ← AUTO-GENERATED 2000-packet table (114k lines)
│   ├── emit/
│   │   ├── actor_builder.cpp              ← build_spawn() — bunch framing emitter
│   │   ├── bunch_writer.h                 ← bit writer primitive (LSB-first)
│   │   ├── package_map_exporter.cpp       ← NetGUID export section
│   │   ├── intrepid_netguid.h             ← AoC 128-bit NetGUID helper
│   │   ├── replay_mutator.cpp             ← Phase II FString mutation (DORMANT — kept for reference)
│   │   └── replayout/
│   │       ├── catalog.cpp                ← Per-class FProperty catalogs (6 classes populated)
│   │       ├── encoder.cpp / decoder.cpp  ← Central dispatch
│   │       └── encoders/                  ← Per-FProperty-type codecs (FString, Bool, Int, Float, Object, Struct, ...)
│   └── tools/                             ← Python decoders + IDA scripts + captured fixtures (see fixtures/ section)
├── services/                              ← gRPC: auth/launcher/xclient/tether
├── world/simulation/                      ← ActorRegistry stub (LiveWorld scaffolding)
├── data/                                  ← Embedded handshake-completion packets
└── tools/                                 ← C++ test executables (test_*.cpp)

fixtures/
└── replay_data.bin                        ← 7.4 MB captured S>C stream (29010 packets, init_seq=14265)

proto/                                     ← protobuf / gRPC definitions
config/                                    ← runtime JSON
certs/                                     ← SSL for auth_server
scripts/build.ps1, launch_all.bat          ← build + run drivers
```

### Key fixtures

- `src/protocol/tools/captured_pc_spawn_reassembled.bin` — pkt#22 reassembled (608 B)
- `src/protocol/tools/captured_pkt_78.bin` — Pawn ActorOpen fixture (816 B)
- `src/protocol/tools/captured_pkt_79.bin`, `captured_pkt_80.bin` — raw fragments
- `src/protocol/tools/captured_pkt_104.bin` — Name property update bunch (978 B, contains `RandomChar`)

### Key Python tooling (in `src/protocol/tools/`)

`phase1_parser.py` (full bunch decomposition), `phase3_walker.py` (RepLayout property walker), `decode_pc_spawn.py`, `decode_property_stream_v5.py`, `extract_pkt_fixture.py`, `find_actor_opens.py`, `find_character_name_in_replay.py`, `inspect_bunch_header.py`, `scan_bootstrap_30.py`, `extract_bootstrap.py` (regenerates `bootstrap_data.h`).

---

*Last updated: 2026-06-12. For session-by-session notes documenting how each finding was reached, see `docs/archive/` and `docs/re-plan/`.*
