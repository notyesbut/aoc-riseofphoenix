# Session Save — 2026-04-21

**Last session covered:** Phase M5.11 variable-length, Session 2 walker port, Session 3 multiplayer foundation, **plus evening RE session on the shipping client**.

---

## LATE-SESSION RE BREAKTHROUGH (2026-04-21 evening)

See `docs/re-aoc-client.md` for full details. **Three game-changing findings:**

1. **Property names identified:** `CharacterName`, `PrimaryArchetype` (not `ArchetypeId`!), `CharacterRace`, `CharacterGender`, `CharacterGuildName`, `CharacterCitizenNodeId`
2. **They're RepLayout, NOT CustomDelta.** `OnRep_CharacterName` and `HandleRaceChanged` prove these are standard UE5 replicated properties — our phase3_walker should decode them directly without CustomDelta reverse-engineering
3. **Target class: `CharacterInformationComponent`** — a subobject of the Pawn. All identity fields live there. Our Session 4 builder target should be this component specifically.

This invalidates the "CustomDelta is hard, we need differential analysis" concern from the earlier session doc. Class/race are actually **decodable with our existing walker** once we focus it on the right content block.

**PART 2 scan added:** 366-keyword comprehensive sweep. Found admin/GM system (`bIsGM`, `bIsDev`, ~50 ServerGM_* commands), full node system, combat, mounts, inventory, NPCs, gathering (anvils!), quests, social — all 15 major systems mapped. **Biggest surprise: `bIsGM` is a single flag we can patch to unlock the entire GM command menu in the client.** See `docs/re-aoc-client.md` Part 2 for the full catalog.

**Tomorrow's single highest-leverage task candidate:** find the `bIsGM` bit in the PlayerController RepLayout handle stream and flip it to 1 in our captured replay. If that works, we get admin commands visible in-game.

**PART 3 scan (deeper RE):** 214 more targeted C++ symbols scanned. Found:
- `SetNodeLevel` (2 hits) — explicit node-level setter function
- `NodeExperience` (10 hits), `NodeXP` (2) — node progression tracking
- `CalculateDamage` (7 hits), `HateMap` (12 hits) — combat internals
- `FCharacterCustomization` (20 hits) — the customization struct
- `MasterLooter` (10), `LootContainer` (12) — loot system
- Mount types: `FlyingMount`, `GroundMount`, `AquaticMount`
- `BeginPlay`, `SpawnActor` (20+ each) — UE5 actor lifecycle
- `AAoCGameState` (4) — game state actor
Full 513-line report: `dist/Release/re_scan_deep.txt`.

---

## CODEBASE AUDIT (2026-04-21)

See `docs/code-audit-2026-04-21.md` for evidence-based findings. TL;DR:

**1 HIGH severity:** two parallel bootstrap systems both active. `src/data/bootstrap_data.h` (500 packets, Feb 21) vs `src/protocol/bootstrap/bootstrap_data.h` (2000 packets, current). Old one used in game_server.h at 6 sites (lines 2751-2985) — a pre-replay "handshake-completion" phase that uses stale data. Not a crash bug, but a stale-data consistency problem.

**2 MEDIUM:** `write_sip` triplicated across `net/game_server.h:198`, `net/ue5_replication.h:110`, `protocol/bunch_builder.h:67`. Identical algorithm. Consolidate to one canonical impl.

**3 MEDIUM:** Orphan actor metadata headers in `src/protocol/actors/{actor_base,characters,npcs,game_state,interactables}.h` — compiled but never included by any .cpp.

**NO active bugs found.** All mutex patterns consistent, all size_t subtractions guarded, no leaks, no hardcoded secrets (the "deadbeef" tokens are intentional emulator placeholders). TODO/FIXME count is 3 across 148k LoC — unusually clean.

The reverted/gated bugs (archetype patch → HUD break, variable-length → loading loop) don't show in static analysis because those code paths are unreachable (one commented out, one behind a `constexpr bool` gate).

---

## Current working state (test this first tomorrow)

Run `dist/Release/launch_all_embedded.bat`. Expected:

1. Client connects, enters world. ZOI debug shows `Verra_RVR_Node_Joeva` — we're INSIDE Joeva's territory (registered in the game's node system)
2. **Citizenship Dues popup appears** (civic/node system active — this WAS NOT present at 400 packets)
3. **Joeva buildings/town are NOT visually rendered yet** — we're in the node's territory but the physical town (houses, decorations, NPCs that populate the visible town) isn't streamed in. Needs more than 2000 packets OR streaming-on-proximity, which isn't replayed.
4. Character renders with current name ("Hatemost" → shown as `Hatemost  ` with trailing spaces due to 10-char padding)
5. **NEW log line**: `[NetGuidAllocator] Allocated block for "Hatemost": base=0x1000000 (PC=16777216, Pawn=16777217, PS=16777218)`
6. On subsequent relaunches: `[GameServer] Reusing NetGUID block for "Hatemost" (base=0x1000000)`

If (1)-(2) or (4)-(6) break, we have a regression. (3) is expected — not a bug.

---

## What's in the build right now

### Shipped today
- **Variable-length name patch** (`patch_fstring_variable`) with safety gate `kEnableVariableLength=false` (OFF because it caused loading-loop)
- **10-char space-padded name fallback** (active path, proven working)
- **Bootstrap expanded to 2000 packets** (was 400) — unlocked Citizenship Dues popup + node/civic mechanics. **Joeva buildings themselves still DO NOT render** — either needs much larger window (5000+) or a true streaming system (they load based on player proximity, which the replay can't simulate)
- **Character persistence** (`data/characters.json`) — survives server restart
- **phase1_parser.py + phase3_walker.py** in `src/protocol/tools/` (3,667 LoC ported from old `aoc-server-emu` project)
- **NetGuidAllocator** class + GameServer integration (passive — allocates blocks but builders don't consume them yet)

### Reverted / gated off
- Variable-length name: `kEnableVariableLength = false` in `src/net/game_server.h`
- Archetype patch (M5.7): commented out in `replay_loop` — broke HUD

### Files modified
| File | Change |
|---|---|
| `src/net/game_server.h` | Variable-length patch + safety gate + NetGuidAllocator integration |
| `src/services/xclient/xclient_service.h` | Character persistence load/save + archetype provider |
| `src/main.cpp` | Archetype provider wiring |
| `src/protocol/net_guid_allocator.h` | NEW — per-player GUID block allocator |
| `src/protocol/tools/phase1_parser.py` | NEW — UE5 bunch parser (from aoc-server-emu) |
| `src/protocol/tools/phase3_walker.py` | NEW — RepLayout property walker |
| `src/protocol/tools/replay_to_jsonl.py` | NEW — format converter |
| `src/protocol/tools/identify_channels.py` | NEW — channel → actor identifier |
| `src/protocol/tools/walk_pkt22.py` | NEW — PC bunch decoder |
| `src/protocol/tools/dump_handle14.py` | NEW — handle-specific property inspector |
| `src/protocol/tools/find_actor_opens.py` | NEW — actor spawn scanner |
| `src/protocol/bootstrap/bootstrap_data.h` | Regenerated with 2000 packets (8.1MB) |
| `CMakeLists.txt` | Added net_guid_allocator.h |
| `dist/Release/launch_all_*.bat`, `config/paths.json` | Game path moved to `C:\Ashes of Creation\Game\` |

---

## Channel → Actor map (discovered today by walker)

First 400 packets of capture contain 90+ distinct actor channels:

| Channel | Actor | Evidence |
|---|---|---|
| **ch=3** | **PlayerController** | `/Game/ThirdPersonCPP/Blueprints/AoCPlayerControllerBP` at +433b |
| ch=0 | AbilityComponent (root) | Component export |
| ch=28 | StatsComponent | Component export |
| ch=20 | StaticMeshActor | Level mesh |
| ch=32 | Quest (SQ_0100_BrokenBarricade) | Quest state |
| ch=43 | GatherableActor | Lootable resource |
| ch=55, 102 | Goblin NPC BPs | `Goblin_LanguidGoblin`, `Goblin_Gravehide` |
| ch=85 | Node_Villager_F | Quest NPC filler |
| **ch=78, 90, 94, 100, 101, 104, 108, 110, 111, 127** | **Character actors** (Pawns) | 6 shared components |

### Character actor component pattern
Every character (player or NPC) has these 6 replicated components as subobjects:
1. AlignmentComponent
2. InteractInfo
3. BaseCharacterInfo ← likely where name/class/race live
4. CombatInfo
5. AbilityComponent
6. StatsComponent

### Known property handles
- **RL handle 14** on character channels = 118-194 bit variable = **RepMovement** (position/velocity/rotation), NOT the name as initially hypothesized
- **RL handle 0** = empty, RepLayout terminator marker
- **CustomDelta** handles 349, 373, 293 etc = large per-frame update blobs
- Most character state is in **CustomDelta** (AoC's custom serialization), NOT in standard RepLayout

---

## Variable-length name bug — unfinished debugging

When `kEnableVariableLength=true`:
- Python prototype (`varlen_name_prototype.py`) passes 8 test cases including byte-identical identity
- C++ port applies patches cleanly (log confirms `pkt 104, 978B->976B, BDB 7180->7164`)
- **But game gets stuck in loading loop**

**Hypothesis (unverified):** The packet's end-of-content marker (`eff_bits` = last '1' bit in buffer) gets misplaced by the bit-shift + buffer resize. Phase1 parser relies on `find_content_end` to determine where packet data ends; if our shift leaves stray '1' bits past the intended end (or moves the real end '1' earlier), the client reads garbage past our bunch → BunchHeaderOverflow → disconnect → loading loop.

**Fix candidates to try:**
1. After shift + resize, explicitly find the NEW last '1' bit and ensure it's at the position our `bunch_bits` claims
2. Write a sentinel '1' at the exact bit position for `bunch_bits` (but build_replay_packet warns this breaks things)
3. Pad remainder of buffer with zeros up to byte boundary + one extra byte of zero

None of these is clearly right without more investigation. Variable-length is a quality-of-life feature; the real multiplayer path (Session 4+) makes it moot because fresh-generated bunches don't need patching.

---

## Strategic North Star

**Vision:** Live multiplayer server — multiple players log in, each with their own character, see each other, act in shared world. No replay.

**Current reality:** Single-player replay with name/nametag patches. Replay produces visible character, node systems work, but class/race come from captured bytes and we can't freely regenerate.

**Gap analysis:**
| Component | Status |
|---|---|
| Single player logs in | ✅ working |
| Character name visible | ✅ working (10-char limit) |
| World loads (base environment, ZOI tracking) | ✅ working |
| Civic systems (Citizenship Dues popup) | ✅ working (unlocked by 400→2000 expansion) |
| Joeva town buildings / NPCs visually render | ❌ NOT loading — needs more packets OR real streaming system |
| Class/race synthesis | ❌ buried in CustomDelta, needs decoder |
| Variable-length names | ❌ shipped but disabled (bug) |
| NetGUID allocator | ✅ infrastructure ready, unused |
| Multi-client broadcast | ❌ not started |
| Fresh actor spawn | ❌ currently splices captured bytes |
| Real property walker | ✅ ported from old project, works |

---

## Next session — concrete starting points

Pick ONE and commit:

### Option A — Extend CharacterProfile for multi-GUID (small, 30 min)
Add fields to `CharacterProfile`:
```cpp
uint32_t pawn_netguid_hint = 0;
uint32_t player_state_netguid_hint = 0;
uint32_t ability_component_netguid_hint = 0;
// ... etc
```
Wire them in `replay_loop` from `block.pawn`, `block.player_state`, etc.
This unblocks Option B by giving builders something to consume.

### Option B — Pawn actor builder (medium, 1-2 sessions)
Write `src/protocol/actors/pawn_actor.cpp`. Emits:
- Bunch header (from scratch using phase1 semantics)
- NetGUID exports (reuse Default__BP_Character path etc from capture)
- SerializeNewActor (using profile's pawn_netguid_hint)
- 6 content blocks for the 6 components (each block header from scratch, CustomDelta payloads spliced from capture)

This is the real "fresh spawn" work. Should produce byte-identical output when profile has default values. Then parameterize name/class/race as we decode them.

### Option C — Fix variable-length name (small, could go wrong)
Investigate eff_bits hypothesis. Add padding / sentinel logic. Re-enable `kEnableVariableLength`. Value: nice-to-have for names not exactly 10 chars. Risk: low value for the multiplayer goal.

### Option D — Multi-client architecture audit (planning, no code)
Map out how the server currently dispatches packets (single-threaded replay per-client). Design how broadcast would work (when client B joins, what packets does client A receive?). Produce an architecture doc before writing code.

**My recommendation: A then B.** A is cheap and unblocks the real work. B is the straight-line path to multiplayer.

---

## Landmines to remember

- **Don't re-enable `kEnableVariableLength`** until the eff_bits issue is understood — it causes loading loops
- **Don't regenerate bootstrap beyond ~10k packets** without checking exe size / link time budget
- **Don't value-scan for IDs** — today we learned (via broken HUD) that 17748 as a u16 at bits 5823/5967 was NOT archetype; it was bytes in an unrelated bunch
- **Don't trust our `decode_pc_precise.py`'s fixed-44-bit bunch header assumption** — phase1 uses variable-length header parsing which is more correct per UE5 source
- **AoC uses CustomDelta heavily** — 80%+ of character state is in AoC-custom serialization, not standard RepLayout. Decoding this requires reverse-engineering their `NetDeltaSerialize` overrides.

---

## Todo list as of session end

```
[x] Session 2: Walker ported, 58k payloads analyzed, channel map solid
[x] Session 3.1: NetGuidAllocator class shipped (16.7M base, 256 GUIDs/block, thread-safe)
[x] Session 3.2: Wired NetGuidAllocator into GameServer — allocates block on replay_loop start, passes block.player_controller via profile.actor_netguid_hint
[x] Session 3.3: Build + test — confirm NetGUID block allocated, replay still loads
[ ] Future Session 3.4: CharacterProfile extension — add pawn_netguid_hint, player_state_netguid_hint, component GUID hints for when fresh-spawn path activates
[ ] Future Session 4: Fresh actor spawn from scratch (no splice) — RepLayout-only components, CustomDelta payloads still spliced
[ ] Future Session 5: Multi-client broadcast — when player B joins, player A sees them
```

---

## Key file inventory (tomorrow's starting points)

**Docs (read these first):**
- `docs/phase-m5-property-decoding.md` — the M5 post-mortem + Session 2 discoveries
- `docs/session-save-2026-04-21.md` — THIS FILE

**Python analysis tools (all in `src/protocol/tools/` and `dist/Release/`):**
- `phase1_parser.py` — UE5 bunch parser (1,449 LoC, ported)
- `phase3_walker.py` — RepLayout walker (1,316 LoC, ported)
- `replay_to_jsonl.py` — converts `replay_data.bin` → `replay_full.jsonl`
- `identify_channels.py` — full channel → actor decoder
- `varlen_name_prototype.py` — Python proof of variable-length patch (works!)

**C++ actors:**
- `src/protocol/actors/player_controller.cpp` — current PC builder (3.4% generated, 96% spliced)
- `src/protocol/net_guid_allocator.h` — NEW today
- `src/protocol/character_profile.h` — needs `pawn_netguid_hint` etc. fields added

**C++ replay:**
- `src/net/game_server.h` — ReplayData + GameServer, now with NetGuidAllocator integration
- `src/protocol/bootstrap/bootstrap_sequence.cpp` — apply_synthesis hook
- `src/protocol/bootstrap/bootstrap_data.h` — 2000 embedded packets (8.1MB)

---

## Session stats

- Net lines of code added today: ~500 (mostly `net_guid_allocator.h`, integration)
- Lines of infrastructure ported from old project: 3,667 (phase1 + phase3)
- Python tools written today: 7
- C++ builds today: ~15 (all clean after initial debug)
- Regressions shipped: 1 (variable-length loading loop), reverted same session
- Features shipped and stable: 2000-packet bootstrap, NUL→space padding (then→variable-length disabled), NetGuidAllocator

Good day. Save, rest, pick up with Option A tomorrow.
