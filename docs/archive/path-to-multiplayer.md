# Path to Multiplayer — Roadmap (2026-04-21)

## Where we are TODAY

- ✅ Emulator boots client into a playable world via `launch_all_bootstrap_only.bat`
- ✅ 400-packet bootstrap subset is enough to enter the world (validated empirically)
- ✅ HUD character name can be patched (`patch_name.py`): `RandomChar` → any 10-char name
- ⚠️ Overhead floating name, class icon, race, appearance, spawn location still
  come from the captured player's data — cannot be chosen by the user
- ⚠️ No real server access (Intrepid Alpha servers are gated)

## What we have to work with

1. **One `replay_data.bin`** — our known-good bootstrap (~400 key packets)
2. **`PCAPRepo-main/` in `dist/Release/`** — **1,792 real AoC pcap captures**
   covering different classes, locations, and actions. These come from a
   community research repository. Examples:
   - `aoc_bard_loggin_in_20260204_042854.pcap` — Bard login (gRPC only though)
   - `aoc_ranger_respawn_home_point_j_20260205_230233.pcap` — Ranger gameplay
   - `aoc_tank_east_20260203_190549.pcap`, `aoc_tank_west.pcap` — Same class at
     different world locations (PERFECT for spawn-location diffs)
   - `aoc_bard_walking_running.pcap`, `aoc_rogue_walking_running.pcap`,
     `aoc_tank_walking_running.pcap` — same action, different classes
     (PERFECT for class-identifier diffs)

## The research technique — diff-based RE

Since we can't connect to Intrepid's live servers, we use **differential
reverse engineering**: compare two captures where only ONE variable differs,
and the changing bits are what encode that variable.

### Target fields to locate

| Field | Diff strategy | Captures to use |
|-------|---------------|-----------------|
| Class | `tank_walking` vs `rogue_walking` vs `bard_walking` | same action, diff class |
| Spawn location | `tank_east` vs `tank_west` vs `tank_south` | same char, diff zone |
| Character name | Any two captures with different player names | any pair with diff names |
| Race / gender | Captures with same class but diff race (need to scan library) | TBD |
| Level | Pcaps mentioning level progression | TBD |

## Roadmap

### Phase A — Diff-based patching (1-2 weeks)

Use PCAPRepo captures to incrementally locate every per-player field, then
patch it in our bootstrap `replay_data.bin`.

**Tools needed:**
- [ ] `pcap_to_replay.py` — convert a pcap's UDP bunches into our
      `replay_data.bin` format (or a subset of packets)
- [ ] `bit_diff.py` — align two bunches and show the differing bits
- [ ] `patch_fields.py` — extend `patch_name.py` with more fields
      (class, location, race, ...)

**Deliverable:** A `player_profile.json` that maps user choices to patched
replay data. Different players can have different (name, class, location).

### Phase B — Multi-replay library (2-4 weeks)

Capture a *set* of replays (or convert pcaps into replays) covering every
(class, location, race) combination. Server picks the right replay for the
player's profile at login time.

**Tools needed:**
- [ ] Fully working pcap→replay converter
- [ ] Replay library index: `index.json` mapping profile → replay filename

**Deliverable:** Emulator supports any character creation — the player sees
their chosen class/location/appearance.

### Phase C — Synthetic player actor (months)

This is the **true multiplayer unlock**. Instead of replaying a captured
player, we **synthesize** the PlayerController/PlayerState/Character actors
from server-side game state.

**What we need to decode:**
- `SerializeNewActor` format: ActorGUID, ArchetypeGUID, Location (FVector),
  Rotation (FRotator), Scale (FVector), Velocity (FVector)
- Key replicated properties on each of those three actors:
  - PlayerController: bHasSpawnedPlayer, ControllerRole
  - PlayerState: PlayerName (FString), Team, Score, PlayerID
  - Character: Location, Rotation, Mesh, Morphs, Equipment visual state
- AoC-specific field layout for each class

**Tools needed:**
- [ ] Decoded `sc_bunch_parser.h` with property-level decode
- [ ] `PlayerActorEmitter` class — takes a `PlayerProfile` struct and emits
      the full PC/PS/Character bunches for that player
- [ ] Multi-player broadcasting loop: when P1 moves, emit an ActorUpdate
      on P2's connection for P1's Character, and vice versa

**Deliverable:** Two or more real players connect to the emulator, each
see each other in the world, can watch each other move.

### Phase D — Full server (year+)

Game state simulation. Server owns positions, HP, inventory, AI, quests.
Replay becomes optional reference. This is "real" MMO server territory.

## Next session's concrete next step

**Recommended: start Phase A by building the `bit_diff.py` tool.**

1. Take two captures that only differ in one variable:
   - `aoc_tank_east_20260203_190549.pcap`
   - `aoc_tank_west_20260203_190628.pcap`
2. Extract the UDP S>C bunches from each
3. Align them and find bit positions that differ
4. Those are the spawn-location encoding

Second step: same with class captures to find class encoding.

## Files and tools saved

- `dist/Release/replay_data.bin.orig` — original unpatched replay
- `dist/Release/replay_data.bin` — currently patched with HATEMOSTTT
- `dist/Release/patch_name.py` — same-length name patcher
- `dist/Release/extract_bunch.py` — raw bit extractor
- `dist/Release/reassemble_chain.py` — partial-bunch reassembler
- `dist/Release/decode_actor_open.py` — decoder with format hypotheses
- `dist/Release/launch_all_bootstrap_only.bat` — 400-packet bootstrap launcher
- `dist/Release/PCAPRepo-main/` — the 1792-pcap research library

## Summary for the user

**"Can we build without replay?"**
Yes — but in stages. We're at Stage A right now. Stage C (real multiplayer) needs
weeks-to-months of reverse engineering the actor-spawn format. Stage D (full MMO
server) is a year+ project.

**"How do we get per-player data working?"**
Phase A: diff-based RE using PCAPRepo captures. We find where each field
(class, location, etc.) lives in the wire format, then patch each one.

**"Do we need new captures from Intrepid?"**
No. PCAPRepo-main gives us all the RE material we need.
