# Phase M5 — Property-Stream Decoding & Live Character Patching

**Status as of:** 2026-04-21
**Goal:** Make the captured bootstrap reflect the live player's identity
(name, class, race, gender) so the game shows the user's character instead
of "RandomChar (Cleric)".

---

## TL;DR — Current State

| Field | Status | Mechanism | Wire location |
|---|---|---|---|
| **HUD name (top-right)** | ✅ Working | `patch_character_name` (byte splice) | pkt idx 104 @ byte 207 |
| **Floating nametag** | ✅ Working | `patch_pawn_nametag` (bit splice) | pkt idx 79 @ bit 1385 |
| **Class / archetype** | ❌ DISABLED — patch broke HUD | `patch_archetype_id` (u16 splice) — left in place but not called | pkt idx 22 @ bits 5823 + 5967 were NOT archetype |
| **Race** | ⬜ Located (hypothesis) — not yet patched | candidate: pkt 22 @ bit 5839 (u16=4) | `patch_race_id` TODO |
| **Gender** | ⬜ Not located | | |
| **Class icon / visuals** | ⬜ Unknown — expected to follow archetype | | |

---

## Todo list (persisted)

1. ✅ **M5.4** — `patch_pawn_nametag` shipped and confirmed in-game (HUD + floating nametag both update)
2. ✅ **M5.6** — Scanned bootstrap; class/race are integer IDs, not strings. Have archetype mapping Bard=17747..Tank=17754 and race mapping Kaelar=2, Dunir=7, Empyrean=8
3. ❌ **M5.7 REVERTED** — `patch_archetype_id()` was wired up and called, but the test in-game showed the HUD/hotbars/map VANISHED and the nametag became "Player". The bits 5823/5967 we thought were archetype were actually something fundamental (likely a NetGUID reference for the HUD widget class or a RepLayout handle). Call site is commented out in `replay_loop`; method body still exists but unused. **DO NOT RE-ENABLE without a different theory.**
4. ⬜ **M5.7.1** — Diagnose what bits 5823/5967 actually encode. Value was 17748 = 0x4554 = ASCII "TE" — investigate whether this is part of a longer FString ("Text"? "TESlot"?) or whether the u16 match was pure coincidence from an unrelated property payload.
5. ⬜ **M5.7.2** — Re-scan for archetype with stricter criteria (e.g. require the value to NOT overlap a printable-ASCII pattern, and cross-reference with pkt 104 / Pawn bunches where the class might actually live).
6. ⬜ **M5.8** — Locate race_id on wire — race hunt is blocked on finding the real archetype location first, since race almost certainly lives adjacent to it.
7. ⬜ **M5.9** — `patch_race_id()` + wire through `CharacterProfile`
8. ⬜ **M5.10** (deferred) — Full `ReceiveProperties_r` walker for arbitrary property edits (the "real" Option C work)

---

## Mental model: where identity data lives on the wire

### The PlayerController bunch — pkt idx 22 (seq 14287, 784B, 6104-bit bunch)

Carries:
- `bHasRepLayoutExport=1` → 411-bit export mask (68 ones)
- SerializeNewActor: Actor/Archetype/Level NetGUIDs + Location/Rotation/Scale/Velocity
- 2,780 bits of property values (bits 522..3301 of bunch payload, i.e. raw bits 728..3507)
- **`archetype_id` u16 lives at raw bits 5823 and 5967** (two copies, 144 bits apart — probably PlayerState + PC replication)

### The Pawn ActorOpen bunches — pkt idx 79 and 104 (978B each, 7665-bit bunches)

Carry:
- `bHasRepLayoutExport=0` (no export mask — format differs from PC bunch)
- `bExports=1`, `bGuids=1` (inline NetGUID exports)
- The FString `"RandomChar"` (int32 length=11 + 10 ASCII + NUL) appears:
  - pkt 79 @ raw bit **1385** (bit-shifted +1, not byte-aligned) — floating nametag source
  - pkt 104 @ byte **207** (byte-aligned) — HUD name source
- BP reference to generic `/Game/ThirdPersonCPP/Blueprints/PlayerPawn` (not class-specific — the captured RandomChar used a placeholder Pawn)

### Key insight

**Name is a byte-visible FString. Class/race are integer enums buried inside RepLayout property payloads.** That's why the name-scanning shortcut worked immediately but class/race needed value-scanning (searching for known ID values at every bit offset).

---

## Known ID mappings (source of truth: `src/services/xclient/xclient_service.h`)

### Archetype (class) IDs

```
Bard     = 17747
Cleric   = 17748
Fighter  = 17749
Mage     = 17750
Ranger   = 17751
Rogue    = 17752
Summoner = 17753
Tank     = 17754
```

Base = 17747. Alphabetical order, consecutive integers, low-16-bit range.

### Race IDs (partial — more to discover)

```
Kaelar   = 2
Dunir    = 7
Empyrean = 8
```

RandomChar (captured) likely race_id = 4 based on the u16 value at bit 5839,
but **we don't yet know what race ID 4 is** in AoC's enum.

### Gender IDs

```
Male   = 1
Female = 2
```

---

## Code inventory

### C++ changes in this phase

**`src/net/game_server.h` (ReplayData struct)**
- `patch_character_name(name)` — pre-existing, pkt 104 byte 207
- `patch_pawn_nametag(name)` — **NEW M5.4**, pkt 79 bit 1385, bit-level splice
- `patch_archetype_id(id)` — **NEW M5.7**, pkt 22 bits 5823 & 5967, u16 splice

**`src/net/game_server.h` (GameServer class)**
- `set_character_name_provider(fn)` — pre-existing
- `set_character_archetype_provider(fn)` — **NEW M5.7**

**`src/net/game_server.h` (replay_loop)**
Profile construction sequence:
```cpp
aoc::protocol::CharacterProfile profile;
if (character_name_provider_)      profile.name         = character_name_provider_();
if (character_archetype_provider_) profile.archetype_id = character_archetype_provider_();

if (!profile.name.empty()) {
    replay_data_->patch_character_name(profile.name);
    replay_data_->patch_pawn_nametag(profile.name);
}
if (profile.archetype_id != 0) {
    replay_data_->patch_archetype_id(profile.archetype_id);
}
aoc::protocol::BootstrapSequence::apply_synthesis(*replay_data_, profile);
```

**`src/services/xclient/xclient_service.h`**
- `last_character_name()` — pre-existing
- `last_character_archetype_id()` — **NEW M5.7**, returns `characters_.back().archetype_id`

**`src/main.cpp`**
```cpp
game_server->set_character_name_provider([&xclient_service]() {
    return xclient_service.last_character_name();
});
game_server->set_character_archetype_provider([&xclient_service]() {  // NEW M5.7
    return xclient_service.last_character_archetype_id();
});
```

### Python tooling (`dist/Release/`)

All scripts live alongside `replay_data.bin`:

| Script | Purpose |
|---|---|
| `decode_pc_precise.py` | Phase 3.7 PC bunch structural decoder (pre-existing, library) |
| `decode_pc_properties.py` | M5.1 property walker + FString scanner for PC bunch |
| `find_player_name.py` | M5.2 scanned all 29k packets for "RandomChar" |
| `confirm_pawn_name.py` | Confirmed int32 len=11 @ bit 1353 + "RandomChar\0" @ bit 1385 |
| `decode_pawn.py` | M5.3 attempted full structural decode of pkt 79 |
| `verify_pawn_patch.py` | Python dry-run of `patch_pawn_nametag` (RandomChar → HATEMOSTTT) |
| `find_class_race.py` | M5.6 scanned bootstrap for all known race/class strings |
| `scan_paths.py` | M5.6 dumped all `/Game/` paths in bootstrap |
| `find_archetype_id.py` | M5.6b scanned PC + Pawn bunches for values 17747..17754 |
| `find_race_gender.py` | M5.6c dumped neighbor bytes around archetype hits |
| `find_race_in_pc.py` | Scanned for race IDs 1..10 within ±256 bits of archetype |
| `verify_archetype_patch.py` | Python dry-run of `patch_archetype_id` (Cleric → Bard) |

---

## Evidence log

### Name is NOT in the PlayerController bunch

Scan of the 2,780-bit PC property region returned zero hits for "RandomChar" in ASCII or UTF-16. Visible strings were all NetGUID export paths:

```
bit 1142 (region+414)  "Default__AoCPlayerControllerBP_C"  (len=33)
bit 2006 (region+1278) "/Game/Levels/Verra_World_Master/Verra_World_Master"
bit 2478 (region+1750) "Verra_World_Master"
bit 2694 (region+1966) "PersistentLevel"
```

These are subobject path references, not player-data strings.

### Name IS in two Pawn bunches

Full-corpus scan (all 29,010 captured packets):

```
pkt idx=79   seq=14344  978B  bb=7665  "RandomChar" @ bit 1385   ← ActorOpen #1 (floating)
pkt idx=104  seq=14369  978B  bb=7665  "RandomChar" @ bit 1656   ← ActorOpen #2 (HUD)
pkt idx=1557 seq=356    292B  bb=2179  "RandomChar" @ bit 2154   ← post-bootstrap update
pkt idx=1643 seq=442    292B  bb=2179  "RandomChar" @ bit 2154
pkt idx=1665 seq=464    360B  bb=2726  "RandomChar" @ bit 2197
pkt idx=7883 seq=6682   360B  bb=2726  "RandomChar" @ bit 2197
```

Only idx 79 & 104 are inside the 400-packet bootstrap window we replay.

### RandomChar's class is Cleric

Scan of PC bunch for u16 values in {17747..17754}:

```
pkt 22 (PC ActorOpen):
  bit 5823 (byte 727.7)  u16 = 17748 (Cleric)
  bit 5967 (byte 745.7)  u16 = 17748 (Cleric)
```

Scan of Pawn bunches (79 & 104): zero matches. Class is PC/PlayerState-scoped.

### RandomChar's race is… value 4 (mapping unknown)

Scan of PC bunch within ±256 bits of archetype hits for u16 in [1,10]:

```
bit 5838 (+15)  u16=8  shift+6   ← overlaps archetype upper byte; false positive
bit 5839 (+16)  u16=4  shift+7   ← byte immediately after archetype → strong race candidate
bit 5840 (+17)  u16=2  aligned   ← could be Kaelar at byte-aligned offset
```

**Best bet:** bit 5839, u16=4 is RandomChar's race_id. We don't have race 4 in our known mapping ({2,7,8}) but AoC has 9+ races. This will be validated when M5.8 patches it to a known value (e.g. 2 = Kaelar) and we observe the race change in-game.

---

## UE5 source references

All source paths are under `<HOME>\Documents\UnrealEngine-release\`.

### RepLayout send/receive

- `Engine/Source/Runtime/Engine/Private/RepLayout.cpp`
  - `FRepLayout::ReceiveProperties` @ line 3789 — non-BC path (live connections)
  - `FRepLayout::ReceiveProperties_BackwardsCompatible` @ line 3872 — replay/InternalAck path
  - `FRepLayout::ReceiveProperties_BackwardsCompatible_r` @ line 3924 — handle+NumBits framing
  - `WritePropertyHandle` @ line 1922 — SerializeIntPacked for handles
  - `ReadPropertyHandle` @ line 3588

### NetField exports (the "411-bit mask" we see in PC bunch)

- `Engine/Source/Runtime/Engine/Private/PackageMapClient.cpp`
  - `PatchHeaderCount` @ line 1491 — writes bHasRepLayoutExport bit
  - `ReceiveNetGUIDBunch` @ line 1537 — reads bHasRepLayoutExport → dispatches
  - `ReceiveNetFieldExportsCompat` @ line 1830 — parses the export group (replay only)

### Wire format core

- `Engine/Source/Runtime/Engine/Private/PackageMapClient.cpp:491` — `SerializeNewActor`
- `Engine/Source/Runtime/Core/Private/Math/UnrealMath.cpp:142` — `FRotator::SerializeCompressedShort`
- `Engine/Source/Runtime/Engine/Public/Net/NetSerialization.h:179` — `LegacyReadPackedVector<10, 24>`

---

## What's still missing for full identity synthesis

### Known-unknowns

1. **Race_id wire position** — hypothesis bit 5839, needs M5.8 patch to confirm
2. **Gender_id wire position** — not yet scanned
3. **RandomChar's actual race** (we see value 4, don't know which race that is)
4. **Full race ID table** (only 3 of ~9 known)
5. **Does class icon/visual actually track archetype_id?** — will know after M5.7b user test

### Fundamental limitations of the shortcut approach

- Every field we want to change requires: scan → find bit offset → write a patcher
- Breaks if the captured bunch format changes (schema shift, engine update)
- Can't change things with variable-length (e.g. a name longer than 10 chars)
- Can't change things that are NetGUID references (class-specific BPs, meshes)

### The "real" Option C (deferred as M5.10)

A full UE5 `ReceiveProperties_r` walker that understands the RepLayout
Cmds array would let us identify every property by name and type, not
just hunt for magic numbers. Not urgent while the shortcut is working.

---

## Session 2 recon results (added)

### Phase B — Character persistence SHIPPED
- `XClientServiceImpl::load_characters()` / `save_characters_locked()` in `xclient_service.h`
- Persists `std::vector<StoredCharacter>` to `data/characters.json` (relative to CWD = `dist/Release/`)
- Binary `create_info_raw` hex-encoded for JSON portability
- Called on constructor (load) + `on_create_char` + `on_delete_char` (save)

### NUL padding on name patches
- `patch_character_name` and `patch_pawn_nametag` now pad with `'\0'` instead of `'.'`
- Most UMG text renderers stop at first NUL — name displays clean

### PC bunch splice region structural map
Raw bits 728..3507 (2,780 bits of spliced region in pkt 22):

| Bit range | Size | Content |
|---|---|---|
| 826..1093 | 268 bits | Actor's own property stream (per-player) |
| 1094..1437 | 344 bits | Subobj: `Default__AoCPlayerControllerBP_C` path export |
| 1438..1753 | 316 bits | ??? likely another subobj block |
| 1958..2445 | 488 bits | Subobj: `/Game/Levels/Verra_World_Master/Verra_World_Master` |
| 2446..2645 | 200 bits | Subobj: `Verra_World_Master` |
| 2662..2853 | 192 bits | Subobj: `PersistentLevel` |
| 3243..3507 | 265 bits | Subobj: `/Script/GameSystemsPlugin` |

**~80% is static NetGUID path exports** — same for every player. Can be emitted as literal C++ byte constants without decoding. Only ~600 bits are truly per-player (the 268-bit and 316-bit unmapped segments).

### Pawn bunch structural map
- Pkt 79: ONE real FString `"RandomChar"` @ bit 1353; no `/Game/` paths; no archetype value hits; 36 long zero runs
- Pkt 104: ONE real FString `"RandomChar"` @ bit 1624; a 16-float array of 2.0 values @ bit 1066 (appearance morph weights)
- Class, race, archetype ID: **NOT present as strings, NOT present as known u16 values (17747..17754)** in either bunch

### PlayerState / Character class name scan
- Scanned all 400 bootstrap packets for `"PlayerState"`, `"AoCPlayerState"`, `"AoCCharacter"`, `"BP_PlayerCharacter"`, `"CharacterMovementComponent"` — **zero hits**
- Conclusion: these classes are referenced by NetGUID (integer index), not path. The GUID-to-path delivery happened before our 400-packet window. Class/race data is buried inside property payloads with no textual signature.

### Implications for the PC builder
- ~80% of the splice region can become literal emits (static path exports)
- ~20% requires the real property walker to decode
- That gets PC builder from "96% splice" to "~40% splice" without needing the walker for the first iteration

### Implications for class/race synthesis
- **Blocked on the real walker.** No value-scan, string-scan, or structural-scan approach has a chance.
- Multi-session Phase C (bunch header parser + content block loop + NetGUID path parser + BackwardsCompatible property walker + type-aware decoding) is the only viable path.

---

## How to continue this work next session

### Post-mortem: the M5.7 archetype patch failure

**What happened:** Patching u16 at bits 5823 and 5967 of pkt 22 (changing 17748 → 17747) caused:
- HUD widgets (hotbars, maps) to fail to render entirely
- Floating nametag to revert to the default "Player"
- (Name patch still worked — those bits are untouched)

**Why our scan was misleading:**
The value 17748 decodes to `0x4554` little-endian, which is ASCII "TE" (bytes 'T'=0x54, 'E'=0x45).
It very likely appeared at bits 5823 and 5967 not because it's an archetype enum, but because:
- It's the start of an ASCII string like "TEST", "TEXT", "TESlot", etc., inside an FString property
- The u16 match with the Bard..Tank range (17747..17754, which spans `0x4553..0x455A` = "SE".."ZE") is coincidence — any short printable string starting with 'T' or similar falls in that range
- Both copies being 144 bits apart suggests the same FString value appearing inside two RepLayout property slots (e.g. HUD widget class name referenced twice)

**Evidence to pursue next time:**
1. Dump the bytes around bits 5823 and 5967 as ASCII — if we see a readable English word, the u16-archetype interpretation was wrong.
2. Scan for archetype IDs 17747..17754 **excluding** any offset where the surrounding bytes form ASCII text.
3. Scan ALL 400 bootstrap packets (not just pkt 22 / 79 / 104) — the class might live in a packet we haven't inspected (e.g. PlayerState if it's its own bunch, or a late-arriving property update).
4. Search for the ARCHETYPE_BASE value 17747 alone — if no hit, RandomChar's class is something else and our scan range was wrong, OR the enum isn't stored as u16 on the wire (could be a varint / SerializeIntPacked with max value 8).

### Steps to resume

1. **First: confirm HUD is back to M5.4 state** (name + nametag working, hotbars present).
2. **Write `dump_pc_context.py`** — print ASCII + u16 + u32 readings for 32 bytes around bits 5823 and 5967 to understand what's really there.
3. **Reconsider the hypothesis:** AoC might encode the class as a SerializeIntPacked varint (1 byte for values 0–127) or as an index into a class table, not a raw u16.
4. **Alternative approach:** instead of scanning for archetype IDs, scan for the ASCII strings of the class names (`Cleric`, `Bard`, etc.) in ALL bootstrap packets — the class might have a visible string in a PlayerState bunch we haven't located yet.

### Orthogonal tasks

- **Character persistence** — save `characters_` to disk so names survive restart. Quality-of-life, independent of M5.
- **Read-path shortcut:** before diving into new decoding, re-read this file
  + `src/net/game_server.h` around `patch_*` methods + any new `find_*.py`
  output from the session. All wire positions live here.

---

## Hash / sanity

- `replay_data.bin` packet count: 29,010
- Embedded bootstrap: first 400 packets (seq 14265..14664)
- Initial seq: 14265
- Session/custom fields: `94bd264cb147`
- PlayerController bunch: pkt idx 22, 3302 payload bits
- Builder byte-identity: ✅ confirmed (3302/3302 bits match capture)
- Phase 3.8 synthesis: ✅ wired and active in live server
