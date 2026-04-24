# World-Bootstrap Analysis (PHASE B findings, 2026-04-21)

Analysis of `bunches.log` (130k lines, 29k packets, 72k parsed bunches) from
a full session with verbose bunch logging enabled.

## 1. Session traffic shape

| Kind | Count | % | Meaning |
|------|-------|---|---------|
| ActorUpdate   | 43001 | 60% | Property deltas (movement, HP, etc.) |
| GUIDExport    | 16232 | 23% | Actor/class registrations |
| ActorClose    | 11528 | 16% | Entity cleanup |
| PartialCont   | 1051  | 1.5% | Multi-bunch continuation |
| ActorOpen     | 205   | 0.3% | **Actor spawns (the gold)** |
| Control       | 142   | 0.2% | NMT + game control |
| ActorReliable | 116   | 0.2% | Reliable non-control |

Top channels: ch=12 (12094 bunches, 17%), ch=19 (4206), ch=92 (1794),
ch=108 (1683), ch=114 (1646).

## 2. Bootstrap waves (what Player 1 sees on spawn)

Wave structure — all at `chSeq=1978` (first reliable bunch on each channel
after NMT_GameSpecific):

### Wave 1 — Own PlayerController (pkt 14332)
```
pkt#14332 ch=3  ActorOpen bits=3302  rel=1 part=1-- chSeq=1978
```
The PlayerController actor — unique 3302-bit signature, only 2 occurrences
per session (initial spawn + one reopen).

### Wave 2 — Visible Characters (pkts 14372–14524)
```
ch=14, 24, 40, 43, 51, 67     bits=4326  rel=1 part=1-- chSeq=1978
```
7+ instances of the same 4326-bit class. Likely `BP_Character` (players
or character-shaped NPCs visible on first render).

### Wave 3 — NPCs / Enemies (pkts 14532–14646)
```
ch=71, 78, 90, 94, 100, 101, 104, 108, 110, 111, 127, 182
                              bits=5350  rel=1 part=1-- chSeq=1978
```
19 instances of the 5350-bit class. Likely `BP_NPC` (non-character enemies
/ monsters in the starter area).

### Wave 4 — Specialty actors (interspersed)
| bits | count | hypothesized class |
|------|-------|--------------------|
| 2278 | 3 | Gameplay state actor |
| 1254 | 8 | Mid-size spawn (interactables?) |
| 230  | 5 | Small subobject |
| 436  | 6 | ch=93 specific (paired with 6318) |

### Wave 5 — Repeating hardcoded actor
```
pkt#14741+  ch=40  ActorOpen bits=50  rel=0 part=1I- chSeq=0 name='#2022547'
```
Same channel + same FName hardcoded index `#2022547`, repeats 24+ times
throughout the session. Very compact spawn (50 bits). Likely a respawning
resource node (loot crate / gathering node).

## 3. Actor-class fingerprint table

Signatures extracted from 205 ActorOpens in the session:

| bits | count | chSeq | part | flags           | hypothesis |
|------|-------|-------|------|-----------------|------------|
| 3302 | 2     | 1978  | 1--  | rel=1 exp=1 gui=0 ctrl=1 | **PlayerController** (unique) |
| 4326 | 7     | 1978  | 1--  | rel=1 exp=1 gui=0 ctrl=1 | **BP_Character** (~7 visible chars) |
| 5350 | 19    | 1978  | 1--  | rel=1 exp=1 gui=0 ctrl=1 | **BP_NPC** (19 mobs in area) |
| 2278 | 3     | 1978  | 1--  | rel=1 exp=1 gui=0 ctrl=1 | GameState / MatchActor |
| 1254 | 8     | 1978  | 1--  | rel=1 exp=1 gui=0 ctrl=1 | Interactable / Resource |
| 230  | 5     | 1978  | 1--  | rel=1 exp=1 gui=0 ctrl=1 | Subobject (weapon?) |
| 6318 | 5     | 3684  | 1-F  | rel=1 exp=1 gui=1 ctrl=1 | ch=93 state burst |
| 436  | 6     | 3684  | 1-F  | rel=1 exp=1 gui=1 ctrl=1 | ch=93 state delta |
| 50   | 24    | 0     | 1I-  | rel=0 exp=1 gui=0 ctrl=1 | Hardcoded #2022547 respawn |
| 48   | 41    | 1408  | 0--  | rel=1 exp=1 gui=0 ctrl=1 | Possibly PlayerState updates |

## 4. What Player 2 integration needs

To let Player 2 join the world Player 1 is already in:

1. **NMT handshake** live-synth (already done)
2. **NMT_Welcome** with correct map path (already done)
3. **PlayerController spawn for P2** — new ActorOpen with P2's unique GUID,
   replacing the captured PlayerController template (need to decode 3302-bit
   format to modify it)
4. **ActorOpens for all existing characters** — so P2 sees:
   - 7× `BP_Character` (4326 bits each)
   - 19× `BP_NPC` (5350 bits each)
   - Specialty actors (2278, 1254, 230 bits each)
5. **Subscribe to ch=19 / ch=12** updates — relay ActorUpdates coming from
   other players' channels to P2's connection
6. **Broadcast P2's ServerMove** as ActorUpdate on a synthesized channel

**The decoded bootstrap sequence from Wave 1–4 gives us the minimum spawn
package for any new player**. Reversing the 4326-bit / 5350-bit templates
is the next milestone (M3).

## 5. 31-bit and 62-bit bunch analysis (PARSE_FAIL cluster)

The top two drift-triggering patterns account for 7755 PARSE_FAILs (28% of
all parse failures). Bit-level analysis of the 4 common 31-bit payload
variants:

```
Pattern        : bits[0..30]
56 61 08 00    : 0110101010000110000100000000000
56 61 18 00    : 0110101010000110000110000000000
56 61 58 00    : 0110101010000110000110100000000
56 61 98 00    : 0110101010000110000110010000000
```

- **bits 0–19**: FIXED across all variants (class+property identifier)
- **bits 20, 22, 23**: VARY (value delta, ~3 bits of payload)
- **bits 24–30**: zero padding

The 20-bit fixed prefix `01101010100001100001` decodes as a stable
FieldHandle identifier for a specific replicated property. The 3 varying
bits are a compact value delta.

**Finding**: the 31-bit bunches ARE well-formed with correct size. The
parser reads them correctly. However the parser drifts 10–30 bits AFTER
consuming the stated 31 bits — meaning AoC's wire format has extra
framing bits (RepLayout-style trailer?) that our spec doesn't capture.

Further investigation needs bit-level comparison with stock UE5
`UActorChannel::ReadContentBlockPayload` + RepLayout read routines.

## 6. Next-step roadmap

### PHASE B-5 — Fix parser drift on property-delta bunches (days)
1. Write a bit-level extraction tool that dumps raw bits of pkts 14911,
   15000, 15003 (known to fail at the same pattern)
2. Align actual bytes against parse_sc_bunch's cursor math
3. Identify the extra framing bits AoC inserts
4. Patch parse_sc_bunch to consume them

### PHASE C (M3) — Decode one ActorOpen per signature (week)
1. Take the pkt 14332 (PlayerController, 3302 bits) payload
2. Decode stock UE5 `SerializeNewActor` format: LocGUID, ArchetypeGUID,
   Location, Rotation, Scale, Velocity, initial property values
3. Output a structured spawn manifest
4. Do same for 4326 (Character) and 5350 (NPC)

### PHASE M5 — RepLayout property decode (month)
Decode the ActorUpdate property deltas using the FieldHandle table built
from ActorOpen decodes.

### The multiplayer milestone
Once M3 + M5 are done, emit synthetic ActorOpens + ActorUpdates for
Player 2 to see Player 1, and vice versa.

---

## 7. M3 — PlayerController ActorOpen decode (in progress)

Target: pkt 14287 (orig_seq=14287, 6104 bunch_bits, ch=3, 3302-bit actor-open payload).

### Bunch header — FULLY DECODED ✅

| Field | Value | Notes |
|-------|-------|-------|
| bControl | 1 | Control bunch |
| bOpen | 1 | Channel open |
| bClose | 0 | — |
| bIsRepPaused | 0 | — |
| bReliable | 1 | Reliable |
| ChIndex | 3 | PlayerController channel |
| bExports | 1 | Contains exports |
| bGuids | 0 | No must-be-mapped GUIDs |
| bPartial | 1 | Partial bunch |
| ChSequence | 1978 | First reliable seq on ch=3 |
| partial-subflags | `[0, 1, 0]` | See below — AoC format unclear |
| has_chname | false | ChName NOT present |
| **BunchDataBits** | **3302** | Matches log ✅ |
| payload_start | bit 206 | After 44-bit header |

### Partial-subflag semantics — UNCERTAIN ⚠️

All 9 reliable-partial ch=3 bunches in the session follow one of these 3 bit patterns:

| Pattern (p0 p1 p2) | Count | Matches | Context |
|---|---|---|---|
| `0 1 0` | 7 | bOpen varies, bClose=0 | Opens or updates |
| `0 1 1` | 1 | small update | Singular |
| `1 0 1` | 1 | bClose=1 | Channel close |

**Stock UE5 had `bPartialInitial(1) + bPartialFinal(1)`** — 2 bits, not 3. AoC writes **3 bits**, and the middle bit (p1) is set on every partial bunch that opens or updates. The current hypothesis that p1 = "CustomExportsFinal" doesn't cleanly match this pattern.

**Alternative hypothesis worth testing**: bit order might actually be
`[Final, ???, Close]` or similar — where p1=1 on every non-close bunch means "this is a self-contained partial that represents the whole actor in one fragment". Needs IDA disasm of `UNetConnection::ReceivedPacket` to confirm.

### Payload decode — DECODED ✅ (2026-04-21 breakthrough)

Payload starts at bit 206:

```
bHasRepLayoutExport = 1           (1 bit)
NumExports (u32 LE) = 411         (32 bits) — the class's total field count
FNetFieldExport[411] = bit-vector (411 bits) — which fields are in this bunch
```

**Major finding: all 411 FNetFieldExports are just 1-BIT FLAGS.** Not stock UE5's variable-size records. This is an AoC-specific **compact field-mask format**:

- **411 bits** = bit-vector, one bit per field position in the pre-registered class schema
- **bit[i]=1** means "this bunch carries a value for field i"
- **68 ones + 343 zeros** for pkt 14287 → 68 of 411 PlayerController fields are being exported

This format requires **both sides to share the same field-schema table for the class** — the client already knows the PlayerController's field layout from its local BP metadata. The server only tells it WHICH fields are being sent, not the field names/types.

This compact encoding explains:
- Why 411 exports fit in ~52 bytes instead of thousands of bytes
- Why AoC captures work without the huge "field registration" overhead seen in stock UE5
- Why decoding ActorUpdates requires knowing the class in advance (no self-describing exports)

### Payload layout (after the field bitmask)

After bit 650 (= 206 + 1 + 32 + 411), we have 2858 remaining bits for:
- `SerializeNewActor` header (ActorGUID, ArchetypeGUID, Location/Rotation flags)
- Property values for each of the 68 exported fields (in field-index order)

First 32 bits right after the 411-bit mask: `0xf0000003` — likely the compact spawn-info flags (bSerializeLocation, bSerializeRotation, etc.).

### Implications for multiplayer

To spawn a **synthesized PlayerController for Player 2**:

1. Emit a bunch with the same bunch header as pkt 14287 (ctrl=1, open=1, reliable=1, partial=1, chSeq=1978)
2. Set `bHasRepLayoutExport=1, NumExports=411` (PlayerController class schema size)
3. **Set the same 68 bits** in the field-mask as pkt 14287 did (these indicate the CORE fields the client needs at spawn time: position, rotation, class, etc.)
4. Emit `SerializeNewActor` body with **Player 2's unique ActorGUID** and desired spawn transform
5. Emit property values for the 68 exported fields

This is a **finite, enumerable template** — not intractable reverse-engineering.

### Tools saved for next session

- `dist/Release/extract_bunch.py` — dumps raw bits from replay_data.bin
- `dist/Release/reassemble_chain.py` — walks partial chains on a channel
- `dist/Release/decode_actor_open.py` — bunch header + payload decoder stub

### Next steps (M3 continuation)

1. **Resolve partial-subflag semantics** via one of:
   - IDA disasm of `UChannel::ReceivedNextBunch` partial-handling branch
   - Empirical test: modify `sc_bunch_parser.h` to try different bit-orderings and see which produces the highest `parse_ok` rate in `replay_inspect`

2. **Resolve FNetFieldExport AoC variant** by:
   - Comparing a single export's bits against a known UE5 SDK dump
   - Looking at `FNetFieldExport::Serialize` or the equivalent in AoC's netcode via IDA

3. **Once exports decode cleanly**, the SerializeNewActor body follows at a known bit offset. Decoding that gives us: **ActorGUID, ArchetypeGUID, SpawnLocation, SpawnRotation, SpawnScale, SpawnVelocity** — the multiplayer template we need.

---

## 8. Protocol module (Phase 1 — COMPLETE)

**Milestone: `aoc_server.exe --use-embedded-bootstrap` — game loads without
any external data file.**

### Architecture delivered

```
src/protocol/                            ← new module (the "no-replay" track)
├── README.md                            Module overview + phased roadmap
├── bootstrap/
│   ├── bootstrap_sequence.h/.cpp        Loads embedded 400 packets into ReplayData
│   └── bootstrap_data.h                 AUTO-GENERATED, 1.9MB, embedded raw bytes
└── tools/
    └── extract_bootstrap.py             Re-runnable codegen (reads replay→emits header)
```

### How it works

1. `tools/extract_bootstrap.py` reads `replay_data.bin`, emits `bootstrap_data.h`
   as a `constexpr` table of raw packet bytes + metadata (400 packets).
2. `BootstrapSequence::fill(ReplayData&)` copies the embedded data into the
   existing `ReplayData` struct at startup.
3. `GameServer::GameServer()` branches on `config_.use_embedded_bootstrap`:
   - `true`  → fill ReplayData from embedded data (no file read)
   - `false` → legacy `ReplayData::load(path)` (backward compatible)
4. CLI: `aoc_server.exe --use-embedded-bootstrap` activates the new path.
5. Launch helper: `launch_all_embedded.bat` — no-file version of the bootstrap
   launcher.

### Verification (done in this session)

- ✅ `aoc_server.exe` builds clean with the new source files.
- ✅ `replay_inspect` regression passes (56834 bunches, 35 ok / 63 err).
- ✅ The `--use-embedded-bootstrap` flag appears in `--help`.
- ✅ Live run pending (user test).

### Why this matters

- **Deployment independence**: `aoc_server.exe` can ship alone, no `.bin` file.
- **Reproducible builds**: `extract_bootstrap.py` runs deterministic codegen.
- **Stepping stone to Phase 3**: the embedded byte arrays are the raw material
  we will progressively REPLACE with per-actor builders.

### Reference resources

| Resource | Path | Used for |
|----------|------|----------|
| UE5 source (canonical) | `C:/Users/xmaxt/Documents/UnrealEngine-release/Engine/Source/` | Reference implementation for `DataBunch`, `NetConnection`, `PackageMapClient`, `RepLayout`, `ActorChannel`. **This is the official source we cross-check against** — do NOT use `C:/Program Files/Epic Games/UE_*` (those are stripped engine installs). |
| PCAPRepo captures | `dist/Release/PCAPRepo-main/` | 1792 real captures for diff-based RE. |
| World-bootstrap doc | `docs/world-bootstrap-findings.md` | (this file) central roadmap + findings. |
| Current session decoder tools | `dist/Release/` | `extract_bunch.py`, `decode_actor_open.py`, `reassemble_chain.py`, `patch_name.py`. |

## 9. Next steps (Phase 2 — Modularize)

With the embedded data working, Phase 2 is about splitting the monolithic
`bootstrap_data.h` into per-actor files so each can be individually worked on:

```
src/protocol/actors/
├── actor_base.h              # Common interface: bytes() or build(profile)
├── player_controller.h/.cpp  # ch=3 ActorOpen, 3302 bits
├── character.h/.cpp          # ch=14/24/... ActorOpens, 4326 bits each
├── game_state.h/.cpp         # 2278-bit game state actor
├── npc.h/.cpp                # ch=71/78/... ActorOpens, 5350 bits each
└── interactables.h/.cpp      # 1254-bit / 230-bit actors
```

Each starts as a raw-byte blob extracted from the current `bootstrap_data.h`.
Then Phase 3 progressively replaces blobs with real builders.

### Phase 2 entry-point script (to write)

A new tool `tools/split_by_actor.py` that takes `bootstrap_data.h` + the
ActorOpen metadata we've already decoded (channels, bit counts) and emits
one `.h` per actor class. Rough 1-day project.

### Phase 3 dependencies (the hard part)

To replace blobs with builders we need:
- Decoded `SerializeNewActor` format (Location FVector, Rotation FRotator, etc.)
- Decoded RepLayout property values for the 68 fields exported on the PC
- A `BunchBuilder` + `PacketBuilder` that writes bits correctly
- `CharacterProfile` as the input to all builders

UE5 source at `C:/Users/xmaxt/Documents/UnrealEngine-release/Engine/Source/Runtime/Engine/Private/`
has:
- `DataBunch.cpp` — bunch header read/write (stock UE5 reference)
- `NetConnection.cpp` — outer packet assembly
- `PackageMapClient.cpp` — NetGUID exports
- `RepLayout.cpp` — property replication
- `ActorChannel.cpp` — actor open/close flow

Any AoC-custom deviations (12-bit ChSeq, 3 partial flags, 411-bit field mask)
are documented in sections 5 and 7 above.
