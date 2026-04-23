# PC Spawn Handle Catalog — Decoder Output
**Source:** `captured_pc_spawn_reassembled.bin` (608 B, reassembled from pkt #22 in bootstrap)
**Decoded:** 2026-04-22 via `src/protocol/tools/decode_pc_spawn.py`
**Updated:** 2026-04-22 — bit-shift decoder cracked the "subobject 506" block ★

## 0.5 ★★★ H.3d-IDA finding — AoC uses a 128-bit NetGUID ★★★

**Decompiling `UIntrepidNetServerPackageMap::InternalLoadObject` (function at
`0x1450347b0`, 3173 bytes, 10th method of the class) with Hex-Rays revealed
a log-format string that leaks AoC's custom NetGUID structure:**

```cpp
Ar << "ObjectId: %llu | ServerId: %u | Randomizer: %u"
```

→

```cpp
struct FIntrepidNetworkGUID {   // 16 bytes (__int128)
    uint64_t ObjectId;      // bytes  0-7   — the actual handle
    uint32_t ServerId;      // bytes  8-11  — which backend server owns it
    uint32_t Randomizer;    // bytes 12-15  — collision-avoidance salt
};
```

This is **completely different from stock UE5's 32-bit FNetworkGUID.**  It
reflects AoC's cross-server architecture (see also
`IntrepidNetInterServerReplicationDriver.cpp`).

**What this changes:**
- Every SIP-decoded "NetGUID" in the captured bunches is only the
  `ObjectId` portion.  `ServerId` + `Randomizer` follow as more bits.
- The "flags byte = 0x2a" mystery is resolved: our decoder was reading
  ExportFlags at the wrong position because the NetGUID is longer than
  we assumed.  The 0x2a contained valid flag bits at a shifted offset.
- The exact per-field encoding (SIP vs fixed-size) still needs RE from
  the serialization function (`sub_14141E960` in the decompile).

## 0. TL;DR (after bit-shift-7 decoding)

The 4,630-bit "subobject NetGUID=506" block is **NOT a subobject** — it's an
inline **PackageMap export block** carrying these NetGUID → path mappings:

| NetGUID (approx) | Path | Purpose |
|---|---|---|
| ≈506 | `/Game/ThirdPersonCPP/Blueprints/AoCPlayerControllerBP` | The PlayerController BP class |
| — | `Default__AoCPlayerControllerBP_C` | Its CDO |
| — | `/Game/Levels/Verra_World_Master/Verra_World_Master` | The level asset |
| — | `Verra_World_Master` | Level short-name |
| — | `PersistentLevel` | Sublevel marker |
| — | `/Script/GameSystemsPlugin` | Module path |
| — | `GlobalGMCommands` | A replicated subobject class |

**Decoding trick:** the payload bytes are bit-shifted by 7 relative to byte
boundaries.  Reconstructing `out[i] = (p[i] | (p[i+1] << 8)) >> 7 & 0xFF`
yields readable ASCII with the usual FString `[int32 length][ascii][NUL]`
framing.

This means our ActorBuilder needs a **PackageMap export emitter**, not a
component-state emitter.  The bunch header flag `bHasPackageMapExports=1`
(which phase3_walker interpreted as a subobject marker) triggers the
embedded export list.

**Target:** `test_pc_spawn_diff` byte-identity (currently 201 vs 4864 bits; delta -4663)

---

## 1. Top-level structure

```
┌─ PC ActorOpen bunch payload (4864 bits = 608 bytes) ─────────────────┐
│                                                                      │
│  [0..8]     SerializeNewActor header                                 │
│              ─ actor NetGUID (SIP) = 3                               │
│              ─ (decode_new_actor signature error — more fields in    │
│                 bits [8..64], needs phase3_walker fix)               │
│                                                                      │
│  [64..74]   Content-block header (2 bits: has_rep=1, is_actor=1)     │
│             + SIP length = 125 bits for actor-root payload           │
│                                                                      │
│  [74..199]  ACTOR ROOT RepLayout payload (125 bits)                  │
│             Contains the root properties: bIsGM, bIsDev, PlayerState │
│             ref, Pawn ref, and any other root-level replicated state │
│                                                                      │
│  [199..234] Content-block header for SUBOBJECT guid=506              │
│             (has_rep=0 → fixed-size payload, no SIP length prefix)   │
│                                                                      │
│  [234..4864] SUBOBJECT payload — 4630 bits (95% of the bunch!)       │
│              This is the major carrier of PC state.  Almost          │
│              certainly a character-info or similar component on the  │
│              PlayerController itself.                                │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

## 2. Critical findings

### Finding #1 — actor NetGUID is 3, not 1
I had assumed the captured PC actor NetGUID was 1.  phase3_walker's SIP
decoder extracts **NetGUID = 3** from bit 0 of the payload.  My test was
feeding the wrong input value.

*Impact on `test_pc_spawn_diff`*: the actor-NetGUID byte at the start of
our output doesn't match captured because we're emitting NetGUID 0x1000000
(from the allocator) while captured has NetGUID 3.  This alone accounts
for the first-diff at bit 1.

### Finding #2 — 95% of the PC spawn is a SUBOBJECT
The actor-root content block is only **125 bits** (tiny).  The 4,630-bit
subobject block dominates the bunch.  That subobject has `has_rep_layout=0`
meaning its payload is fixed-size, not RepLayout-encoded.

Our current `ActorBuilder::build_spawn` emits ONLY the actor-root content
block and does not emit any subobject blocks.  This is the primary
reason our output is 201 bits instead of 4864 bits.

### Finding #3 — subobject NetGUID = 506
The subobject identifier `506` likely refers to a specific
character-component class NetGUID that the client already has loaded via
prior NMT_NetGUIDAssign or via the PackageMap static assignment.

We need to decode what class-name corresponds to NetGUID 506 in AoC.
Most likely candidates (from the OnRep_* catalog inventory):
- `AppearanceComponent` (OnRep_AppearanceComponent @ 0xb790730)
- `BaseCharacterInfo`
- `StatsComponent`
- Something AoC-specific linked to the PlayerController

### Finding #4 — subobject has `has_rep_layout=0`
UE5 content-block format:
- `has_rep_layout=1` → RepLayout handle stream (SIP-encoded handles)
- `has_rep_layout=0` → raw property bits / custom-delta serialization

A 4,630-bit fixed-size subobject payload almost certainly means this is a
**CustomDelta / FastArraySerializer** payload, not standard RepLayout.
That's consistent with AoC's heavy use of custom serialization.

### Finding #5 — AoC source paths leak in the binary
From `re_review_customdelta.txt`:
- `C:\P4\rel\AOCUE5\Game\Plugins\GameSystems\Source\GameSystemsPlugin\Private\AoCPlayerController.cpp` @ 0xb8fd020
- `AoCPlayerControllerCheats.cpp` @ 0xb90e5a0
- `AAoCPlayerController_Dialogue.cpp` @ 0xb7c2d80

The binary has RTTI/debug strings with full source paths.  IDA can extract
the vtable for `AoCPlayerController` to enumerate its properties.

---

## 3. What our builder is missing (scope of H.3c)

| Missing component | Approximate bit cost | Difficulty |
|---|---|---|
| Correct SerializeNewActor header (NetGUID=3 etc.) | ~20-60 bits | LOW — plumbing |
| Actor-root RepLayout emit with the right handles | ~125 bits | MEDIUM — schema calibration |
| Subobject 506 content-block emission | 4,630 bits | **HIGH** — need CustomDelta builder |
| Outgoing fragmentation (bunch splits at ~3545 bits) | — | MEDIUM — framing |

**Biggest chunk is the subobject.** H.3c can focus on just that to
recover 4,630 / 4,663 ≈ 99% of the missing bits.

---

## 4. Recommended H.3c plan

### H.3c.1 — Identify subobject 506
1. Grep the binary RTTI / debug strings for class names referenced by the
   PlayerController with NetGUID 506.
2. Run `decode_new_actor` fixed (small patch to phase3_walker.py) to see
   if the captured payload's SerializeNewActor subobject name is logged.
3. Cross-check against UE5's `AoCPlayerController.h` in the binary
   (via IDA's struct recovery).

### H.3c.2 — Decode the subobject payload
The 4,630-bit payload with `has_rep_layout=0` likely has structure:
```
[SIP class NetGUID? or just bHasBacking=1]
[repeated: custom-delta chunks, each with:
   ─ property index
   ─ length prefix
   ─ serialized bytes ]
```
Run `re_customdelta_deep.py` on the payload to extract its structure.

### H.3c.3 — Implement the subobject emitter
Add to `ActorBuilder`:
- `build_subobject_block(subobj_schema, subobj_runtime, content_block_header, BunchWriter&)`
- Support `has_rep_layout=0` fixed-size emission
- Chain into `build_spawn` after the root actor content block

### H.3c.4 — Close the diff
Re-run `test_pc_spawn_diff` after each subfix.  Target: `matching_bits == 4864`.

---

## 5. Questions for user / next-session homework

1. **Subobject NetGUID 506** — do you have access to the PackageMapClient
   dump or cached NetGUID → path mappings from a real-client run?  That
   would immediately tell us what class 506 is.
2. **IDA artefacts** — the `.i64` IDA database in `dist/Release` — can you
   open it and extract the vtable for `AAoCPlayerController` or its
   BP-generated subobjects?  Specifically the subobject replication list.
3. **Priority** — do you want to push for full byte-identity (H.3c), or
   accept that our PC bunch might not byte-match but will still be
   ACCEPTED by the UE5 client (structurally valid → client parses the
   properties it recognises and ignores the rest)?

Option "structural accept" is a viable shortcut for H.5 if UE5's decoder
is tolerant enough — we'd send a smaller but valid PC spawn and hope the
client fills in defaults for missing fields.  Worth smoke-testing before
committing to the full byte-identity path.
