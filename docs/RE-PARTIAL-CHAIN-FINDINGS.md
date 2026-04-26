# Partial-chain reassembly findings (2026-04-26)

## Summary

Attempted to decode pkt#22 (PC ActorOpen) to find the inline subobject NetGUID
declarations that would tell us what class GUID 7193 actually is. Hit several
unexpected wire-format details that mean further RE is required.

## What was tried

1. **Identified all ch=3 bunches in first 50 packets**:
   - pkt#22: `ctrl=1 open=1 rel=1 pme=1 part=1 pi=0 cef=1 pf=0 chSeq=1978 bdb=3302`
   - pkt#29, 31, 33, 35, 37, 39, 41, 43, 45: alternating partial=1 bunches with bdb~4667
   - pkt#30, 32, 34, 36, 38, 40, 42, 44: non-partial property updates targeting GUID 7193
2. **Attempted PME decode of pkt#22** as documented in `package_map_exporter.cpp`:
   - Expected: `[1 bit bHasRepLayoutExport=0][u32 NumGUIDsInBunch][entries]`
   - Actual: first bit reads as `1` (bHasRepLayoutExport=1), then `NumGUIDs=411` — clearly misframed.

## Key facts learned

### pkt#22 is NOT the partial-initial fragment

Despite being the first ch=3 bunch in the capture, pkt#22 has `bPartialInitial=0`
and `bPartialCustomExportsFinal=1`. This means there must be EARLIER fragments
of the same bunch (possibly on a different channel during pre-bunch handshake?)
OR AoC's partial-initial flag has different semantics than stock UE5.

### AOC PME format ≠ our `package_map_exporter.cpp` spec

The first bit of pkt#22's payload reads as 1 (would mean `bHasRepLayoutExport=1`
in our spec), and `NumGUIDsInBunch=411` is impossible.  Either:

- AOC's PME structure has additional header fields BEFORE `bHasRepLayoutExport`
- The PME data is at a different offset (not start of bunch payload)
- AOC uses a completely different export format

Our `package_map_exporter.cpp` (RE'd from `sub_1450360E0`) may be writing the
WRONG format on the wire. Or `sub_1450360E0` is the writer for one specific
codepath we observed, while pkt#22 uses a different writer path (e.g. partial-
fragment exports vs full-bunch exports).

### NetGUID ID-space mismatch confirmed

Searched entire 7.8 MB capture for byte pattern `19 1c 00 00 00 00 00 00`
(= ObjectId u64 = 7193) — **zero hits**. The SIP value 7193 in content blocks
is not the same ID space as ObjectId 7193 in PME exports.

Most plausible explanation: AOC's content-block NetGUID references use a
**channel-local subobject index**, not a global ObjectId. SIP value 7193 might
mean "subobject #7193 within this channel's actor". This is not stock UE5
behavior — would be an AOC customization.

### Class strings DO exist in pkt#127

ASCII strings found at byte boundaries in pkt#127:
- `BaseCharacterInfo` at byte 726
- `AbilityComponent` at byte 839
- `StatsComponent` at byte 898
- `InteractInfo`, `CombatInfo` (also seen)

These are AOC custom subobject classes attached to the PC. Whichever one is
GUID 7193 — that's what our V3 should target.

## What this means for V3

The V3 silent drop is almost certainly because:

1. NetGUID 7193 in content blocks refers to a **CUSTOM AOC SUBOBJECT** (most
   likely `BaseCharacterInfo`, `StatsComponent`, or `AbilityComponent`).
2. APlayerState's cmd_handle 10 (= PlayerNamePrivate) does NOT apply to that
   custom class. Our property write targets a meaningless handle.
3. The 2755-bit payload format used by GUID 7193 in capture is likely a
   custom NetSerialize/CustomDelta format specific to that subobject's class.

## Next steps required

1. **Get RepLayout for AOC custom classes** (BaseCharacterInfo, StatsComponent,
   AbilityComponent, etc.) — currently being extracted by background agent.
2. **Determine which custom class GUID 7193 maps to** — needs proper PME bunch
   reassembly OR runtime instrumentation.
3. **Decode the actual wire format** the captured GUID-7193 payload uses
   (probably class-specific CustomDelta).

## Files produced

- `src/protocol/tools/v3_bunch_diff.py` — V3 vs captured header diff (proved header is correct)
- `src/protocol/tools/v3_inner_diff.py` — tries to walk inner property stream (proved our format is wrong)
- `src/protocol/tools/pme_walker.py` — bit-aligned PME decoder (works for some bunches but partial-chain handling incomplete)
