# V3 Subobject Targeting — empirical RE from replay_data.bin

**Date:** 2026-04-26
**Scope:** Verified by direct decode of captured wire bytes, not codebase echo.

## Summary

The previous V3 emit set `bIsChannelActor=1`, targeting the channel's root
actor (PlayerController). Captured property updates on the same channel
predominantly use `bIsChannelActor=0` and address a **subobject by SIP
NetGUID**. For ch=3 (the PC channel), the dominant subobject is
**NetGUID 7193**, which receives 6 update bunches in the 29010-packet
capture, with payload sizes up to 2755 bits — almost certainly the
PlayerState (where `Name` lives in stock UE5).

## Wire format (verified)

Content block on a property-update bunch:

```
[1 bit] bOutermostEnd     = 0
[1 bit] bIsChannelActor   = 0          ← key bit
[SIP]   subobject_netguid              ← previously-cached GUID, plain SIP ref
[SIP]   NumPayloadBits
[NumPayloadBits bits] inner property stream:
    For each property:
        [SerializeInt(NumProperties_in_class)] cmd_handle
        [SIP]                                  NumBits
        [NumBits bits]                         value
[1 bit] bOutermostEnd     = 1          ← terminator (after all blocks)
```

**Verification:** `pkt#30` ch=3 bunch (BDB=4574) decoded with this format
yields a clean first content block: NetGUID=7193, NumPayloadBits=2755,
exact-fit consumption from bit 213 to bit 2968.

## Per-channel subobject NetGUID histogram (29010 packets)

Top channels by occupancy:

| Channel | Subobject GUID | Count | Max payload | Likely class |
|---|---|---|---|---|
| ch=3  | **7193**  | 6  | **2755 bits** | PlayerState (PC) |
| ch=4  | 64        | 6  | 1857 bits     | (Pawn?) |
| ch=8  | 84, 81    | 15+14 | small      | components |
| ch=9  | 72, 11934 | 15+1  | 256-1000   | mixed |
| ch=12 | 13523     | 4   | 2486 bits    | another big actor |
| ch=20 | 111       | 40  | 52 bits      | small ticker |

GUID=0 with tiny payloads appears across many channels — likely a
periodic "actor still alive" heartbeat (channel-actor alias).

## ChName empirical EName values per channel

Decoded from 285 hardcoded-ChName bunches in capture:

| Channel | EName seen | Count |
|---|---|---|
| ch=0 (NMT) | 255 | 3 (always) |
| ch=2 | 103 (×5), 71 (×1) | mostly Actor |
| **ch=3 (PC)** | **71 (×3)**, 103 (×2) | mixed |
| ch=5 | 103 (×6) | Actor |
| ch=6 | 71 (×8), 103 (×6) | mixed |
| ch=20 | 71 (×20) | always 71 |

**Codebase pre-existing default of 102 NEVER appears** anywhere in the
capture. That value was an unverified guess in `actor_builder.h:115`
and `pc_emitter.cpp:215`. New `PropertyUpdateBunchBuilder` default is
**103** (most common Actor-like value); callers targeting ch=3 PC
should override to **71**.

Note: V3 emit uses `--v3-reliable 0`, so `chname_present` is `false`
in the parser — ChName is not written, not expected. Default value is
only relevant for reliable bunches (PcEmitter, future native sends).

## What's still NOT verified

- **`NumProperties`** for the PlayerState class. Tried 32, 64, 128,
  256, 512, 1024, 2048, 4096, 8192, 16384 against pkt#30's 2755-bit
  payload with skip prefixes 0..32 — no exact-fit walk. Either:
  - There's interleaved framing (rep-notify markers, sub-block headers)
    we don't yet model
  - Specific properties consume non-trivial bits (FStrings, FastArrays)
    that our naive walker misses
- **`cmd_handle` for `Name`** on the PlayerState. To find empirically:
  iterate `--v3-cmd-name 1, 2, 3, ...` until in-game name changes.

## Tooling produced (knowledge)

The Python decoders that established these facts are inline in the
session transcript (not committed as scripts). Key invocations
documented in chat:

1. Per-channel ChName EName histogram — confirms 102 wrong, 103/71 right.
2. Per-channel subobject NetGUID frequency — identified 7193 as ch=3
   primary subobject.
3. pkt#30 content-block exact-fit decode — verified the SIP-NetGUID
   encoding is correct.
4. pkt#104 RandomChar location — at byte 207 (bit 1656), inside a
   partial-initial open bunch (chained across multiple fragments).

## Code changes made

| File | Change |
|---|---|
| `src/protocol/emit/property_update_bunch_builder.h` | Added `v3_begin_content_block_subobject(guid, num_props)`. ChName default → 103 (was 102). |
| `src/protocol/emit/property_update_bunch_builder.cpp` | Implemented subobject begin + writes SIP NetGUID in `v3_end_content_block`. |
| `src/main.cpp` | Added `--v3-subobject-guid` CLI flag. |
| `src/net/game_server.h` | Added `v3_subobject_guid` config field; `inject_v3_property_update` selects subobject vs root path. |
| `dist/Release/launch_all_v3_emit.bat` | Defaults: `V3_SUBOBJECT_GUID=7193`, `V3_NUM_PROPERTIES=64`, `V3_CMD_NAME=1` (PlayerState typically has Name at low handles). |

## Iteration plan for the user

With the launcher defaults:
- `V3_SUBOBJECT_GUID=7193` — PC's PlayerState (verified from capture)
- `V3_NUM_PROPERTIES=64` — PlayerState typically has ~30 replicated props
- `V3_CMD_NAME=1` — try low handles first

If HUD doesn't change after first launch:
1. Bump `V3_CMD_NAME` to 2, 3, 4, 5, ..., 30 — restart between each
2. If still nothing, try `V3_NUM_PROPERTIES=128`, then 256, then 32
3. If client disconnects → format error — back off and report log

If HUD changes to wrong-looking value, you've hit a different property.
Note which `cmd_name` did what — that's free RE.
