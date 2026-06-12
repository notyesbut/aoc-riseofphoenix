# ClientRestart / Possession parameter — ground truth from the retail capture

**Date:** 2026-06-11
**Source:** offline decode of `dist/Release/replay_data.bin` (== `fixtures/replay_data.bin`,
YLPR v1, 29 010 records / 7.4 MB). No game client involved.
**Tooling:** reused `phase1_parser.py` (proven bunch parser), `walk_replay_props.py`
(loader + V3 block parser), `decode_sc_rpcs.py` / `find_possession_signature.py`
(YLPR loaders), plus new scratch decoders `_cr_dump_ch3.py`, `_cr_fieldwalk2.py`,
`_cr_objref.py`, `_cr_selector.py` under `src/protocol/tools/`.

---

## TL;DR (the answer that ends the guessing loop)

- The captured retail server **did NOT send a `ClientRestart` RPC on the
  PlayerController channel (ch=3)** in this replay. There is **no field with the
  FClassNetCache selector 45** anywhere on ch=3 (or any channel) in the capture.
- There is also **no standalone `AController::Pawn` property field** carrying an
  object reference on ch=3 (no selector 14 / 73 — both candidate index models).
- **Decisively: there is NO flat 128-bit `FIntrepidNetGUID` value anywhere in the
  property/RPC field streams** — not on ch=3, not on any channel, not in the
  whole 29 010-record capture. Two independent scans agree:
  - `walk_replay_props.py` (whole capture): **0** values of 128/129 bits.
  - per-field NumBits histogram at the correct selector width MAX=1035
    (login window, all channels): **0** fields of 128/129/136/137/160 bits.
- **Conclusion about wire size:** the `NewPawn`/`Pawn` object reference is **NOT**
  128 bits and **NOT** 136 bits (128 + 8-bit ExportFlags). That is exactly why both
  `NumBits=128` and `NumBits=136` were rejected by the live client with
  "ReceivePropertiesForRPC - Mismatch read". A UE5 object reference is serialized
  by `UPackageMapClient::SerializeObject` as a **compact packed NetGUID**
  (`SerializeIntPacked(NetGUID.Value)`, ~8–40 bits for a cached/already-exported
  object), optionally preceded by export data only on first mention. The flat
  128-bit `{ObjectId.lo, ObjectId.hi, ServerId, Randomizer}` struct that the
  emulator has been writing is **not** the on-wire form the client's RPC reader
  expects for a NetGUID parameter.

**Confidence:** HIGH for the negative results (no CR=45, no 128/136-bit GUID
field — these are exhaustive, exact-fit decodes). MEDIUM for the precise compact
encoding, because the capture does not contain the possession event itself in a
cleanly-isolable field, so the exact NumBits of the real `NewPawn` could not be
read off a captured ClientRestart bunch (there isn't one).

---

## What ch=3 actually contains (timeline)

`replay_flow_timeline.py` places the PC channel-3 activity:

```
pkt# 22 OPEN ch=3          chSeq=954 bdb=3545   <- PlayerController ActorOpen (+ partials 955/956/957)
pkt# 31 RELIABLE ch=3      chSeq=948 bdb=42     <- all-zero empty content blocks (no payload)
pkt# 77 RELIABLE ch=3      chSeq=965 bdb=2537   <- single big property struct (selector 213, 2493b)
pkt#127 RELIABLE ch=3      chSeq=997 bdb=1238   <- single big property struct (selector 183, 1194b)
pkt#127 RELIABLE ch=3      chSeq=998 bdb=32     <- selector 257, 4-bit value = 5
... then steady-state replication (selectors 219/232/233/260, large structs)
```

There are **52 reliable ch=3 logical bunches** (after partial-chain reassembly);
**42 decodable content blocks** once exports/opens are excluded.

### Selector decode is exact and the width is pinned

Walking each ch=3 content block as
`[bHasRepLayout:1][bIsActor:1] (+ SubGUID) [SIP NumPayloadBits]` then the field
loop `{ SerializeInt(selector, MAX) ; SIP(FieldNumBits) ; value[FieldNumBits] }`:

| MAX  | exact-fit blocks | bad blocks | verdict |
|------|------------------|-----------|---------|
| **1035** | **42 / 42** | **0** | correct selector width |
| 216  | 2 / 42  | 39 | wrong |
| 46   | 2 / 42  | 37 | wrong |

MAX=1035 (FieldCount 1034 + 1) is confirmed as the selector width: it is the only
MAX under which **every** ch=3 block decodes with zero leftover/overrun bits.

### ch=3 selector histogram (MAX=1035, exact-fit)

```
233×11, 219×9, 232×8, 260×7, 213×1, 183×1, 257×1, 214×1, 221×1
selector 45 (ClientRestart): 0     <-- NOT PRESENT
selector 14 / 73 (Pawn property, either index model): 0
```

The recurring selectors (233/219/232/260) are the steady-state replicated
PlayerController properties (movement / transform-component / state structs).
Their values are large multi-bit blobs (130–2493 bits), and **none** decodes as a
compact or 128-bit object reference. Example: selector 260 (recurs 7×) carries a
130-bit value `9719d4f0cdb5498302ea4f7c83e9b20501` — not a GUID, not a Pawn ref
(leading SIP → objid 869157, which matches no Pawn).

---

## Why the 128-bit / 136-bit hypotheses are wrong

`find_possession_signature.py --mode framing` scanned every reliable ch=3 bunch
for the shape `[SerializeInt(selector,max)][SIP(128|136)][128-bit FIntrepidNetGUID]`:

```
scanned 38 reliable bunches; 128-bit framing hits: 0
FRAMING-SCAN VERDICT: NO possession-shaped field [selector][SIP(128|136)][128-bit GUID] found
```

`walk_replay_props.py` over the **entire** capture:

```
NetGUID-shaped values (128/129 bits): (none)
```

So the on-wire `NewPawn` reference cannot be the flat 16-byte
`{ObjectId.lo, ObjectId.hi, ServerId, Randomizer}` struct. The client's RPC param
reader (`sub_1444E8910` PathA + leaf `sub_1444E9EF0`) reads each parameter as
`SIP(handle) ; SIP(NumBits) ; NumBits raw bits`, and for a `UObject*` parameter the
`NumBits` payload is whatever `SerializeObject` writes — a **packed NetGUID index**,
not 128 bits. The emulator must emit the Pawn ref via the compact NetGUID path
(`SerializeIntPacked(NetGUID.Value)`), exporting the GUID once if it was never
sent, NOT as a 128-bit struct and NOT as 128+8.

---

## Possession mechanism in this build

From the live reflection dump (`_cr_acontroller.txt`): `AController::Pawn` is a
**replicated net property** (`CPF` `0x4144000100000020`, net=True) with
`OnRep_Pawn`. So in principle possession can be driven by the replicated `Pawn`
property → `OnRep_Pawn` → `AcknowledgePossession`, in addition to / instead of the
`ClientRestart(NewPawn)` RPC. In THIS capture neither a `ClientRestart` RPC (sel 45)
nor an isolated `Pawn`-property field (sel 14/73) appears on ch=3 — meaning the
possession event for the captured session is not present as a standalone decodable
field in the replay window (it is likely folded inside one of the large initial
property structs sent in the partial/export bunches around pkt#22–127, or occurred
outside the captured window).

---

## Recommendation for the emulator

Stop emitting the `NewPawn` ref as a 128-bit `FIntrepidNetGUID` (or 128+8). Emit it
the way UE5 `SerializeObject` does:

1. If the Pawn's NetGUID has already been exported to this client, write only
   `SerializeIntPacked(NetGUID.Value)` (the small packed index) — `NumBits` will be
   ~8–40, not 128.
2. If it has not been exported, write the full export (GUID + ExportFlags + path /
   outer chain) the first time, then the packed index thereafter.

The RPC param framing the client expects is unchanged: `SIP(handle=cmd+1)`,
`SIP(NumBits)`, then exactly `NumBits` bits = the compact-NetGUID serialization.
`NumBits` is therefore the *bit length of the packed NetGUID*, not a fixed 128/136.

---

## Files / repro

- New scratch decoders (read-only): `src/protocol/tools/_cr_dump_ch3.py`,
  `_cr_fieldwalk2.py`, `_cr_objref.py`, `_cr_selector.py`.
- Existing: `find_possession_signature.py --mode framing` (zero 128b hits),
  `walk_replay_props.py` (zero 128/129b values), `replay_flow_timeline.py`
  (ch=3 timeline), `decode_sc_rpcs.py` (YLPR loader).
