# FOCUS [pc-channel-identify] — which capture channel carries the PlayerController, and the rec#22 ActorOpen decode

**Date:** 2026-06-09
**Scope:** Identify, from the retail capture `fixtures/replay_data.bin` (YLPR v1,
29010 records), **which channel index carries the `APlayerController`**, decode its
ActorOpen bunch (the rec#22 region), and confirm/refute the emulator's `ch=3`
assumption.
**Loaders used (stable):** `src/protocol/tools/phase1_parser.py`
(`parse_packet`, `reassemble_partial_bunches`) — the same loaders that
`decode_sc_rpcs.py` and `find_possession_signature.py` are validated against
(consume all 29010 records). Stdlib only, LSB-first per byte (UE5 `FBitReader`).

**CONFIRMED** = decoded directly from the wire bytes; **INFERRED** = reasoned from
UE5 semantics + code without a fresh byte to pin it.

---

## 0. VERDICT (lead with the answer)

**The PlayerController is on channel index `ch=3`. CONFIRMED — and now upgraded from
"inferred" to "decoded class name".** The emulator's `ch=3` assumption is **correct**.

The rec#22 (`pkt#22`, `seq=14287`) ch=3 ActorOpen, after partial-chain reassembly,
is **4859 data bits** and its replicated body contains the decoded UE5 FStrings:

- `/Game/ThirdPersonCPP/Blueprints/AoCPlayerControllerBP`  (+433 bits)
- `Default__AoCPlayerControllerBP_C`                        (+929 bits)

`ch=3` is the **only** channel in the entire capture whose ActorOpen carries a
`PlayerController` class path — i.e. the identification is unique, not merely a
"PC-shaped traffic" inference. This closes the residual in
`POSSESSION-FROM-REPLAY.md §6` ("ch=3 = PlayerController (inferred from traffic
shape; class name not decoded)") — **the class name IS now decoded.**

---

## 1. How ch=3 was identified (reproducible, CONFIRMED)

Method: reassemble all partial-bunch chains per channel
(`reassemble_partial_bunches`), take each channel's first export-bearing open
bunch, and scan its reassembled data for UE5 FStrings (int32 length + ASCII).
The **only** channel whose first open contains a `PlayerController` string is
`ch=3`:

```
*** ch=3  BDB=4859  origin=reassembled  ch_name='EName[102]'
      +  433b: '/Game/ThirdPersonCPP/Blueprints/AoCPlayerControllerBP'
      +  929b: 'Default__AoCPlayerControllerBP_C'
      + 1793b: '/Game/Levels/Verra_World_Master/Verra_World_Master'
      + 2265b: 'Verra_World_Master'
      + 2481b: 'PersistentLevel'
      + 3073b: '/Script/GameSystemsPlugin'
      + 3345b: 'GlobalGMCommands'
```

The presence of the `Verra_World_Master` / `PersistentLevel` path is exactly what
a PlayerController's `SerializeNewActor` (archetype + level outer chain) plus its
initial replicated-subobject exports look like; `/Script/GameSystemsPlugin` /
`GlobalGMCommands` are the PC's replicated GM-command subobject. No other channel
in the file produced a `*PlayerController*` string.

This **matches the prior `identify_channels_output.txt`** (lines 17-24) which
independently surfaced the same two PC strings on ch=3 — so the result is
corroborated by two separate scans.

### Why the channel NAME does not distinguish the PC (important nuance)

The ch=3 bunch's `ch_name` decodes to **`EName[102]`**. This is **not**
PlayerController-specific — `EName[102]` is the UE5 hardcoded-name token for the
generic actor-channel class name (`NAME_Actor`). **Every** actor channel in the
capture (ch=32, 55, 78, 90, 100, 101, 104, 108, 110, 111, 127, 137, 147, …) opens
with `ch_name='EName[102]'`. So the discriminator is **not** the channel name —
it is the **decoded class path string inside the ActorOpen replicated body**, and
that string is unique to ch=3. CONFIRMED.

---

## 2. The rec#22 ActorOpen — byte-exact structure (CONFIRMED)

`pkt#22` (`seq=14287`, `bsb=162`, `bb=6104`, raw 784 bytes) holds **4 bunches, all
on ch=3**, forming **two partial chains**:

| bunch | ctrl | open | reliable | partial | p_init | p_fin | ch_seq | bdb | exports | must_map |
|---|---|---|---|---|---|---|---|---|---|---|
| [0] | 1 | **1** | 1 | 1 | 1 | 0 | **954** | 3545 | **1** | 0 |
| [1] | 0 | 0 | 1 | 1 | 0 | **1** | **955** | 1314 | 0 | 0 |
| [2] | 0 | 0 | 1 | 1 | 1 | 0 | 956 | 873 | 1 | 0 |
| [3] | 0 | 0 | 1 | 1 | 0 | 1 | 957 | 173 | 0 | 0 |

- **Chain A = bunch[0]+bunch[1]** (`ch_seq 954→955`) is the **PlayerController
  ActorOpen**: `open=1`, `has_exports=1`, reassembled to **3545 + 1314 = 4859
  bits** (608 bytes). This is the bunch decoded in §1.
- **Chain B = bunch[2]+bunch[3]** (`ch_seq 956→957`) is an immediate **follow-up
  reliable replication** on the same channel (1046 bits; another exports chunk),
  not a second open.

The reassembled Chain-A first 16 bytes:

```
06 00 00 00 66 78 54 22 eb af 3f 61 00 00 00 00
```

- `06 00 00 00` = **NumGUIDs = 6** (LE u32 export-section prefix). CONFIRMED.
- The following bytes `66 78 54 22 eb af 3f 61 …` are the **AoC-custom GUID-export
  records**. A stock UE5 `SerializeIntPacked64` walk of them **misaligns** (yields
  objid=25, 21, 50591226, then zero-runs — clearly garbage), which is exactly the
  documented "dense AoC export encoding" wall (`POSSESSION-FROM-REPLAY.md §1, §5`).
  The export GUIDs therefore can **not** be recovered by a bare SIP64 read — only
  the FString class/level paths inside the body are cleanly decodable, and those
  are what give the identification. CONFIRMED (negative on bare-SIP64 export read).

**Total channel reuse:** ch=3 yields **5** reassembled chains across the session
(the PC's reliable bunch stream is long-lived); rec#22's chain (4859 bits) is the
first and is the ActorOpen.

---

## 3. The documented PC instance NetGUID 10341530 is NOT readable from this open

**CONFIRMED negative.** Searching the reassembled 4859-bit ch=3 ActorOpen for
ObjectId **10341530** (the "real PC NetGUID ~10341530" cited in the task) as a
bare `SerializeIntPacked64(objid<<1|dyn)` at **every** bit offset returns **zero
hits**. This is the *expected* result and is consistent with §2: the PC's instance
NetGUID lives inside the AoC-custom export block whose encoding stock decoders
misalign, so the raw ObjectId is not exposed as a clean bare ref here. The value
10341530 must come from the proxy/AOC.log oracle or the export-block RE, **not**
from a bare read of this bunch.

> Note: this is the same class of result as `POSSESSION-FROM-REPLAY.md §1`, which
> reported the PC instance NetGUID (~10341530) "could not be recovered from a bare
> SerializeNewActor read". This worker confirms it independently.

---

## 4. Cross-check: ch=3 is consistent with every other PC anchor in the repo

- **Emulator emits the PC on ch=3.** `clientrestart-wire.md`, `pc_emitter.cpp`,
  and the possession path all assume the PlayerController channel = `ch=3`. This
  decode **confirms** that assumption against the retail wire. CONFIRMED.
- **The stuck-client poll rides ch=3.** `stuck-ch3-bunch.md` decodes the 241-bit
  unreliable client→server poll (`ServerCheckClientPossession`) as a content block
  on **ch=3** ("the bunch rides an open actor channel ch=3 = PlayerController").
  Same channel — consistent. CONFIRMED cross-ref.
- **SerializeNewActor topology.** The ch=3 open carries the level outer chain
  `/Game/Levels/Verra_World_Master/Verra_World_Master` + `PersistentLevel`, the
  expected `Outer` chain for a PlayerController spawned into the persistent level.
  CONFIRMED.
- **Channel-name token `EName[102]` is shared by all actor channels** (§1) — it is
  NOT evidence for/against PC; only the class-path string is. Documented here so a
  future reader does not mistake `EName[102]` for a PC marker.

---

## 5. Implications for the possession path

1. **The `ch=3` assumption is validated.** The emulator does not need to change the
   PlayerController channel index — `ch=3` is correct against retail. Any
   ClientRestart framing work should continue to target ch=3.
2. **The capture does not hand us the PC instance NetGUID as a clean field** (§3),
   so the native path's choice to mint its own PC/Pawn GUIDs
   (`native-pawn-guid.md`) rather than reproduce the captured 10341530 is sound —
   there is no readable captured value to copy, and the client only needs the CR
   to reference *whatever* Pawn the native ActorOpen registered.
3. **The selector/framing bug is unaffected by this finding** — channel identity
   was never the blocker. This result removes `ch=3` from the list of suspects and
   re-focuses the live-oracle work (selector 31/69/129 "Invalid replicated field
   0"; 73/170 "ReadContentBlockPayload FAILED") squarely on the **content-block
   framing** inside the ch=3 bunch, per the REAL-RECEIVER-FRAMING analysis. The
   channel is right; the field framing is the problem.

---

## 6. CONFIRMED vs INFERRED

**CONFIRMED (decoded from the wire this pass):**
- **PlayerController channel = `ch=3`** — the only channel whose ActorOpen carries
  `AoCPlayerControllerBP` / `Default__AoCPlayerControllerBP_C`.
- rec#22 = `pkt#22` (seq 14287) holds 4 ch=3 bunches; the ActorOpen is the
  `ch_seq 954→955` partial chain (3545+1314 = **4859 bits**), `has_exports=1`,
  `NumGUIDs=6`, first bytes `06 00 00 00 66 78 54 22 eb af 3f 61 …`.
- The ch=3 channel-name token is the generic `EName[102]` (NAME_Actor), shared by
  ALL actor channels — NOT a PC discriminator.
- ObjectId 10341530 is NOT readable as a bare SIP64 in the ch=3 open (AoC-custom
  export encoding hides it).
- ch=3 carries the Verra_World_Master / PersistentLevel level outer chain and the
  `/Script/GameSystemsPlugin` GlobalGMCommands replicated subobject.

**INFERRED:**
- The 6 NetGUID exports in the open include the PC instance GUID, the
  `AoCPlayerControllerBP_C` class GUID, and the level/archetype outer GUIDs — but
  their exact values are NOT recoverable here because the AoC-custom export
  encoding misaligns a stock SIP64 walk.
- The Chain-B follow-up (`ch_seq 956→957`, 1046 bits) is the PC's first
  replicated-property delta after open (not independently class-decoded).

**Bottom line:** The emulator's PlayerController channel = `ch=3` is **CONFIRMED
correct** against the retail capture, by the decoded class name in the rec#22
ActorOpen — upgrading the prior inference to a hard fact. Channel identity is not
the possession blocker; the content-block field framing on ch=3 is.

---

## 7. Reproduction

The identification reproduces from two independent paths:

1. **`src/protocol/tools/identify_channels_output.txt`** (already in repo) —
   lines 17-24 show the same two PC strings on ch=3 (BDB=4859, EName[102]).
2. A self-contained scan over `phase1_parser.reassemble_partial_bunches`
   (this pass, run against `fixtures/replay_data.bin`): for each channel's first
   open, scan the reassembled body for FStrings; only ch=3 yields
   `*PlayerController*`. The byte-exact rec#22 structure in §2 is read directly
   from `parse_packet(packets[22])`.
