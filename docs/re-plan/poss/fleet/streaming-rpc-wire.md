# Streaming make-visible handshake — full wire formats: CUSLSS + SULV + CALV

**Date:** 2026-06-09
**Type:** READ-ONLY RE note (fleet). Focus task: document the full 7-param
`ClientUpdateLevelStreamingStatus` (CUSLSS, S→C), `ServerUpdateLevelVisibility`
(SULV, C→S), and `ClientAckUpdateLevelVisibility` (CALV, S→C) wire formats so the
World-Partition make-visible handshake completes and the "Waiting for World
Partition Streaming" screen clears.

Image base `0x140000000`. LSB-first per byte (UE5 `FBitReader`). Every claim is
tagged **CONFIRMED** (read at a cited `file:line` / SDK dump / decompiled VA /
oracle fact stated in prior notes) or **INFERRED** (derived; needs a live relogin
to verify).

---

## 0. TL;DR — the one finding that matters

**All three RPCs are structurally built.  Before the 2026-06-11 emitter fix, the
two S→C RPCs (CUSLSS and CALV) almost certainly never dispatched, because their
field selector landed on the WRONG (or empty) `FClassNetCache` slot.** This is
the SAME receiver-framing bug the ClientRestart oracle anchors describe
— the selector VALUE the emitter writes is a red herring; what matters is that
the S→C receiver
(`FUN_143f30e10`, flag0 path) reads the selector as a **bounded `SerializeInt`,
NOT `SerializeIntPacked`**, and indexes a sparse 40-byte/0x18-stride class-segment
array. The legacy emitters wrote SIP. Concretely (CONFIRMED by computation, §5):

| RPC | emitter writes | receiver (8-bit SerializeInt) decodes it as | correct FieldNetIndex (rank-1 table) | lands on |
|-----|----------------|---------------------------------------------|---------------------------------------|----------|
| **CUSLSS** | `SIP(53)` = byte `0x6A` | value **106** | **151** | `ClientCapBandwidth` (106, NET prop) — wrong RPC |
| **CALV** (legacy) | `SIP(7)` = byte `0x0E` | value **14** | **103** | `bCanBeDamaged` (14, NET prop, no dispatch) — silent no-op |

The CALV and CUSLSS encoders now both default to probe-switchable
`SerializeInt(handle, max)` framing: CALV handle **103**, CUSLSS handle **151**,
with `max=216` first and `256` as the live fallback probe.  The legacy SIP paths
remain available only as rollback probes. The SULV (C→S) decode is sound
(payload struct correct; `VisibilityRequestId` now harvested live). See §6 for
the live verification order.

> **Bottom line:** the make-visible handshake's wire payloads are all correct;
> the fixed default is the **field-selector framing** of the two S→C RPCs:
> `write_serialize_int(value, max≈216/256)` with value **151 (CUSLSS) / 103
> (CALV)** and the content-block field-record envelope, matching the
> ClientRestart path now used by the native emitter.

---

## 1. SDK ground truth — the three RPC param structs (CONFIRMED)

All from the Dumper-7 SDK in `docs/aoc-sdk/CppSDK/SDK/`.

### 1.1 `ClientUpdateLevelStreamingStatus` (S→C) — 7 params, ParmsSize 0x18
`Engine_classes.hpp:8369` (decl), `Engine_parameters.hpp:10337-10350` (Parms):

| # | Param | Type | C++ off | Wire serialization |
|---|-------|------|---------|--------------------|
| 1 | `PackageName` | `FName` | 0x00 | bit-packed FName: `[1]bIsHardcoded` then soft form `[i32 SaveNum=len+1][N ASCII][8 NUL][i32 Number=0]`, OR hardcoded `SIP(EName)` |
| 2 | `bNewShouldBeLoaded` | `bool` | 0x08 | 1 bit |
| 3 | `bNewShouldBeVisible` | `bool` | 0x09 | 1 bit |
| 4 | `bNewShouldBlockOnLoad` | `bool` | 0x0A | 1 bit |
| 5 | `LODIndex` | `int32` | 0x0C | 32 bits LSB-first (0 = full detail; non-0 = HLOD proxy) |
| 6 | `TransactionId` | `FNetLevelVisibilityTransactionId` (`uint32 Data`) | 0x10 | 32 bits LSB-first |
| 7 | `bNewShouldBlockOnUnload` | `bool` | 0x14 | 1 bit |

CONFIRMED 7-param UE 5.1+/5.2+ form (NOT the 4-param UE 5.0 form). `Pad_B[0x1]`
at 0x0B is C++ struct padding only — **not on the wire**.

### 1.2 `ServerUpdateLevelVisibility` (C→S) — 1 struct param, 0x18 bytes
`Engine_classes.hpp:8408`, `Engine_parameters.hpp:10600-10604`. The struct
`FUpdateLevelVisibilityLevelInfo` (`Engine_structs.hpp:10163-10174`, CONFIRMED
offsets):

| Off | Field | Type | Wire |
|-----|-------|------|------|
| 0x00 | `PackageName` | `FName` | bit-packed FName (soft or hardcoded) |
| 0x08 | `Filename` | `FName` | bit-packed FName — **second name, present on wire** |
| 0x10 | `VisibilityRequestId` | `FNetLevelVisibilityTransactionId` (`uint32 Data`) | 32 bits LSB-first |
| 0x14 bit0 | `bIsVisible` | `bool:1` | 1 bit |
| 0x14 bit1 | `bTryMakeVisible` | `bool:1` | 1 bit |
| 0x14 bit2 | `bSkipCloseOnError` | `bool:1` **(RepSkip)** | 1 bit, may be omitted on wire (RepSkip) |

`Pad_15[0x3]` is C++ padding only.

### 1.3 `ClientAckUpdateLevelVisibility` (S→C) — 3 params, ParmsSize 0x10
`Engine_classes.hpp:8320`, `Engine_parameters.hpp:9909-9917` (CONFIRMED):

| # | Param | Type | C++ off | Wire |
|---|-------|------|---------|------|
| 1 | `PackageName` | `FName` | 0x00 | bit-packed FName |
| 2 | `TransactionId` | `FNetLevelVisibilityTransactionId` (`uint32 Data`) | 0x08 | 32 bits LSB-first — **MUST echo the SULV `VisibilityRequestId`** |
| 3 | `bClientAckCanMakeVisible` | `bool` | 0x0C | **1 bit** (FBoolProperty NetSerialize = 1 bit, not 1 byte) |

`FNetLevelVisibilityTransactionId` = `struct { uint32 Data; }`, size 0x4
(`Engine_structs.hpp:9979-9983`). CONFIRMED.

### 1.4 Batch siblings (for completeness)
- `ClientUpdateMultipleLevelsStreamingStatus(TArray<FUpdateLevelStreamingLevelStatus>)`
  (`Engine_classes.hpp:8370`). `FUpdateLevelStreamingLevelStatus`
  (`Engine_structs.hpp:10129-10139`): `PackageName(FName@0x00)`,
  `LODIndex(int32@0x08)`, then 4 bools (`bNewShouldBeLoaded@0x0C`,
  `bNewShouldBeVisible@0x0D`, `bNewShouldBlockOnLoad@0x0E`,
  `bNewShouldBlockOnUnload@0x0F`). **Field order differs from the single RPC
  (LODIndex is 2nd here) and there is NO TransactionId.** CONFIRMED.
- `ServerUpdateMultipleLevelsVisibility(TArray<FUpdateLevelVisibilityLevelInfo>)`
  (`Engine_classes.hpp:8409`). This is the batched C→S form; the emulator does
  not recognize it (single-cell harvest only).

---

## 2. The S→C receiver framing — why the selector VALUE is the bug (CONFIRMED decode)

Both CUSLSS and CALV are S→C RPCs delivered on the PlayerController channel (ch=3)
and therefore pass through the SAME receiver chain identified in RE:
`FUN_143f329d0` (ReceivedBunch) → `FUN_143f30bf0` (ReadContentBlockPayload) →
`FUN_143f2f4f0` (ReadContentBlockHeader) → **`FUN_143f30e10`
(ReadFieldHeaderAndPayload)**.

`FUN_143f30e10` decompile (`docs/re-plan/poss/_ghidra_decomp_out2.txt:5-101`),
flag0 path (`(*(*(conn+0x60)+0x48)+0xF0)&1 == 0`, line 44):

```c
// line 46  — read the selector as a BOUNDED SerializeInt, NOT SerializeIntPacked:
(**(code **)(*param_5 + 400))(param_5, &param_6, param_3[10] + *param_3 + 1);
//   value = param_6 ; max = (segment_base *param_3) + (segment_count param_3[10]) + 1
// line 49  — out-of-range ⇒ "ReadFieldHeaderAndPayload: RepIndex..." reject (line 55)
// line 68-77 — walk class segments, stride 0x18:
//   entry = *(param_3+8) + ((int)param_6 - *param_3) * 0x18   (line 70)
//   if entry == 0 → "Invalid replicated field" (the empty-slot reject)
```

**Decisive facts:**
1. The selector is decoded with `SerializeInt(value, max)` (FBitReader vtbl+400),
   **not** `SerializeIntPacked`. CONFIRMED at line 46. The emitters writing
   `write_sip(handle)` produce a byte the receiver re-interprets as a fixed-width
   `SerializeInt` — a different value (§5).
2. The index space is a flat, sparse array; empty entries print "Invalid
   replicated field" (the §0/oracle anchor). To dispatch an RPC the value must
   land on the OCCUPIED slot holding that RPC's `FieldNetIndex`.
3. The correct `FieldNetIndex`es come from the rank-1 `FClassNetCache` table
   (`docs/re-plan/poss/CLASSNETCACHE-TABLE.md §6`, CONFIRMED-by-construction
   against the live oracle): **CUSLSS = 151** (`CLASSNETCACHE-TABLE.md:191,262`),
   **CALV = 103** (`:190,268`), FieldCount = 216.

This is why the oracle says selector 31/69/129 → "Invalid replicated
field 0" and 62 → silent: those land on empty / property slots. CUSLSS's SIP-53
and CALV's SIP-7 are the streaming analogue of the same class of mistake.

---

## 3. What the emulator builds today (CONFIRMED file:line)

### 3.1 CUSLSS — `PcEmitter::build_streaming_status_bunch` (`src/net/pc_emitter.cpp:1230-1304`)
The **payload is correct** (7-param form, params 6 & 7 present):
- Param 1 FName soft form: `[0]bIsHardcoded` + `write_fstring(pkg)` +
  `write_uint32(0)` Number (`:1245-1247`).
- Params 2-4 bools (`:1250-1252`), Param 5 `write_uint32(LODIndex)` (`:1255`),
  Param 6 `write_uint32(transaction_id)` (`:1259`), Param 7
  `write_bit(block_on_unload)` (`:1261`).
- **Selector — fixed default:** `rpc_payload.write_serialize_int(p.field_handle,
  p.field_max)` with `field_handle=151`, `field_max=216`, and a
  `probe_streaming_keepalive_serializeint.txt=0` rollback to legacy SIP.
- Envelope: content block `[0]bHasRepLayout [1]bIsActor [SIP outer_bits]`
  (`:1276-1279`), ch=3 reliable `NAME_Actor` `PropertyUpdateBunchBuilder`
  (`:1288-1296`).

Defaults (`pc_emitter.h:106-115`): `should_be_loaded=true`,
`should_be_visible=true`, `block_on_load=false`, `lod_index=0`,
`transaction_id=0`, `block_on_unload=false`, `field_handle=151`,
`field_max=216`, `use_serializeint=true`. Params 2-5,7 are the correct residency
values; live verification is now about `field_max` (216 vs 256) and transaction
ID correlation (§4), not SIP selector framing.

Driver: `GameServer::emit_level_streaming_status` (`game_server.h:1340-1390`)
bakes a live ch=3 reliable chSeq (`cs.last_outgoing_reliable_chseq[3]+1`,
`:1358-1363`) and bumps the tracker on success (`:1383`) — chSeq bookkeeping is
CONFIRMED correct. `drive_streaming_keepalive` (`:1467-1494`) iterates the full
`streaming_relevant_cells` set at ~1 Hz.

### 3.2 CALV — `send_client_ack_update_level_visibility` (`game_server.h:8071-8380`)
**ENABLED** now (`kSendSulvAckStub = true`, `game_server.h:5312` — past the
earlier doc state which had it `false`). Two framing paths gated by
`probe_calv_serializeint.txt`:

- **Legacy path (probe "0" only):** writes a single dispatch byte
  `SIP(7) = 0x0E` (`:8328`), then the 3 params. **This lands on empty slot 14
  (§5) — the no-op earlier history describes.**
- **SerializeInt path (default, probe absent/"1"):** writes the content-block field-record
  framing (`:8287-8294`): `[0]bHasRepLayout [1]bIsActor [SIP outer_bits]` then
  `write_serialize_int(calv_handle, calv_max)` + `SIP(param_bits)` + params.
  Defaults: `calv_handle=103` (`probe_calv_handle.txt`, `:8252`), `calv_max=216`
  (`probe_calv_max.txt`, `:8254`). **handle 103 is the rank-1-correct CALV index.**

CALV params (both paths, `:8298-8308` / `:8330-8352`): Param 1 FName soft form,
Param 2 `write_bits(visibility_request_id, 32)`, Param 3
`write_bits(1, 1)` (`bClientAckCanMakeVisible` TRUE, 1 bit). CONFIRMED correct
per the §1.3 SDK struct and the client exec-thunk decode `sub_144441E00`
(documented in `we/serverupdatelevelvisibility.md §3`).

Bunch header (`:8091-8151`): ch=3, reliable, 10-bit ChSeq from the per-channel
tracker, ChName `[1]bIsHardcoded + SIP(102=NAME_Actor)`. CONFIRMED width-correct.

### 3.3 SULV decode — `game_server.h:5088-5197` (CONFIRMED improved)
Recognizes SULV by ASCII-scanning the payload for `_Generated_/` (`kSigGenerated`,
`:5089-5098`), harvests the cell `PackageName` (`:5105-5112`), and **now decodes
the live `VisibilityRequestId`** (`:5158-5166`): it skips the zero padding after
the FName ASCII tail (NUL + Number=0) and reads the next `uint32` LSB-first
(empirically at `aftASCII+6` per `:5155`). It records
`streaming_relevant_cells[pkg] = vis_req_id` (`:5180-5197`) for the keepalive,
and queues a CALV per `bTryMakeVisible` SULV (`:5314-5351`), draining inline if
bootstrap is complete (`:5340-5348`).

> This is a real improvement over the older `we/serverupdatelevelvisibility.md`
> note (which said the id was hardcoded 0). **Caveat (INFERRED):** the ASCII-scan
> + fixed-offset uint32 read is heuristic, not a true bit-accurate RPC parse — it
> assumes byte alignment at the cell name and a specific padding layout. It will
> mis-read if `Filename` (the §1.2 second FName at struct +0x08) is non-empty on
> the wire, because then the `VisibilityRequestId` does not sit at a fixed offset
> after `PackageName`. Verify against a live `[SULV-PROBE]` hex dump (`:5141-5148`).

---

## 4. TransactionId correlation — the value that closes the loop (CONFIRMED roles)

There are TWO transaction ids; do not conflate:

| Id | Lives in | Dir | Role |
|----|----------|-----|------|
| **SULV `VisibilityRequestId`** | `FUpdateLevelVisibilityLevelInfo +0x10` (`Engine_structs.hpp:10168`) | C→S | the request the client is **waiting to be confirmed** |
| **CALV `TransactionId`** | CALV param 2 (`Engine_parameters.hpp:9913`) | S→C | **MUST equal** the SULV `VisibilityRequestId` to release the cell |
| **CUSLSS `TransactionId`** | CUSLSS param 6 (`Engine_parameters.hpp:10346`) | S→C | residency-push correlation only; does NOT complete the transaction |

**The make-visible handshake completes when CALV echoes the exact
`VisibilityRequestId`** the client sent in the SULV for that cell, with
`bClientAckCanMakeVisible=1`. CUSLSS is a residency keepalive — it keeps the cell
loaded/visible against GC, but does not satisfy the pending transaction. So:
- CALV param 2 must carry the live `vis_req_id` (the emulator now passes it,
  `game_server.h:5322` → `:8306`/`:8346`). CONFIRMED wired.
- CUSLSS param 6 (`transaction_id`) is fed from `streaming_relevant_cells[pkg]`,
  which now holds the harvested `vis_req_id` (`:5188`, `:1368`). So CUSLSS also
  echoes it — hygiene-correct.

INFERRED: the WP gate is `UWorldPartitionSubsystem::IsAllStreamingCompleted`
(an **all**-pending predicate per `we/clientupdatelevelstreamingstatus.md §2`),
so EVERY relevant cell (~12 around the Riverlands spawn) must be CALV-confirmed,
not just one. The single-cell-harvest limit (ASCII scan `break`s at first
`_Generated_/`, and `ServerUpdateMultipleLevelsVisibility` index 204 unrecognized)
keeps the set small — fix to grow it toward the full set.

---

## 5. The selector arithmetic — exact bytes (CONFIRMED by computation)

Using `ue5::serialize_int_bit_count` / `write_serialize_int`
(`ue5_primitives.h:141-167`) and `write_sip` (`:175-182`):

| What the emitter writes | byte(s) | 8-bit `SerializeInt` decode | rank-1 slot hit | result |
|--------------------------|---------|------------------------------|-----------------|--------|
| CUSLSS `SIP(53)` | `0x6A` | **106** | `ClientCapBandwidth` (NET) | wrong RPC, mis-parses params |
| CALV legacy `SIP(7)` | `0x0E` | **14** | `bCanBeDamaged` (NET prop) | silent no-op (no dispatch) |
| CALV SerializeInt `SInt(103,256)` | `0xCE` LSB-first `11100110` (8 bits) | **103** | `ClientAckUpdateLevelVisibility` | **dispatches** ✓ |
| CUSLSS *should* write `SInt(151,256)` | LSB-first `11101001` (8 bits) | **151** | `ClientUpdateLevelStreamingStatus` | **would dispatch** ✓ |

Width subtlety (CONFIRMED): `serialize_int_bit_count(103, 216) = 7 bits`, but
`serialize_int_bit_count(103, 256) = 8 bits`; `serialize_int_bit_count(151, 216)
= 8 bits` and `(151, 256) = 8 bits`. The receiver's `max` is
`segment_base + segment_count + 1` (`FUN_143f30e10:46`) — for FieldCount 216 that
is exactly 216, so **the emitter's `max` must match the receiver's runtime max
(≈216), or both writer and reader desync by a bit.** The oracle proved the
ClientRestart selector parses at **8 bits** (`CLASSNETCACHE-TABLE.md` C1), which
holds for FieldCount ∈ [198, 256]. Recommended: write `SerializeInt(value, 216)`
(matches the predicted runtime FieldCount) — for value 151 that is the 8-bit
`11101001`; for value 103 it is the **7-bit** `1110011` (NOT 8). If the runtime
FieldCount is actually ≥255, 103 becomes 8 bits. **This is exactly why the CALV
probe exposes `probe_calv_max` — tune it live (216 vs 256) against the oracle.**

---

## 6. Applied defaults and live verification order

1. **CUSLSS default is now SerializeInt, value 151.** `pc_emitter.cpp` writes
   `write_serialize_int(handle, max)` by default, with
   `probe_streaming_keepalive_handle.txt` and `probe_streaming_keepalive_max.txt`
   still available.  Set `probe_streaming_keepalive_serializeint.txt=0` only for
   legacy SIP rollback.
2. **CALV default is now SerializeInt, value 103.** `game_server.h` defaults
   `probe_calv_serializeint` to ON and `probe_calv_max` to 216.  Set
   `probe_calv_serializeint.txt=0` only for legacy SIP rollback.
3. **Verify the FieldCount/max live (216 vs 256).** Probe order for both RPCs:
   `max=216` → if "Invalid replicated field" or no effect, `max=256`. The §5
   width table shows 103 flips 7↔8 bits across this boundary, so a 1-bit desync
   here mis-frames the whole payload. (INFERRED — one relogin each.)
4. **Harden the SULV `VisibilityRequestId` decode.** The current ASCII-scan +
   fixed-offset read (`game_server.h:5158-5166`) assumes `Filename` (FName #2,
   §1.2) is empty and a fixed padding layout. Confirm via the `[SULV-PROBE]` hex
   dump (`:5141-5148`); if `Filename` is present, parse the struct properly
   (two FNames, then the uint32). A wrong `vis_req_id` makes CALV echo a
   non-matching TransactionId and the cell never releases. (INFERRED.)
5. **Grow the cell set to ALL relevant cells.** The ASCII scan records only the
   first `_Generated_/` per bunch (`:5094-5098` `break`s at first match) and the
   batch RPC `ServerUpdateMultipleLevelsVisibility` (rank-1 index **204**,
   `CLASSNETCACHE-TABLE.md:261`) is unrecognized. Iterate every occurrence and
   recognize the batch form so `IsAllStreamingCompleted` can flip. (CONFIRMED gap.)
6. **Keep CUSLSS params 2-5,7 and CALV params as-is** — payloads are SDK-correct
   (§1, §3). Do NOT touch them; the bug is purely the selector framing.

---

## 7. CONFIRMED vs INFERRED summary

| Claim | Status | Source |
|-------|--------|--------|
| CUSLSS = 7-param form; SDK offsets/types | CONFIRMED | `Engine_parameters.hpp:10337-10350`; `Engine_classes.hpp:8369` |
| SULV = `FUpdateLevelVisibilityLevelInfo` (2 FNames + uint32 + 3 bits) | CONFIRMED | `Engine_structs.hpp:10163-10174` |
| CALV = 3 params (FName, uint32 TxnId, 1-bit bool) | CONFIRMED | `Engine_parameters.hpp:9909-9917` |
| S→C receiver decodes selector as `SerializeInt(value, base+count+1)`, NOT SIP | CONFIRMED | `_ghidra_decomp_out2.txt:44-46,68-77` (`FUN_143f30e10`) |
| Empty slot → "Invalid replicated field"; sparse 0x18-stride array | CONFIRMED | `_ghidra_decomp_out2.txt:70-79`; oracle anchors |
| Rank-1 FieldNetIndex: CUSLSS=151, CALV=103, FieldCount=216 | CONFIRMED-by-construction (oracle-fit) | `CLASSNETCACHE-TABLE.md:190-191,262,268` |
| CUSLSS legacy wrote SIP(53)=0x6A → decoded as 106 (wrong RPC) | CONFIRMED; fixed by default | `pc_emitter.cpp`; `pc_emitter.h`; §5 computation |
| CALV legacy writes SIP(7)=0x0E → decoded as 14 (empty/no-op) | CONFIRMED | `game_server.h:8328`; §5 computation |
| CALV defaults to SerializeInt path, handle 103 / max 216 | CONFIRMED | `game_server.h`; §6 |
| `kSendSulvAckStub = true` (CALV enabled now) | CONFIRMED | `game_server.h:5312` |
| SULV recognizer harvests live `VisibilityRequestId` | CONFIRMED | `game_server.h:5158-5166,5188` |
| CALV/CUSLSS echo the harvested `vis_req_id` | CONFIRMED wired | `game_server.h:5322,8306/8346`; `:1368` |
| 103 = 7 bits @max216 but 8 bits @max256 (1-bit desync risk) | CONFIRMED computation | `ue5_primitives.h:156-167`; §5 |
| Runtime FieldCount is exactly 216 (vs 235/241/256) | INFERRED | `CLASSNETCACHE-TABLE.md` (oracle-fit, ~45%) |
| `IsAllStreamingCompleted` gates the UI (ALL cells must ack) | INFERRED-strong | `we/clientupdatelevelstreamingstatus.md §2` |
| SULV `Filename` (FName #2) is empty on wire (fixed-offset read holds) | INFERRED | §3.3 caveat; needs `[SULV-PROBE]` dump |
| `bSkipCloseOnError` (bit2, RepSkip) serialized vs omitted | INFERRED | `Engine_structs.hpp:10171` (RepSkip flag) |

---

## 8. needs_ghidra

**No fresh decompile required to act.** The receiver framing (`FUN_143f30e10`),
the three RPC param structs (SDK), the selector arithmetic (§5), and the
`FClassNetCache` index table (`CLASSNETCACHE-TABLE.md`) are all already RE'd and
present. The two emitter changes are now applied by default (CUSLSS 151
SerializeInt; CALV 103 SerializeInt). Remaining live work is the `max=216/256`
probe and the next ClientRestart/Pawn registration verdict.

**Optional follow-up Ghidra (only if 151/103 both still "Invalid replicated
field" after the §6 fix):** read the cache builder (`GetClassNetCache`-equivalent
`FUN_143f27e50`) for the array `SetNum` value — predicted
`0xD8 (216)` — and read CUSLSS's / CALV's placed `FieldNetIndex` directly, to
confirm 151/103 and the exact runtime FieldCount (resolving the §5 max ambiguity).
