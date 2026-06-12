# mine-bunch-header — CURRENT-binary bunch-header reader (UNetConnection::ReceivedPacket)

Focus: confirm the reliable/partial/chseq/ChName framing in the **current**
binary (image base `0x140000000`). The prior "stale-binary" worry does **not**
apply to the bunch-header layer: the bunch-header reader is `sub_144230D50`,
which is the LIVE `UNetConnection::ReceivedPacket` in the current build (all its
string xrefs are at `0x14423xxxx`, the current `.text`).

## Sources (all current-base)
- `docs/ida-dumps/sub_144230D50.txt` — full Hex-Rays decompile of the reader (1467 lines). **PRIMARY.**
- `docs/ida-dumps/ALLBUNCHKEYWORD.txt:103-117,410-444` — string xrefs proving `sub_144230D50` owns the bunch-header logs (current base).
- `C:\Tools\ghidra-out\decomp2\141d44440_FUN_141d44440.c` — `LexToString(ENetCloseResult)`: the exact close-reason enum (current binary). CALLERS include `144230c30`/`14422e710` (the ReceivedPacket cluster).
- `C:\Tools\ghidra-out\strings_keyword.txt:330-394,522-537` — current-base bunch strings (for the `UChannel::ReceivedRawBunch`/`ReceivedNextBunch`/`ProcessBunch` layer, owned by `sub_143F32E00` / `sub_143F34BA0`).
- `src/net/game_server.h:2042-2122,2143-2230` — our emitter's bunch-header writer + scanner (the side we control).

CONFIRMED = read directly from the decompile. INFERRED = derived from UE5 layout + decompile shape.

---

## 1. `sub_144230D50` IS `UNetConnection::ReceivedPacket` (CONFIRMED)

`ALLBUNCHKEYWORD.txt` lines 103-117 — every bunch-header log string is `lea`'d
from inside `sub_144230D50` at current-base addresses:

| offset | string (off_…) | meaning |
|---|---|---|
| `+0xE83` | `   Reliable Bunch, Channel %i Sequence %i` (off_14A9D1BC0) | bReliable verbose |
| `+0xC2D`-ish | `   Unreliable Bunch, Channel %i: Size` (off_14A9D1C58) | bUnreliable verbose |
| `+0xC93`-ish | `   bOpen Bunch, Channel %i Sequence %i:` (off_14A9D1CE0) | bOpen verbose |
| `+0x135F` | `Ignoring Bunch for ChIndex %i …rejected` | dup-channel reject |
| `+0x16DA` | `Ignoring Bunch Create received from client…` | server-only-create guard |
| `+0x19F5` | `Open bunch with invalid actor guid, Channel` | AoC actor-GUID guard |
| `+0x1AE0` | `Bunch Create %i: ChName %s, ChSequence: %i, bReliable…` (off_14A9D2AC0) | the header-decoded log |
| `+0x2228` | `Bunch data overflowed (%i %i+%i/%lld)` | → close `BunchDataOverflow` (0x25) |
| `+0x2256` | `Bunch header overflowed` | → close `BunchHeaderOverflow` (0x24) |
| `+0x22AF` | `Bunch channel index exceeds channel limit` | → close `BunchBadChannelIndex` (0x21) |

The function signature (`sub_144230D50.txt:1`):
`__int64 __fastcall sub_144230D50(__int64 a1 /*UNetConnection* */, __int64 a2 /*FBitReader* */, unsigned int a3 /*PacketId*/, _BYTE *a4 /*&bOutSkipAck*/, _BYTE *a5 /*&bOutHasBunchErrors*/)`.

The per-bunch loop is `while (*(_DWORD*)(a1+404) != 1)` (line 254); each iteration
reads ONE bunch header then dispatches via `sub_143F34BA0`
(`UChannel::ReceivedRawBunch`, line 1379).

---

## 2. The bunch-header bit layout (CONFIRMED, LSB-first per byte)

The flag byte is the local `v188` (an `FInBunch` flag bitfield). Each header bit
is a single LSB-first `ReadBit` of the form
`(1 << (bitpos & 7)) & buf[bitpos>>3]`, `bitpos = *(a2+168)` (the bit cursor),
buffer at `*(a2+144)`, max-bits at `*(a2+160)`. Trace, in wire order:

| # | decompile | v188 bit | UE field | notes |
|---|---|---|---|---|
| 1 | line 282 `v14` | (gate) | **bControl** | if set → control-message chain (NMT). Read FIRST. |
| 2 | line 294-306 `v22`→`v188&0xFE` | **bit0** | **bIsReplicationPaused** (`v22`) | the actor/rep-paused flag |
| 3 | line 318-323 `v18`→`(v17&0xFD)|2*v18` | **bit1** | **bReliable** | when set, a 15-bit value (`v190`, line 330, `vtable+0x190`, max=15) is read — this is the *bControl* message type, NOT chseq (chseq is later) |
| 4 | line 362-371 `v25`→`(v188&0xFB)|4*v25` | **bit2** | **bOpen** (`v25`) | |
| 5 | line 378-387 `v28`→`(v27&0xF7)|8*v28` | **bit3** | **bClose** (`v28`) | the `Bunch Create` log prints `(v188>>3)&1` as **bReliable**, see §3 — so the *log's* bReliable arg = bit3. The on-wire order is what matters; see WARNING below. |
| 6 | line 391 / 407 `v185`=channel index | — | **ChIndex** | `vtable+0x198` packed read (`v176`) when `v10>=3`; else `vtable+0x190` SerializeInt max=10240. Bounds-checked vs `*(a1+5208)` → `BunchBadChannelIndex` (0x21) on overflow (line 393-401, `+0x22AF`). |
| 7 | line 544-554 `v41`→`(v188&0x7F)|v41<<7` | **bit7** | **bHasPackageMapExports** (`v41`) | the PME flag (`v188 & 0x80` is tested at line 796 → close `BunchServerPackageMapExports` 0x26) |
| 8 | line 561-571 `v50`→`v189` bit0 | (`v189` b0) | **bHasMustBeMappedGUIDs** | separate flag byte `v189` |
| 9 | line 578-589 `v52`→`(v54&0xEF)|16*v52` | **bit4** | **bPartial** (`v52`) | the `Bunch Create` log prints `(v188>>4)&1` as bPartial (line 1184/1311) |
| 10 | line 590-595 / 1439-1452 | — | **ChSequence** (`v187`) | read ONLY if bClose-bit (`v54 & 8`) set. **AoC-flag path** (`*(a1+240)&1`): `v187 = AckSeq[chidx] + 1` (line 595, no wire bits). **Stock path** (line 1439-1442): read **10-bit** value (`vtable+0x190`, **max=1024**), then delta-reconstruct `v57 = base + (((read - base - 512) & 0x3FF) - 512)` → `MAX_CHSEQUENCE = 1024` (10-bit). |
| 11 | line 598-617 `v58`→`(v54&0xDF)|32*v58` | **bit5** | **bPartialInitial** (`v58`) | read only if bPartial (bit4) set |
| 12 | line 620-642 `v61`→`v189` bit1 | (`v189` b1) | (partial-merge-destroy flag) | read only if bit4 set AND `v168` |
| 13 | line 644-663 `v63`→`(v65&0xBF)|v63<<6` | **bit6** | **bPartialFinal** (`v63`) | read only if bPartial (bit4) set |
| 14 | line 664-714 (`v66 = v65 & 9`) | — | **ChName / EName** | read if (bit0 OR bit3) set. AoC-flag path: `vtable+0x190` read of a 3-bit selector (`v167`, max=8) → switch: case 1 → `SerializeInt(max=255)` (`sub_141505900(…,255)`, the EName=255 control name), case 2 → `max=102`, case 4 → `max=256`. Stock path: read FName directly (`sub_14168B8D0`, line 669). |
| 15 | line 748-752 | — | **BunchDataBits (BDB)** | `vtable+0x190` SerializeInt with **max = `8 * *(a1+192)`** (i.e. `8 * MaxPacketBytes`). Followed by `Bunch.SetData` (`sub_1414F3CC0`, line 784). Overflow → `BunchHeaderOverflow`/`BunchDataOverflow` (line 776-794, `+0x2256`/`+0x2228`). |

> **WARNING on bit names (INFERRED ordering caveat):** The `Bunch Create` log
> at `off_14A9D2AC0` passes `v185`(ChIndex), ChName, `v164=v187`(ChSequence),
> then `v165=(v188>>3)&1` and `v166=(v188>>4)&1` (lines 1311-1314). The printf
> format is `…bReliable: %i, bPartial: %i, bPartialInitial: %i, bPartialFinal: %i`,
> so UE *labels* bit3 as "bReliable" and bit4 as "bPartial" **in that log**.
> However the *wire read order* above (bit1 is the reliable-gated 15-bit read,
> bit3 gates the ChSequence read, bit4 gates the partial-initial/final reads) is
> what the decompile actually executes. The safe, load-bearing facts are the
> **read order** and the **widths** (rows 6/10/14/15), not the human labels.

---

## 3. The two LOAD-BEARING corrections for our emitter

### (a) CONFIRMED BUG: ChSequence is **10-bit (max=1024)**, not 12-bit
`sub_144230D50.txt:1441-1442`:
```c
(*(...)( *(_QWORD*)a2 + 400 ))(a2, &v167, 1024);          // SerializeInt(value, 1024) → 10 bits
v57 = v56 + (((WORD)v167 - (WORD)v56 - 512) & 0x3FF) - 512;  // delta, mask 0x3FF = MAX_CHSEQUENCE 1024
```
So **`MAX_CHSEQUENCE = 1024` (10 bits)** in the current binary.

Our emitter is INCONSISTENT about this:
- The runtime chseq math is **correct**: `chseq = (last+1) & 0x3FF` (10-bit)
  at `game_server.h:1362,1434,2077,2110`. The `& 0x3FF` masks are right.
- But the DOC comments are WRONG and will mislead future framing work:
  - `game_server.h:746-747`: "S>C ChSequence is 12-bit (MAX_CHSEQUENCE = 4096)" — **FALSE**, it is 10-bit/1024.
  - `game_server.h:2149`: "`+ ChSeq(12) IF bReliable`" in `scan_outgoing_packet_chseq`'s header doc — **FALSE**, should be `ChSeq(10)`.

  These are comment-only (the actual masks are 10-bit), so they don't currently
  corrupt the wire, but any code that trusts the "12-bit" comment to *parse* a
  ChSeq field will mis-align by 2 bits. **Fix the comments to 10-bit.**

  Note also the gate: ChSequence is read **only when the bClose-bit (`v54 & 8`)
  is set** (line 590) — i.e. the receiver couples the sequence-read to that flag,
  not to "bReliable" as the comment implies. (Stock-UE5 normally gates ChSeq on
  `bReliable || bOpen`; here the decompile gates on bit3. If a ch=3 reliable
  bunch is ever sent with bit3 clear, the receiver will NOT consume a ChSeq —
  verify our reliable bunches set the flag the receiver expects.)

### (b) ChName / EName read width (CONFIRMED, matches emitter)
Receiver (line 686-708): when the ChName-present gate fires, it reads a 3-bit
selector (max=8) and then a sub-read at max **255** (case 1, control name),
**102** (case 2), or **256** (case 4). Our emitter writes
`write_sip(EName=255)` then `bIsHardcoded=1` (game_server.h:2078-2079). The
emitter's SIP write of 255 is reachable, but the receiver's first read here is a
**fixed-width `SerializeInt(max=8)` selector**, not a bare SIP — the selector
value (1/2/4) chooses which EName-width follows. For the ch=0 control name the
selector=1 → max=255 path. This needs a parity check against our ch=0 control
bunches (the control path works today, so it is at least functionally aligned),
but the receiver's selector-then-width shape is NOT the plain `SIP(255)` our
comment describes. Mark for follow-up if ch=0 control framing ever regresses.

### (c) Channel-limit (CONFIRMED)
`*(a1 + 5208)` is `MaxChannelSize` (the channel count). ChIndex `>= *(a1+5208)`
→ `BunchBadChannelIndex` (close reason 0x21). Our ch=3 is well within range; not
a current risk, but documents the bound.

---

## 4. The AoC-custom inline actor-GUID in the bunch header (CONFIRMED, NEW)

`sub_144230D50.txt:1218-1304` is an **AoC-specific** branch (gated by
`*(a1+240)&1` AND `*(a1+6904)`) that runs for an **bOpen** bunch
(`(v188 & 1) != 0` AND not a partial-continuation) whose ChName resolves to the
AoC actor ename (`v186 == 102`, line 1222). It reads a **FIntrepidNetGUID inline
in the bunch header** via `sub_1442360E0(a1, &v194, &v178)` and logs
`ObjectId: %llu | ServerId: %u | Randomizer: %u` (line 1240/1274 — the 128-bit
`{ObjectId(u64), ServerId(u32), Randomizer(u32)}`). It then registers the GUID
into the connection's actor-GUID map (`a1+6824`, `sub_141462460`, line 1248).

Implication for possession framing: the actor-channel **open** carries the
FIntrepidNetGUID **in the bunch header here**, ahead of the content blocks. This
is the bunch-header-level home of the 128-bit AoC GUID, and it is keyed off
`ChName == 102` (the same value seen as case-2 in the EName switch at line 695).
This is consistent with — and upstream of — the content-block field decode that
`REAL-RECEIVER-FRAMING.md` analyzes. **For ch=3 (PlayerController) our bunches
do not take this open path** (we send onto an already-open channel), so this
branch is informational, but it pins `ChName=102` as the AoC actor-channel ename
constant.

---

## 5. ENetCloseResult enum (CONFIRMED) — the close-reason oracle

`141d44440_FUN_141d44440.c` is `LexToString(ENetCloseResult)`. The bunch-layer
reasons the receiver can emit from `sub_144230D50` and the channel layer:

| # | name | trigger |
|---|---|---|
| 0x1e | ReadHeaderFail | outer packet header |
| 0x1f | ReadHeaderExtraFail | outer packet header (AoC extra) |
| 0x21 | BunchBadChannelIndex | ChIndex ≥ MaxChannelSize (`+0x22AF`) |
| 0x22 | BunchChannelNameFail | ChName read failed |
| 0x23 | BunchWrongChannelType | ename mismatch vs open channel (line 740, `sub_143F174A0(…,0x23)`) |
| 0x24 | BunchHeaderOverflow | header bits exceeded (`+0x2256`) |
| 0x25 | BunchDataOverflow | BDB exceeded (`+0x2228`) |
| 0x26 | BunchServerPackageMapExports | client set PME flag (`v188 & 0x80`, line 802) |
| 0x2C | (PrematureSend-ish) | line 1400 `sub_143F174A0(…,0x2C)` |
| 0x4e | ContentBlockFail | content-block payload (the §REAL-RECEIVER zone) |
| 0x5c-0x5f | FieldHeader{RepIndex,BadRepIndex,PayloadBitsFail},FieldPayloadFail | the field-record layer |

If a future test sees the connection close, `FUN_141d44440(reason)` decodes
exactly which header/field stage failed. **None of 0x21-0x26 are in our current
oracle table** (which shows ContentBlock/Field-layer errors) — strong evidence
that **our bunch HEADER parses cleanly** and the fault is purely in the
content-block/field payload, consistent with `REAL-RECEIVER-FRAMING.md`.

---

## 6. Verdict

- **Bunch HEADER framing is NOT the bug.** The header reader is `sub_144230D50`
  (current binary, CONFIRMED). Our emitter's header bit-order and the 10-bit
  chseq masks are correct on the wire; the only header-level defects are
  **stale comments** claiming 12-bit ChSeq (`game_server.h:746-747,2149`) — fix
  to 10-bit to avoid future mis-parsing.
- **ChSequence width = 10-bit / MAX_CHSEQUENCE = 1024** (CONFIRMED, line 1441).
- **ChName ename constant for AoC actor channels = 102** (CONFIRMED, lines 695,1222).
- **MaxChannelSize bound at `conn+5208`**; AoC-flag at `conn+240 & 1`; AckSeq
  table at `conn+5232` (`v187 = AckSeq[ch]+1` on the AoC path).
- The 128-bit FIntrepidNetGUID is read **inline in the bunch header** on the AoC
  bOpen path (lines 1218-1248) — not relevant to our already-open ch=3 sends but
  documents where the GUID lives at the header layer.
- Confirms `REAL-RECEIVER-FRAMING.md`'s conclusion from the opposite direction:
  since no `Bunch*`/`ReadHeader*` close reason (0x1e-0x26) appears in the oracle,
  the header is consumed correctly and the remaining work is entirely in the
  content-block/field decode.
