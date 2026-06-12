# ClientRestart RepIndex — Resolution

**Status:** RESOLVED (synthesis of 4 independent RE methods).
**Failure being fixed:** client closes ch=3 with `Invalid replicated field` /
`ObjectReplicatorReceivedBunchFail` after we send ClientRestart with the wrong
`ClassNetCache` FieldNetIndex.
**Receiver:** `sub_143F2DC60` (ReadFieldHeaderAndPayload), AoC-custom Path A
(`*(*(a1+72)+240) & 1` set). It reads
`SerializeInt(&RepIndex, max(2, FieldCount))` via vtable+400, bounds-checks
`RepIndex < FieldCount=*(a4+32)`, then dereferences
`entry = *(a4+24) + 40*RepIndex` and rejects if `*(entry+20) == 0` (empty slot).

---

## 1. CONSENSUS FieldNetIndex

**BEST PICK: `RepIndex = 31`.**

Three of the four methods converge on 31 independently; the fourth (CALV-anchor)
is the only dissenter at 22 and is the weakest because it depends on an
unverified intervening-field count.

| Rank | Value | Methods | Why |
|------|-------|---------|-----|
| **1 (PICK)** | **31** | `ue5-algo-full`, `ue5-algo-funcsonly` (both HIGH), matches codebase `kClientRestartHandle=31` | APlayerController FUNC_Net local index of ClientRestart = 26; the FUNC_Net block base = 5, **anchor-locked** by four live C→S Server* RPC wire bytes (0x76/0x7E/0x80/0x86 → 59/63/64/67), each reproducing `localidx+5` with zero error. 26+5 = 31. |
| 2 | 22 | `calv-anchor` (HIGH but weakest) | Anchors to CALV=7 (client-accepted) + an asserted 14-FUNC_Net gap (delta +15). Plausible, but the gap count is the soft link; try only if 31 fails. |
| 3 | 28 | functions-only base (=2), no reserved slots | Pure UObject0+AActor0+AController2 cumulative base; contradicted by the ServerNotifyLoadedWorld=67 anchor, so almost certainly wrong, but a cheap nearby probe. |
| — | 69 | (current code — WRONG) | `0x45` is the FPropertyParams/FFuncParams descriptor **constant marker** (`+32`), not an index; in runtime numbering 69 ≈ a Server* RPC (`ServerRestartPlayer`), invalid on an S→C client-receive bunch. Lands on an empty/overrun FieldCache slot → close. **Do not use.** |

### Why the two "31" methods agree despite different models
- `ue5-algo-full`: one combined property+function index space per class;
  APlayerController FUNC_Net block starts at absolute cache index 5;
  ClientRestart is FUNC_Net local 0-index 26 (…ClientRepObjRef=24, ClientReset=25,
  **ClientRestart=26**, ClientRetryClientRestart=27…) → 5+26 = **31**.
- `ue5-algo-funcsonly`: alphabetical FUNC_Net ordering; ClientRestart local 26,
  ServerNotifyLoadedWorld local 62 (offset 36, model-independent because both
  live in the same contiguous block on the same class). Ground-truth
  ServerNotifyLoadedWorld wire byte `0x86` = 67 ⇒ ClientRestart = 67−36 = **31**.

Both pin the +5 base from the same four live anchors, so 31 is the only value
supported by *captured wire bytes* rather than by an SDK field count.

---

## 2. Encoding — FieldCount / MaxIndex, bit-width, LSB-first bytes

**CRITICAL: UE5 `SerializeInt(value, max)` is NOT a fixed `ceil(log2(max))`-bit
write.** Per `ue5_primitives.h:141` `write_serialize_int`, it writes one bit per
`mask` (1,2,4,…) **only while `new_val + mask < max`**. So the bit count is
value- AND max-dependent, and the low bits are just `value`'s binary digits
LSB-first, padded with high zero-bits up to the stop condition.

The receiver reads with the **same** `max = max(2, FieldCount=*(a4+32))`, so the
write `max` MUST equal the client's runtime `GetMaxIndex()` for the *channel
actor class* `AAoCPlayerControllerBP_C` — NOT APlayerController.

- **FieldCount / MaxIndex (use): `1048`** (best estimate; APlayerController 79 +
  AController 2 + 5 base + AAoCPlayerController 908 + BP 6, combined prop+func
  space ≈ 1000–1055). Any `max` in **[1056 … 2047]** yields the same width for
  value 31; `[1048…1055]` yields one bit fewer. Both decode correctly **iff the
  client's real MaxIndex falls in the same window** — so 1048 is the value to
  ship, with a probe override.

- **Resulting SerializeInt for `value = 31`:**

  | max | bit-width | LSB-first bits | LSB-first bytes |
  |-----|-----------|----------------|-----------------|
  | 1048 | **10 bits** | `1 1 1 1 1 0 0 0 0 0` | `0x1F 0x00` |
  | 1056–2047 | 11 bits | `1 1 1 1 1 0 0 0 0 0 0` | `0x1F 0x00` |
  | 4096 | 12 bits | same + zero | `0x1F 0x00` |
  | 256 (current bug) | 8 bits | `1 1 1 1 1 0 0 0` | `0x1F` |

  In every case the meaningful byte is **`0x1F`** (= 31), followed by zero
  high-bits. The bug in the current code is twofold: (a) it writes value **69**
  (`0x45`), and (b) it writes a **fixed 8 bits at max=256**. Fix the value to 31
  and the max to the full BP-class MaxIndex (1048) so width = 10 bits.

  > The earlier "31 failed live → field 0" result is explained by writing 31 in
  > too few bits / as a 1-byte SIP: the genuine 10–11-bit `SerializeInt` reader
  > then realigns and decodes 0. Width correctness (driven by the right `max`)
  > is as load-bearing as the value.

**Do NOT use `write_sip` (SerializeIntPacked) for RepIndex.** RepIndex is a
plain `SerializeInt`. SIP is only for `NumPayloadBits` (next section).

---

## 3. Outer-payload framing `[RepIndex][NumPayloadBits SIP][param]`

Per `sub_143F2DC60` Path A, the outer payload (inside the content block's
`SIP(outer_payload_bits)` envelope) is exactly three tokens — **no 1-bit
advance, no field-index SIP, no SIP(0) terminator** (those were the old
field-loop guess and desync the param read):

```
[ RepIndex      = SerializeInt(31, FieldCount=1048) ]   → 10 bits, bytes 0x1F 0x00
[ NumPayloadBits = SerializeIntPacked(128)          ]   → SIP, 16 bits (0x02 0x02)
[ param: APawn* NewPawn = FIntrepidNetGUID          ]   → 128 bits (4× uint32 LSB-first)
```

- **NumPayloadBits = 128** (the param's bit length). SIP-encoded:
  128 = `0b10000000`; SIP emits low 7 bits `0000000` with continuation, then
  `0000001` → bytes **`0x02 0x02`** (16 bits). `sip_bit_count(128) = 16`.
- **param bit count = 128**: `FIntrepidNetGUID` = 4× uint32 LSB-first
  (ObjectId.lo, ObjectId.hi, ServerId, Randomizer), per `sub_14141E960`.
  **No trailing 8-bit ExportFlags pad** for a non-export reference (136 overran
  → ContentBlockFail; use 128).
- **outer_payload_bits** = `repindex_bits(10) + sip_bit_count(128)=16 + 128` =
  **154 bits**. This is the value written as the content-block `SIP` and folded
  into `BunchDataBits` (`total_bdb = 2 + sip_bit_count(154) + 154`).

  (Current code computes `repindex_bits = 8`; bump to 10 so the outer SIP and
  BunchDataBits stay consistent with the wider RepIndex.)

---

## 4. The exact code change (`send_client_restart_native`)

File: `src/net/game_server.h`, fn `send_client_restart_native`
(line **2685**). This is the native path that actually fires (`[PAWN]
ClientRestart` log). Two edits:

1. **Line 2804** — value: `const uint32_t wire_handle = 69u;` →
   `const uint32_t wire_handle = 31u;`
2. **Lines 2883–2884 / 2944** — width: replace the fixed
   `const size_t repindex_bits = 8;` + `write_bits(..., wire_handle, 8)` with a
   real `SerializeInt(31, 1048)`:
   ```cpp
   const uint32_t kClientRestartMaxIndex = 1048u;  // AAoCPlayerControllerBP_C GetMaxIndex
   // RepIndex = SerializeInt(31, 1048) → 10 bits, LSB-first 0x1F 0x00
   ue5::write_serialize_int(bunch_buf, sizeof(bunch_buf), bb,
                            wire_handle, kClientRestartMaxIndex);
   ```
   and set `repindex_bits` to the actual bit count produced
   (`serialize_int_bit_count(31, 1048) = 10`) so `outer_payload_bits` /
   `total_bdb` match. Keep `NumPayloadBits = SIP(128)` and the 128-bit GUID
   exactly as-is (lines 2945–2955).

The sibling probe path `pc_emitter.cpp` already has `kClientRestartHandle = 31`
(line 736) but uses `handle_max` default **256** (line 680, 8-bit) — change that
default to **1048** too so both paths agree.

---

## 5. Ranked post-entry P0 list (file:line)

1. **P0 — Fix RepIndex value + width (THIS doc).**
   `src/net/game_server.h:2804` (`69`→`31`),
   `:2883`/`:2944` (fixed-8-bit → `write_serialize_int(31, 1048)`);
   mirror `src/net/pc_emitter.cpp:680` (`probe_max` default 256→1048),
   `:736` already 31. **Unblocks possession.**
2. **P0 — Verify client's real `AAoCPlayerControllerBP_C` MaxIndex.**
   If 31@max=1048 still decodes wrong, the `max` window is off. Probe
   `max ∈ {998, 1048, 1056, 2048}` via `pc_emitter.cpp:680` `probe_max.txt`;
   the *value* stays 31 (`0x1F`), only trailing zero-bits change.
3. **P1 — Candidate 22 fallback.** If 31 is rejected, set
   `game_server.h:2804 = 22` and `pc_emitter.cpp:736 = 22` (SerializeInt 22,1048
   = bytes `0x16 0x00`, 11 bits). Then 28 (`0x1C`).
4. **P1 — Param/NumPayloadBits sanity.** Confirm `pawn_field_bits = 128` (no 136
   pad) at `game_server.h:2874`; ensure `outer_payload_bits` recomputed from the
   new 10-bit RepIndex at `:2885`.
5. **P2 — Post-restart possession follow-through.** Once ClientRestart is
   accepted, the client emits `ServerAcknowledgePossession`
   (anchor localidx 54 → wire 59 = `0x76`); verify the server-side handler and
   the pawn NetGUID minted in `send_client_restart_native` (lines 2828–2847)
   match what the client possesses. See `docs/re-plan/poss/`.
