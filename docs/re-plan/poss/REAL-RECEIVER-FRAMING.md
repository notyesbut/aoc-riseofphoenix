# REAL-RECEIVER-FRAMING — the current-binary actor-channel content-block decode

Ground truth: `docs/re-plan/poss/_ghidra_decomp_out.txt` (FUN_143f329d0,
FUN_143f224d0, FUN_143f27e50, FUN_143f3c090, ReceivePropertiesForRPC) and
`_ghidra_decomp_out2.txt` (FUN_143f30e10, FUN_143f37030, FUN_143f30bf0), plus
the xref appendix `_ghidra_xref_out.txt` (which also contains FUN_143f27c80).

Every claim below cites a specific line (`out.txt:N` / `out2.txt:N` / `xref:N`).
This supersedes every prior framing doc that modeled the receiver as
`sub_143F2DC60` — that was a STALE binary. The names below are the CURRENT
binary's functions.

| Function | Role |
|---|---|
| `FUN_143f329d0` | `UActorChannel::ReceivedBunch` — per-content-block dispatcher |
| `FUN_143f30bf0` | `ReadContentBlockPayload` — wraps the header reader, logs the strings |
| `FUN_143f2f4f0` | `ReadContentBlockHeader` — reads the per-block header (NOT in dump; derived) |
| `FUN_143f30e10` | `ReadFieldHeaderAndPayload` — reads ONE field selector + payload |
| `FUN_143f3c090` | `RepLayout::ReceiveProperties` — handle-based property receive |
| `FUN_143f37030` | `ReceivedRPC` — RPC dispatch ("Received RPC", "Function not found") |
| `FUN_143f27e50` | `GetClassNetCache`; `FUN_143f224d0` = cache builder |
| `FUN_143f27c80` | builds the channel-actor class FName key for GetClassNetCache |

---

## 0. The decisive flag: `*(*(conn+0x48)+0xF0) & 1`

This bit appears in FOUR functions and is the master switch between the
*stock-UE5* receive path and the *AoC-custom* receive path. `conn+0x48` is the
`UNetDriver*` (or the AoC net-context), and `+0xF0 & 1` is **"AoC custom net is
active"**:

- `FUN_143f27c80` xref:35 — `if ((*(byte *)(*(longlong *)(param_1+0x48)+0xf0)&1)==0) return 0;`
  i.e. the class-FName key is only built when the flag is **set**.
- `FUN_143f27e50` (GetClassNetCache) out.txt:682 — same guard; when the flag is
  **clear** it `return 0` (no cache); when **set** it walks the AoC FName→cache map.
- `FUN_143f30e10` out2.txt:44 — `if ((... +0xf0 & 1) == 0) { …RepLayout-cmd path… } else { …FieldCount path… }`.
- `FUN_143f37030` out2.txt:487 — used to gate the throttle path.

**Determination of which value is live for our ch=3 bunch.** In
`FUN_143f329d0` the cache pointer used for the whole field loop is
`local_260 = FUN_14163a6a0(plVar10[0x42], conn+0x48)` (out.txt:113) and the loop
only runs `if (local_260 != 0)` (out.txt:129). `local_260` is the **GetClassNetCache
result**, and GetClassNetCache (`FUN_143f27e50`) returns a non-null cache **only
when `+0xF0 & 1` is SET** (out.txt:682-794; the `==0` branch returns 0,
out.txt:683). The client logs `LogRep: ReceivedBunch: Invalid replicated field`
and `ReadFieldHeaderAndPayload: NetField…` — strings that ONLY exist on the
field-loop path that requires a non-null cache. **Therefore the live client has
`+0xF0 & 1 == 1`** (AoC-custom net is active). That means:

> **Our ch=3 bunch hits the FLAG==1 path of `FUN_143f30e10` (out2.txt:211-314):
> the FieldCount / 0x28-stride / hash-resolve path — NOT the RepLayout-cmd path
> the emitter comments assume.**

This is the single biggest correction. The emitter's
`SerializeInt(value, max(2,FieldCount))` intuition is RIGHT for the selector
width, but its *reasoning* ("AoC-custom path = +0x240 bit0 set = the
RepLayout-cmd path") is inverted, and the consequences (below) are what break us.

---

## 1. Content-block HEADER layout (FUN_143f30bf0 → FUN_143f2f4f0)

`FUN_143f2f4f0` (the header reader) is not in the dump, but `FUN_143f30bf0`
(out2.txt:895-989) shows exactly how its result is consumed, which pins the
layout. `FUN_143f30bf0`:

```
lVar3 = FUN_143f2f4f0(param_1, param_2 /*FBitReader*/, &bObjectDeleted, param_4, 0);   // out2.txt:916
if (Bunch.IsError()) { …log "ReadContentBlockPayload: …" ; return 0; }                 // out2.txt:917,973
if (bObjectDeleted /*local_res10*/) { FUN_1414f8f50(repObj, reader, 0); return 0; }    // out2.txt:918-921
NumPayloadBits = 0;
(*reader->vtable[0x198/8])(reader, &NumPayloadBits);   // SerializeIntPacked → SIP    // out2.txt:923
if (!Bunch.IsError()) { FUN_1414f8f50(repObj, reader, NumPayloadBits); return lVar3; } // out2.txt:924-926
else { …log "ReceivedBunch: Read NumPayloadBits FAILED" … }                            // out2.txt:944, ALLBUNCHKEYWORD:380
```

So the header reader returns **the resolved sub-object/actor pointer** (`lVar3`),
sets **bObjectDeleted** (`local_res10`), and AFTER it returns, the caller reads
**NumPayloadBits via SerializeIntPacked** (vtable+0x198, out2.txt:923 — this is
the SAME vtable slot the field reader uses for its payload-size SIP, out2.txt:96).
The standard UE5 `ReadContentBlockHeader` bit layout that produces exactly this
behaviour, confirmed by the `ReadContentBlockHeader` strings
(`ALLBUNCHKEYWORD.txt:371-376`) and the `ReadContentBlockPayload` log path, is:

```
Content-block HEADER  (LSB-first per byte, UE5 FBitReader)
┌─ bOutHasRepLayout : 1 bit   ── if 1, this block is a RepLayout property stream
├─ bIsActor         : 1 bit   ── if 1, sub-object = the channel Actor itself
│                               if 0, a sub-object NetGUID FPackageMap ref follows
├─ (sub-object ref) : 0 bits when bIsActor=1
├─ bObjectDeleted / "stably-named" pad handling …
└─ (returns: sub-object ptr, bObjectDeleted)        ← FUN_143f2f4f0 return + out-param
Content-block PAYLOAD (read by the CALLER, FUN_143f30bf0):
└─ NumPayloadBits   : SerializeIntPacked (SIP)      ← out2.txt:923, vtable+0x198
   <NumPayloadBits bits of field data follow>
```

Our emitter's content-block envelope (game_server.h:3065-3068) is therefore
**structurally correct**:
`[bHasRepLayout=0 : 1][bIsActor=1 : 1][SIP(outer_payload_bits)]`. The header
itself is NOT the bug. (`bIsActor=1` ⇒ no sub-object NetGUID is read, which is
what we want — the field targets the PlayerController actor on ch=3.)

> **Header verdict: the content-block header bytes we send are correct.** The
> failure is entirely INSIDE the payload — the field record — and in the
> NumPayloadBits accounting around it.

---

## 2. The field record (FUN_143f30e10, FLAG==1 path — out2.txt:211-314)

Because `+0xF0 & 1 == 1` (§0), our field is parsed by the **else** branch:

```c
// out2.txt:211-217
uVar15 = 2;
if (2 < *(int *)(param_4 + 0x20)) uVar15 = *(int *)(param_4 + 0x20);   // FieldCount
(*reader->vtable[400/8])(reader, &value, uVar15);   // SerializeInt(value, max(2,FieldCount))  out2.txt:217
iVar9 = (int)value;
// out2.txt:234
if (value < FieldCount) {
    entry = *(param_4 + 0x18) + value*0x28;          // FieldCache[value], 40-byte stride  out2.txt:235
    id    = *(uint*)(entry + 0x14);                   // the field's hash id            out2.txt:236
    if (id != 0) {
        // walk param_3 (RepLayout chain) hashing for `id` → resolves real field  out2.txt:239-258
        *plVar17 = resolved_field;                    // out2.txt:262
        if (resolved == 0 && !already_warned) { …"GetFr…" log; mark warned; }       out2.txt:263-288
        goto read_payload;                            // out2.txt:290 → LAB_143f3138d
    }
    // id == 0 → "NetField…" warn, fall through                                     out2.txt:292-313
}
else { …"NetFieldIndex %d out of bounds" (DAT_14d944738)… ; SetError; return 0; }  out2.txt:315-326
```

`param_4` here is the **GetClassNetCache result** (`local_260`, passed as the 3rd
arg `local_260` at out.txt:203 / out2.txt arg `param_4`). So:

- **`param_4 + 0x20` = FieldCount** = number of replicated fields+RPCs in the
  PlayerController's ClassNetCache (out2.txt:214). This is the `0x100` /
  per-entry count built by `FUN_143f224d0` (out.txt:638-650, entry stride `0x28`,
  count at `lVar7+0x20`).
- **The selector is `SerializeInt(value, max(2, FieldCount))`** (out2.txt:213-217).
  Width = `serialize_int_bit_count(value, FieldCount)`. For a FieldCount on the
  order of a few hundred this is ~8-9 bits.
- **`entry = base + value*0x28`** (out2.txt:235): the selector indexes the
  **ClassNetCache field table directly** (the table `FUN_143f224d0` builds with
  0x28-byte entries, out.txt:643). `id = entry[0x14]` (out2.txt:236) is the
  field's hash id (set from `*(puVar9+0xc)` in the builder, out.txt:648). The
  receiver then **searches the per-property RepLayout chain (`param_3`) by that
  hash** to map the cache index to the actual `FProperty*`/`UFunction*`
  (out2.txt:239-262).

### What `id == 0` and out-of-bounds mean for the oracle
- **value ≥ FieldCount → out_of_bounds** → `LogNet:…NetFieldIndex %d`
  (DAT_14d944738, out2.txt:315-326) → `SetError`, `return 0` →
  `ReadContentBlockPayload FAILED. Bunch.IsError()`.
- **value < FieldCount but `id == 0`** (an empty/non-net cache slot) → "NetField"
  warn path (out2.txt:292-313) → resolved field stays NULL.
- **value < FieldCount, id ≠ 0, but hash not found in RepLayout chain** →
  resolved NULL, `lVar1+0x23` warn marker (out2.txt:263-288) → returns to caller
  with `*OutField == NULL`.

### The dispatcher's reaction to `*OutField` (FUN_143f329d0, out.txt:204-507)
After `FUN_143f30e10` returns 1 (a field was read), `FUN_143f329d0` inspects the
field handle `local_298` (the `*OutField`):

- **`local_298 == 0` (NULL field)** → out.txt:224-239 logs
  `ReceivedBunch: FieldCache == nullptr` — i.e. the slot resolved to nothing.
- **`(byte)local_298[2] == 0`** (a real field) → out.txt:240. Then:
  - if the field is a **UFunction** (the `(uVar13 & ...)` RPC test at
    out.txt:242-254 checks the function-flag bit `>>0x14 & 1`) → calls
    **`FUN_143f37030` (ReceivedRPC)** (out.txt:266).
  - else (a **property**) → builds the property-receive state (out.txt:420-440)
    and calls **`FUN_1444e7980`** (RepLayout single-property receive, out.txt:440).
  - **If neither (uVar13 == 0)** → out.txt:370-381 logs
    **`ReceivedBunch: Invalid replicated field %d`** (DAT_14d944738,
    out.txt:375, arg `(int)puVar3[1]`) → `goto LAB_143f33321` (abort the loop).

That `Invalid replicated field %d` at out.txt:375 is the **exact oracle string**,
and its argument `puVar3[1]` is `FieldCache.FieldNetIndex` — **the cache index**,
not our raw selector.

---

## 3. Explaining EVERY oracle observation

We write the selector as **8-bit** `SerializeInt(N, 256)` (game_server.h:3075,
`kClientRestartMaxIndex=256`). But the receiver reads it as
`SerializeInt(value, max(2, FieldCount))` (out2.txt:217). **FieldCount is NOT
256.** The decode width is `serialize_int_bit_count(*, FieldCount)`. THIS WIDTH
MISMATCH is the master fault, and it explains the whole table:

### Why N=31, 69, 129 → "Invalid replicated field 0"
These three values, read at the receiver's real width and indexed into the
cache, all land on a slot whose resolved field is **neither a net-function nor a
net-property** (uVar13==0 at out.txt:245) — so the dispatcher takes the
out.txt:370-381 branch and logs `Invalid replicated field %d`. The reported
index is **0**, which is the telltale: our 8-bit write of N, when re-read at the
receiver's true width, **desynchronizes the bit cursor** so that the *following*
SIP(NumPayloadBits) and the subsequent loop iteration's `SerializeInt` decode to
**index 0** (the cursor has slipped, and the loop re-reads a zero selector from
mid-payload). Field 0 in the PlayerController cache is a non-replicated slot ⇒
"Invalid replicated field 0". The constant `0` across N=31/69/129 is the
fingerprint of a **width/cursor desync**, not of three distinct bad indices.

### Why N=62 → accepted SILENTLY
At the receiver's true width, 62 decodes to a cache slot that resolves to a
**valid net field whose receive consumes exactly the bits we supplied** (or a
property whose `FUN_1444e7980` returns success, out.txt:447-473, with no
`DAT_14d944778 > 4` verbose logging fired). The field is consumed, no error
string is emitted, the content block closes cleanly. "Silent" = our bytes
*happened* to align for that one index, but it is NOT ClientRestart and NOT
Pawn — it's whatever the PlayerController cache slot at the decoded index is, and
it carried our 128-bit GUID as an opaque payload that the slot's reader
swallowed. (This is the dangerous false-positive: silent ≠ possession.)

### Why N=73 AND N=170 BOTH → OutField=AuthServerIDReplicated, then ContentBlockFail
This is the critical clue, and the FLAG==1 path explains it cleanly where a flat
index cannot. **Two different selectors collapse to the SAME first property
because the resolution is two-stage and hash-based, not a flat array index:**

1. `entry = FieldCache.base + value*0x28`; `id = entry[0x14]` (out2.txt:235-236).
2. The receiver then **searches the RepLayout hash chain for `id`**
   (out2.txt:239-258) to get the actual property. The mapping
   `cache_index → id → RepLayout property` is **NOT order-preserving**: distinct
   cache indices can carry hash ids that both miss the RPC/handle table and fall
   through to the **first replicated property handle (handle 0 =
   AuthServerIDReplicated, AActor's first net property @ offset 0x84)**.

Concretely: when our desynced selector lands on a cache slot whose `id` does
**not** resolve to a function, the dispatcher does NOT take the RPC branch; it
takes the **property** branch (out.txt:420-440) and calls the RepLayout property
receiver, which begins at **handle 0**. The RepLayout receiver
(`FUN_143f3c090`, out.txt:800+) iterates handles starting from the first net
property; with our payload bit-misaligned, the first handle's read
(`AuthServerIDReplicated`) fails to consume cleanly ⇒
`ReadFieldHeaderAndPayload: Error reading payload … OutField:
AuthServerIDReplicated` ⇒ `ReadContentBlockPayload FAILED. Bunch.IsError()`.
Because BOTH 73 and 170 desync into the **property path that always starts at
handle 0**, they BOTH name AuthServerIDReplicated — exactly the observed collapse,
and exactly why "no SerializeInt max makes 73 and 170 decode to the same flat
value": the collapse is at the **id→handle-0 fallback**, downstream of the flat
index, not at the index itself.

> The 73/170 collapse is the strongest proof that **our bunch is being parsed as a
> RepLayout PROPERTY stream that restarts at handle 0**, not as an RPC and not as
> the field we intend. The selector width is wrong, the bit cursor is desynced,
> and the dispatcher falls into the property branch.

---

## 4. Is ClientRestart even deliverable as a "field" here?

Yes — RPCs and properties share the SAME content-block + field-record envelope
and the SAME `FUN_143f30e10` reader. The fork is purely in the dispatcher AFTER
the field resolves:

- If the resolved field is a **UFunction with the net-function flag**
  (`>>0x14 & 1`, out.txt:242-254) → **`FUN_143f37030` (ReceivedRPC)**
  (out.txt:266). Inside, `FUN_143f37030` re-looks-up the function by name on the
  channel actor (out2.txt:402-403), and if found+RPC-flagged
  (`pcVar14[0xd0] & 0x40`, out2.txt:449-450), reads its params via
  `FUN_1444e8080` (out2.txt:639) and dispatches (`Received RPC %s`, out2.txt:559).
  **For ClientRestart to fire, our selector must resolve to a cache slot whose
  `id` maps to the `ClientRestart` UFunction**, AND our payload must be the
  RPC's parameter blob in `ReceivePropertiesForRPC` form (a `NewPawn` object
  reference field), NOT a bare 128-bit GUID.
- If the resolved field is a **property** → the RepLayout property branch
  (out.txt:420-440). For the Pawn path, the selector must resolve to the
  `AController::Pawn` property handle, and the payload is the property value in
  **handle-based RepLayout form** (handle SerializeInt + value), which is read by
  `FUN_143f3c090`/`FUN_1444e7980` — again NOT a bare 128-bit GUID at a raw offset.

The `OutField=AuthServerIDReplicated` collapse (§3) reveals our current bunch is
hitting the **property** branch and restarting at handle 0. So today we are
neither dispatching ClientRestart (RPC branch never taken) nor updating Pawn
(handle 0 ≠ Pawn handle) — we desync into AActor's first property and error out.

### The RPC param shape (ReceivePropertiesForRPC, out.txt:1184+)
`FUN_143f37030` reads RPC params via `FUN_1444e8080` → `ReceivePropertiesForRPC`
(out.txt:1189). That function drives the function's **own RepLayout** over the
parameter struct (`_Size = *(ushort*)(pcVar14+0xd6)` param-size, out2.txt:606;
`memset` a param buffer, out2.txt:620; then `FUN_1444e8080`, out2.txt:639). For
`ClientRestart(APawn* NewPawn)` the single param is an **object reference**, which
on the wire is a **FPackageMap object serialize** (NetGUID), NOT four raw uint32.
The 128-bit `{ObjectId,ServerId,Randomizer}` raw form is the AoC FIntrepidNetGUID
*payload*, but inside an RPC param it must go through the package-map object
writer (the same path `bIsActor`/sub-object refs use). Our raw 4×uint32 is only
correct if the param reader is the raw FIntrepidNetGUID reader (sub_14141E960);
that needs separate confirmation — see "highest-confidence next step".

---

## 5. What is WRONG with our current content-block bytes (summary)

1. **Selector WIDTH is wrong.** We write `SerializeInt(N, 256)` = fixed 8 bits
   (game_server.h:3075, `kClientRestartMaxIndex=256`). The receiver reads
   `SerializeInt(value, max(2, FieldCount))` (out2.txt:217) where **FieldCount is
   the PlayerController ClassNetCache field count, NOT 256**. Unless FieldCount
   happens to put N in an 8-bit window, every bit after the selector is shifted ⇒
   the SIP(NumPayloadBits) and the payload are read at the wrong offset ⇒ desync.
2. **Selector VALUE is a guess.** 31/69/129/73/170 are all SDK-rank guesses;
   none is anchored to the live cache. The cache index space is
   `FUN_143f224d0`-built and **hash-id-resolved** (out2.txt:236-258), so the
   correct value is "the cache index whose `id` hashes to ClientRestart (or
   Pawn)" — not an alphabetical/SDK rank.
3. **Payload SHAPE is wrong for an RPC.** Bare 4×uint32 (game_server.h:3082-3087)
   is not the `ReceivePropertiesForRPC` param-struct form (out.txt:1184+). Even
   with the right selector, the param read would mis-consume.
4. **The header is FINE** (§1) — do not touch `[bHasRepLayout=0][bIsActor=1][SIP]`.

The desync from (1) is sufficient by itself to produce ALL the oracle errors;
(2) and (3) are why even a width fix won't dispatch ClientRestart without the
right index and param shape.

---

## 6. CORRECTED emitter wire layout

### Shared content-block envelope (UNCHANGED — keep as-is)
```
[bHasRepLayout = 0      : 1 bit]            game_server.h:3065
[bIsActor      = 1      : 1 bit]            game_server.h:3066
[NumPayloadBits = SIP(outer_payload_bits)]  game_server.h:3067
```

### (a) ClientRestart RPC — corrected field record
```
outer_payload (NumPayloadBits worth):
  [RepIndex   = SerializeInt(CR_cache_index, max(2, FieldCount))]   ← WIDTH = FieldCount, not 256
  [NumPayloadBits_inner = SIP(param_bits)]                          ← bits of the param blob
  [ NewPawn param = FPackageMap object-ref of the pawn NetGUID ]    ← RPC param form, via ReceivePropertiesForRPC
```
Required code changes in `send_client_restart_native` (game_server.h:2886-3088):
- **`kClientRestartMaxIndex` must be the live FieldCount**, not 256
  (game_server.h:2889). Source it from the PlayerController ClassNetCache field
  count (see §7). Until known, treat it as the dominant unknown — sweeping `N`
  at the WRONG max can never hit, because the width itself is wrong.
- **`wire_handle` (CR_cache_index)** must be the cache index whose hash id maps
  to `ClientRestart`, not an SDK rank (game_server.h:2886-2887).
- **The param** (game_server.h:3082-3087) must be written as the RPC's parameter
  RepLayout, i.e. the `NewPawn` object reference through the package-map object
  writer, sized to `*(UFunction+0xd6)` param bytes — NOT four raw uint32 unless
  sub_14141E960 (raw FIntrepidNetGUID) is confirmed as the param reader.

### (b) AController::Pawn property update — corrected field record
```
outer_payload (NumPayloadBits worth):
  [RepIndex   = SerializeInt(Pawn_cache_index, max(2, FieldCount))] ← WIDTH = FieldCount
  [NumPayloadBits_inner = SIP(prop_bits)]
  [ Pawn property value = RepLayout handle-based property write:    ← NOT bare 4×uint32
      handle for AController::Pawn, then the object-ref NetGUID ]
```
Required changes in `send_pawn_property_native` (game_server.h:3225-3356):
- `kPawnMaxIndex = 256` (game_server.h:3228) → live FieldCount.
- `pawn_repindex = 73` (game_server.h:3226) → the cache index resolving to the
  `Pawn` property's hash id.
- The 4×uint32 payload (game_server.h:3351-3356) → handle-based RepLayout
  property value, read by `FUN_143f3c090`/`FUN_1444e7980`.

---

## 7. Single highest-confidence change to try next

**Stop writing the selector at the fixed 8-bit `max=256`; write it at
`max = max(2, FieldCount)` where FieldCount is the PlayerController
ClassNetCache's real field count.** The width — not the value — is what desyncs
the cursor and produces the entire oracle table (the constant "field 0", the
silent N=62 fluke, and the 73/170 → handle-0 AuthServerIDReplicated collapse all
follow from a bit-misaligned payload, §3). The value is a separate (also-needed)
unknown, but the width is the change that converts "garbage everywhere" into
"selector lands where intended."

**How to obtain FieldCount empirically (no further RE needed):** the receiver's
out-of-bounds log `LogNet: ReadFieldHeaderAndPayload: NetFieldIndex %d`
(out2.txt:315-320, DAT_14d944738 = Warning) fires precisely when
`value >= FieldCount` (out2.txt:234). Sweep the selector UPWARD writing it at a
known max and watch the client log: the **lowest N that flips from "Invalid
replicated field"/silent to "NetFieldIndex %d out of bounds" is FieldCount**.
Equivalently, binary-search the boundary. Once FieldCount is known, set
`kClientRestartMaxIndex = FieldCount` and the selector width becomes correct;
then sweep the value to find the index whose payload dispatches ClientRestart
(`Received RPC ClientRestart`, out2.txt:559) or updates Pawn.

Concretely as a probe with zero rebuild:
1. `probe_cr_max.txt = <largeMax, e.g. 1048>` so the WIDTH covers the whole
   table, then sweep `probe_cr_handle.txt` 0,1,2,… and find the N where the log
   switches to `NetFieldIndex … out of bounds` → that N = FieldCount.
2. Set `probe_cr_max.txt = FieldCount`. Now the selector is the correct width.
3. Sweep `probe_cr_handle.txt` again; the index that yields `Received RPC
   ClientRestart` (out2.txt:559) is the answer. (If instead you see the
   property/RepLayout receive succeed for a Pawn handle, that's path (b).)

Note: the in-tree `write_serialize_int` (ue5_primitives.h:141-151) already
matches the receiver's exact stop condition (`new_val + mask < max_val`,
out2.txt:217 reads via the same SerializeInt), so once `max` = FieldCount the
emitted bits are guaranteed to match the reader — no codec change needed, only
the `max` value.

---

## Appendix — line-evidence index

| Claim | Evidence |
|---|---|
| AoC-custom flag = `(conn+0x48)+0xF0 & 1` | out2.txt:44, out.txt:682, xref:35 |
| Field loop only runs with non-null ClassNetCache | out.txt:113,129 |
| GetClassNetCache returns 0 when flag clear → flag is SET live | out.txt:682-683 |
| FLAG==1 ⇒ FieldCount path | out2.txt:211-314 |
| Selector = SerializeInt(value, max(2,FieldCount)) | out2.txt:213-217 |
| FieldCount @ `cache+0x20` | out2.txt:214 |
| Cache entry stride 0x28, id @ +0x14 | out2.txt:235-236; builder out.txt:643,648 |
| id→RepLayout hash resolve | out2.txt:239-258 |
| value ≥ FieldCount → "NetFieldIndex out of bounds" + SetError | out2.txt:315-326 |
| RPC vs property fork (`>>0x14 & 1`) | out.txt:242-254 |
| RPC branch → FUN_143f37030 | out.txt:266 |
| "Invalid replicated field %d" (arg = FieldNetIndex) | out.txt:375 |
| Property branch → FUN_1444e7980 | out.txt:440 |
| Content-block header reader + NumPayloadBits SIP | out2.txt:916,923 |
| "ReadContentBlockHeader" strings | ALLBUNCHKEYWORD.txt:371-376 |
| "Read NumPayloadBits FAILED" | ALLBUNCHKEYWORD.txt:380 |
| ReceivedRPC "Received RPC %s" | out2.txt:559 |
| RPC param size `*(UFunction+0xd6)` | out2.txt:606 |
| ReceivePropertiesForRPC entry | out.txt:1184-1189 |
| Emitter content-block envelope (correct) | game_server.h:3065-3068 |
| Emitter selector write (wrong max=256) | game_server.h:2889, 3075 |
| Emitter raw 4×uint32 payload (wrong shape for RPC) | game_server.h:3082-3087 |
| write_serialize_int matches receiver stop condition | ue5_primitives.h:141-151 |
