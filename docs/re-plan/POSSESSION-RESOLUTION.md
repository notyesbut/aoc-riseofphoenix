# POSSESSION-RESOLUTION.md

**Status:** RESOLVED (synthesis of multi-agent RE, 2026-06-09)
**Blocker:** retail client stuck on "Waiting for World Partition Streaming 100%"
**Subsystem:** native AoC possession (ClientRestart → SetPawn → AcknowledgePossession)

This document closes out the multi-agent investigation into native possession. It
picks a single answer for each contested point, states the evidence weight, and
gives a ranked, concrete change list. Where the source already encodes the correct
answer, that is called out so nobody "fixes" a working path back into a bug.

---

## 1. ClientRestart NewPawn param format — RESOLVED: **128-bit FIntrepidNetGUID** (not an 8-bit alias)

### Verdict
The `APawn* NewPawn` param is a **full 128-bit FIntrepidNetGUID** (4× uint32
LSB-first: `{ObjectId.lo, ObjectId.hi, ServerId, Randomizer}`), written **inside the
AoC custom field-loop**. The PM84 "exactly 8 bits / SIP alias" note is a **MISREAD
and is rejected.** There is no compressed/index/alias form anywhere in the AoC read
path — Intrepid replaced stock UE5's varint `FNetworkGUID` with a fixed-width
`FIntrepidNetworkGUID`.

### Vote tally (8 of 9 agents agree on 128-bit; the 1 alias vote was retracted)
- **128-bit GUID (FOR):** `clientrestart_impl` (high), `fobjectproperty` (high),
  `pawn_export` (high), `netguid_88` (high), `pc_pawn_link` (high),
  `FIntrepidNetGUID-layout` sweep (high), `NetGUID-EXPORT-wire` sweep (high),
  `content-block-parse` sweep (high). Eight HIGH-confidence votes.
- **8-bit alias (AGAINST):** only `aoc_field_loop` proposed shrinking to an 8-bit
  alias, and it did so *solely* on the strength of the PM84 note it had not
  re-derived. Its own primary evidence (the +0x240 field-loop) is about the
  *framing*, not the param width. **Vote discarded** — it rests on the misread.

### The one real wrinkle: 128 vs 136 bits (ExportFlags byte)
`packagemap_ref` correctly observed from `InternalLoadObject` (`sub_1442740F0`) that
the 8-bit ExportFlags byte is **conditional**, gated at decomp line 174:

```c
v16 = (_BYTE *)(a1 + 336);          // a1+336 = IsExportingNetGUIDBunch
if ( v11 == 1 || *v16 )             // v11 = ObjectId; read flags ONLY IF
{                                   //   ObjectId==1 (IsDefault) OR exporting-bunch
    v57[0] = *(_BYTE *)(*v17)++;    // <-- the single ExportFlags byte
}
```

For our minted pawn `ObjectId = 0x01000002` (≠ 1) read as an **RPC param** outside an
export bunch (`IsExportingNetGUIDBunch = 0`), the client reads **128 bits only** and
does **not** read ExportFlags. So a naive "always append 8 ExportFlags bits" would,
*on a direct/outer reader*, leave 8 stray bits → desync.

**BUT** that desync does NOT happen here, because the param is read inside the AoC
field-loop (`sub_7FF6BD8155B0`), which sizes a **bounded sub-reader to exactly the
SIP-declared `field_size_bits`** before calling `NetSerializeItem`:

```c
SIP(field_idx+1) -> v90;  if (v90==0) break;     // field-loop body
SIP(field_size_bits) -> v98;
sub_7FF6BA823CC0(sub_sub_reader, reader, v98, 0); // sub-reader = EXACTLY v98 bits
NetSerializeItem(sub_sub_reader);                 // reads <= v98; loop skips remainder
```

The outer cursor advances by the full declared `field_size_bits` regardless of how
many bits `NetSerializeItem` actually consumed. So if we declare `field_size_bits =
136` and `InternalLoadObject` consumes only 128, the trailing 8 zero bits are
**swallowed by the sub-reader boundary** — benign. If we declare `128`, also fine.
**Both 128 and 136 work; the bounded sub-reader makes the difference cosmetic.**
We standardize on **136** (matches the existing PcEmitter default and is robust if a
future param is ever read against a non-bounded path) but 128 is equally acceptable.

> **Therefore: keep the 128-bit GUID value. Do NOT shrink to an 8-bit alias. The
> 8-bit-vs-128-bit "contradiction" is resolved decisively in favor of 128 bits, and
> the 128/136 sub-question is a no-op thanks to sub-reader bounding.**

The `packagemap_ref` proposed edit to strip to 128 and rewrite the "always reads
ExportFlags" comment is a valid *doc-hygiene* fix (the comment at
`pc_emitter.cpp:781-785` is technically wrong about "ALWAYS"), but it is **not** a
functional bug and must **not** be turned into an 8-bit alias.

### Exact wire (S→C, ch=3, inside the V3 content block), for native pawn `{0x01000002, 60, rnd_for(obj)}`
```
SerializeInt(handle=31, MAX=256/4096)   8 or 13 bits   (see §2 — handle encoding)
1-bit advance                           1 bit          (consumed by sub_7FF6BD814D20)
SIP(field_idx+1 = 1)                     8 bits         (single param, field index 0)
SIP(field_size_bits = 136)              16 bits         (>=128 => 2 SIP bytes)
VALUE  = 4x uint32 LSB-first:           128 bits
    [02 00 00 01]  ObjectId.lo = 0x01000002
    [00 00 00 00]  ObjectId.hi = 0
    [3C 00 00 00]  ServerId    = 60
    [<rnd LE>]     Randomizer  = rnd_for(0x01000002)
  + 8 zero ExportFlags/pad bits          8 bits         (-> 136 total; swallowed)
SIP(0) terminator                        8 bits
```

---

## 2. Function handle encoding — RESOLVED: **handle value = 31**, written as **SIP byte 0x3E** on the dispatch path; SerializeInt(31, MAX) on the AoC field-loop path

### Verdict (two facts, do not conflate them)
1. **The handle VALUE is 31.** ClientRestart = APlayerController alpha-FUNC_Net
   0-index 26 + 5 reserved = 31. Anchored to captured ground truth:
   ServerNotifyLoadedWorld first wire byte `0x86` decodes to 67 *only* as
   `SIP(67)` (`0x86>>1`), proving the dispatch selector is SerializeIntPacked, not
   raw bounded SerializeInt. The old value **45 = ClientSetHUD** (a HUD RPC,
   nothing to do with possession) — that mis-dispatch is why this path never even
   attempted possession. **Already fixed** in source: `pc_emitter.cpp:736 = 31`,
   `game_server.h:2786 = 31`.
2. **The 37/36 FunctionLinks ordinal is a red herring.** One sweep agent
   (`SIP-vs-SerializeInt`, medium) floated 37/36 from a FunctionLinks index. It is
   *lower confidence* and contradicts the captured-wire anchor (0x86 → 67 → +5
   formula). **Use 31.**

### The encoder nuance
- On `send_client_restart_native` (`game_server.h`) the handle is written with
  `write_sip(31)` → byte `0x3E`. Correct.
- On the PcEmitter field-loop path
  (`property_update_bunch_builder.cpp:762`), the handle is currently written with
  `write_serialize_int(cmd_handle, v3_num_properties_)`. The inbound reader
  `ReadFieldHeaderAndPayload` (`sub_7FF6BD25DC60`) reads the AoC-branch handle via
  **vtable slot +400 = SerializeIntPacked** (decomp line 80), bound
  `max(2, FieldCount)`. So the field-loop handle SHOULD also be **SIP**, not bounded
  SerializeInt. This is the live discrepancy between the two encoders — see change #2.

> **Resolved handle: value 31, encoded as SerializeIntPacked (byte 0x3E for idx<64)
> on both the dispatch and the AoC field-loop paths.**

---

## 3. chSeq fix — RESOLVED: native ch=3 sends must advance `cs.last_outgoing_reliable_chseq[3]`; PcEmitter never does, so CR fires at chSeq=1 and is silently dropped

### Root cause (CONFIRMED, high confidence, 2 agents independently)
In OPTION_C minimal mode (`world_bootstrap_plan.cpp:62 AOC_OPTION_C_MINIMAL=1`) the PC
chain is emitted **natively** by `PcEmitter`, not spliced:
- `PcEmitter::emit_open` hardcodes chSeq **954** (`pc_emitter.cpp:242`),
  `emit_pawn_link` **955**, `emit_player_state_link` **956** — all via
  `host_.send_bunch_packet(...)`.
- `send_bunch_packet` (`game_server.h:1962-2026`) ships builder bits **verbatim** and
  bumps only `cs.out_seq`. It **never** writes `cs.last_outgoing_reliable_chseq[3]`.
- Only `scan_outgoing_packet_chseq` (splice path) and `patch_replay_chseq` (replay
  path) advance that tracker — neither runs in OPTION_C native mode.

Consequence: when `send_client_restart_native` computes
`candidate = (last_ch3_seen + 1) & 0x3FF` (`game_server.h:2730`), `last_ch3_seen`
reads **0** (default-init), so CR (and CALV) fire at **chSeq = 1**. The client's
`InReliable[3]` is already ~954–956, so the bunch is discarded as a stale duplicate
(`sub_144230D50:1065`, the `ChSequence <= InReliable[ch]` LABEL_407 discard).
**Possession never runs.**

### Fix
Make every native ch=3 reliable send seed/advance the tracker so it equals the
client's true `InReliable[3]`. Smallest correct seed: set the tracker to the chSeq
each `PcEmitter` ch=3 bunch actually shipped (954 → 955 → 956). Then the existing
`tracker+1` math in `send_client_restart_native` and CALV yields **957**, the correct
next contiguous chSeq.

Related, separate bug (also high confidence): the **PlayerController-spawn ActorOpen**
writes ChSeq as **12 bits** at `game_server.h:5485-5487` — must be **10 bits**
(`SerializeInt(MAX=1024)` per `sub_144230D50:1441`). A 12-bit write overshoots and
corrupts the following ChName field. This is on the bootstrap path and must be fixed
too (change #4).

---

## 4. Predicate requirements — what actually keeps the screen up

The loading-screen "ready" predicate `sub_146B00200` checks `AcknowledgedPawn`
(PC+0x428) non-null. **The server cannot write AcknowledgedPawn** — it is set
*client-side* by `AcknowledgePossession()`, which runs only after a **resolvable**
`ClientRestart(NewPawn)` is processed. The server's only two levers are:

1. **Make WP streaming completable.** The actual gate is
   `UWorldPartitionSubsystem::IsStreamingCompleted(QueryState=Activated, ..., bExact=false)`
   — every cell intersecting the player's streaming-source query must reach
   `Activated`. The streaming source defaults to the **possessed pawn's location**
   (`wp.Runtime.PlayerController.ForceUsingCameraAsStreamingSource = 0`). The pawn
   already ships a valid non-origin Riverlands location, so location is **not** the
   blocker. The blocker is the **make-visible handshake**: the client holds cells in
   `MakingVisibleLevels` until the server replies **CALV** echoing the same 32-bit
   `VisibilityRequestId` with `bClientAckCanMakeVisible=1`. A missing/mismatched CALV
   echo loops the screen. (`kSendSulvAckStub` is already `true` at
   `game_server.h:4898`; the remaining risk is the `VisibilityRequestId` extraction
   heuristic — change #6.)
2. **Deliver a resolvable ClientRestart(pawn).** Requires (a) the pawn ActorOpen
   (`SerializeNewActor`) registers the 128-bit GUID **before** CR is processed
   (already ordered correctly — same packet `[pawn-open][CR]` is allowed because UE5
   processes bunches in-order and registers the GUID before reading CR), and (b) the
   CR references that exact 128-bit triple `{0x01000002, 60, rnd_for(obj)}` (already
   correct). If the GUID does not resolve, the client bounces
   `ServerCheckClientPossession` (wire 63, byte 0x7E) and the server is expected to
   resend via `ClientRetryClientRestart` (server→client RPC, wire 32 / byte 0x40).

**Pawn property pre-req:** the replicated `AController::Pawn` (+0x3A8, Net+RepNotify,
fires `OnRep_Pawn → AcknowledgePossession`) is an *alternative* trigger to the CR
path; either suffices. Both must reference the SAME native pawn NetGUID. (Note the
SDK-confirmed offsets, correcting swapped RE notes: `Pawn @ +0x3A8`,
`AcknowledgedPawn @ +0x428`.)

---

## 5. RANKED concrete code changes (confidence × impact)

Ordering note: several "fixes" are **already applied** in the current tree (handle 31,
native pawn GUID binding, `kSendSulvAckStub=true`, 10-bit CR chSeq). Those are listed
as VERIFY items, not edits. The list below is the *remaining* work, highest leverage
first.

### RANK 1 — chSeq tracker seed (THE live blocker). Confidence: HIGH. Impact: HIGH.
**File:** `src/net/pc_emitter.cpp` (after each ch=3 reliable send) + a host accessor.
Add `GameServer::set_last_reliable_chseq(client_key, 3, chseq)` and call it on send
success:
- after `emit_open` send (chSeq 954) → `set_last_reliable_chseq(key, 3, 954)`
- after `emit_pawn_link` send (chSeq 955) → `... 3, 955`
- after `emit_player_state_link` send (chSeq 956) → `... 3, 956`

Accessor body in `game_server.h`:
```cpp
void set_last_reliable_chseq(uint64_t client_key, uint32_t ch, uint16_t seq) {
    std::lock_guard<std::mutex> lk(clients_mutex_);
    auto it = clients_.find(client_key);
    if (it != clients_.end())
        it->second.last_outgoing_reliable_chseq[ch] = seq;
}
```
Result: `send_client_restart_native` computes chSeq `956+1 = 957` (contiguous), the
client accepts the bunch, possession runs. **This is the single highest-value change.**

### RANK 2 — make the PcEmitter field-loop handle SIP, not bounded SerializeInt. Confidence: HIGH. Impact: HIGH (only if RANK-1 path uses PcEmitter CR).
**File:** `src/protocol/emit/property_update_bunch_builder.cpp:762`
```diff
- v3_inner_payload_.write_serialize_int(cmd_handle, v3_num_properties_);
+ v3_inner_payload_.write_sip(cmd_handle);          // handle=31 -> byte 0x3E
```
Reader `sub_7FF6BD25DC60` reads the AoC-branch handle via vtable+400 (SIP). Matches
the proven `send_client_restart_native` path (`game_server.h:2915`, `write_sip(31)`).
Apply identically to any other `v3_add_rpc_*_aoc*` first-line handle write
(`:455`, `:489` if present).

### RANK 3 — VERIFY handle already 31 on both live emit sites. Confidence: HIGH. Impact: HIGH (already landed).
`pc_emitter.cpp:736 = 31` ✓ and `game_server.h:2786 = 31` ✓. No edit; confirm no
probe file (`dist/Release/probe_*.txt`) overrides them at runtime.

### RANK 4 — PlayerController-spawn ActorOpen ChSeq 12-bit → 10-bit. Confidence: HIGH. Impact: HIGH (bootstrap GUID export must parse).
**File:** `src/net/game_server.h:5485-5487`
```diff
- // ChSeq (12-bit)
- uint16_t pc_chseq = static_cast<uint16_t>((cs.in_reliable_base + 1) & 0xFFF);
- ue5::write_bits(buf, sizeof(buf), off, pc_chseq, 12);
+ // ChSeq (10-bit) — SerializeInt(MAX=1024) per sub_144230D50:1441
+ uint16_t pc_chseq = static_cast<uint16_t>((cs.in_reliable_base + 1) & 0x3FF);
+ ue5::write_bits(buf, sizeof(buf), off, pc_chseq, 10);
```

### RANK 5 — VERIFY native CR param value = 128-bit GUID; standardize width. Confidence: HIGH. Impact: MEDIUM (already correct).
`game_server.h:2927-2932` writes the 4× uint32 GUID correctly. The
`pawn_netguid_bits = 128` literal at `:2851` vs PcEmitter default `136` differ but
are equivalent under sub-reader bounding (§1). Optional: set both to **136** for
consistency. **Do NOT change to an 8-bit alias.**

### RANK 6 — fix VisibilityRequestId extraction for CALV echo. Confidence: MEDIUM. Impact: HIGH (clears the WP streaming gate).
**File:** `src/net/game_server.h:4744-4752` — replace the byte-skip heuristic with a
structured FName-tail parse: after PackageName ASCII, consume 1 NUL + 4 FName Number;
parse Filename FName likewise; then read `uint32 VisibilityRequestId` LSB-first. Echo
that exact id in CALV (`:7821`) with `bClientAckCanMakeVisible=1`. Gate on
`bTryMakeVisible`.

### RANK 7 — de-risk minimal possession repro. Confidence: MEDIUM. Impact: MEDIUM.
Disable bundled fields so a wrong CIC/PS handle cannot poison the field loop and
trigger "Invalid replicated field N": `pc_emitter.cpp:838` `bundle_enabled = 0` and
`:866` `iter4_bundle_enabled = 0`. Re-enable after the bare CR is confirmed accepted.

### RANK 8 — doc/comment hygiene (no functional effect). Confidence: HIGH. Impact: LOW.
- `pc_emitter.cpp:781-785`: "reads 8-bit ExportFlags (ALWAYS)" is wrong — ExportFlags
  is read only when `IsDefault() || IsExportingNetGUIDBunch`. Correct the comment.
- `pc_emitter.h:87`, `pc_emitter.cpp:577`: "ClientRestart=45" is false (45 =
  ClientSetHUD). Correct to 31.
- `game_server.h:2467`: ClientRetryClientRestart direction is backwards — it is
  **server→client** (NetClient), sent in response to a `ServerCheckClientPossession`
  (0x7E) bounce.
- `docs/re-plan/WORLD-ENTRY-ANSWERS.md:609-633`, `clientrestart-wire.md:118,200,263`:
  delete the stale "exactly 8 bits" / "handle 37/45" claims; replace with 128-bit
  GUID + handle 31.

---

## Appendix — primary evidence index
- `sub_1442740F0.txt` (InternalLoadObject): L77 always reads 128-bit GUID; L174
  `if (v11==1 || *v16)` gates the single ExportFlags byte. → §1.
- `sub_14141E960.txt`: four unrolled 4-byte reads, no varint/index. → §1.
- `sub_7FF6BD8155B0.txt:176-201`: field loop, SIP handle via vtable+408, sub-reader
  sized to SIP(field_size_bits). → §1, §2.
- `sub_7FF6BD25DC60.txt:80`: inbound handle via vtable+400 = SIP. → §2.
- `sub_144230D50.txt:1065,1441-1442`: reliable discard + 10-bit ChSeq read. → §3.
- `game_server.h:1962-2026` (send_bunch_packet, no tracker bump), `:2730-2737` (CR
  chSeq = tracker+1), `pc_emitter.cpp:242` (hardcoded 954). → §3.
- `sub_146B00200.txt`: AcknowledgedPawn-non-null readiness predicate. → §4.
- `Engine_classes.hpp:8160,8224,42014`: Pawn@0x3A8, AcknowledgedPawn@0x428,
  IsStreamingCompleted. → §1, §4.
