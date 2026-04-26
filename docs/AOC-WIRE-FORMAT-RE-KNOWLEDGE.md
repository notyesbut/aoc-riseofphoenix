# AoC Wire Format — Reverse-Engineering Knowledge Base

Consolidated findings from IDA + decompilation of AOCClient-Win64-Shipping.exe.
Last updated: 2026-04-25.

Every fact below is either directly confirmed by disassembly/Hex-Rays evidence,
or was empirically validated against captured packets (pkt#22, pkt#78, pkt#104).

---

## 1. AoC-SIP encoding (SerializeIntPacked)

AoC uses **LOW-BIT continuation** (not stock UE5's high-bit).

```
Write: byte = ((value & 0x7F) << 1) | (has_more ? 1 : 0)
Read:  data = byte >> 1;  continuation = (byte & 1) == 1
```

- Source of truth: `src/protocol/wire/ue5_primitives.h::{write_sip, read_sip}`
- Each byte carries 7 data bits; value is LSB-first across bytes.
- Max 5 bytes (for uint32 values up to ~28 bits).
- Reached via FArchive vtable offset **+408 = method index 51** (`SerializeIntPacked`).

---

## 2. FIntrepidNetworkGUID (AoC's extended NetGUID)

**128-bit struct** replacing stock UE5's 32-bit FNetworkGUID:

| Offset | Type | Field |
|---|---|---|
| 0..7 | uint64 | `ObjectId` |
| 8..11 | uint32 | `ServerId` |
| 12..15 | uint32 | `Randomizer` |

Log format seen in both `sub_141D20340` and `sub_143F30430`:
`"ObjectId: %llu \| ServerId: %u \| Randomizer: %u"` (at `off_149F5DE60`).

Code artifact: `src/protocol/emit/intrepid_netguid.h`.

---

## 3. Bunch header wire format (confirmed canonical)

**Source**: `src/net/sc_bunch_parser.h` — validated field-by-field against captures.

```
[1 bit]     bControl
[1 bit]     bCtrlOpen             — if bControl
[1 bit]     bClose                — if bControl
[1-3 bits]  CloseReason           — if bControl && bClose; SerializeInt(MAX=7)
[1 bit]     bIsReplicationPaused
[1 bit]     bReliable
[1-5 B]     ChIndex               — SerializeIntPacked (AoC-SIP)
[1 bit]     bHasPackageMapExports
[1 bit]     bHasMustBeMappedGUIDs
[1 bit]     bPartial
[10 or 12b] ChSequence            — if bReliable; 10 for ch=0, 12 otherwise
[3 bits]    PartialFlags          — if bPartial: bPartialInitial + bPartialCustomExportsFinal + bPartialFinal
[variable]  ChName                — if (bReliable||bCtrlOpen) && (!bPartial||bPartialInitial)
[13 bits]   BunchDataBits         — SerializeInt(MAX=1024*8=8192)
```

Emit-side code: `actor_builder.cpp` uses `write_serialize_int(bdb, 1024 * 8)` for bdb
and `write_sip(ctx.channel)` for ChIndex. Matches parser.

---

## 4. Bunch payload inner structure — FULLY DECODED

Per `UActorChannel::ReceivedBunch` (sub_143F30430) and `UActorChannel::ProcessBunch` (sub_143F2A2A0):

```
[Bunch payload — bdb bits total:]

  ── PackageMapExports section (if bHasPackageMapExports=1): ──
       byte-aligned; processed by PackageMap (UIntrepidNetServerPackageMap)
       Format: [bHasRepLayoutExport:1][u32 NumGUIDsInBunch][N × export entries]
       Each entry:
         [128 bits] FIntrepidNetworkGUID
         if ObjectId != 0:
           [uint8]   FExportFlags (bit0=bHasPath, bit1=bNoLoad, bit2=bHasChecksum)
           if bHasPath:
             [recursive outer entry]
             [FString Path]
             if bHasChecksum:
               [uint32 Checksum]

  ── MustBeMappedGUIDs section (if bHasMustBeMappedGUIDs=1): ──
       byte-aligned
       [2 bytes LE]           uint16 NumMustBeMappedGUIDs
       [N × 16 bytes]         FIntrepidNetworkGUID[N]
       (Confirmed: sub_143F30430 lines 105-129 read 2 bytes via vtable+384,
        then loops NumMBG times reading 16-byte GUIDs via sub_14141E960)

  ── SerializeNewActor (if !Actor && bOpen): ──
       [Actor NetGUID]       SIP or 128-bit inline
       [Archetype NetGUID]   SIP or 128-bit inline
       [Level NetGUID]       SIP or 128-bit inline
       [4 bits]              bSerializeLocation / Rotation / Scale / Velocity
       (optional FTransform components based on the flags)

  ── Content block loop (one iter per subobject): ──
       // Header via sub_143F2C340 (ReadContentBlockHeader — TBD)
       [Subobject NetGUID]        — SIP-indexed or 16B inline
       [bHasRepLayout : 1 bit]
       [bOutermostEndMarker : 1 bit]   — if set, terminates loop
       
       NumPayloadBits = SerializeIntPacked()   ← AoC-SIP, 1-5 bytes
       
       // Inner FInBunch with NumPayloadBits of outer bits
       → FObjectReplicator::ReceivedBunch(inner)   (sub_143F2F820)
         → URepLayout::ReceiveProperties(inner)
           → cmd_index dispatch (varint/SIP)
           → FString reads, FName reads, NetDeltaSerialize for FastArrays
```

---

## 5. FastArray serializer (fully RE'd)

Four functions handle all FastArray NetDelta traffic:

| EA | Name | Role |
|---|---|---|
| `sub_141D432C0` | `FFastArraySerializer::FastArrayDeltaSerialize` | RECV entry point |
| `sub_141D20340` | `FastArrayDeltaSerialize_DeltaSerializeStructs` | Orchestrator (5 paths: Gather/Move/Read/Write/Fixup) |
| `sub_141D36DD0` | `FFastArraySerializerHelper::BuildChangelist` | SEND side |
| `sub_141D48FD0` | Internal changelist-header reader | Reads RepKey+BaseKey+NumChanged+NumDeletes+IDs[] |

### FastArray wire format

```
[4 bytes] ArrayReplicationKey  (byte-aligned DWORD)
[4 bytes] BaseReplicationKey
[4 bytes] NumChanged           — max from CVar dword_14D20AD28 (threshold warn)
[4 bytes] NumDeletes           — max from CVar dword_14D20AD24
[NumChanged × 4 bytes] ChangedElementIDs
// Per-element body delegated to NetSerialize CB (FFastArrayDeltaSerializeParms.v4[8]->vtable[+8])
// Element bodies are byte-aligned.
```

### FFastArrayDeltaSerializeParms structure

| Field | Type | Meaning |
|---|---|---|
| `parms[0]` | FArchive* | Stream (sink or source) |
| `parms[1]` | BitReader* | Used in Read path |
| `parms[2]` | void* | Output changelist |
| `parms[3]` | void* | Baseline state (previous snapshot) |
| `parms[4]` | UObject* | Owning FastArraySerializer |
| `parms[7]` | UEnum*/UStruct* | Type info (set per iteration) |
| `parms[8]` | INetSerializeCB* | Callback — `vtable[+8]` = `NetSerializeStruct` |
| `parms[11]` | void* | Another callback (vtable +680) |
| `parms[13]` | void* | Gather-phase buffer |
| `parms[15]` | void* | Move-phase buffer |
| `parms[16]` | void* | Output chain |
| `parms+72` | byte | Flag (bit 0 = bIsWriting?) |
| `parms+73..+82` | bytes | More flags (bDirty, bObjectDeleted, bHasRepLayout, ...) |

---

## 6. UActorChannel struct layout (partial)

| Offset | Type | Field |
|---|---|---|
| +48 | UNetConnection* | Connection |
| +50 | uint32 | ChannelFlags (bit 6/7 = bClosingDueToLevelUnload / bTornOff) |
| +54 | int32 | ChIndex (scope copy) |
| +72 | UNetConnection* | Connection (duplicate — common UE pattern) |
| +80 | uint32 | State flags (bit 6 = bClosing, OR'd in with 0x40) |
| +84 | int32 | ChIndex |
| +88 | UObject* | Actor |
| +136 | UPackageMapClient* | PackageMap |
| +144 | FIntrepidNetworkGUID | ActorNetGUID (16 bytes) |
| +168 | size_t | FInBunch cursor save slot |
| +184 | uint32 | Reader-state saved block |
| +208..+248 | TArray | OpenActorChannels (inline 4) |
| +270 | — | Queued reliable bundle state |
| +288..+300 | TArray | QueuedBunches (2056-byte items) |
| +296 | int32 | QueuedBunchCount |
| +304 | double | QueuedBunchStartTime |
| +312 | — | MustBeMappedGUIDs list (inline) |
| +320 | int32 | NumInRec (partial bunch counter) |
| +364 | int32 | NumInRecLastAck |
| +624 | FObjectReplicator | RepState root |
| +5768 | TMap | Bundle queue |
| +6176 | TArray | OpenAcked bundle list |

---

## 7. FInBunch struct layout (partial)

| Offset | Type | Field |
|---|---|---|
| +0 | vtable | Inherited from FArchive |
| +8 | `{int* pos, int* end}` | Byte-iterator pair (fast-path reads) |
| +41 | byte | Error flag (bit 1 = IsCriticalError) |
| +42 | byte | Error flag (bit 0 = IsError) |
| +168 | size_t | Bit-position save slot |
| +176 | byte* | Bunch data pointer |
| +184 | void* | Saved reader state |
| +192 | uint32 | ChSequence |
| +216 | uint32 | Bit position within bunch |
| +228 | uint32 | PacketId |
| +232 | byte | Flag byte A (bit 0 = bOpen, bit 1 = bClose, bit 3 = bReliable) |
| +233 | byte | Flag byte B (bit 0 = bHasMustBeMappedGUIDs) |

### Vtable methods (FArchive derived)

| Offset | Slot | Method |
|---|---|---|
| +56 | 7 | `AtEnd()` — used to detect end of bunch |
| +180 | — | alternate (used in sub_143F30430 line 99 for 2-byte read with r8d=2) |
| +358 | — | `UPackageMap::SerializeNewActor`-like |
| +384 | 48 | `Serialize(void* buf, int64 n)` — byte-aligned byte copy |
| +408 | 51 | `SerializeIntPacked(uint32&)` — AoC-SIP |

---

## 8. ENetCloseResult enum

Location: name-value table at `0x149F5AC80`. Each entry = `[QWORD FName-ptr, int64 value]`.
Confirmed values:

- `BunchHeaderOverflow = 36`

Full table has ~40+ values. Strings are at `0x149F5BB29` (start of `"ENetCloseResult::BunchHeaderOverflow"`), etc.

Static-enum getter: `sub_141D10280`. Only referenced indirectly via `off_149F5CBA8`
(registered function pointer in .rdata) — cannot be found via normal xref walk.

---

## 9. Key function map (RE'd or partially RE'd)

| EA | Name | Status |
|---|---|---|
| `sub_143F30430` | `UActorChannel::ReceivedBunch` | Full Hex-Rays |
| `sub_143F2A2A0` | `UActorChannel::ProcessBunch` | Full Hex-Rays |
| `sub_143F2DA40` | `UActorChannel::ReadContentBlockPayload` | Full Hex-Rays |
| `sub_143F2C340` | `UActorChannel::ReadContentBlockHeader` | **TBD — next to dump** |
| `sub_143F2F820` | `FObjectReplicator::ReceivedBunch` | TBD |
| `sub_143F17580` | FInBunch clone (240-byte alloc) | Called in queuing path |
| `sub_143F1BB50` | Set bunch reader error state | Called on parse fail |
| `sub_143F174A0` | Initialize FBunchReason struct (line number tag) | Error tagging |
| `sub_143F3E000` | Actor channel post-spawn initializer | Called after SerializeNewActor |
| `sub_143F3ADC0` | UActorChannel::Close error dispatcher | Called on fatal parse error |
| `sub_141D20340` | FastArrayDeltaSerialize orchestrator | Full Hex-Rays |
| `sub_141D432C0` | FFastArraySerializer::FastArrayDeltaSerialize RECV | Partial |
| `sub_141D36DD0` | FFastArraySerializerHelper::BuildChangelist | Full disasm |
| `sub_141D48FD0` | FastArray changelist header reader | Full Hex-Rays |
| `sub_141D10280` | StaticEnum<ENetCloseResult>() | Full Hex-Rays |
| `sub_141768740` | FName → FString conversion (for logs) | Utility |
| `sub_141421C70` | Log/printf routing | Utility |
| `sub_14141E960` | Read 16-byte FIntrepidNetworkGUID | Primitive |
| `sub_1414E7250` | Error-path 2-byte read | Primitive |
| `sub_14131C0A0` | Advance bit iterator | Primitive |
| `sub_1414F5CB0` | `FInBunch::Init(outer, NumBits)` — create inner bunch | Primitive |
| `sub_14150CFA0` | FString copy | Utility |
| `sub_1413B0B20` | FString free | Utility |

---

## 10. pkt#104 known offsets (CharacterName capture)

Established via `test_pkt104_round_trip.cpp`:

| Bit | Byte | What |
|---|---|---|
| 0..151 | 0..18 | Packet/frame prefix |
| 152 | 19 | Bunch region starts (bunch_start_bit) |
| 152..189 | 19..23 | Bunch #0 header (38 bits) |
| 177 | — | BunchDataBits field (13 bits fixed) |
| 190..1007 | 23..125 | Bunch #0 payload per current decoder (bdb=818 bits) |
| 1592 | 199 | **cmd_index/handle** (32-bit uint) |
| 1616 | 202 | `0x6A` marker byte (looks like part of cmd_index or a separate cmd) |
| 1624 | 203 | **FString save_num** (int32 = 11) |
| 1656 | 207 | **FString ASCII** "RandomChar" begins |
| 1744 | 218 | After FString + NUL terminator |
| 7665 | — | Total bunch region size (bunch_bits in replay metadata) |
| 7824 | 978 | Total packet size |

**Outstanding mystery**: bdb=818 puts Bunch #0's payload end at bit 1008, but RandomChar
sits at bit 1656 — outside that range. Either the bdb decoder is wrong, or the packet
contains multiple bunches and RandomChar is in a later one. Requires RE of
`UChannel::ReceivedRawBunch` to resolve.

---

## 11. Current implementation status

### Working (tested in-game)
- **Hybrid replay mode**: native NMT control channel + captured replay packets —
  character spawns, in-world, HUD populated.
- **M2.1 NUL-pad CharacterName patcher** (1-10 chars) — works for 4-10 char names;
  11-16 currently truncates to 10 with warning.
- **Replay packet rewriter**: binary needle/replace inside replay_data.bin.

### Native emit path (code written, Phase 3.8+)
- `actor_builder.cpp` — builds bunches byte-by-bit using `write_sip` / `write_serialize_int`.
- `package_map_exporter.h` — emits PME sections matching RE'd format.
- `bunch_writer.h` — bit-level writer.
- `ActorBuilder` can synthesize PlayerController/Pawn bunches.

### Known limitations
- Variable-length patching (11-16 char names) blocked on one more RE round.
- Full URepLayout::ReceiveProperties not decoded — limits full cmd-dispatch
  knowledge but **not needed for current goals**.
- AES-GCM StatelessConnect handshake not decoded — bypassed by hybrid mode using
  captured encrypted packets; would be needed for pure-native bootstrap.

---

## 12. What this unlocks

See `docs/WHAT-WE-CAN-DO-NOW.md` (companion doc) for the full capability catalog.
