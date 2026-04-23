# AoC Wire Format — Consolidated RE Findings

This is the authoritative summary of what we know about Ashes of Creation's
network wire format, as reverse-engineered from the retail game client and
validated against captured traffic.  Historical working notes live elsewhere
in `docs/` (see `aoc-wire-format-decoded.md`, `ue5-actor-replication-wire-format.md`,
`re-*.md`) — this document is the curated stable reference.

> Bit notation: we use LSB-first per byte, matching UE5's `FBitReader` /
> `FBitWriter`.  `read 32 bits` means consume 4 bytes and interpret them as
> little-endian uint32.

---

## 1. Transport & Packet Outer Framing

AoC uses **stock UE5 `NetDriver`** over UDP to port 443, with AoC-specific
additions sprinkled through the middle layers.  The outer packet shape is
the stock `UIpNetDriver` / `UNetConnection` layout:

```
[Connectionless handshake?]  ← StatelessConnect protocol (see re-aoc-client.md)
[Outer packet bits]
  - client identity (custom 6-byte field)
  - PacketNotify (14-bit OutSeq, 14-bit InAck, history bits)
  - bHasPacketInfoPayload
  - (optional) server frame time (8 bits)
[One or more Bunches, contiguously bit-packed]
[Termination: 1 bit set, then zero pad to byte boundary]
```

The outer framing is the same as stock UE5 with AoC's 6-byte client-identity
field inserted.  See `src/net/game_server.h` `write_sc_packet_prefix()` for
the emit side.

---

## 2. Bunch Header

Every replication bunch starts with this variable-length header:

```
1 bit    bControl
1 bit    bControlOpen         (only if bControl)
1 bit    bClose               (only if bControl)
N bits   CloseReason          (only if bControl && bClose; SerializeInt(7))
1 bit    bIsReplicationPaused   ← added in UE5; not in stock UE4
1 bit    bReliable
SIP      ChIndex              (SerializeIntPacked, 8-40 bits)
1 bit    bHasPackageMapExports
1 bit    bHasMustBeMappedGUIDs
1 bit    bPartial
10/12 bits ChSequence         (only if bReliable; 10 for ch=0, 12 for ch>0)
1 bit    bPartialInitial      (only if bPartial)
1 bit    bPartialFinal        (only if bPartial)
—        (* partial flags: see §5)
[ChName block]                (only if (bReliable || bControlOpen) && !bPartial || bPartialInitial)
13 bits  BunchDataBits (BDB)  ← CRITICAL: this is the payload size in bits
N bits   Payload              ← BDB bits of body
```

### ChName block (when present)

```
1 bit    bHasChNameCompact
    if bHasChNameCompact:
      SIP   ChNameCompact       (index into a hardcoded AoC-specific table)
    else:
      32 bits FName::SaveNum
      SaveNum bytes ASCII + NUL
      32 bits FName::Number
```

### Important: BDB is at bit 176 for typical-sized packets

In pkt#104 / pkt#79 fixtures, the BDB field (13 bits) starts at **bit 176**.
An earlier patcher assumed bit 183 — that was **wrong by 7 bits** and was
silently writing into the payload instead of the BDB field.  Fixed in
`src/protocol/emit/replay_mutator.cpp`.

---

## 3. Package Map Export Section

When `bHasRepLayoutExport = 0` (standard case), and the bunch has
`bHasPackageMapExports = 1`, the payload starts with:

```
1 bit      bHasRepLayoutExport = 0
32 bits    NumGUIDsInBunch
For each export:
  [Recursive NetGUID entry — see §4]
```

Each recursive entry emits the full outer chain (package → subpackage →
object → subobject) before the leaf.  Our `PackageMapExporter` (in
`src/protocol/emit/package_map_exporter.cpp`) implements this exactly; it's
validated bit-identical against pkt#22's 3-export section.

---

## 4. FIntrepidNetworkGUID (AoC's NetGUID replacement)

Stock UE5 uses `FNetworkGUID` — a uint32.  **AoC replaced it with a 16-byte
struct** called `FIntrepidNetworkGUID` for cross-server actor identity:

```cpp
struct FIntrepidNetworkGUID {
    uint64_t ObjectId;     // +0 (low) and +4 (high) → uint64 combined
    uint32_t ServerId;     // +8
    uint32_t Randomizer;   // +12
};                         // 16 bytes = 128 bits
```

On the wire these 128 bits are written as **four contiguous uint32s
LSB-first**.  If the write position isn't byte-aligned, the 128 bits are
still emitted as-is (bit-contiguous).

Source: `sub_14141E960` (reader) + `sub_1450360E0` (writer), cross-verified
with log strings in `UIntrepidNetServerPackageMap::InternalLoadObject`:
> `"ObjectId: %llu | ServerId: %u | Randomizer: %u"`

Emit helper: `src/protocol/emit/intrepid_netguid.h` `write_intrepid_guid()`.

### Recursive export entry format

Per `sub_1450360E0` (the NetGUID writer, called per export):

```
128 bits  FIntrepidNetworkGUID   (object's own GUID)
(if ObjectId != 0)
  1 byte   flag byte             (bit 0 = has-outer && IsSupportedForNetworking)
  (if flag bit 0 set)
    [recursive export entry for outer]
    FString  path / name         (int32 save_num + bytes + NUL)
```

---

## 5. Partial Bunches

When a logical bunch exceeds one packet's payload budget, UE5 splits it
into multiple **fragment bunches** across consecutive packets, marked via
`bPartial=1`.  The client reassembles by concatenating fragment payloads.

```
bPartialInitial=1, bPartialFinal=0   → first fragment
bPartialInitial=0, bPartialFinal=0   → middle fragment
bPartialInitial=0, bPartialFinal=1   → last fragment
(Both bits set = a single-packet "partial-framed" bunch, seen occasionally)
```

AoC's pkt#79 and pkt#104 fixtures are **partial-Initial** fragments of
longer logical bunches that continue into later packets.  Mutating such a
fragment's size changes the reassembled total, which the client rejects —
see [`phase-ii-postmortem.md`](./phase-ii-postmortem.md).

Typical partial-flags encoding: **2 bits** (`Initial` + `Final`).  Pkt#22
(the PC ActorOpen) uses a **3-bit** variant that adds `CustomExportsFinal`
— which is the AoC extension.  Code assumes 2-bit unless the bunch is an
ActorOpen.

---

## 6. SerializeNewActor Block

At the start of an ActorOpen bunch's payload (after package-map exports),
stock UE5 emits `FNetGUIDCache::SerializeNewActor()`.  AoC's version does
the same, using `FIntrepidNetworkGUID` in place of stock `FNetworkGUID`:

```
128 bits  Actor NetGUID
128 bits  Archetype NetGUID    (references an export entry)
128 bits  Level NetGUID        (references an export entry)
1 bit     bSerializeLocation
1 bit     bSerializeRotation
1 bit     bSerializeScale
1 bit     bSerializeVelocity
(optional packed-vector bodies, only if respective flag is set)
```

### Packed Vector (Location used in pkt#22)

Standard UE5 `WritePackedVector<ScaleFactor, MaxBitsPerComponent>`:
- pkt#22 observed: `SerializePackedVector<10, 24>` (FVector_NetQuantize10-like)
- Format:
  - 1 bit   bitsNeeded-nonzero flag
  - 5 bits  BitsNeeded (only if flag set; `SerializeInt(max=24+1)`)
  - 3 × BitsNeeded  offset-binary-encoded components

For all-zero vectors, the body is just 1 zero bit.

---

## 7. RepLayout Property Stream

After `SerializeNewActor`, the bunch payload continues with the
property-update stream.  This is AoC's per-property replication.

### Top-level iterator: Function G (`sub_14504F1A0` — `WriteActorChanges`)

Iterates every property in the class's flat RepLayout command array.  For
each dirty cmd, stores `a2[dword_7] = cmd_index` before dispatching to
**Function D** (scalar path) or **Function F** (array path).

### Wire format

```
for each non-default property:
    32 bits  cmd_index            (LSB-first, byte-contiguous)
    N bits   property data        (type-dependent — see §8)
(optional)
    32 bits  0xDEADBEEF           (terminator; absent in pkt#22 — stream
                                   ends when BDB is exhausted)
```

**Default-valued properties are rolled back** — both the cmd_index and
the body are discarded if the data-write consumed zero bits or failed.

---

## 8. Per-Property Dispatch — Function D (`sub_1450357C0`)

`Function D` is the per-property dispatcher.  It reads the FCmd at
`a2+40` (which actually points at an FProperty*, not an FCmd wrapper — see
below) and branches based on flags:

```
Function D (sub_1450357C0)
├── v5 == 0                               → vtable+200 or sub_145035420
├── (FFieldClass+16 flags & 0x100000)==0
│     ├── flags & 0x200000                → sub_145035420 (special fork; unknown)
│     └── else                            → vtable+200 (stock NetSerializeItem)
├── flags & 0x100000 set                  → FastArraySerializer NetDelta path
│     └── via sub_141D0EA50 /
│         hash-table lookup
└── (fallback)                            → sub_145037460 (struct sub-field walker)
```

- **Standard path**: calls `FProperty::NetSerializeItem` via vtable slot 25
  (offset 200).  Each FProperty subclass writes its own format
  (`FBoolProperty` = 1 bit, `FIntProperty` = 32 bits, `FObjectProperty` =
  depends, etc.).
- **FastArraySerializer path**: for `TArray<T>` where `T` derives from
  `FFastArraySerializerItem`.  Uses UE5's NetDelta protocol (add/remove/
  modify per-item).
- **Struct fallback**: for `FStructProperty` without a custom NetSerialize,
  calls `sub_145037460` which walks the inner fields via `Next` pointer
  at `FProperty+24` and recurses into Function D per field.

### Flag bits on FProperty (at `FProperty+56` — PropertyFlags)

| Bit | Name | Behaviour when set |
|---|---|---|
| `0x20` | `CPF_Net` | property is replicated (we scan for this) |
| `0x400000` | `CPF_RepSkip` | skipped by struct walker unless override bit set |
| `0x800000` | (AoC-specific? possibly `CPF_NoExport`) | always skipped |

### Flag bits on FFieldClass (at `FProperty+8 → +16`)

| Bit | Meaning |
|---|---|
| `0x100000` | FastArraySerializer-compatible class |
| `0x200000` | Special dispatch fork (via `sub_145035420`; role TBD) |

---

## 9. FProperty struct layout (verified)

```
FProperty memory layout:
  +0    vtable
  +8    FFieldClass*             ← flags at (*+16) drive Function D dispatch
  +16   Owner (FFieldVariant 16B)
  +24   Next FProperty*          ← linked list for struct inner fields
  +32   Name (FName 8B)
  +40   ...
  +48   ArrayDim (int32)         ← our "ElementCount"; 1 for scalar, >1 for static array
  +52   ElementSize (int32)      ← our "Stride"
  +56   PropertyFlags (uint64)   ← our "Flags" (CPF_* bits)
  +68   Offset_Internal (int32)  ← field offset within owning UObject
  +112  (AoC-specific)           ← sub-pointer used on InterServer/FastArray path
```

---

## 10. FString on the wire

Format used by `FProperty::NetSerializeItem` for FStrProperty and by FName
where explicit serialization is needed:

```
32 bits  int32 save_num
   if save_num > 0  → save_num ASCII bytes (last is NUL terminator)
   if save_num < 0  → (-save_num) UCS-2 chars LE (last is NUL u16)
   if save_num == 0 → empty string
```

A 10-char ASCII name "RandomChar" encodes as:
`save_num=11, 10 bytes 'R','a',...,'r', 1 NUL byte` → 120 bits total.

Our codec: `src/protocol/emit/replayout/encoders/fstring_codec.*`.

---

## 11. Primitive wire formats (from `FProperty::NetSerializeItem`)

| FProperty subclass | Body size | Notes |
|---|---|---|
| `FBoolProperty` | 1 bit | LSB of a conceptual byte |
| `FByteProperty` | 8 bits | fixed |
| `FIntProperty` | 32 bits | LSB-first |
| `FInt64Property` | 64 bits | LSB-first |
| `FFloatProperty` | 32 bits | IEEE 754 |
| `FDoubleProperty` | 64 bits | IEEE 754 |
| `FNameProperty` | SIP-packed uint32 | indexed via PackageMap |
| `FObjectProperty` | SIP-packed uint32 (stock UE5) OR 128-bit `FIntrepidNetworkGUID` inline (AoC custom path) | depends on whether PackageMap resolves |
| `FStrProperty` | FString (see §10) | |
| `FStructProperty` w/ NetSerialize | per-struct specific | e.g. `FRepMovement`, `FRepAttachment`, `FUniqueNetIdRepl` |
| `FStructProperty` w/o NetSerialize | concatenation of inner fields | via `sub_145037460` |
| `FArrayProperty` | NetDelta (FastArraySerializer) or plain count + elements | |

---

## 12. Known-identified properties (AAoCPlayerController hierarchy)

| cmd_index (flat) | Class | Property | Type | Body |
|---|---|---|---|---|
| 0 | AActor | `AuthServerIDReplicated` | **FIntProperty** | 32 bits |
| 1 | AActor | `bReplicateMovement` | FBoolProperty | 1 bit |
| 2 | AActor | `bHidden` | FBoolProperty | 1 bit |
| ... | AActor | other 11 stock props | various | see full catalog |
| 13 | AController | `PlayerState` | FObjectProperty | SIP/GUID |
| 14 | AController | `Pawn` | FObjectProperty | SIP/GUID |
| 15 | APlayerController | `TargetViewRotation` | FStructProperty (FRotator) | NetSerialize |
| 16 | APlayerController | `SpawnLocation` | FStructProperty (FVector_NetQuantize10) | packed |
| 17 | AAoCPlayerController | `bRegisteredForDamageMeter` | FBoolProperty | 1 bit |
| 28 | AAoCPlayerController | `Name` (OnRep_CharacterName) | FStrProperty | FString |
| ... | ... | 17 more AoC-specific | various | mostly Unknown |

Full catalog in `src/protocol/emit/replayout/catalog.cpp`.  The note
about cmd_indices not being observable as monotonic in captured streams
(we've seen `cmd=0` appear twice) suggests **per-subobject cmd tables**
get interleaved — each replicated subobject starts its own cmd_index
space at 0.

---

## 13. Known gaps / open questions

- **`sub_145037460`**: struct fallback walker, decompiled — confirmed as
  inner-field iterator with skip flags.
- **`sub_145035420`**: dispatched on FFieldClass flag `0x200000`.
  Unknown purpose.  Not yet RE'd.
- **Subobject framing**: pkt#22 replicates multiple cmd_index=0 entries.
  This strongly implies replicated subobjects get their own content blocks.
  We haven't pinned down the framing marker between them.
- **`sub_14502D230`**: precondition check gating scalar writes.  Looks like
  a shadow-state comparator that decides whether the property value
  actually changed.  Unverified.
- **Encryption**: AoC uses AES-GCM at some layer (noted in early RE) but
  captured replay streams are cleartext, suggesting either handshake-time
  key derivation we don't trigger, or the capture was done pre-encryption.

---

## 14. Validation / test coverage

| What | Where | Status |
|---|---|---|
| Bit reader/writer primitives | `src/protocol/wire/ue5_primitives.h` | Used in all tests |
| Outer bunch framing | `actor_builder.cpp` | Bit-identical vs pkt#22 first 4011 bits |
| PackageMap export section | `package_map_exporter.cpp` | Bit-identical vs pkt#22 exports |
| `FIntrepidNetworkGUID` | `intrepid_netguid.h` | Identity round-trip tests |
| FString codec | `replayout/encoders/fstring_codec.cpp` | 14 tests pass |
| Primitive codecs (Bool/Byte/Int/etc.) | `replayout/encoders/scalar_codec.cpp` | 94 tests pass |
| FStruct dispatcher | `replayout/encoders/fstruct_codec.cpp` | Covered in 94-test suite |
| ReplayMutator (FString region rewrite) | `replay_mutator.cpp` | 40 tests pass |
| Replay mutation end-to-end | `test_pkt104_round_trip.exe` | 14 tests pass |

**Total: 148 automated tests, all green.**

---

## 15. Function taxonomy (for navigating IDA)

Known AoC client functions in the RepLayout pipeline (addresses as of
`AOCClient-Win64-Shipping.exe` build used for this project's RE):

| Address | Name | Role |
|---|---|---|
| `sub_14141E960` | `ReadFIntrepidNetworkGUID` | reads 128-bit NetGUID (4× uint32) |
| `sub_1450360E0` | `WriteFIntrepidNetworkGUID` | recursive NetGUID writer w/ outer chain |
| `sub_1450318A0` | `FGuidCache::GetOrAssignNetGUID` | UObject → NetGUID resolver |
| `sub_14504F1A0` | **Function G**: `WriteActorChanges` | top-level RepLayout iterator |
| `sub_145057C30` | **Function J**: per-cmd entry | writes 32-bit cmd_index; dispatches |
| `sub_1450357C0` | **Function D**: per-property dispatcher | 4-branch flag-based routing |
| `sub_14503E260` | Function F: array writer | TArray per-element |
| `sub_145056800` | Shadow state updater | NOT a network writer |
| `sub_145037460` | Struct sub-field walker | recursive for inner fields |
| `sub_141D0EA50` | `GetFastArraySerializerClass` | lazy-init FFieldClass getter |
| `sub_145035420` | (special flag 0x200000 path) | unknown |

This taxonomy is how you navigate from a decompiled function back to "what
layer of the protocol am I looking at."
