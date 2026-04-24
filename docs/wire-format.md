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
| `sub_14504F1A0` | **Function G**: `WriteActorChanges` | top-level RepLayout iterator — walks phase bitmask at ctx[+0], emits `[cmd_idx][body]*[0xDEADBEEF]` per phase (see §16) |
| `sub_145057C30` | **Function J**: per-cmd entry | writes 32-bit cmd_index atomically; runs diff-check, skips unchanged; rewinds if body empty |
| `sub_1450357C0` | **Function D**: per-property dispatcher | 4-branch flag-based routing |
| `sub_14503E260` | Function F: array writer | TArray flag-detect + dispatch |
| `sub_145056800` | Shadow state updater | NOT a network writer |
| `sub_145037460` | Struct sub-field walker | recursive for inner fields |
| `sub_141D0EA50` | `GetFastArraySerializerClass` | lazy-init FFieldClass getter |
| `sub_145035420` | **Function F-body**: TArray element iteration | uint16 Num + per-elem dispatch |

This taxonomy is how you navigate from a decompiled function back to "what
layer of the protocol am I looking at."

### 15.1 `sub_145035420` — TArray element serializer (RE'd 2026-04-23)

Previously marked "special flag 0x200000 path: unknown".  Full decomp
(see session notes) shows this is the **inner body of the TArray
serializer** — `sub_14503E260` detects the `FArrayProperty` flag and
tail-calls here for the actual element loop.

Behaviour:

1. **Read/write uint16 Num** through FArchive:
   ```
   v39 = *(_WORD *)(v4 + 8);     // in-memory Num snapshot
   if (cursor + 1 > end) {
       // slow path: virtual FArchive::Serialize(&v39, 2)
       // at vtable offset 384 (method #48)
   } else {
       v39 = **cursor;                     // fast-path load
       *cursor += 2;                        // advance 2 bytes
   }
   ```
   So TArray Num on the wire is **16 bits, byte-aligned** (not a
   SerializeIntPacked as stock UE5 uses on disk).

2. **Validate Num < 0xFFFF**.  Sentinel value hits error path
   `sub_1414E84D0` which logs "Serializing/Deserializing FField: None
   (size 0xFFFF)" and aborts.

3. **Resize in-memory TArray** (load path only):
   - Shrink: call element destructors via vtable method @ +312 (#39),
     then `sub_1416D0920` to truncate.
   - Grow: `sub_1416B5170(new_count - old_count)`.

4. **Per-element loop**:
   ```
   for (v3 = 0; v3 < Num; ++v3) {
       context.field = v6[15];                      // FField* for elem type
       context.data  = array_base + v3 * stride;    // element address
       // stride = FField[+0x34] = ElementSize
       if (!sub_1450357C0(a1, context)) break;
   }
   ```
   This means each TArray element goes through the full **FProperty
   dispatcher** (`sub_1450357C0`, "Function D"), so nested structures,
   TArray-of-struct, etc. all recurse correctly.

5. **Element destructor fast-path** gated by FField flag
   `0x1000000000` (bit 36).  When SET, the destructor virtual call is
   skipped — likely a POD-like flag ("TriviallyDestructible").  Combined
   with `0x40000000` (bit 30) as `0x1040000000`, the entire destroy
   phase is skipped.  This matters for our synthesiser: if we ever
   construct a TArray<T> for replication, T's FField flags must mark
   either the destructible path OR the POD flag, otherwise we hit a
   virtual call on an uninitialised vtable.

**Consequence for our decoder**: when we see a cmd_index whose catalog
entry is `FPropertyType::Array`, the wire encoding is:
  ```
  uint16 Num
  Num × <element_body>   // each via decode_property(element_desc, ...)
  ```
No per-element header, no termination sentinel.  This gives us the
decoder to implement once we start seeing array-typed properties in
pkt#22 / pkt#78 (e.g. `MarkedTargets` on AAoCPlayerController at
RepIndex 16 is likely `TArray<AActor*>`).

---

## 16. RepLayout property stream format (RE'd 2026-04-24)

**THIS SUPERSEDES** our earlier assumption of a flat per-class cmd_index
list.  `sub_14504F1A0` (Function G) is the top-level RepLayout iterator
and it emits properties **partitioned into phases, each phase terminated
by a 0xDEADBEEF sentinel**.

### 16.1 Phase model

Function G reads an 8-bit **phase bitmask** from `context[+0]` and iterates
the set bits lowest-first:

```c
for ( i = *(_BYTE *)a2; v27; ... )
    *(_BYTE *)(a2 + 64) = v27 & -v27;      // isolate lowest set bit
```

Each phase bit selects a different property list on the actor's UClass:

| Phase bit | UClass offset | List name (our naming)      | Meaning                        |
|-----------|---------------|-----------------------------|--------------------------------|
| `0x01`    | `+0x130` (304)| **InitialRepProps**         | "constant once" — sent at open |
| others    | `+0x120` (288)| **LifetimeRepProps**        | "change over time" — deltas    |

Each list is a `TArray<FRepParentCmd>` (16-byte entries) at `offset+0` with
`Num` at `offset+8`.

### 16.2 Per-phase stream layout

Within a phase, Function G emits a sequence of `[cmd_index][body]` pairs
with cmd_index starting at 0 and **incrementing by 1 per property** (not
skipping unreplicated ones — the list is already filtered).  After the
last property, Function G writes **`0xDEADBEEF` (little-endian: `DE AD
BE EF`)** as a 4-byte sentinel.

**Writer path** (v31 & 4 = `IsSaving`):
```
for v33 = 0; v33 < num_props; ++v33:
    context.cmd_index = v33
    context.field     = property_list[v33]
    Function J(a1, context)     // may emit [cmd_idx][body], or skip if unchanged
0xDEADBEEF                       // phase terminator
```

**Reader path** (v31 & 1 = `IsLoading`):
```
loop:
    read uint32 cmd_index
    if cmd_index == 0xDEADBEEF: break
    field = property_list[cmd_index]           // 16-byte stride lookup
    dispatch via sub_14503E260 or Function J
    if loop_count >= 1024: break                // safety bound
```

### 16.3 Why pkt#22 shows cmd_index=0 twice

pkt#22 is an actor-**OPEN**, which runs **both phases** in one
burst:

```
[Phase 1 — InitialRepProps]
    uint32 cmd_index = 0      (e.g. AuthServerIDReplicated)
    <body>
    uint32 cmd_index = 1      (e.g. bIsInterServerReplicated)
    <body>
    ...
    uint32 0xDEADBEEF
[Phase 0 — LifetimeRepProps]
    uint32 cmd_index = 0      (e.g. bReplicateMovement — NEW phase, NEW index space)
    <body>
    ...
    uint32 0xDEADBEEF
```

Our earlier decoder saw "cmd_index=0 twice" because it was walking a
single-list model.  The correct model is **two lists back-to-back,
each starting at cmd_index=0**, with a sentinel between them.

This also explains why delta packets (pkt#79, mutation tests) have fewer
cmd_indices — those are LifetimeRepProps-only, and properties unchanged
since last tick are filtered by the diff-checker (`sub_14502D230`, see
§16.5).

### 16.4 Wire bitness — cmd_index and sentinel are byte-aligned

Both cmd_index and the 0xDEADBEEF sentinel are **32-bit byte-aligned**
writes through FArchive:

```c
if ( (unsigned __int64)(*(_QWORD *)v21 + 4LL) > *(_QWORD *)(v21 + 8) )
    virtual FArchive::Serialize(&val, 4)    // slow path: may realign
else
    *(uint32*)cursor = val; cursor += 4;    // fast path: byte-aligned
```

However, a bunch is a bit stream — so when RepLayout calls into Function
G, the archive is a `FBitArchive` subclass whose `Serialize()` vtable slot
writes a 32-bit value at the **current bit position**, rounded up / not,
depending on whether bit-packing is enabled.  For our decoder: read the
cmd_index and sentinel as **32 bits at the current bit cursor, no byte
realignment**.  This is confirmed by `test_pkt104_round_trip` which
already assumes this bitness.

### 16.5 Diff-check (delta path) — `sub_14502D230`

Function J gates every write on `sub_14502D230(shadow_state, cmd_index,
FField, data_base)`.  This function walks a 3-level hashtable (cmd_index
→ shadow entry at 32-byte stride), then invokes **FField vtable slot 23**
(offset 184) = `FField::Identical(current_ptr, shadow_ptr, 0)`.

- `Identical()` returns 1 → value unchanged → Function J's rewind logic
  cancels the cmd_index write, so the property is **silently skipped**
- `Identical()` returns 0 → value changed → Function J emits
  `[cmd_index][body]` and calls `sub_145056800` to update the shadow state

On actor OPEN (pkt#22), the shadow state is fresh (all default values),
so every property that differs from its class-default value is emitted.
For subsequent deltas, only changed properties are emitted.

### 16.6 Phase-mask for pkt#22 (conjecture, to verify)

Our fixture (`captured_pc_spawn_reassembled.bin`) almost certainly has
phase mask `0x03` (both bits 0 and 1 set) based on the "two concatenated
property streams" observation.  This should be visible in the bunch
payload immediately before the stream start — search for an 8-bit field
with value `0x03` around the pkt#22 RepLayout offset (bit 4003 or so in
our capture).

### 16.7 Shadow-state hashing — `sub_145032980`

Function J keys its shadow-state lookup with a Bob Jenkins mix over 16
bytes at `object+40` (the FName + some padding).  The magic constant
`0x9E3779B9` (golden ratio) is the canonical Jenkins mixing seed.  This
gives us a stable hash per actor instance — we don't need to replicate
this hash unless we implement our own shadow-state tracking, which is
not on the M1 critical path.

### 16.8 Implications for `decode_pc_spawn.cpp`

Given this wire format, the **Phase e** (property-stream walker) pseudo
becomes:

```cpp
std::vector<DecodedPhase> phases;
uint8_t phase_mask = read_byte();           // context[+0]
for (int phase_bit = 0; phase_bit < 8; ++phase_bit) {
    if (!(phase_mask & (1 << phase_bit))) continue;
    DecodedPhase phase{};
    phase.phase_id = phase_bit;
    const auto& list = phase_bit == 0
        ? catalog.lifetime_props()   // UClass+288
        : catalog.initial_props();   // UClass+304
    while (true) {
        uint32_t cmd_index = read_uint32_lsb();
        if (cmd_index == 0xDEADBEEFu) break;
        if (cmd_index >= list.size()) return std::nullopt;  // corrupt
        const auto& prop = list[cmd_index];
        DecodedProperty dp{ cmd_index, decode_body(prop) };
        phase.properties.push_back(std::move(dp));
    }
    phases.push_back(std::move(phase));
}
```

**Catalog change needed**: our current `class_catalog` is a flat
`vector<PropertyDesc>`.  We now need to split it into **two lists per
class** (initial vs lifetime) to match the phase model.  Stock UE5
`GetLifetimeReplicatedProps()` tags each `FDoRepLifetimeParams` with
`Condition` and `RepNotifyCondition`, and the RepLayout builder sorts
them into these two lists based on the `COND_InitialOnly` condition.

We don't have the AoC client's exact list ordering — but the IDA
FPropertyParams table dumps (off_14A77DB70 upward) give us the full
property set in declaration order, and we can infer the split by looking
for `COND_InitialOnly` usage in `AAoCPlayerController::GetLifetimeReplicatedProps`
(or equivalent).

### 16.9 Updated function taxonomy

Add these to §15's table:

| Address | Name | Role |
|---|---|---|
| `sub_145032980` | Shadow-hash (Jenkins) | FName-based 16-byte content hash → shadow-state slot |
| `sub_14502D230` | Diff-checker | 3-level hashtable → `FField::Identical()` comparison |
| `sub_1414E84D0` | `FArchive::SetError` (+ chain propagate) | sets bit 1 of archive[+41], walks linked chain at +136 |
| `sub_1416B5170` | `FArrayProperty::AddUninitialized` + init | grow TArray + per-elem `InitializeValue` or bulk memset |
| `sub_14502EBC0` | Shadow-state getter | returns per-object shadow-state ptr (keyed by hash) |
| `sub_1450205D0` | Shadow-state hashtable lookup | input: hash, returns: entry index or -1 |

### 16.10 FField offsets (consolidated from Functions D, F, G, J)

Confirmed field offsets in `FField` (needed for the walker):

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| `+0x00` | ptr  | vtable | slot 23 = `Identical`, slot 42 = `InitializeValue`, slot 48 = `Serialize` |
| `+0x30` | 4    | **ArrayDim** | fixed-array dimension (1 for scalars) |
| `+0x34` | 4    | **ElementSize** | stride per element |
| `+0x38` | 8    | **FieldFlags** | CPF_* bits; bit 9 (0x200) = POD init, bit 36 (0x1000000000) = POD destroy |
| `+0x44` | 4    | **Offset_Internal** | offset within enclosing actor/struct |

### 16.11 FArchive offsets (consolidated)

Confirmed field offsets in the bit-archive flavour used by Function G:

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| `+0x08` | ptr  | buffer cursor (uint8**)  | fast-path byte writer target |
| `+0x28` | 1    | mode flags | bit 0 = IsLoading, bit 2 = IsSaving |
| `+0x29` | 1    | status flags | bit 1 = ArError (set by `sub_1414E84D0`) |
| `+0x2A` | 1    | bit-pack mode | bit 0 = use bit writer slow path |
| `+0x88` | 8    | linked chain next | for error propagation |
| `+0xA0` | 4    | bit position | `FBitWriter::Pos` — Function J's rewind target |

---

## 17. FPropertyParams layout (RE'd 2026-04-24 via direct binary read)

Rather than rely on IDA XRefs (which the Shipping build strips), we read
`AOCClient-Win64-Shipping.exe` directly via a Python PE parser — see
`C:\Users\xmaxt\AppData\Local\Temp\re_pe_dump.py`.  This gave us the full
structure layout of every UE5 `FPropertyParams` entry.

### 17.1 64-byte layout

```
struct FPropertyParams {
    +0x00  const char*  NameUTF8;           // property name (always set)
    +0x08  void (*)()   RepNotifyFunc;      // OnRep_X callback OR nullptr
    +0x10  uint64       PropertyFlags;      // CPF_* bits (EPropertyFlags)
    +0x18  uint32       ObjectFlags;        // EObjectFlags for the property
    +0x1C  uint32       Discriminator;      // always 0x00000045 for AActor's props
    +0x20  uint64       Reserved_0;         // always 0 in observed samples
    +0x28  uint64       Reserved_1;         // always 0
    +0x30  uint16       ArrayDim;           // 1 for non-array
    +0x32  uint16       BitIndex_or_Offset; // for Bool: bitfield bit index
                                             // for non-Bool: byte offset lo16
    +0x34  uint32       OffsetInClass;      // absolute byte offset within UObject
    +0x38  void*        ExtraPtr;           // for Bool/Struct: getter/setter thunk
                                             // for Int/Float: nullptr
}                                            // TOTAL: 0x40 (64) bytes
```

### 17.2 PropertyFlags bits (EPropertyFlags)

Standard UE5 bits:

| Bit | Value | Name |
|-----|-------|------|
| 0 | `0x1` | `CPF_Edit` |
| 2 | `0x4` | `CPF_BlueprintVisible` |
| 4 | `0x10` | `CPF_BlueprintReadOnly` |
| **5** | **`0x20`** | **`CPF_Net`** (is replicated through standard RepLayout) |
| 16 | `0x10000` | `CPF_DisableEditOnInstance` |
| 30 | `0x40000000` | `CPF_IsPlainOldData` |
| **32** | **`0x100000000`** | **`CPF_RepNotify`** (has OnRep_ callback) |
| 36 | `0x1000000000` | `CPF_NoDestructor` |

**AoC-specific** (not in stock UE5):

| Bit | Value | Name (hypothesis) |
|-----|-------|------|
| **63** | **`0x8000000000000000`** | **`CPF_InterServer`** — replicates across AoC's server mesh |

### 17.3 How to tell if a property is in pkt#22's stream

A property is emitted in pkt#22's RepLayout property stream **if and only
if** its `PropertyFlags & CPF_Net (0x20)` is set.

### 17.4 Critical correction: AActor catalog has 13 entries, not 15

Our earlier catalog had 15 entries including `bIsInterServerReplicated`
and `ProxyNetUpdateInterval`.  Binary RE shows these two **do NOT have
`CPF_Net` set** — only `CPF_InterServer` (bit 63).  They replicate via
AoC's server-to-server channel, NOT the standard RepLayout stream in
pkt#22.  The corrected AActor catalog:

| RepIdx | Name | CPF flags |
|--------|------|-----------|
| 0 | AuthServerIDReplicated | CPF_Net (AoC add, IS stream) |
| 1 | bReplicateMovement | CPF_Net \| CPF_RepNotify |
| 2 | bHidden | CPF_Net |
| 3 | bTearOff | CPF_Net |
| 4 | bCanBeDamaged | CPF_Net |
| 5 | bReplicates | CPF_Net \| CPF_RepNotify |
| 6 | ReplicatedMovement | CPF_Net \| CPF_RepNotify |
| 7 | RemoteRole | CPF_Net |
| 8 | AttachmentReplication | CPF_Net \| CPF_RepNotify |
| 9 | Owner | CPF_Net \| CPF_RepNotify |
| 10 | Role | CPF_Net |
| 11 | NetDormancy | CPF_Net \| CPF_RepNotify |
| 12 | Instigator | CPF_Net \| CPF_RepNotify |

This correction likely resolves our "cmd_index=0 twice" mystery **without
needing the phase model**: our old 15-entry catalog caused mis-indexing
during the walk.  The phase-model hypothesis (§16) may still be correct
architecturally, but pkt#22 might be walkable as a single flat stream
with the corrected catalog.  To be verified via round-trip test.

### 17.5 AAoCPlayerController catalog (19 entries, full ground truth)

See `catalog.cpp::aaoc_player_controller_catalog()` for the complete
list with PropertyFlags, RepNotify markers, and type inferences.  All
19 properties extracted from the binary pointer table at VA
`0x14B6D5410` (224 total fields; filtered to CPF_Net subset).
