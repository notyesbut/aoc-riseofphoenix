# UE5 Actor Replication Wire Format — Complete Specification

> Extracted directly from UE5 source at `C:\dev\UnrealEngine\Engine` on 2026-02-17.

---

## Table of Contents

1. [Primitive Serialization Formats](#1-primitive-serialization-formats)
2. [NetGUID Export Bunch (bHasPackageMapExports=1)](#2-netguid-export-bunch)
3. [Actor Channel Bunch — Top-Level](#3-actor-channel-bunch-top-level)
4. [SerializeNewActor (Open Bunches)](#4-serializenewactor)
5. [Content Block Header + Payload](#5-content-block-header--payload)
6. [Field Header + Payload (Property Replication)](#6-field-header--payload)
7. [RepLayout Property Replication (ReceiveProperties)](#7-replayout-property-replication)
8. [Complete Wire Format Diagram](#8-complete-wire-format-diagram)
9. [Phase 1 Parser Findings & AoC-Specific Behavior](#9-phase-1-parser-findings--aoc-specific-behavior)
10. [Phase 2 Game Data Extraction Results](#10-phase-2-game-data-extraction-results)
11. [Tools Reference](#11-tools-reference)
12. [Phase 3: Custom Delta Property Analysis](#12-phase-3-custom-delta-property-analysis)

---

## 1. Primitive Serialization Formats

### 1.1 `SerializeIntPacked` (uint32) — Variable-length 7-bit encoding

**File:** `Core/Private/Serialization/Archive.cpp:1326`  
**BitReader override:** `Core/Private/Serialization/BitReader.cpp:313` (bit-compatible, reads 8 bits at a time from bitstream)

```
Format: Each byte = [7 bits of value] [1 bit "more" flag (LSB)]

Byte layout (LSB first in wire order):
  bit 0:     more (1 = another byte follows, 0 = last byte)
  bits 1-7:  value[6:0] of this segment

Decoding:
  value = 0, shift = 0
  loop:
    read 1 byte
    more = byte & 1
    data = byte >> 1   (7 bits)
    value |= data << (7 * iteration)
    if !more: break

Max: 5 bytes for 32-bit value (7*5=35 bits capacity)
```

### 1.2 `SerializeIntPacked64` (uint64) — Same encoding, 64-bit

**File:** `Core/Private/Serialization/Archive.cpp:1368`

Identical algorithm to `SerializeIntPacked` but up to **10 bytes** (7*10=70 bits capacity for uint64).  
**This is how `FNetworkGUID` is now serialized** (UE 5.3+).

### 1.3 `FNetworkGUID` Serialization

**File:** `Core/Public/Misc/NetworkGuid.h`

```cpp
union {
    uint32 Value;    // deprecated (5.3)
    uint64 ObjectId; // current
};

friend FArchive& operator<<(FArchive& Ar, FNetworkGUID& G) {
    Ar.SerializeIntPacked64(G.ObjectId);  // Variable-length encoded uint64
    return Ar;
}
```

**Wire format:** 1-10 bytes, variable-length packed uint64.

**Bit semantics of ObjectId:**
- `ObjectId == 0` → Invalid
- `ObjectId & 1 == 1` → Static (level-placed, always exists on both sides)
- `ObjectId & 1 == 0` → Dynamic (spawned at runtime)
- `ObjectId == 1` → Default (valid but unassigned)
- Actual index = `ObjectId >> 1`

### 1.4 `SerializeInt(Value, Max)` — Bit-packed bounded integer

**File:** `Core/Public/Serialization/BitReader.h:81`

Writes/reads the minimum number of bits to represent values `[0, Max-1]`.  
Number of bits = `⌈log₂(Max)⌉` (reads bits one at a time while `Value + Mask < Max`).

### 1.5 `WriteIntWrapped(Value, Max)` / `ReadInt(Max)`

Same as `SerializeInt` — uses `⌈log₂(Max)⌉` bits.

### 1.6 `FRotator::NetSerialize` — `SerializeCompressedShort`

**File:** `Core/Private/Math/UnrealMath.cpp:142`

For each axis (Pitch, Yaw, Roll):
```
1 bit:  bNonZero
if bNonZero:
  16 bits: uint16 compressed axis value (CompressAxisToShort)
```
**Total: 3 bits (all zero) to 51 bits (3 + 3×16)**

### 1.7 Quantized Vector — `SerializeQuantizedVector` / `WriteQuantizedVector`

**File:** `Net/Core/Private/Net/Core/Serialization/QuantizedVectorSerialization.cpp:38`

```
SerializeInt(ComponentBitCountAndExtraInfo, 128)   // 7 bits max

Lower 6 bits = ComponentBitCount (0..63)
Bit 6 = extra info flag

If ComponentBitCount == 0:
  // Full precision fallback
  Bit 6 = type flag: 0 = float32, 1 = float64
  Raw bits: 3 × (32 or 64) bits of IEEE float

If ComponentBitCount > 0:
  // Quantized path
  Bit 6 = bUseScaledValue (1 = values were multiplied by ScaleFactor)
  SerializeBits(X, ComponentBitCount)  // signed integer
  SerializeBits(Y, ComponentBitCount)
  SerializeBits(Z, ComponentBitCount)
```

**For `FVector_NetQuantize10`:** ScaleFactor=10, MaxBitsPerComponent=24

### 1.8 `ConditionallySerializeQuantizedVector` (used in SerializeNewActor)

```
1 bit:  bWasSerialized
if bWasSerialized:
  1 bit:  bShouldQuantize  (omitted in older versions, forced true)
  if bShouldQuantize:
    FVector_NetQuantize10::NetSerialize(...)  // See §1.7 with Scale=10
  else:
    FVector (raw): 3 × double (24 bytes, 192 bits) via operator<<
```

---

## 2. NetGUID Export Bunch (`bHasPackageMapExports=1`)

**File:** `PackageMapClient.cpp:1509 — ReceiveNetGUIDBunch`

This is processed **before** the actor data when `FInBunch::bHasPackageMapExports` is set.

```
1 bit:    bHasRepLayoutExport
  if 1: → ReceiveNetFieldExportsCompat (separate format, not covered here)
  if 0: → NetGUID exports follow

int32:    NumGUIDsInBunch (SerializeIntPacked, via operator<<)
NET_CHECKSUM (debug only, stripped in shipping)

Repeat NumGUIDsInBunch times:
  InternalLoadObject(...)   // recursive, see §2.1
```

### 2.1 `InternalLoadObject` — Recursive NetGUID + Path

**File:** `PackageMapClient.cpp:1089`

```
FNetworkGUID:  NetGUID                    // SerializeIntPacked64 (1-10 bytes)
NET_CHECKSUM_OR_END (debug only)

if NetGUID == 0 (invalid): STOP (null object)

if NetGUID.IsDefault() OR IsExportingNetGUIDBunch:
  uint8:   ExportFlags.Value             // 1 byte
    bit 0: bHasPath
    bit 1: bNoLoad  
    bit 2: bHasNetworkChecksum

if ExportFlags.bHasPath:
  [RECURSE] InternalLoadObject(...)       // Reads OuterGUID (same format)
  FString: ObjectName                     // int32 length + UTF-16/ASCII data
  if ExportFlags.bHasNetworkChecksum:
    uint32: NetworkChecksum               // 4 bytes
```

### 2.2 `FExportFlags` Layout

**File:** `PackageMapClient.cpp:828`

```
uint8 Value:
  bit 0: bHasPath
  bit 1: bNoLoad
  bit 2: bHasNetworkChecksum
  bits 3-7: unused (0)
```

### 2.3 `InternalWriteObject` (Server → Client)

**File:** `PackageMapClient.cpp:890`

```
FNetworkGUID: NetGUID                     // SerializeIntPacked64
NET_CHECKSUM

if NetGUID invalid: STOP

uint8: ExportFlags.Value                  // only if IsDefault || IsExportingNetGUIDBunch
  bHasPath = 1 if path needs to be sent
  bNoLoad = 1 if client can't load this
  bHasNetworkChecksum = 1 if checksum mode enabled

if ExportFlags.bHasPath:
  [RECURSE] InternalWriteObject(OuterGUID, Outer, ...)   // Outer's NetGUID+path
  FString: ObjectPathName
  if bHasNetworkChecksum:
    uint32: NetworkChecksum
```

---

## 3. Actor Channel Bunch — Top-Level

**File:** `DataChannel.cpp:3087 — UActorChannel::ReceivedBunch`

### 3.1 MustBeMappedGUIDs Header (Client-side only, `bHasMustBeMappedGUIDs=1`)

```
uint16: NumMustBeMappedGUIDs     // operator<< (16 bits)

Repeat NumMustBeMappedGUIDs times:
  FNetworkGUID: NetGUID          // SerializeIntPacked64
```

### 3.2 Actor Preview (for bOpen bunches, client-side)

Before queueing, the client peeks at:
```
NET_CHECKSUM
FNetworkGUID: ActorNetGUID       // SerializeIntPacked64
(then rewinds via FBitReaderMark)
```

### 3.3 Main Processing — `ProcessBunchInternal`

**File:** `DataChannel.cpp:3258`

If `Actor == NULL && bOpen`:
```
→ SerializeNewActor(Bunch, ...)  // See §4
```

Then the main content loop:
```
while (!Bunch.AtEnd()):
  ReadContentBlockPayload(Bunch, Reader, bHasRepLayout)  // See §5
  if Reader has data:
    FObjectReplicator::ReceivedBunch(Reader, ...)          // See §6+§7
```

---

## 4. SerializeNewActor (Open Bunches Only)

**File:** `PackageMapClient.cpp:490`

Called when `Actor == NULL && Bunch.bOpen`. Reads the initial actor spawn data.

```
NET_CHECKSUM

// Step 1: Actor NetGUID + Object
SerializeObject(AActor::StaticClass()):
  → InternalLoadObject(...)
  → Yields: Actor NetGUID, resolved Actor pointer

// If AtEnd() && NetGUID.IsDynamic(): 
//   This is a destruction info, no more data. Return.

// Step 2: For dynamic actors (NetGUID.IsDynamic()):

  // Archetype
  SerializeObject(UObject::StaticClass()):
    → InternalLoadObject(...)             // Archetype's NetGUID + path

  // Actor Level (if EngineNetVer >= NewActorOverrideLevel)
  SerializeObject(ULevel::StaticClass()):
    → InternalLoadObject(...)             // Level's NetGUID

  // Spawn info: Location, Rotation, Scale, Velocity

  // Location:
  1 bit:   bSerializeLocation
  if bSerializeLocation:
    1 bit: bShouldQuantize
    if bShouldQuantize:
      QuantizedVector(Scale=10, ...)      // See §1.7
    else:
      FVector: 3 × double (192 bits)

  // Rotation:
  1 bit:   bSerializeRotation
  if bSerializeRotation:
    if GbQuantizeActorRotationOnSpawn:
      FRotator::NetSerialize(...)         // See §1.6 — CompressedShort
    else:
      FRotator: 3 × double (192 bits)

  // Scale:
  1 bit:   bSerializeScale
  if bSerializeScale:
    1 bit: bShouldQuantize
    if bShouldQuantize:
      QuantizedVector(Scale=10, ...)
    else:
      FVector: 3 × double (192 bits)

  // Velocity:
  1 bit:   bSerializeVelocity
  if bSerializeVelocity:
    1 bit: bShouldQuantize
    if bShouldQuantize:
      QuantizedVector(Scale=10, ...)
    else:
      FVector: 3 × double (192 bits)

// For static actors: Nothing more is serialized after the NetGUID.
```

---

## 5. Content Block Header + Payload

Each content block within an actor bunch encapsulates data for one object (the actor itself, or a subobject/component).

### 5.1 `ReadContentBlockPayload`

**File:** `DataChannel.cpp:5091`

```
ContentBlockHeader (see §5.2)
if not deleted:
  uint32: NumPayloadBits            // SerializeIntPacked
  [NumPayloadBits bits]: Payload    // Read into separate FNetBitReader
```

#### 5.1.1 AoC Custom: `bHasRepLayout` Controls NumPayloadBits Presence

> **CRITICAL AoC-SPECIFIC FINDING** (discovered 2026-02-18)
>
> In standard UE5, `NumPayloadBits` is ALWAYS present (SerializeIntPacked).
> In AoC, `bHasRepLayout` from the content block header controls whether
> `NumPayloadBits` exists:
>
> - **`bHasRepLayout = 1`**: NumPayloadBits is encoded via SerializeIntPacked (explicit size).
>   Used for intermediate content blocks in multi-block bunches.
> - **`bHasRepLayout = 0`**: **No NumPayloadBits field**. Payload extends to end of bunch.
>   Used for the last (or only) content block in a bunch.
>
> This is an optimization: most bunches contain a single content block, so
> the explicit size is unnecessary. For multi-block bunches, all blocks
> except the last use `bHasRepLayout=1` with an explicit size, and the final
> block uses `bHasRepLayout=0` to consume remaining bits.
>
> **Accuracy impact:** This single change improved parser accuracy from ~40% to ~97-99%
> across all capture files tested.
>
> **Observed patterns (from 5856 scored bunches):**
> - `(0,)` — 3493 bunches: single block, no explicit size
> - `(1,)` — 339 bunches: single block with explicit size
> - `(1, 0)` — 32: two blocks, first with size, last without
> - `(0, 0)` — 70: two blocks, first is null sub-object (sub_guid=0), last consumes rest
> - `(1, 0, 0, 0)` — 25: four blocks, first with size, rest null sub-objects + final

### 5.2 `ReadContentBlockHeader`

**File:** `DataChannel.cpp:4764`

```
1 bit:  bOutHasRepLayout        // Does this block contain RepLayout property data?
1 bit:  bIsActor                // Is this for the channel's main actor?

if bIsActor == 1:
  → Return Actor (no more header data)

// ---- Sub-object path ----

SerializeObject(UObject::StaticClass()):
  → InternalLoadObject(...)     // SubObject's NetGUID
NET_CHECKSUM_OR_END

// Server receiving from client: STOP here, return SubObj

// ---- Client reading from server: ----

1 bit:  bStablyNamed
if bStablyNamed:
  → Return SubObj (already exists, no need to create)

// ---- Dynamic sub-object (not stably named): ----

if EngineNetVer >= SubObjectDestroyFlag:
  1 bit:  bIsDestroyMessage
  if bIsDestroyMessage:
    uint8: DeleteFlag             // ESubObjectDeleteFlag enum (1 byte)
    NET_CHECKSUM
    → Return (object deleted)

// ---- Sub-object class (for creation): ----
SerializeObject(UObject::StaticClass()):
  → InternalLoadObject(...)     // SubObjClass NetGUID + path

if ClassNetGUID invalid:
  → Delete sub-object

// ---- Sub-object outer chain (if EngineNetVer >= SubObjectOuterChain): ----
1 bit:  bActorIsOuter
if !bActorIsOuter:
  UObject*: ObjOuter             // operator<< → SerializeObject → InternalLoadObject

// ---- Create/return sub-object ----
// If SubObj doesn't exist, instantiate from SubObjClass
```

### 5.3 `WriteContentBlockForSubObjectDelete`

**File:** `DataChannel.cpp:4705`

```
1 bit:  0 (bHasRepLayout = false)
1 bit:  0 (bIsActor = false)
FNetworkGUID: GuidToDelete        // SerializeIntPacked64
NET_CHECKSUM
1 bit:  0 (bStablyNamed = false)
1 bit:  1 (bIsDestroyMessage = true)
uint8:  DeleteFlag
NET_CHECKSUM
```

---

## 6. Field Header + Payload (Individual Property/RPC Blocks)

Inside the payload of a content block, properties and RPCs are serialized as a sequence of field blocks.

### 6.1 `ReadFieldHeaderAndPayload`

**File:** `DataChannel.cpp:5178`

```
if Bunch.GetBitsLeft() == 0: → done (return false)

NET_CHECKSUM

// ---- Standard path (non-replay / non-InternalAck): ----
uint32: RepIndex                  // ReadInt(ClassCache.MaxIndex + 1)
                                  // Uses ⌈log₂(MaxIndex+1)⌉ bits

// ---- Backwards-compatible/Replay path (IsInternalAck): ----
uint32: NetFieldExportHandle      // ReadInt(Max(NetFieldExports.Num(), 2))

// ---- Common: ----
uint32: NumPayloadBits            // SerializeIntPacked
[NumPayloadBits bits]: Payload    // Read into separate FNetBitReader
```

### 6.2 `WriteFieldHeaderAndPayload`

**File:** `DataChannel.cpp:5138`

```
NET_CHECKSUM

if IsInternalAck:
  WriteIntWrapped(NetFieldExportHandle, Max(NetFieldExports.Num(), 2))
else:
  WriteIntWrapped(FieldNetIndex, MaxFieldNetIndex)

uint32: NumPayloadBits            // SerializeIntPacked
[NumPayloadBits bits]: Payload data
```

---

## 7. RepLayout Property Replication (`ReceiveProperties`)

**File:** `RepLayout.cpp:3791`

This reads the **RepLayout** properties from the content block payload (when `bHasRepLayout=true`).

### 7.1 Standard Path (non-InternalAck)

```
#ifdef ENABLE_PROPERTY_CHECKSUMS:
  1 bit: bDoChecksum
#endif

// Property handle stream:
uint32: Handle_0                  // SerializeIntPacked — first property handle

// Then recursive processing (ReceiveProperties_r):
for each RepLayoutCmd in order:
  CurrentHandle++
  if CurrentHandle != ReadHandle:
    skip (if DynamicArray, skip to EndCmd)
  else:
    // ---- This property is present ----

    if DynamicArray:
      uint16: ArrayNum            // operator<< (16 bits)
      uint32: Handle              // SerializeIntPacked — next handle
      if Handle != 0:
        for each array element [0..ArrayNum-1]:
          recurse ReceiveProperties_r(...)
        // After last element, expect Handle == 0 (array terminator)

    else:
      // Scalar property — read inline from bitstream
      // Format depends on property type (NetSerialize, etc.)
      ReceivePropertyHelper(...)

    uint32: NextHandle            // SerializeIntPacked
    // NextHandle == 0 means "done, no more properties"
```

**Key insight:** Properties are identified by their **handle** (1-based index in the RepLayout command list). Only changed properties are sent. The handle stream is:
1. Read first handle
2. Walk through commands, incrementing CurrentHandle
3. When CurrentHandle matches ReadHandle, deserialize that property
4. Read next handle (0 = terminator)

### 7.2 Backwards-Compatible Path (InternalAck / Replays)

Uses `ReceiveProperties_BackwardsCompatible` which reads NetFieldExportGroup-based handles instead of raw indices.

### 7.3 Custom Delta Properties (FastArraySerializer, etc.)

After RepLayout properties, `FObjectReplicator::ReceivedBunch` reads Custom Delta Properties using `ReadFieldHeaderAndPayload`:

```
while true:
  ReadFieldHeaderAndPayload(Object, ClassCache, ...)  // §6.1
  if no more fields: break
  
  if field is FStructProperty (Custom Delta):
    FNetDeltaSerializeInfo → ReceiveCustomDeltaProperty(...)
    // Format is struct-specific (e.g., FastArraySerializer)
  
  else if field is UFunction (RPC):
    ReceivedRPC(...)
    // Parameters serialized by RepLayout
```

---

## 8. Complete Wire Format Diagram

### 8.1 Full Actor Channel Open Bunch (Server → Client)

```
┌─────────────────────────────────────────────────────────────────┐
│ BUNCH HEADER (from UChannel layer, not covered here)            │
├─────────────────────────────────────────────────────────────────┤
│ [IF bHasPackageMapExports]                                      │
│   NetGUID Export Bunch (§2):                                    │
│     1 bit: bHasRepLayoutExport (0)                              │
│     packed_uint32: NumGUIDs                                     │
│     for each GUID:                                              │
│       packed_uint64: NetGUID                                    │
│       [if exporting] uint8: ExportFlags                         │
│       [if bHasPath] recurse Outer + FString Name + checksum     │
├─────────────────────────────────────────────────────────────────┤
│ [IF bHasMustBeMappedGUIDs]                                      │
│   uint16: NumMustBeMappedGUIDs                                  │
│   for each: packed_uint64: NetGUID                              │
├─────────────────────────────────────────────────────────────────┤
│ SerializeNewActor (§4):                                         │
│   packed_uint64: ActorNetGUID                                   │
│   [if exporting] uint8: ExportFlags + path                      │
│   [if dynamic]:                                                 │
│     packed_uint64: ArchetypeNetGUID + export                    │
│     packed_uint64: LevelNetGUID + export                        │
│     1 bit: bLoc → [1 bit: bQuant → QuantVec or raw FVector]    │
│     1 bit: bRot → [CompressedShort or raw FRotator]             │
│     1 bit: bScale → [1 bit: bQuant → QuantVec or raw FVector]  │
│     1 bit: bVel → [1 bit: bQuant → QuantVec or raw FVector]    │
├─────────────────────────────────────────────────────────────────┤
│ Content Block Loop (repeated until Bunch.AtEnd()):              │
│                                                                 │
│ ┌─ Content Block ──────────────────────────────────────────┐    │
│ │ HEADER:                                                  │    │
│ │   1 bit: bHasRepLayout                                   │    │
│ │   1 bit: bIsActor                                        │    │
│ │   [if !bIsActor]:                                        │    │
│ │     packed_uint64: SubObjNetGUID + export                │    │
│ │     1 bit: bStablyNamed                                  │    │
│ │     [if !bStablyNamed]:                                  │    │
│ │       1 bit: bIsDestroyMessage                           │    │
│ │       [if destroy]: uint8 DeleteFlag                     │    │
│ │       [if !destroy]:                                     │    │
│ │         packed_uint64: ClassNetGUID + export              │    │
│ │         1 bit: bActorIsOuter                             │    │
│ │         [if !bActorIsOuter]: packed_uint64 OuterNetGUID  │    │
│ │                                                          │    │
│ │ PAYLOAD SIZE:                                            │    │
│ │   packed_uint32: NumPayloadBits                          │    │
│ │                                                          │    │
│ │ PAYLOAD [NumPayloadBits]:                                │    │
│ │   [if bHasRepLayout]:                                    │    │
│ │     RepLayout Properties (§7):                           │    │
│ │       packed_uint32: Handle₀                             │    │
│ │       for each matched handle:                           │    │
│ │         [property data — type-specific]                  │    │
│ │         packed_uint32: NextHandle (0=done)               │    │
│ │                                                          │    │
│ │   Custom Delta Properties / RPCs:                        │    │
│ │     Field Block Loop:                                    │    │
│ │       ReadInt(MaxIndex+1): RepIndex  // ⌈log₂(N)⌉ bits  │    │
│ │       packed_uint32: NumPayloadBits                      │    │
│ │       [NumPayloadBits]: field-specific data              │    │
│ │     (loop until GetBitsLeft()==0)                         │    │
│ └──────────────────────────────────────────────────────────┘    │
│                                                                 │
│ (next content block or Bunch.AtEnd())                           │
└─────────────────────────────────────────────────────────────────┘
```

### 8.2 Actor Update Bunch (Non-Open, Existing Actor)

```
┌─────────────────────────────────────────────────────────────┐
│ [IF bHasPackageMapExports] NetGUID exports (§2)             │
│ [IF bHasMustBeMappedGUIDs] MustBeMappedGUIDs header         │
├─────────────────────────────────────────────────────────────┤
│ Content Block Loop:                                         │
│   (Same as §8.1 content blocks, but Actor already exists)   │
│   (No SerializeNewActor — actor was already spawned)        │
└─────────────────────────────────────────────────────────────┘
```

---

## Summary of Key Sizes

| Field | Size | Encoding |
|-------|------|----------|
| `FNetworkGUID` | 1-10 bytes | `SerializeIntPacked64` (7-bit VLQ on uint64) |
| `ExportFlags` | 1 byte | uint8 bitfield |
| `FString` | 4 bytes (len) + N bytes (chars) | int32 + UTF-8 or UTF-16 |
| `bHasRepLayout` | 1 bit | single bit |
| `bIsActor` | 1 bit | single bit |
| `bStablyNamed` | 1 bit | single bit |
| `bIsDestroyMessage` | 1 bit | single bit |
| `bActorIsOuter` | 1 bit | single bit |
| `NumPayloadBits` | 1-5 bytes | `SerializeIntPacked` (uint32) |
| Property Handle | 1-5 bytes | `SerializeIntPacked` (uint32) |
| RepIndex | ⌈log₂(MaxIndex+1)⌉ bits | `SerializeInt` |
| `FRotator` (net) | 3-51 bits | 3×(1 bit flag + optional uint16) |
| `FVector` (quantized) | 7 + 3×N bits | header(7 bits) + 3 components |
| Dynamic Array count | 16 bits | uint16 |
| `DeleteFlag` | 8 bits | uint8 |
| `NetworkChecksum` | 32 bits | uint32 |

---

## Notes

1. **`NET_CHECKSUM`** — Only present in debug/non-shipping builds. In production/shipping builds these are compiled out. Do **not** expect them in live traffic.

2. **`FString` serialization** — Uses `operator<<` which writes `int32 length` (negative = UTF-16, positive = ASCII/Latin-1), then the character data. Empty strings write length=0.

3. **Bit alignment** — The entire actor channel bunch is a bitstream. Nothing is byte-aligned unless explicitly read via `Serialize(void*, int64)` which reads bytes through `SerializeBits`.

4. **`SerializeIntPacked` in bitstreams** — In `FBitReader`, `SerializeIntPacked` reads 8 bits at a time from the bitstream (which may be non-byte-aligned). The encoding is byte-compatible with the `FArchive` version.

5. **Version gating** — Several fields are version-gated:
   - `SubObjectOuterChain` → `bActorIsOuter` bit
   - `SubObjectDestroyFlag` → `bIsDestroyMessage` bit
   - `NewActorOverrideLevel` → Level serialization in SerializeNewActor
   - `OptionallyQuantizeSpawnInfo` → `bShouldQuantize` bit per vector
   - `PackedVectorLWCSupport` → new vs legacy vector quantization

---

## 9. Phase 1 Parser Findings — AoC Capture Analysis

> Added 2026-02-19 based on actual AoC Alpha 2 network capture analysis.

### 9.1 Parser Accuracy

**100.0% accuracy** across all 3 captures:

| Capture | Packets | Bunches | Accuracy | Reassembled |
|---------|---------|---------|----------|-------------|
| `capture-20260218-171433.jsonl` | 5,597 | 6,466 | 100.0% | 116 (116 perfect) |
| `capture-20260218-201852.jsonl` | 4,150 | 5,384 | 100.0% | 76 (76 perfect) |
| `capture-20260218-123935.jsonl` | 57,236 | 80,819 | 100.0% | 135 (135 perfect) |
| **Total** | **66,983** | **92,669** | **100.0%** | **327** |

### 9.2 AoC-Specific Encoding Details

**Critical discovery — `bHasRepLayout` flag behavior in AoC:**
- `bHasRepLayout=0` → **NO `NumPayloadBits` field**; payload extends to the next content block or end of bunch
- `bHasRepLayout=1` → **`NumPayloadBits`** is present (SIP-encoded), specifying exact payload length

This differs from the default UE5 behavior where `NumPayloadBits` always follows `bIsActor=0`. AoC's custom serialization omits the payload length for non-RepLayout blocks.

**FString in GUID exports:**
GUID export names (from `InternalLoadObject`) contain mixed binary/readable data. The FString includes full UE5 object paths embedded after binary prefix bytes. Example:
```
\x059?]\x05[74\x02\x04\x19Default__GatherableActor;-]\x18...
```
Game paths can be extracted via regex: `/Game/...`, `/Script/...`

### 9.3 Non-Quantized Vectors

Only 2 actors in the capture use non-quantized positions (`bShouldQuantize=0`). These produce unreadable values when decoded as float64 — likely bit misalignment or custom encoding. Tagged as `location_raw=True` and filtered in analysis.

---

## 10. Phase 2 Game Data Extraction Results

### 10.1 Identified Actor Types

From the large capture (57,236 packets, 80,819 bunches, 105 actors):

| Category | Count | Examples |
|----------|-------|---------|
| **UI** | 1 | `BP_AOCHUD` (Ch 3) — 1.4M bits, heaviest replication |
| **Player Character** | 1 | Ch 19 (behavioral: highest traffic, 1.3M bits, 8557 bunches) |
| **Gatherable** | 9-10 | `GatherableActor` + `InteractableComponent` |
| **Quest Object** | 2-10 | `CSQ_PROP_RedGoblinBanner`, `CSQ_INT_New_Gravestone`, `Despawning_Interactable_Sparkly` |
| **NPC** | 0-4 | `AmbientVillager_Male`, `Wretched Goblin` (embedded in data) |
| **World** | 3 | `WorldDataLayers`, `StaticMeshActor`, `BP_LA_GOB_Braizer` |
| **Unknown** | 75-91 | Channels with unresolvable GUID exports |

### 10.2 Resolved Game Paths

```
/Game/UI/Widgets/BP_AOCHUD
/Game/DesignAssets/Quests/Ambients/AmbientVillager_Male
/Game/DesignAssets/Quests/ANV_FTUE_BF_Quests/Despawning_Interactable_Sparkly_ANV_FTUE_DiscardedWeapon
/Game/DesignAssets/Quests/SidequestAssets/CSQ_0081_COW/CSQ_INT_New_Gravestone
/Game/DesignAssets/Quests/SidequestAssets/CSQ_INTS_NEW/CSQ_PROP_RedGoblinBanner
```

### 10.3 Channel Architecture

| Channel | Type | Bunches | Bits | Notes |
|---------|------|---------|------|-------|
| 0 | Control | 2,490-5,779 | — | Connection management, always present |
| 3 | BP_AOCHUD | 194-872 | 250K-1.4M | Game HUD, heaviest single-actor replication |
| 19 | Player Character | 784-8,557 | 168K-1.3M | Identified by behavioral analysis (most replication traffic) |
| 12xxx | Voice | 2-35 each | — | Voice chat channels (`EName[2]`), 2-21 per session |

### 10.4 Lifecycle Patterns

- **Session start**: Rapid burst of 50+ actor spawns in <1 second
- **Spawn pattern**: Static actors (GUID=0) open first, followed by dynamic actors
- **Close/despawn**: 15,793 close events in long session (frequent actor streaming)
- **Channel reuse**: Channels are opened, closed, and reopened for new actors
- **Ch 117**: Special multiplexed channel — multiple spawn events on same channel

### 10.5 Limitations

- ~80% of actors remain "unknown" due to:
  - GUID export FStrings containing only binary data (no readable paths)
  - Archetype GUIDs not present in the GUID name cache
  - No EName index → string mapping table (would need game data files)
- Position data: Only actors with `bShouldQuantize=1` have valid decoded positions
- Property replication payloads: Not yet decoded (Phase 3 target)

---

## 11. Tools Reference

| Tool | Purpose |
|------|---------|
| `tools/phase1_parse_capture.py` | Phase 1: 100% accuracy bunch parser |
| `tools/phase2_extract_gamedata.py` | Phase 2: Game data extraction & reporting |
| `tools/phase3_rep_layout.py` | Phase 3: Custom Delta + RepLayout property analyzer |
| `tools/diag_movement_format.py` | Movement format discovery diagnostic |
| `tools/diag_guid_analysis.py` | GUID export data analysis |
| `tools/diag_resolve_actors.py` | Cross-reference GUID → actor resolution |
| `tools/diag_channel_names.py` | Channel FName analysis |

---

## 12. Phase 3: Custom Delta Property Analysis

### 12.1 Format Split Discovery

Content block payloads divide into two fundamentally different formats based on `bHasRepLayout`:

| Flag | Format | Description |
|------|--------|-------------|
| `has_rep=1` | **RepLayout** | Standard UE5 property replication: SIP handle stream with typed property data between handles, terminated by SIP(0) |
| `has_rep=0` | **Custom Delta** | AoC custom serialization: SIP(NumPayloadBits) → field data. Contains movement, timers, and game state |

**Ch 19 (Player Character)** statistics:
- RepLayout: 23 payloads (2.9%)
- CustomDelta: **762 payloads (97.1%)** — the vast majority!

### 12.2 Custom Delta Wire Format

For actors with `MaxIndex=0` (single Custom Delta property, common for Character movement):

```
┌─ Content Block ─────────────────────────────────────────┐
│ bHasRepLayout = 0                                       │
│ bIsActor = 1                                            │
│ [payload extends to end of bunch — no size prefix]      │
│                                                         │
│ ┌─ Custom Delta Payload ─────────────────────────────┐  │
│ │ SIP(NumPayloadBits)     ← field data size          │  │
│ │ [NumPayloadBits bits]   ← field data               │  │
│ └────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

### 12.3 AoC Movement Field Data Format

Discovered via bit entropy analysis and cross-validated across 3 captures:

```
┌─ Field Data (N bits) ────────────────────────────────────┐
│                                                          │
│ [8b]  Flags Byte = 0x2C (44) for player movement         │
│       bit 0:   bSimulatedPhysicSleep = 0                 │
│       bit 1:   bRepPhysics = 0                           │
│       bits 2-3: LocQuantLevel = 3 (AoC extension)        │
│       bits 4-5: VelQuantLevel = 2                        │
│       bits 6-7: RotQuantLevel = 0 (ByteCompressed)       │
│                                                          │
│ [SIP] InnerPayloadSize = N - 8 - SIP_bits               │
│       *** NOT ServerFrame! Encodes remaining bit count ***│
│       Validation: field_size - SIP_value = 24 (always)   │
│                                                          │
│ [7b+3×Cb] Location: WritePackedVector                    │
│           7-bit header: comp_bits & 0x1F + extra << 5    │
│           3 × comp_bits signed components / scale        │
│                                                          │
│ [3×8b] Rotation: ByteCompressed (RotQuantLevel=0)        │
│        3 × uint8: angle = value × 360.0 / 256.0         │
│                                                          │
│ [7b+3×Cb] Velocity: WritePackedVector (if moving)        │
│           Same format as Location                        │
│           May be zero-size if player is stationary        │
│                                                          │
│ [Variable] AoC Game State (remaining bits)               │
│            Equipment, timers, abilities, etc.            │
│            Size varies: 58-700+ bits                     │
└──────────────────────────────────────────────────────────┘
```

**Critical finding**: The SIP after the flags byte encodes the **remaining payload bit count**, NOT the ServerFrame as in standard UE5. Verified by: `field_data_size - SIP_value = 24` (for 16-bit SIP) across ALL payload sizes tested (220b, 252b, 268b, 460b, 466b, 499b, 723b).

### 12.4 Payload Classification

Custom Delta payloads on Ch 19 fall into three categories:

| Category | Sizes | Count | Variable Bits | Description |
|----------|-------|-------|---------------|-------------|
| **Timer/Heartbeat** | 58b, 204b, 212b | 298+45+136 = 479 | 13-31b (15-43%) | Mostly constant, single incrementing counter |
| **Movement** | 220b, 252b, 268b | 18+23+33 = 74 | 79-138b (36-51%) | Position + rotation + velocity + game state |
| **Full State** | 460-726b | ~50 | 200-450b (45-62%) | Movement + extensive game state (equipment, abilities) |

### 12.5 Movement Decoder Validation

Cross-validated across all three captures:

| Capture | Packets | Validated Samples | Quality | Dominant Size | Z Baseline |
|---------|---------|-------------------|---------|---------------|------------|
| Small (171s) | 5,597 | 287 | 100% | 212b (136×) | ~512 cm |
| Mid (201s) | 4,150 | 185 | 100% | 212b (134×) | ~515 cm |
| Large (1239s) | 57,236 | 3,369 | 100% | 220b (3,311×) | ~517 cm |

**Position characteristics** (from small capture 212b samples):
- X range: ±1,638 cm (32.8m walking area)
- Y range: ±1,543 cm (30.9m walking area)
- Z range: 510-512.7 cm (flat terrain, 2.7cm elevation change)
- Rotation: constant per payload size (11.2°, 244.7°, 78.8° for 212b)
- Velocity: constant per payload size (4.6, 2.7, 1.0 for 212b)
- Game state: 84 extra bits after movement data

### 12.6 Bit Entropy Findings

Per-bit analysis of constant vs variable regions in the 271-bit field data (43 samples):

| Bit Range | Width | Type | Content |
|-----------|-------|------|---------|
| 0-40 | 41b | Constant | Flags + SIP + QVec header + partial X component |
| 41-62 | 21b | Variable | Incrementing timestamp/position data |
| 63-79 | 17b | Constant | Rotation/velocity headers |
| 80-116 | 36b | Variable | Packed position/velocity components |
| 117-140 | 24b | Constant | Field separators/headers |
| 141-158 | 17b | Variable | Quantized X position (±6,500 range) |
| 169-186 | 17b | Variable | Quantized Y position (±6,400 range) |
| 197-210 | 13b | Variable | Quantized Z position (±407 range) |
| 226-239 | 13b | Variable | Velocity magnitude (193-392 range) |
| 243-259 | 16b | Variable | Rotation yaw (uint16) |
| 264-268 | 4b | Variable | Movement mode enum |

### 12.7 RepLayout Properties

Standard RepLayout (`has_rep=1`) handles found on Ch 19:

| Handle | Count | Size | Type | Description |
|--------|-------|------|------|-------------|
| RL 6 | 1 | 2b | enum2 | Boolean/enum flag |
| RL 38 | 20 | 17b | fixed_17b | Quantized scalar (±392 range) |
| RL 58 | 1 | 57b | fixed_57b | Compound property |

### 12.8 Multi-Channel Patterns

Other channels with significant Custom Delta traffic:

| Channel | Actor | CustomDelta | RepLayout | Notable |
|---------|-------|-------------|-----------|---------|
| Ch 3 | BP_AOCHUD | 171 | 15 | CD816 (60×), CD235 (55×), CD1195 (8×) |
| Ch 7 | Unknown | 0 | 62 | Pure RepLayout, variable 65-287b |
| Ch 116 | Unknown | 51 | 4 | RL 0 (45×) — mostly empty RepLayout |
| Ch 12 | Unknown | 71 | 2 | CD32 (1×), RL 81 = FRotator |
| Ch 20 | Unknown | 41 | 0 | CD1345 (1×) — pure Custom Delta |

### 12.9 Emulator Implications

For the server emulator to replicate player movement:

1. **Content block**: `bHasRepLayout=0, bIsActor=1`
2. **Custom Delta wrapper**: `SIP(field_data_bits)` → field data
3. **Field data construction**:
   - Write flags byte `0x2C`
   - Write `SIP(remaining_bits)` where remaining = total - 8 - SIP_size
   - Write Location via `WritePackedVector(scale=10)`: 7-bit header + 3 signed components
   - Write Rotation: 3 × uint8 (angle × 256 / 360)
   - Write Velocity via `WritePackedVector(scale=10)`: 7-bit header + 3 signed components
   - Write AoC game state (84+ bits of additional state data)
4. **has_rep=0 framing**: No `NumPayloadBits` prefix — payload extends to end of bunch
