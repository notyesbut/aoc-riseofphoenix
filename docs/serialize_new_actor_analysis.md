# SerializeNewActor — Phase 3 decoding notes

Source: `<HOME>/Documents/UnrealEngine-release/Engine/Source/Runtime/Engine/Private/PackageMapClient.cpp`
(UE 5.7, function `UPackageMapClient::SerializeNewActor`, line 491+)

## Canonical format (reading order)

An ActorOpen bunch payload is layered as:

```
[1]  bHasRepLayoutExport      (1 bit)

[2]  if bHasRepLayoutExport:
     ── NumExports            (uint32, 32 bits LE)      ← 411 for AoC PC
     ── Export mask / fields  (AoC: 1 bit per field)    ← 411 bits for AoC PC

[3]  SerializeNewActor(Ar, Channel, Actor):
     ── NET_CHECKSUM(Ar)                 ← no-op in shipping (0 bits)
     ── SerializeObject(AActor, &NetGUID) ← the actor's own NetGUID
     ── if NetGUID is dynamic:
        ── SerializeObject(UObject, &Archetype, &ArchetypeNetGUID)
        ── if EngineNetVer >= NewActorOverrideLevel:
           ── SerializeObject(ULevel, &ActorLevel)
        ── ConditionallySerializeQuantizedVector(Location, ZeroVector, bQuant)
        ── 1 bit: bSerializeRotation
           ── if true: if bQuantize: Rotation.NetSerialize()
                       else:         plain FRotator (3 × 32-bit floats)
        ── ConditionallySerializeQuantizedVector(Scale, OneVector, bQuant)
        ── ConditionallySerializeQuantizedVector(Velocity, ZeroVector, bQuant)

[4]  Initial property values (RepLayout-driven, one per "1" bit in the mask)
```

### `ConditionallySerializeQuantizedVector` details

```
── 1 bit: bWasSerialized (= bSerializeX flag)
── if bWasSerialized:
   ── 1 bit: bShouldQuantize (NEWER ENGINES — see OptionallyQuantizeSpawnInfo)
   ── if bShouldQuantize:
      ── FVector_NetQuantize10.NetSerialize(Ar)   ← compact encoding
   ── else:
      ── plain FVector                            ← 3 × 32-bit floats = 96 bits
```

## Our captured PlayerController breakdown (3302-bit payload)

Already decoded in prior sessions:
- Bit 0        : bHasRepLayoutExport = 1
- Bits 1..32   : NumExports = 411 (uint32 LE)
- Bits 33..443 : 411-bit export mask (68 bits set)

**Everything from bit 444 onward is SerializeNewActor + initial property values**
= 3302 - 444 = **2858 remaining bits** for SerializeNewActor body + properties.

### Expected structure from bit 444

```
Bit 444+        : SerializeObject for Actor's own NetGUID
                  = NET_CHECKSUM(no-op) + FNetworkGUID serialization
                  ≈ 10-40 bits depending on whether full path is exported
Bit ~480+       : SerializeObject for Archetype NetGUID (the class BP)
                  ≈ 10-40 bits, same pattern
Bit ~520+       : SerializeObject for ActorLevel (UE 5.5+)
                  ≈ 10-40 bits
Bit ~560+       : bWasSerialized (Location) (1 bit)
                  + if true, bShouldQuantize (1 bit) + compact vector (~40 bits)
Bit ~600+       : bSerializeRotation (1 bit)
                  + if true, quantized rotation (~24 bits)
Bit ~625+       : bWasSerialized (Scale) (1 bit)
                  + if true, quantized vector (~40 bits)
Bit ~670+       : bWasSerialized (Velocity) (1 bit)
                  + if true, quantized vector (~40 bits)
Bit ~720+       : Initial property values begin
                  ≈ 2580 bits for 68 property values (avg ~38 bits each)
```

These offsets are ESTIMATES — actual bit positions depend on:
- Whether actor/archetype/level GUIDs are "bare" (already known) or "full" (need path)
- Whether quantization is enabled (`GbQuantizeActorLocationOnSpawn` etc.)
- Engine net version (affects OptionallyQuantizeSpawnInfo + NewActorOverrideLevel)

## Critical UE5 engine net versions

Relevant version gates (from `EngineVersionCompatibleWith` / `FEngineNetworkCustomVersion`):

| Gate name                         | Effect when ON              |
|-----------------------------------|-----------------------------|
| `NewActorOverrideLevel`           | Actor includes ActorLevel GUID after Archetype GUID |
| `OptionallyQuantizeSpawnInfo`     | Adds `bShouldQuantize` bit per vector |

AoC's replay was captured at some specific engine-net-version — we need to
determine which by decoding and cross-checking.

## Decoding plan

1. **Extract bits 444+ from pkt 14287's payload** (using extract_bunch.py)
2. **Attempt NetGUID decode** for the actor's own GUID:
   - SIP-encoded GUID int
   - 1-bit: bHasPath
   - if bHasPath: outer GUID (recursive) + FString path + optional 32-bit checksum
3. **Same for Archetype + ActorLevel**
4. **Parse the 4 bSerialize flags** with their optional bQuantize bits
5. **Cross-check remaining bit count** — if we land within reason of 2858, the
   model is correct
6. **Identify "initial property values" region** — the final ~2000-2500 bits

## AoC-specific deviations expected

Based on earlier findings:
- 12-bit ChSequence (vs 10-bit stock) — doesn't affect SerializeNewActor content
- 3 partial-subflag bits (vs 2 stock) — doesn't affect SerializeNewActor content
- 411-bit field mask format (AoC custom) — DIFFERENT from stock FNetFieldExport
  serialization, but MATCHES the number of RepLayout fields expected

SerializeNewActor itself is most likely unchanged from stock UE5, since it's
on the PackageMap replication path and the client's PackageMapClient would
reject anything non-standard. **We expect this part to be byte-identical to stock**.

## Phase 3 — initial decode results (2026-04-21)

Ran `dist/Release/decode_serialize_new_actor.py` against pkt 14287 (the
PlayerController ActorOpen). Results:

### ✅ Confirmed: SerializeNewActor starts at bit 650

Payload layout up to bit 650:
- Bit 206:   `bHasRepLayoutExport` = 1
- Bits 207–238: `NumExports` = 411
- Bits 239–649: 411-bit export mask (68 ones, 343 zeros)
- **Bit 650+**: SerializeNewActor body ← now readable ✓

### ✅ Confirmed: three "bare" NetGUID references

| Field | Bit offset | NetGUID | Flags (hex) | Type |
|-------|-----------|---------|-------------|------|
| Actor NetGUID | 650 | 1 | 0x00 | bare ref (no path) |
| Archetype NetGUID | 674 | 120 | 0x72 | bare ref + `bNoLoad=1` |
| ActorLevel NetGUID | 690 | 10 | 0xd6 | bare ref + `bNoLoad=1` + checksum |

All three are "bare references" — neither the Archetype (class BP) nor the
Level needed to send a path FString because the client already has them
loaded. This is the efficient case, and it means for a fresh PlayerController
we only need to produce these 3 GUIDs (we already know them from the
captured bytes).

### ✅ Confirmed: Location was NOT serialized

| Field | Bit offset | Flag | Meaning |
|-------|-----------|------|---------|
| Location flag | 706 | `false` | → defaults to `(0,0,0)` |

This makes sense — a PlayerController spawns at origin and gets its visible
position from its possessed pawn.

### ⚠️ Partial: rotation / scale / velocity

The decoder reads these but the exact bit-layout of the quantized vectors
(`FVector_NetQuantize10` and `FRotator::NetSerialize`) needs refinement.
Observed:

- Rotation: `bSerialize=true`, followed by some bits (estimated 24–48 — we
  assumed 24, likely actually 48 with 3×16-bit pitch/yaw/roll)
- Scale: `bSerialize=true`, `bShouldQuantize=false` — would read 96 plain
  float bits (3 × 32), which doesn't match the remaining bit budget cleanly

These vectors need the UE5 `FVector_NetQuantize10::NetSerialize` source read
for exact bit layout. Deferred to **Phase 3.2**.

### Remaining bits after SerializeNewActor

Based on current decoder: ~850 bits consumed through rotation, leaving
~1,200-1,600 bits for initial property values. This is where the 68
exported fields' values live.

### Phase 3.1 milestone — DONE

We can now confidently say:
- The actor's NetGUID, Archetype, Level are all **bare references** with
  small integer IDs — trivial to re-emit
- Location/Rotation/Scale/Velocity are flag-gated — most PlayerController
  spawns only need rotation (all others default)
- This means **a PlayerController builder can be ~200 lines of C++**: write
  the known prefix + 3 NetGUID refs + 4 flag bits + quantized rotation +
  then copy the property-values portion (Phase M5) from captured bytes

## Phase 3.5 — quantized-vector bit layouts (DECODED)

### FRotator::NetSerialize → SerializeCompressedShort

Source: `Engine/Source/Runtime/Core/Private/Math/UnrealMath.cpp:142`

```
[1 bit]  bPitchNonZero
[16 bit] uint16 ShortPitch    (only if bPitchNonZero)
[1 bit]  bYawNonZero
[16 bit] uint16 ShortYaw      (only if bYawNonZero)
[1 bit]  bRollNonZero
[16 bit] uint16 ShortRoll     (only if bRollNonZero)
```

**Size**: 3 bits if all zero → 51 bits if all non-zero. **Variable**.

Values are fixed-point quantized: each axis stored as `uint16` mapped to
360° via `DecompressAxisFromShort(s) = (s * 360) / 65536`.

### FVector_NetQuantize10 → SerializePackedVector<10, 24>

Source: `Engine/Source/Runtime/Engine/Classes/Engine/NetSerialization.h:179` (legacy),
~:265 (modern).

#### Legacy path (older engine net versions)

```
[SerializeInt(24)]        uint32 Bits     — "how many bits per component"
[SerializeInt(1<<(B+2))]  uint32 DX       — encoded X (with bias)
[SerializeInt(1<<(B+2))]  uint32 DY       — encoded Y
[SerializeInt(1<<(B+2))]  uint32 DZ       — encoded Z
```

Where `SerializeInt(Max)` is UE5's adaptive integer read — takes
`ceil(log2(Max))` bits max but may take fewer.

- `Bits` takes up to `ceil(log2(24)) = 5` bits (adaptive)
- Each component takes up to `Bits+2` bits
- Decoded value: `(DX - (1 << (B+1))) / ScaleFactor`  (ScaleFactor=10 for
  NetQuantize10)

**Size range**: ~11 bits (small vector) up to ~77 bits (large magnitude).

#### Modern path (`PackedVectorLWCSupport` engine gate)

Uses `UE::Net::ReadQuantizedVector` — LWC-compatible double-precision. Different
layout. We'll determine which path AoC uses empirically by trying both and
seeing which produces consistent vectors across multiple captured spawns.

## Phase 3 — readiness summary

With SerializeNewActor + quantized-vector formats understood, we can now:

1. **Fully decode** any captured ActorOpen bunch's SerializeNewActor portion
2. **Byte-equivalent synthesize** a PlayerController ActorOpen for any player

What REMAINS for a complete PlayerController synthesizer:
- The ~1,600 property-value bits after SerializeNewActor — these are the 68
  initial replicated fields. **This is Phase M5 territory and we can keep
  using captured bytes for now while we synthesize everything around them**.

The Phase 3.6 builder will:
- Write the bunch header ✅ (already know format)
- Write `bHasRepLayoutExport`, `NumExports=411`, the 68-bit mask ✅
- Write 3 NetGUIDs (Actor, Archetype=120, Level=10) ✅
- Write 4 gated vectors ✅
- **Copy the captured property bytes** (Phase M5 replaces this gradually)

## Phase 3.3 — first builder skeleton

Once vector layouts are known, `src/protocol/actors/player_controller.cpp`
gets a `build(BunchBuffer& out, const CharacterProfile& profile)` function
that emits:

1. Bunch header (known: ctrl/open/reliable/partial/chSeq/BunchDataBits)
2. `bHasRepLayoutExport=1`, `NumExports=411`, same 68-bit mask as capture
3. Actor NetGUID (from profile or session-generated)
4. Archetype NetGUID = 120 (the PlayerController class)
5. ActorLevel NetGUID = 10 (the persistent level)
6. Location flag = 0, Rotation flag + quantized rotation, Scale flag = 0,
   Velocity flag = 0
7. Property values — start with captured bytes, later gain per-property
   synthesizers

When step 7 still uses captured bytes, Phase 3 is ~80% done; the remaining
20% is the per-property RepLayout decode (Phase M5).
