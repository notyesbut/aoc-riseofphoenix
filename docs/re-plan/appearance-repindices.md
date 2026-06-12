# UCharacterAppearanceComponent — Replication Indices & Wire Layout

**Target:** PM151 (visible body mesh) — seed the possessed Pawn's
`CharacterAppearanceComponent` subobject with property-update bunches so the
`MergeableSkeletalMeshComponent` (`CharacterMesh0`) assembles a body.

**Scope:** Derive the RepIndex/handle and on-wire encoding of every replicated
(lifetime) property on `UCharacterAppearanceComponent` and its parents, and
cross-check against the current guesses in `src/net/appearance_emitter.cpp`.

**Legend:** every claim is tagged **[CONFIRMED]** (directly read from an SDK
dump / source file cited inline) or **[INFERRED]** (derived from UE5 replication
rules; not yet validated against a live handshake/pcap).

---

## 1. Class hierarchy (the property chain)

`UCharacterAppearanceComponent` inherits, leaf→root:

```
UCharacterAppearanceComponent
  └─ UBaseModularAppearanceComponent
       └─ UIntrepidRepKeyComponent
            └─ UActorComponent
                 └─ UObject
```

**[CONFIRMED]** Inheritance chain:
- `docs/aoc-sdk/Dumpspace/ClassesInfo.json` → `UCharacterAppearanceComponent.__InheritInfo`
  = `["UBaseModularAppearanceComponent","UIntrepidRepKeyComponent","UActorComponent","UObject"]`.
- `docs/aoc-sdk/CppSDK/SDK/GameSystemsPlugin_classes.hpp:17332`
  (`class UCharacterAppearanceComponent : public UBaseModularAppearanceComponent`),
  `:17266` (`UBaseModularAppearanceComponent : public UIntrepidRepKeyComponent`),
  `docs/aoc-sdk/CppSDK/SDK/IntrepidNet_classes.hpp:521`
  (`UIntrepidRepKeyComponent : public UActorComponent`),
  `docs/aoc-sdk/CppSDK/SDK/Engine_classes.hpp:160` (`UActorComponent : public UObject`).

### How UE5 assigns RepIndex (the rule we apply)

**[INFERRED — UE5 engine rule, not RE'd from this binary]**
`UClass::SetUpRuntimeReplicationData()` walks the class's property chain
**superclass-first, then declaration order within each class**, and assigns a
monotonically increasing `RepIndex` to every property whose flags include
`CPF_Net`. `UObject` contributes zero net properties, so the first net property
in the chain is the first `CPF_Net` property of `UActorComponent`.

This is exactly the convention the codebase already uses for `APlayerState`
(`src/net/player_state_emitter.cpp:281-288`): *"parent props come first in
RepLayout … AOC uses 0-indexed handles, MAX = NumProps (no +1, no end-marker)."*

> ⚠️ **Caveat on "RepIndex" vs "command handle".** In stock UE5 the value
> written on the wire in a property-update is the **RepLayout command handle**
> (`FRepLayout` `Cmds` index, 1-based after a `RollbackToBaseline`/handle
> remap), *not* always identical to `UProperty::RepIndex`. For **flat, scalar,
> non-array** replicated properties with no dynamic-array children, the handle
> sequence is a dense 1..N that lines up with declaration order — which is the
> regime all five appearance properties fall in **except** `AppearanceIDs`
> (a `TArray`, which in UE5 RepLayout gets a parent handle plus per-element
> child handles). The codebase's empirical convention (player_state_emitter)
> treats the wire value as a **0-indexed dense handle with `MAX = NumReplicated`**.
> The table below gives both the engine RepIndex (declaration ordinal) and the
> 0-indexed dense handle the emitter actually serializes. See §6 for the
> dynamic-array hazard on `AppearanceIDs`.

---

## 2. The replicated (CPF_Net) properties, in chain order

Only properties flagged `Net` participate. Walking the chain:

### UActorComponent (`Engine_classes.hpp:160-192`) — 2 net props
| Decl ordinal | Property | Offset | Bit | Flags (cited) |
|---|---|---|---|---|
| 1 | `bReplicates` | `0x00B4` | bit 7 | **[CONFIRMED]** `:173` — `Net, RepNotify` |
| 2 | `bIsActive` | `0x00BD` | bit 4 | **[CONFIRMED]** `:180` — `Net, Transient, RepNotify` |

`bReplicates` (offset 0xB4) is declared before `bIsActive` (offset 0xBD); the
other bitfields between them (`bNetAddressable`, `bReplicateUsingRegisteredSubObjectList`,
`bAutoActivate`, …) lack the `Net` flag and are skipped.
**[CONFIRMED]** member ordering also reproduced from
`ClassesInfo.json` `UActorComponent` member list (bReplicates precedes bIsActive).

### UIntrepidRepKeyComponent (`IntrepidNet_classes.hpp:521-547`) — 0 net props
**[CONFIRMED]** Body is a single `uint8 Pad_108[0x10]` (`:524`); no `Net`
properties. Contributes nothing to the RepIndex sequence.
(Note: `MarkDirtyForReplication` / `GetReplicationKey` are *functions*, not
replicated properties — the "RepKey" is an inter-server push-model key, not a
wire RepIndex.)

### UBaseModularAppearanceComponent (`GameSystemsPlugin_classes.hpp:17266-17301`) — 2 net props
| Decl ordinal | Property | Offset | Flags (cited) |
|---|---|---|---|
| 3 | `AppearanceIDs` | `0x04D0` | **[CONFIRMED]** `:17300` — `TArray<FAppearanceId>` `Net, ZeroConstructor, RepNotify` |
| 4 | `SharedAppearanceInfoId` | `0x04E0` | **[CONFIRMED]** `:17301` — `FAppearanceInfoId` `Net, RepNotify` |

**[CONFIRMED]** offsets cross-checked against Dumpspace:
`AppearanceIDs @1232 (=0x4D0)`, `SharedAppearanceInfoId @1248 (=0x4E0)`.
OnRep handlers exist: `OnRep_AppearanceIDs` (`:17305`),
`OnRep_SharedAppearanceInfo` (`:17306`).

### UCharacterAppearanceComponent (`GameSystemsPlugin_classes.hpp:17332-17342`) — 2 net props
| Decl ordinal | Property | Offset | Flags (cited) |
|---|---|---|---|
| 5 | `CharacterCustomization` | `0x0690` | **[CONFIRMED]** `:17340` — `FCharacterCustomizationSaveData` `Edit, BlueprintVisible, Net, EditConst, RepNotify, Protected` |
| 6 | `bForceHideHeldItems` | `0x0828` bit 0 | **[CONFIRMED]** `:17341` — `Net, Transient, RepNotify` |

**[CONFIRMED]** offsets cross-checked against Dumpspace:
`CharacterCustomization @1680 (=0x690)`, `bForceHideHeldItems @2088 (=0x828)`.
OnRep handlers exist: `OnRep_CharacterCustomization` (`:17347`),
`OnRep_ForceHideHeldItems` (`:17348`).

> The 5th "prop" named in `appearance_emitter.h:21-27` — **CosmeticData** — does
> **not exist** as a replicated property on this class in the SDK dump. The
> header's list (AppearanceIDs, SharedAppearanceInfoId, CharacterCustomization,
> CosmeticData, ForceHideHeldItems) was an ASM-grep guess. The real replicated
> set is the **four** data properties above plus the two inherited
> `UActorComponent` flags. **[CONFIRMED — by absence in SDK dump.]** There is no
> `CosmeticData` field anywhere on the chain; cosmetic asset references travel
> inside `AppearanceIDs` (`FAppearanceId.TypeId`/`RecordGuid`) and
> `CharacterCustomization`.

---

## 3. RepIndex / handle table (the deliverable)

`NumReplicated = 6` → `MAX = 6` → handle bits = `ceil(log2(6)) = 3`.
Engine RepIndex shown 1-based (declaration ordinal). Wire handle shown
0-indexed per the emitter's `serialize_int(handle, MAX)` convention
(`appearance_data.cpp:363-371`, `player_state_emitter.cpp:300-309`).

| Engine RepIndex (1-based) | Wire handle (0-idx) | Property | Owning class | Offset | Type | On wire? | Status |
|---|---|---|---|---|---|---|---|
| 1 | 0 | `bReplicates` | UActorComponent | 0x0B4 b7 | bool (1 bit) | yes | **[INFERRED]** order |
| 2 | 1 | `bIsActive` | UActorComponent | 0x0BD b4 | bool (1 bit) | yes | **[INFERRED]** order |
| 3 | 2 | `AppearanceIDs` | UBaseModularAppearanceComponent | 0x4D0 | `TArray<FAppearanceId>` | yes (array — see §6) | **[INFERRED]** order |
| 4 | 3 | `SharedAppearanceInfoId` | UBaseModularAppearanceComponent | 0x4E0 | `FAppearanceInfoId` (0x38) | yes | **[INFERRED]** order |
| 5 | **4** | `CharacterCustomization` | UCharacterAppearanceComponent | 0x690 | `FCharacterCustomizationSaveData` (0x198) | yes | **[INFERRED]** order |
| 6 | **5** | `bForceHideHeldItems` | UCharacterAppearanceComponent | 0x828 b0 | bool (1 bit) | yes | **[INFERRED]** order |

**Cross-check vs `appearance_emitter.cpp:231-252`:** the emitter's current
defaults are `handle_max = 6`, `handle_custom = 4`, `handle_force_hide = 5`.
**These match this derivation exactly.** The chain it documents
(`:233-238`) is identical to §2 above. The *property identities, offsets and
ordering are CONFIRMED from the SDK*; what remains **[INFERRED]** is that AOC's
RepLayout emits these in pure declaration order with no array-handle expansion
shifting the later indices — see §6.

**Prior (wrong) guesses for the record** (`appearance_emitter.cpp:244`):
`max=4, handle_custom=0, handle_force_hide=1 or 3`. Those predate the SDK RE and
should not be used.

---

## 4. Wire encoding of one property update

Each property update inside the V3 content-block payload is
(`appearance_data.cpp:363-399`, `player_state_emitter.cpp:323-329`):

```
[ SerializeInt(handle, MAX) ]   ← ceil(log2(MAX)) bits, here 3 bits, value = 0-indexed handle
[ SIP(NumPayloadBits) ]         ← FIntrepidPackedInt / "SIP" varint = bit length of the value blob
[ <NumPayloadBits> bits ]       ← the property value, serialized below
```

`SIP` = the project's packed-int varint (`BunchWriter::write_sip`); same encoder
used for NetGUIDs. No trailing end-marker handle is written (the V3
`NumPayloadBits` on the content block bounds the stream).
**[CONFIRMED]** from `appearance_data.cpp` mode-1/mode-2 builders and
`player_state_emitter.cpp` FString builder.

### 4.1 `bForceHideHeldItems` (handle 5) — smallest useful update
```
3 bits : handle  = 5         (SerializeInt(5,6))
SIP    : 1                    (1 payload bit)
1 bit  : value   = 0 or 1
```
**[CONFIRMED]** layout (`appearance_data.cpp:384-386`). Total ≈ 12–15 bits.

### 4.2 `CharacterCustomization` (handle 4) — the struct
```
3 bits : handle  = 4         (SerializeInt(4,6))
SIP    : struct_bits         (= 8 * serialized byte count)
N bits : FCharacterCustomizationSaveData wire bytes (see §5)
```
**[CONFIRMED]** framing (`appearance_data.cpp:392-395`). `STRUCT_NetSerializeNative`
is **off** for this struct, so UE5 uses default per-property struct streaming
(no custom `NetSerialize`). **[INFERRED — from absence of a NetSerialize override
in the dump; not yet RE-confirmed from the binary's struct flags.]**

---

## 5. `FCharacterCustomizationSaveData` byte layout (handle-4 value)

**[CONFIRMED]** from `GameSystemsPlugin_structs.hpp:15878-15926`. The struct is
`final : public FTableRowBase`; `FTableRowBase` has no replicated members, so
the wire stream starts at the first own field. UE5 default struct net
serialization emits each non-`RepSkip` property in declaration order,
little-endian, **skipping C++ alignment padding** (the `Pad_*` holes are *not*
on the wire).

`RepSkip` fields are **excluded** from the net stream. Flagged `RepSkip` in the
dump: `Gender` (`:15920`), `Race` (`:15921`), `Class` (`:15922`),
`FaceMorphWeightMaps` (`:15924`), `SectionsValues` (`:15925`). Those are filled
client-side (notably via `UCharacterAppearanceComponent::SetRace`, classes.hpp
`:17349`, which sets `RaceGenderAppearanceId`).

### 5.1 Wire field order (non-RepSkip), little-endian

| # | Field | C++ type | Wire bytes | Struct off | Notes |
|---|---|---|---|---|---|
| 1 | PresetGuid | int64 | 8 | 0x008 | |
| 2 | RandomSeed | int32 | 4 | 0x010 | |
| 3 | SkinColorHue | float | 4 | 0x014 | |
| 4 | SkinColorPigmentation | float | 4 | 0x018 | |
| 5 | NormalDetailStrength01 | float | 4 | 0x01C | |
| 6 | NormalDetailStrength02 | float | 4 | 0x020 | |
| 7 | SkinSet | int32 | 4 | 0x024 | |
| 8 | EyeColor | int64 | 8 | 0x028 | |
| 9 | EyeShape | int64 | 8 | 0x030 | |
| 10 | ScleraShape | int64 | 8 | 0x038 | |
| 11 | Eyebrows | int64 | 8 | 0x040 | |
| 12 | HeadHair | int64 | 8 | 0x048 | |
| 13 | HeadHairRootColor | int64 | 8 | 0x050 | |
| 14 | HeadHairTipColor | int64 | 8 | 0x058 | |
| 15 | HeadHairLength | float | 4 | 0x060 | |
| 16 | HeadHairContrast | float | 4 | 0x064 | |
| 17 | HeadHairGradient | float | 4 | 0x068 | `Pad_6C[4]` follows — NOT on wire |
| 18 | FacialHairLip | int64 | 8 | 0x070 | |
| 19 | FacialHairChin | int64 | 8 | 0x078 | |
| 20 | FacialHairCheek | int64 | 8 | 0x080 | |
| 21 | FacialHairLipLength | float | 4 | 0x088 | |
| 22 | FacialHairChinLength | float | 4 | 0x08C | |
| 23 | FacialHairCheekLength | float | 4 | 0x090 | |
| 24 | EyelashLength | float | 4 | 0x094 | |
| 25 | FacialHairRootColor | int64 | 8 | 0x098 | |
| 26 | FacialHairTipColor | int64 | 8 | 0x0A0 | |
| 27 | FacialHairContrast | float | 4 | 0x0A8 | |
| 28 | FacialHairGradient | float | 4 | 0x0AC | |
| 29 | **RacialHorns** | int64 | 8 | 0x0B0 | **exists & NOT RepSkip** |
| 30 | **RacialHornsLength** | float | 4 | 0x0B8 | **exists & NOT RepSkip**; `Pad_BC[4]` follows — NOT on wire |
| 31 | NailColor | int64 | 8 | 0x0C0 | |
| 32 | NailOpacity | float | 4 | 0x0C8 | `Pad_CC[4]` follows — NOT on wire |
| 33 | DecalData | `TArray<FCharacterCustomizationDecalData>` | 4 + N·elt | 0x0D0 | int32 count, then elements |
| 34 | DecalBlendGroups | `TArray<FCharacterDecalBlendGroup>` | 4 + N·elt | 0x0E0 | int32 count, then elements |
| 35 | **bIsHelmetVisible** | bool | 1 | 0x0F0 | **exists & NOT RepSkip** |
| 36 | **bIsCapeVisible** | bool | 1 | 0x0F1 | **exists & NOT RepSkip** |
| — | Gender | TEnumAsByte | — | 0x0F2 | **RepSkip — excluded** |
| — | Race | TEnumAsByte | — | 0x0F3 | **RepSkip — excluded** |
| — | Class | TEnumAsByte | — | 0x0F4 | **RepSkip — excluded** |
| — | FaceMorphWeightMaps | TMap | — | 0x0F8 | **RepSkip — excluded** |
| — | SectionsValues | TMap | — | 0x148 | **RepSkip — excluded** |

With both `DecalData` and `DecalBlendGroups` empty (count=0), the wire size is:

```
8+4 + 4·4 + 4 + 4·8 + 3·8 + 3·4 + 3·8 + 4·4 + 2·8 + 2·4   (fields 1..28)
  +  8 + 4                                                  (RacialHorns/Length, 29-30)
  +  8 + 4                                                  (NailColor/Opacity, 31-32)
  +  4 + 4                                                  (two empty TArray counts, 33-34)
  +  1 + 1                                                  (two bools, 35-36)
= 200 bytes
```

### 5.2 ⚠️ BUG in the current serializer — wire layout is wrong

**[CONFIRMED — discrepancy between `appearance_data.cpp` and the SDK dump.]**

`serialize_customization_to_wire` (`appearance_data.cpp:223-320`) deviates from
the SDK ground truth in three places, all of which **desync the client's struct
deserializer**:

1. **Omits `RacialHorns` (int64) + `RacialHornsLength` (float).** The code's
   comment (`:264-285`) claims these fields *"DO NOT EXIST … hallucinated"*.
   **That is incorrect** — the SDK dump shows them at `0x0B0`/`0x0B8`
   (`structs.hpp:15910-15911`), not `RepSkip`. They ARE on the wire. Omitting
   12 bytes here shifts every following field (NailColor, NailOpacity, the two
   TArray counts) 12 bytes early in the stream → client misreads.
2. **Omits `bIsHelmetVisible` + `bIsCapeVisible` (1 byte each).** Same comment
   calls them *"FICTIONAL"*. They exist at `0x0F0`/`0x0F1`
   (`structs.hpp:15918-15919`), not `RepSkip`. The struct is truncated 2 bytes
   early.
3. Consequence: the serializer emits **184 bytes** (its own `:293` estimate)
   where the SDK layout requires **200 bytes** (the 12 horns + 2 visibility +
   net of its other arithmetic). The struct length prefix
   (`SIP(struct_bits)`) and the body therefore disagree with what the client's
   `FCharacterCustomizationSaveData` reader expects.

The serializer is **correct** on the RepSkip exclusions (Gender/Race/Class/two
TMaps) and on skipping alignment padding. The fix for PM151 is to **re-add the
two horns fields and the two visibility bools** in declaration order (see §5.1).

> This bug only bites in `payload_mode == 2` (full struct). The emitter
> currently defaults to `payload_mode == 0` (empty touch) /
> `strip_assets == 1`, so it is latent until the full-struct path is enabled.

---

## 6. Hazards & open questions

### 6.1 ⚠️ `AppearanceIDs` is a dynamic array — handle expansion risk
**[INFERRED]** `AppearanceIDs` (RepIndex 3) is a `TArray<FAppearanceId>`. In
stock UE5 `FRepLayout`, dynamic arrays get a **parent handle** plus a nested
handle space for elements (`FRepLayoutCmd` `EReplicationFlags`/array terminator
`0`). This means the *flat* "declaration ordinal == dense handle" assumption can
break: properties **after** the array (`SharedAppearanceInfoId`,
`CharacterCustomization`, `bForceHideHeldItems`) may carry handles shifted by the
array's command expansion, **or** AOC may flatten them — unknown without a live
RepLayout. For PM151 we only need `CharacterCustomization` (handle 4) and
`bForceHideHeldItems` (handle 5); if those updates dispatch to the wrong OnRep,
the array-handle expansion is the prime suspect. This is the single biggest
**[INFERRED]** risk in the table. Validate by capturing a real handle from a
live appearance bunch (none present in `docs/ida-dumps/` — `netcache_dump.txt`
only covers Pawn/PlayerController).

### 6.2 ⚠️ ASSET-PRELOAD HAZARD — real asset IDs break possession
**[CONFIRMED from source]** `appearance_emitter.cpp:280-327`.

When `CharacterCustomization` / `AppearanceIDs` / `SharedAppearanceInfoId` carry
**real** asset references (e.g. `race=2 Kaelar`, `head_hair=6064632019650478080`),
the client's `OnRep_CharacterCustomization` / `OnRep_AppearanceIDs` immediately
tries to **load the referenced SkeletalMesh / appearance-record assets**.
Without the lobby-side asset-registry pre-warm that the real AOC server performs,
those loads **fail silently**, the appearance subobject's state corrupts, and —
critically — `ClientRestart`'s `AcknowledgePossession` **never fires**, so
possession itself dies. (Confirmed empirically per the PD2.3.1 comment.)

Current mitigation (`appearance_emitter.cpp:299-327`,
`probe_appearance_strip_assets.txt` default `1`): **zero out** every
asset-reference field (`preset_guid`, `skin_set`, eye/hair/facial-hair GUIDs,
`racial_horns`, `nail_color`, gender/race/class enums) before serializing,
keeping only float sliders + bools. Possession stays alive but the body is
generic/empty. Setting the probe to `0` sends real IDs and is expected to break
possession **until preload is implemented**.

**What would pre-warm the registry (so real IDs are safe):**
- The asset reference path is `RecordGuid`/`TypeId` (in `FAppearanceId`,
  `structs.hpp:22911-22919`) and the `FDesignDataObjectId` `Guid`/`TypeId`/`Name`
  in `SharedAppearanceInfoId` (`structs.hpp:37135` → `DesignDataPlugin_structs.hpp:183-191`).
  These resolve through AOC's **DesignData / AsyncAssetLoadingSubsystem**
  (`UASyncAssetLoadingSubsystem* AssetLoader`, classes.hpp `:17277`).
- **[INFERRED]** The real server pre-warms by replicating the design-data
  records (or an asset-manifest RPC) on a **prior reliable bunch** before the
  appearance OnRep fires — i.e. the cooked character-data table the
  `appearance_ids` comment in `appearance_emitter.h:67` references. Candidate
  mechanisms to RE next: (a) a `DesignData`/`IntrepidNetUtilitySubsystem`
  client RPC that ships the record set, (b) `PostAssetsReadyForInitAppearance`
  (classes.hpp `:17307`) which is the gate the component waits on before
  applying — the server likely drives the preload, then the appearance update,
  in that order. **Until that bunch is reverse-engineered and emitted first,
  keep `strip_assets=1`.**

### 6.3 Bunch framing (context, not part of the index table)
**[CONFIRMED]** `appearance_emitter.cpp`. The appearance update is a **separate
reliable bunch** on the Pawn channel (`ch=19`, `chSeq≈956`), sent *after*
possession is acknowledged, wrapping the §4 payload in a V3 stably-named
content block targeting the `Character Appearance` subobject
(`sub_guid = pawn + 8`, e.g. `16777226`). Splitting it out of the ActorOpen
bunch avoids the UE5 `SerializeInt` 8192-bit `BunchDataBits` cap that broke
possession in PD2.1 (`appearance_emitter.cpp:6-36`).

---

## 7. Summary of what is CONFIRMED vs INFERRED

**CONFIRMED (from SDK dumps / source):**
- The exact replicated property set: `bReplicates`, `bIsActive`,
  `AppearanceIDs`, `SharedAppearanceInfoId`, `CharacterCustomization`,
  `bForceHideHeldItems` (6 total). `CosmeticData` does **not** exist.
- Every offset, type, owning class, and `Net`/`RepSkip` flag.
- The inheritance chain and that `UIntrepidRepKeyComponent` adds 0 net props.
- The per-property update wire framing (handle / SIP(len) / value).
- The `FCharacterCustomizationSaveData` byte layout and which fields are RepSkip.
- The serializer's missing-fields bug (§5.2).
- The asset-preload possession hazard and the current strip-assets mitigation.

**INFERRED (UE5 rules; needs a live RepLayout/pcap to validate):**
- That RepIndex == declaration ordinal and the 0-indexed dense handles are
  `4` (CharacterCustomization) and `5` (bForceHideHeldItems) with `MAX=6`.
  (Matches the emitter's current defaults — but unverified against live wire.)
- That `AppearanceIDs` being a `TArray` does **not** shift the later handles
  (§6.1). **Highest-risk assumption.**
- That `FCharacterCustomizationSaveData` uses default struct streaming
  (no native `NetSerialize`).

**Recommended next RE step:** capture one real `UCharacterAppearanceComponent`
property-update bunch (handle bits + struct length) from a live/replay session
to nail down (a) the actual handle values and (b) whether the array expands the
handle space — both currently INFERRED.
