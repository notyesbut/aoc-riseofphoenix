# RE: APawn / ACharacter / APlayerPawn (PlayerPawn_C)

**Class hierarchy:** AActor → APawn → ACharacter → APlayerPawn_C (Blueprint)
**Blueprint path:** `/Game/ThirdPersonCPP/Blueprints/PlayerPawn`
**Archetype:** `Default__PlayerPawn_C` (FString len 22)
**Sources:** re-aoc-client.md (Part 2), re-review-2026-04-22.md, pawn_schema.cpp, native-bootstrap-sequence.md, captured pkt#78

---

## Actor Root Replicated Properties

| Handle | Property Name | Type | CPF Flags | OnRep Callback | Source |
|---|---|---|---|---|---|
| 1 | ActorLocation | FVector | CPF_Net | OnRep_ActorLocation | re_review_customdelta.txt @ 0xb433608 |
| 2 | ActorRotation | FRotator | CPF_Net | (standard) | pawn_schema.cpp |
| 3 | Velocity | FVector | CPF_Net | (standard) | pawn_schema.cpp |
| 4 | AttachmentReplication | ByteArray | CPF_Net | OnRep_AttachmentReplication | re_review_customdelta.txt @ 0xa774180 |
| 5 | Controller | NetGUID | CPF_Net | OnRep_Controller | re_review_customdelta.txt @ 0xaa09f80 |
| 6 | PlayerState | NetGUID | CPF_Net | (standard) | pawn_schema.cpp |
| 7 | AttachedPawn | NetGUID | CPF_Net | OnRep_AttachedPawn | re_review_customdelta.txt @ 0xb581160 |
| 8 | MountedPawn | NetGUID | CPF_Net | OnRep_MountedPawn | (not found) |
| 9 | ActorStatus | UInt32 | CPF_Net | OnRep_ActorStatus | re_review_customdelta.txt @ 0xb39ab38 |
| 10 | bIsDead | Bool | CPF_Net | (standard) | pawn_schema.cpp |

---

## Subobject Components (6 total)

### 1. AlignmentComponent
| Handle | Property Name | Type |
|---|---|---|
| 1 | Alignment | UInt32 |
| 2 | CorruptionLevel | UInt32 |
| 3 | CurrentCorruption | UInt32 |
| 4 | FactionId | UInt32 |

### 2. InteractInfo Component
| Handle | Property Name | Type |
|---|---|---|
| 1 | bCanInteract | Bool |
| 2 | InteractType | UInt8 |
| 3 | InteractRange | Float |

### 3. CharacterInformationComponent ★ CRITICAL FOR IDENTITY
Carries name, class, race, gender visible to other players.

| Handle | Property Name | Type | OnRep | Notes |
|---|---|---|---|---|
| 1 | CharacterName | FString | OnRep_CharacterName @ 0xb7081f0 | Variable-length |
| 2 | PrimaryArchetype | UInt32 | (not in catalog) | 17747-17754 (8 classes) |
| 3 | CharacterRace | UInt32 | HandleRaceChanged @ 0xb201060 | 9 races |
| 4 | CharacterGender | UInt32 | (not found) | 1=Male, 2=Female |
| 5 | CharacterAlignment | UInt32 | (via AlignmentComponent) | |
| 6 | CharacterLevel | UInt32 | (not found) | 1-50+ |
| 7 | AdventureLevel | UInt32 | (not found) | |
| 8 | CharacterTitle | FString | (not found) | |
| 9 | CharacterGuildName | FString | (not found) | |
| 10 | CharacterCitizenNodeId | NetGUID | OnRep_CitizenNodeGuid @ 0xb7aa580 | |
| 11 | CharacterCustomization | ByteArray | OnRep_CharacterCustomization @ 0xb2282e0 | 16-float morph array |
| 12 | AppearanceIDs | ByteArray | OnRep_AppearanceIDs @ 0xb1bca90 | Equipped cosmetics |

### 4. CharacterCombatInformationComponent
- CombatState (UInt8), InCombat (Bool), CurrentTarget (NetGUID)
- CombatSkills (CustomDelta), ActiveTargets (CustomDelta)

### 5. AbilityComponent
- ActiveAbilities, Cooldowns, HotbarSlots, ChannelingData (all CustomDelta)

### 6. StatsComponent
- HealthData, ManaData, StaminaData (CustomDelta)
- CurrentHealth, MaxHealth, CurrentMana, MaxMana, CurrentStamina, MaxStamina (Float)

---

## Known Unknowns

1. Exact component subobject NetGUIDs — handle indices in PackageMap
2. Handle order within components — sequential by C++ declaration order, unverified
3. CustomDelta encoding for StatsComponent / AbilityComponent
4. Fixture: pkt#78 (816 bytes) — not yet bit-identical to ActorBuilder output

## Calibration Fixtures
- **pkt#78** — src/protocol/tools/captured_pkt_78.bin
- **pkt#104** — Character with full CharacterCustomization (16-float morphs)
