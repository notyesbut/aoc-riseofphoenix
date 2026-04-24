# RE: AoCPlayerState

**Class hierarchy:** AActor → APlayerState → AoCPlayerState
**Blueprint path:** `/Game/ThirdPersonCPP/Blueprints/AoCPlayerStateBP`
**Parent:** APlayerState (UE5 standard base)
**Sources:** re-aoc-client.md (Part 1), re-review-2026-04-22.md, player_state_schema.cpp

---

## Actor Root Replicated Properties

PlayerState is replicated to ALL clients — every player sees every other's name, score, guild.

| Handle | Property | Type | CPF Flags | OnRep | Notes |
|---|---|---|---|---|---|
| 1 | Score | Float | CPF_Net | OnRep_Score @ 0xaa472f8 | Game score |
| 2 | Ping | UInt8 | CPF_Net | (standard) | ms |
| 3 | PlayerName | FString | CPF_Net | OnRep_PlayerName @ 0xaa47218 | EOS/Steam display |
| 4 | PlayerId | Int32 | CPF_Net | OnRep_PlayerId @ 0xaa471e0 | |
| 5 | UniqueId | ByteArray | CPF_Net | (standard) | EOS/Steam ID |
| 6 | bIsABot | Bool | CPF_Net | (standard) | |
| 7 | bIsInactive | Bool | CPF_Net | (standard) | Disconnected |
| 8 | bOnlySpectator | Bool | CPF_Net | (standard) | |
| 9 | StartTime | Int32 | CPF_Net | (standard) | Join timestamp |
| 10 | CharacterArchetype | UInt32 | CPF_Net | (no OnRep) | 17747-17754 class ID |
| 11 | CharacterGuildName | FString | CPF_Net | (not found) | Replicated to all |
| 12 | CharacterCitizenNodeId | NetGUID | CPF_Net | OnRep_CitizenNodeGuid @ 0xb7aa580 | |
| 13 | CharacterGuid | ByteArray | CPF_Net | OnRep_CharacterGuid @ 0xb2006e0 | 16-byte FGuid |
| 14 | SiegeParticipantDisplayData | ByteArray | CPF_Net | (custom) | CustomDelta |
| 15 | RealTimeCooldownExpiration | CustomDelta | CPF_Net | (inferred) | PvP/shared cooldowns |
| 16 | DeathInfo | ByteArray | CPF_Net | OnRep_DeathInfo | |
| 17 | NextAllowedRespawnTime | Float | CPF_Net | (standard) | |
| 18 | Alignments | CustomDelta | CPF_Net | OnRep_Alignments @ 0xb0d2348 | |
| 19 | CurrencyAmount | CustomDelta | CPF_Net | OnRep_CurrencyAmount | Gold/resources |
| 20 | CharacterInGameSettings | ByteArray | CPF_Net | OnRep_CharacterInGameSettings @ 0xb707f68 | |

---

## Design Split: Pawn vs PlayerState Identity

- **Pawn carries**: CharacterName, CharacterRace, CharacterGender (renderable state)
- **PlayerState carries**: CharacterArchetype, CharacterGuildName, CharacterCitizenNodeId (global social state)

Both have CharacterCitizenNodeId. Pawn's is owner-only; PlayerState's is replicated to all.

## Known Unknowns

1. Archetype/Level NetGUIDs — not extracted from captures
2. Which of the 20 properties are actually replicated vs. just defined
3. Subobject component list — player_state_schema.cpp lines 55-56 explicitly TODO
4. CustomDelta encoding for CurrencyAmount / SiegeParticipantDisplayData

---

## References
- `re-aoc-client.md:314-333` — Identity fields catalog
- `re-review-2026-04-22.md:63-110` — OnRep catalog (277 entries)
- `player_state_schema.cpp` — Current scaffolding
