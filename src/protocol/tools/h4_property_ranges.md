# H.4a — Empirical Property Byte Ranges

Goal: map known character properties to exact byte ranges in replay
packets, so we can modify them for custom characters.

## Replay packet roles (from src/protocol/tools/replay_full.jsonl)

| Packet# | Direction | Size (B) | Role |
|---|---|---:|---|
| 22 | S>C | — | **PlayerController spawn** (reassembled to captured_pc_spawn_reassembled.bin, 4859 bits) |
| 104 | S>C | 978 | **Pawn + CharacterInformationComponent spawn** (contains character name, class, race) |

## Property byte ranges — pkt#104 (the Pawn/CharacterInfo bunch)

### CharacterName (FString "RandomChar")

| Offset | Size | Content | Meaning |
|---|---:|---|---|
| byte 205 | 4 | `0B 00 00 00` | `int32 SaveNum = 11` (10 chars + NUL) |
| byte 209 | 11 | `52 61 6e 64 6f 6d 43 68 61 72 00` | ASCII `"RandomChar\0"` |

To inject a custom name at pkt#104:
1. Choose new name `N` with `len(N) <= 10` (same-length replacement keeps byte layout stable)
2. Write `N` left-padded/truncated to byte 209
3. Write `\0` terminator at byte 209+len(N)
4. For variable-length: update SaveNum at byte 205 AND resize the bunch

### Future property ranges (to be located)

These haven't been confirmed yet but likely patterns in pkt#104:
- `PrimaryArchetype` (enum/int) — probably a 4-byte or SIP-encoded value
- `CharacterRace` (enum) — probably 1-4 bytes
- `CharacterGender` (bool/enum) — probably 1 byte
- `CharacterLevel` (int) — probably 4 bytes
- `GuildName` (FString) — variable

Will be mapped empirically by comparing captures with different characters,
OR via H.4e-f live experimentation.

## Property byte ranges — pkt#22 (the PC spawn bunch)

The PC spawn bunch does NOT contain CharacterName.  It only carries PlayerController
state:
- 3 × export chains (class BP, Level, GlobalGMCommands)
- Actor/Archetype/Level NetGUIDs
- Transform (quantized location)
- 848-bit RepLayout property stream (server-side state of AAoCPC itself)

Properties in pkt#22 relate to the PC's own state (current commission board,
current dialogue instance, vehicle recovery transform, etc.), not the
character appearance which lives on the Pawn.

---

*Updated H.4a — date 2026-04-23*
