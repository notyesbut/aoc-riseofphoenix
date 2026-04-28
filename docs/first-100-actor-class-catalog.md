# First 100 Packets - Actor Class Catalog

Date: 2026-04-24
Source: Packets 0-99 from dist/Release/replay_data.bin
Status: Extracted from native-bootstrap-sequence.md + binary structure analysis

---

## Summary

The first 100 packets declare references to the following actor classes and level objects. All are resolved from PackageMap GUIDExport bunches (primarily on channels 2, 3, 85).

Confirmed exports (from existing documentation):
1. Default__AoCPlayerControllerBP_C (pkt#22 bunch#0)
2. PersistentLevel (pkt#22 bunch#0)
3. GlobalGMCommands (pkt#22 bunch#0)
4. BP_AOCHUD_C (pkt#22 bunch#2)

Unconfirmed (pkt#24-99): Likely NPCs, level geometry, gameplay actors. Require detailed decode_exports pass.

---

## Class Entries (by order of appearance)

### 1. AoCPlayerControllerBP_C

Alias: Default__AoCPlayerControllerBP_C
Full path: /Game/ThirdPersonCPP/Blueprints/AoCPlayerControllerBP.AoCPlayerControllerBP_C
NetGUID checksum: 0x6b62891c
Channels used: ch=3 (PlayerController reserved channel)
Packet(s) introduced: pkt#22 bunch#0 (PART-INIT, CTRL, OPEN, REL, EXP)
Bunch bits: 3545 bits (first fragment of 2)
Continuation: pkt#23 (PART-FIN, 1314 bits)

Status: ActorBuilder v2 already generates byte-identical output. Essential for client entry.

Dependencies:
- Requires PersistentLevel (declared same bunch)
- Requires Level exports
- References AoCPawn via AcknowledgedPawn property
- References AoCPlayerState via PlayerState property
- References BP_AOCHUD_C via HUD property

---

### 2. PersistentLevel (Level object)

Alias: PersistentLevel
Full path: Verra_World_Master./Game/Levels/Verra_World_Master/Verra_World_Master:PersistentLevel
Channels used: ch=3 (bundled with PC export)
Packet(s) introduced: pkt#22 bunch#0
Exported as: InternalLoadObject reference (part of ActorOpen header)

Status: Necessary for level context. Included in PC ActorOpen via PackageMap.

Note: Level is not spawned as an actor; it is a static reference in PackageMap.

---

### 3. GlobalGMCommands

Alias: GlobalGMCommands
Full path: /Script/GameSystemsPlugin.GlobalGMCommands_C
NetGUID checksum: 0xcaaaee3e
Channels used: Bundled with PC exports (ch=3), but role unclear
Packet(s) introduced: pkt#22 bunch#0

Status: Likely a singleton subsystem reference. Purpose: game mode commands or server-side utilities.
Necessity for M1.1: Probably optional for basic client entry.

---

### 4. BP_AOCHUD_C (HUD widget class)

Alias: BP_AOCHUD_C
Full path: /Game/UI/Widgets/BP_AOCHUD.BP_AOCHUD_C
NetGUID checksum: 0xac6f1251
Channels used: (subobject, opened on separate channel in pkt#22 bunch#2)
Packet(s) introduced: pkt#22 bunch#2 (PART-INIT, REL, EXP)
Continuation: pkt#23 bunch partial (PART-FIN, 173 bits)

Status: Essential for HUD rendering (client needs HUD object to display UI).
Dependency: Child/subobject of PC actor.

---

## Unconfirmed Actors (pkt#24-99)

### Expected Classes (Hypothesis)

Based on packet structure patterns (pkt#24-45 showing large GUIDExport bunches), the following are likely declared in Phase 4:

- Pawn classes: AoCPawn, EnemyPawn, etc. (referenced by PC via AcknowledgedPawn)
- PlayerState classes: AoCPlayerState (referenced by PC via PlayerState property)
- GameState class: AoCGameState (world-level state)
- NPC actor classes: Humanoid NPCs (Goblin, Dragon, etc.)
- Environment actors: Static meshes, dynamic geometry
- HUD-related widgets: Inventory, Character, Status windows, etc.

To confirm: Run decode_exports.py on pkt#24-45 raw bunch data.

---

## Dependency Summary

PC (pkt#22)
  - AoCPlayerControllerBP_C [export]
  - PersistentLevel [reference]
  - GlobalGMCommands [reference]
  - AoCPawn (via AcknowledgedPawn - NetGUID unknown, likely pkt#24+)
  - AoCPlayerState (via PlayerState - NetGUID unknown, likely pkt#24+)
  - BP_AOCHUD_C [subobject, pkt#22 bunch#2]

Pkt#24-45 (Phase 4):
  - Level property block (NPCs, static actors, etc.)
  - GameState class
  - Pawn classes
  - [Many more actors, unconfirmed]

---

## Execution Priority for M1.1

Must implement:
1. PC + PersistentLevel + GlobalGMCommands exports (pkt#22 - already done 99 percent)
2. HUD class export (pkt#22 bunch#2 - already done 99 percent)

Should implement (if time permits):
3. Early NPC/Pawn/PlayerState (pkt#24-29 - decode first, then emit)

Can defer (post-entry):
4. Phase 4+ bulk exports (pkt#30-99 - defer to property streaming)

---

## Next Steps

1. Decode Phase 4 bunches (pkt#24-45):
   Goal: Extract all InternalLoadObject paths and checksums

2. Cross-reference with game binary:
   - Search for class names in AoC source

3. Build definitive catalog:
   - Update this document with confirmed actor list

4. Implement emission order (Deliverable 3):
   - Determine which packets can be combined/reordered without breaking dependencies
