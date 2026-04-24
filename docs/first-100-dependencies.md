# First 100 Packets - Dependencies Graph

**Date**: 2026-04-24  
**Status**: Dependency analysis and forward-reference tracking

---

## Overview

This document maps which packets declare NetGUID exports and which packets reference them. The goal is to ensure all forward-references are satisfied before the client attempts to use them.

---

## Critical Dependency Chain

### 1. Level/World References (Always Available)

**PersistentLevel**
- Declared in: pkt#22 bunch#0 (ActorOpen export)
- NetGUID: hardcoded, likely index 1 or reserved
- Referenced by: All actors, implicitly (actors exist within a level)
- Risk level: **LOW** - always available before any actors spawn

---

### 2. Player Character Dependencies (Critical Path)

**PC: AoCPlayerControllerBP_C**
- Declared in: pkt#22 bunch#0
- NetGUID: assigned by ActorBuilder, likely index ~10000
- Full path: `/Game/ThirdPersonCPP/Blueprints/AoCPlayerControllerBP`
- Checksum: `0x6b62891c`
- Channel: ch=3 (reserved)

**PC References (Properties)**:

**a) AcknowledgedPawn property**
- Points to: AoCPawn actor (or similar)
- Expected NetGUID: UNKNOWN (likely pkt#24-29)
- Serialization: RepLayout tail (property stream in bunch#1)
- Status: **FORWARD REFERENCE** (not yet declared in minimal set)
- Risk: **MEDIUM** - Client may fail to deserialize if Pawn not yet loaded
- Mitigation: Either (a) declare Pawn before PC, or (b) assume lazy resolution

**b) PlayerState property**
- Points to: AoCPlayerState actor (or similar)
- Expected NetGUID: UNKNOWN (likely pkt#24-29)
- Serialization: RepLayout tail (property stream in bunch#1)
- Status: **FORWARD REFERENCE** (not yet declared)
- Risk: **MEDIUM** - PlayerState drives HUD updates, character stats, etc.
- Mitigation: Same as AcknowledgedPawn

**c) HUD property**
- Points to: BP_AOCHUD_C
- NetGUID: Assigned in pkt#22 bunch#2 (subobject ActorOpen)
- Serialization: Declared immediately after (same packet)
- Status: **SATISFIED** - HUD declared in pkt#22, same bunch sequence
- Risk: **LOW**

---

### 3. HUD Dependencies (Sub-Critical)

**HUD: BP_AOCHUD_C**
- Declared in: pkt#22 bunch#2 (subobject ActorOpen, PART-INIT)
- NetGUID: assigned by subobject, likely ch=? reserved
- Full path: `/Game/UI/Widgets/BP_AOCHUD`
- Checksum: `0xac6f1251`
- Channel: (unknown, but marked as subobject of PC)
- Continuation: pkt#23 bunch (PART-FIN, 173 bits)

**HUD References**:
- Parent: PlayerController (PC actor)
  - Satisfied in: pkt#22 (PC is owner/parent)
- Child widgets: (Inventory, Status bars, etc.)
  - Likely declared in: pkt#22 bunch#2 exports
  - Status: TBD after detailed decode

**Risk level**: **LOW** - HUD is subobject of PC, declared in same bunch sequence

---

### 4. Supporting Objects (May Be Optional)

**GlobalGMCommands**
- Declared in: pkt#22 bunch#0
- NetGUID: static, likely index 2 or reserved
- Full path: `/Script/GameSystemsPlugin.GlobalGMCommands_C`
- Checksum: `0xcaaaee3e`
- Purpose: Server-side command context (probably not used by client)
- Referenced by: (likely only server-side, or PC for admin commands)
- Risk level: **UNKNOWN** - May not be necessary for client rendering

**Recommendation**: Include for safety (already in pkt#22), but can be deferred if causes issues.

---

## Dependency Table (Pkt#0-99)

| Declaring Packet | Actor/Class | Referenced By | Risk | Status |
|---|---|---|---|---|
| pkt#22 b#0 | AoCPlayerControllerBP_C (PC) | ActorOpen ch=3 | LOW | OK |
| pkt#22 b#0 | PersistentLevel | All actors | LOW | OK |
| pkt#22 b#0 | GlobalGMCommands | PC maybe | MED | MAYBE |
| pkt#22 b#2 | BP_AOCHUD_C (HUD) | PC.HUD property | LOW | OK |
| pkt#22 b#1 | AoCPawn FORWARD REF | PC.AcknowledgedPawn | MEDIUM | UNSAT |
| pkt#24-29 | AoCPawn actual | PC.AcknowledgedPawn | MEDIUM | TBD |
| pkt#24-29 | AoCPlayerState actual | PC.PlayerState | MEDIUM | TBD |
| pkt#24-29 | AoCGameState assumed | Level.GameState | LOW | TBD |
| pkt#30-45 | NPC/Actor spawns | Level.Actors | LOW | TBD |
| pkt#46-99 | Property updates | Various | LOW | TBD |

---

## Forward Reference Analysis

### Case 1: PC.AcknowledgedPawn (CRITICAL FORWARD REF)

**Problem**: PC actor references a Pawn actor that may not be declared yet.

**Scenarios**:

1. **Optimistic (Lazy Resolution)**: Client deserializes PC, encounters Pawn NetGUID, queues it as "pending". When actual Pawn arrives in pkt#24+, client resolves retroactively. This is UE5 standard.
   - Expected behavior: Works if client waits for all actors before updating PC state
   - Risk: **MEDIUM** - May not work if client tries to use Pawn immediately

2. **Pessimistic (Eager Validation)**: Client tries to look up Pawn in NetGUID map, fails because Pawn not yet spawned, crashes or rejects PC.
   - Expected behavior: Fails
   - Risk: **HIGH**

3. **Safe Path (Reorder Emissions)**: Emit Pawn BEFORE PC, so all references are satisfied forward. Requires M1.2 to decode pkt#24-29 and extract Pawn/PlayerState.
   - Expected behavior: Works
   - Risk: **LOW**

**Recommendation for M1.1**:
Assume UE5 lazy resolution (scenario 1). If client crashes after PC spawn, pivot to scenario 3 (M1.2).

---

### Case 2: PC.PlayerState (CRITICAL FORWARD REF)

Same analysis as Case 1. PlayerState is likely declared in pkt#25-26.

---

### Case 3: PC.HUD (SATISFIED)

No forward reference; HUD is declared in same pkt#22 (bunch#2).

---

## Packet Emission Order for Dependency Satisfaction

### Option A: Current Plan (M1.1)

```
1. pkt#0 equiv (opcode 3)
2. pkt#2 equiv (NMT_Welcome)
3. pkt#22 equiv (PC ActorOpen + HUD)
   -> PC references Pawn/PlayerState (FORWARD REFS)
4. [Defer pkt#24-29 to M1.2]
```

**Problem**: PC has forward references.  
**Mitigation**: Assume lazy resolution; if client crashes, implement Option B.

### Option B: Dependency-First Order (M1.2)

```
1. pkt#0 equiv (opcode 3)
2. pkt#2 equiv (NMT_Welcome)
3. pkt#24 equiv (AoCPawn ActorOpen) -- if decoded
4. pkt#25 equiv (AoCPlayerState ActorOpen) -- if decoded
5. pkt#22 equiv (PC ActorOpen + HUD)
   -> PC references Pawn/PlayerState (NOW SATISFIED)
```

**Advantage**: All references satisfied in order.  
**Cost**: 3-4 extra packets worth of bytes (~2-3KB).  
**Effort**: Requires M1.2 to complete.

---

## Recommendations

1. **For M1.1**: Implement Option A (current plan).
   - Assume UE5 lazy resolution of forward references.
   - If client crashes post-PC spawn, add issue to backlog for M1.2.

2. **For M1.2 (if needed)**: Implement Option B.
   - Decode pkt#24-29 to identify Pawn/PlayerState classes.
   - Emit Pawn and PlayerState before PC.
   - Test with actual client connection.

3. **For long-term**: Document actual UE5 behavior.
   - Confirm whether lazy resolution is supported.

---

## Open Questions

1. **What is the exact NetGUID allocation strategy in AoC?**
   - Are client actor NetGUIDs hardcoded or dynamically assigned?

2. **Does AoC client support lazy forward-reference resolution?**
   - Or does it require all referenced actors to exist before deserialization?

3. **What are the names/classes of pkt#24-29 actors?**
   - Must decode with `decode_exports.py`

4. **Are there other hidden dependencies in HUD layout properties?**
   - HUD may reference UI elements, fonts, materials, etc.

---

## Summary

- **Dependency risk**: MEDIUM (one critical forward reference)
- **Mitigation**: Assume lazy resolution; test in M1.2
- **Next step**: Decode pkt#24-29 to satisfy dependencies explicitly
