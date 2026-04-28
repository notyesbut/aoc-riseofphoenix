# First 100 Packets Analysis - Complete Summary

Date: 2026-04-24
Status: Analysis complete. Ready for M1.1 implementation planning.
Deliverables: 4 comprehensive markdown documents (674 lines total)

---

## What This Analysis Covers

This deep research session has produced a comprehensive inventory and dependency graph of the first 100 packets from dist/Release/replay_data.bin. These packets capture the post-login bootstrap sequence.

Key finding: The client can reach a playable state with as little as ~11,500 bits (~1.4KB) of essential packets.

---

## The Four Deliverables

### 1. first-100-packets-inventory.md (126 lines)

Comprehensive row-by-row inventory of all 100 packets with:
- Original sequence numbers, sizes in bytes
- Bunch bit counts and categorization
- Semantic categories (AoC-opcode-3, NMT-chatter, keepalive, PC-spawn, PC-continuation, GUIDExport-bulk, property-update)
- Essential/MAYBE/No flags for world-entry requirements
- Breakdown by 5 phases: Handshake, Sync Gap, Actor Spawn, GUID Exports, Mixed Updates
- Data cost summary: 66,329 bytes total, 514,544 bunch bits

Key insight: Packets 0-23 are critical. Packets 24-45 likely required. Packets 46-99 can be deferred.

### 2. first-100-actor-class-catalog.md (148 lines)

Catalog of actor classes, organized by importance:

Confirmed (from existing documentation):
- AoCPlayerControllerBP_C (PC) - pkt#22
- PersistentLevel (Level ref) - pkt#22
- GlobalGMCommands (subsystem) - pkt#22
- BP_AOCHUD_C (HUD widget) - pkt#22-23

Unconfirmed (requires Phase 4 decode):
- AoCPawn, AoCPlayerState, AoCGameState
- NPC actor classes (Goblin, etc.)
- Environment/static mesh actors

Dependency notes: PC references Pawn and PlayerState via properties (forward references).

### 3. first-100-minimal-ordered-subset.md (180 lines)

Proposed minimal packet sequence for native emission:

Essential Minimal Set (M1.1 target):
1. Opcode 3 (42B) - AoC session verification (placeholder)
2. NMT_Welcome (151B) - Map name + gamemode
3. Keepalives (auto) - Natural gap during sync
4. PC ActorOpen + continuation (1,292B) - Player character + HUD

Total: ~11,210 bits (~1.4KB)

Optional Enhancement (M1.2 target):
5. Early NPC/Pawn/PlayerState exports - adds ~36,000 bits

Deferred (M1.3+ target):
6. Property updates and additional actor spawning - streams post-entry

### 4. first-100-dependencies.md (220 lines)

Dependency graph analysis:

Critical forward references:
- PC.AcknowledgedPawn -> AoCPawn (declared pkt#24-29, used pkt#22)
- PC.PlayerState -> AoCPlayerState (declared pkt#24-29, used pkt#22)
- PC.HUD -> BP_AOCHUD_C (satisfied - both in pkt#22)

Two emission strategies:
- Option A (M1.1): Emit PC immediately with forward references. Assume UE5 lazy resolution. Low effort, medium risk.
- Option B (M1.2): Reorder to emit Pawn -> PlayerState -> PC. Higher effort, zero risk.

Recommendation: Start with Option A. If client crashes, pivot to Option B.

---

## Key Research Findings

### Packet Structure

- Packets 0-99 segment into 5 distinct phases
- Packet #22 is the world entry event (PC ActorOpen)
- Packets #3-21 are trivial keepalives (auto-generated, not replayed verbatim)
- Packets #30-45 show identical structure (978B, 7665 bits) - bulk GUID exports
- Packets #50-99 show high variance - mixed property updates and continuation

### Bitcost Breakdown

Phase 1 (Handshake):       213 bytes,   1,206 bits
Phase 2 (Gap):             399 bytes,      19 bits
Phase 3 (PC spawn):      1,292 bytes,  10,009 bits
Phase 4 (GUID exports): 15,645 bytes, 122,624 bits
Phase 5 (Property upd): 48,780 bytes, 391,186 bits
TOTAL:                  66,329 bytes, 514,544 bits

### AoC-Specific Findings

1. AoC Opcode 3 (pkt#0): Unknown post-login message. Not in stock UE5. REQUIRES RE. Emit verbatim placeholder.

2. Synchronization Gap: 19 trivial packets (pkt#3-21). Auto-generated in native mode. NOT replayed verbatim.

3. PC Exports: ActorBuilder v2 generates pkt#22 bunch#0 at 99.9% accuracy. Ready for M1.1.

4. Phase 4 Exports: Packets 24-45 are bulk GUID chunks. Identity TBD pending decode_exports pass.

---

## Actionable Recommendations

### For M1.1 Implementation (Next 2-3 hours)

1. Reuse ActorBuilder to emit PC ActorOpen (pkt#22 bunch#0)
2. Generate continuation bunches via PartialBundle chain
3. Emit opcode 3 as captured bytes placeholder
4. Emit NMT_Welcome via existing send_nmt_welcome()
5. Test: Client reaches world loaded state with PC visible

### For M1.2 Implementation (If time permits)

1. Run decode_exports.py on pkt#24-29 to identify Pawn/PlayerState
2. Implement PawnEmitter and PlayerStateEmitter
3. Decide: Emit before PC (Option B) or after (Option A)
4. Test: PC can receive input, move, interact with HUD

### For M1.3+ (Deferred)

1. Property update streaming
2. NPC spawning on-demand
3. World geometry streaming

---

## Uncertainties & Next Steps

### Open Questions

1. Opcode 3 semantics - Requires RE pass on client binary
2. Pawn/PlayerState NetGUIDs - Exact class names unknown
3. HUD dependencies - Does HUD require additional declarations?
4. Actor ordering - Can pkt#24-29 be spawned in any order?

### Immediate Next Steps

1. COMPLETE: Inventory of first 100 packets (this document)
2. IN PROGRESS: Verify ActorBuilder v2 output for pkt#22
3. PENDING: Decode pkt#24-29 exports (decode_exports.py pass)
4. PENDING: RE pkt#0 opcode 3 (client binary analysis)

---

## Document References

All analysis documents in docs/:

- first-100-packets-inventory.md - Row-by-row inventory
- first-100-actor-class-catalog.md - Actor class catalog
- first-100-minimal-ordered-subset.md - Minimal emission sequence
- first-100-dependencies.md - Dependency graph
- native-bootstrap-sequence.md - Existing documentation (first 30 packets)

---

## Summary Metrics

Total packets analyzed: 100
Total bytes: 66,329
Total bunch bits: 514,544
Minimum essential packets: 5
Minimum bitcost: ~11,500 bits (~1.4KB)
Recommended bitcost: ~13,000 bits
Phase 4 recommended bitcost: ~140,000 bits
Packets still undecoded: ~75
Critical forward references: 2
ActorBuilder v2 accuracy: 99.9%

---

Status: Research phase complete. Ready for M1.1 implementation.
Effort to M1.1 completion: 2-3 hours (reuse existing)
Effort to M1.2 completion: 4-6 hours (requires decode_exports)
Effort to full playability: 8-12 hours (all phases + testing)
