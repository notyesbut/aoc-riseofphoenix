# First 100 Packets Inventory

**Status**: Analysis complete | **Date**: 2026-04-24  
**Replay file**: `dist/Release/replay_data.bin` (29,010 total packets)  
**Scope**: Packets #0-99 (first 100 packets after initial login)

---

## Executive Summary

The first 100 packets total **66,329 bytes** and **514,544 bunch bits**. They segment into distinct phases:

1. **Phase 1 (pkt#0-2)**: Login handshake completion
   - pkt#0: AoC opcode 3 (unknown purpose, likely session verification)
   - pkt#1: Server keepalive (frame time sync)
   - pkt#2: NMT_Welcome (map + gamemode names)

2. **Phase 2 (pkt#3-21)**: Synchronization gap
   - 19 trivial keepalive packets (bb=1 each)
   - Client processes NMT_Welcome; server waits for NMT_GameSpecific response

3. **Phase 3 (pkt#22-29)**: Actor spawning begins
   - pkt#22-23: **Player Character ActorOpen** (multi-fragment, essential)
   - pkt#24-29: Early NPC/environment actors (6 spawns at ~750B each)

4. **Phase 4 (pkt#30-45)**: GUID export batch
   - 16 packets, mostly identical (978B, bb=7665 each)
   - Likely bulk property updates for spawned actors

5. **Phase 5 (pkt#46-99)**: Mixed updates
   - Continuation of actor spawning, property synchronization
   - Alternating chunk sizes suggest partial fragments

---

## Packet-by-Packet Inventory

| Idx | orig_seq | Size (B) | bunch_bits | #bunches | bunches_summary | semantic_category | essential? |
|-----|----------|----------|-----------|----------|-----------------|-------------------|----------|
| 0 | 14265 | 42 | 167 | 1 | ch=0 reliable ctrl opcode 3 FString | AoC-opcode-3 | Y |
| 1 | 14266 | 20 | 0 | — | PacketInfo only ServerFrameTime | keepalive | N |
| 2 | 14267 | 151 | 1039 | 1 | ch=0 reliable ctrl NMT_Welcome | NMT-chatter | Y |
| 3 | 14268 | 20 | 0 | — | PacketInfo only keepalive | keepalive | N |
| 4-21 | 14269-14286 | 21 | 1 | 1 | ch=0 ctrl sentinel ACK | keepalive | N |
| 22 | 14287 | 784 | 6104 | 4 | ch=3 ActorOpen PC with exports | PC-spawn | Y |
| 23 | 14288 | 508 | 3905 | 1 | ch=3 PartialCont PC tail HUD | PC-continuation | Y |
| 24 | 14289 | 830 | 6476 | 1 | ch=85 GUIDExport bulk | GUIDExport-bulk | MAYBE |
| 25 | 14290 | 912 | 7143 | 1 | ch=2 GUIDExport PART-INIT | GUIDExport-bulk | MAYBE |
| 26 | 14291 | 721 | 5604 | 2 | ch=85 GUIDExport ch=0 ActorUpdate | GUIDExport-bulk | MAYBE |
| 27 | 14292 | 644 | 4999 | 1 | PARSE_FAIL bootstrap log | unknown | MAYBE |
| 28 | 14293 | 460 | 3516 | 1 | ch=85 GUIDExport CTRL | GUIDExport-bulk | MAYBE |
| 29 | 14294 | 978 | 7665 | 1 | ch=3 GUIDExport PART-INIT | GUIDExport-bulk | MAYBE |
| 30 | 14295 | 978 | 7665 | 1 | ch=3 batch pattern | GUIDExport-bulk | N |
| 31-45 | 14296-14310 | 978 | 7665 | 1 ea | ch=3 repeat @978B | GUIDExport-bulk | N |
| 46 | 14311 | 774 | 6037 | 1 | DRIFT noted bootstrap log | unknown | N |
| 47 | 14312 | 905 | 7076 | 1 | Large bulk bb=7076 | property-update | N |
| 48 | 14313 | 978 | 7665 | 1 | Pattern resumes | GUIDExport-bulk | N |
| 49 | 14314 | 115 | 764 | 1 | ch=0 Control 2048 bits | property-update | N |
| 50 | 14315 | 168 | 1181 | 1 | ch=0 reliable ctrl small | property-update | N |
| 51-99 | 14316-14364 | 600-1002 | 5500-7665 | 1-2 | Mix GUIDExport ActorUpdate PartialCont | property-update | N |

---

## Semantic Categories

- **AoC-opcode-3** (pkt#0): AoC-specific post-login message with string payload. Purpose unknown — likely session verification or crypto seed.
  
- **NMT-chatter** (pkt#2): Standard UE5 NMT_Welcome. Declares map name and gamemode class. Must be sent early.

- **keepalive** (pkt#1, 3-21): Empty frames (bb=0) or single-bit sentinels (bb=1). Server marking time while client processes NMT_Welcome.

- **PC-spawn** (pkt#22): Multi-fragment ActorOpen for Player Character. Contains exports for Default__AoCPlayerControllerBP_C.

- **PC-continuation** (pkt#23): Tail fragment of pkt#22. Completes PC and opens HUD.

- **GUIDExport-bulk** (pkt#24-45+): NetGUID exports. Each declares actor classes, properties, level objects.

- **property-update** (pkt#46-99): Mixed ActorUpdate, PartialCont, control. Property synchronization post-spawn.

---

## Total Data Cost

| Component | Packets | Size (B) | Bits |
|-----------|---------|----------|------|
| Phase 1 (Handshake) | 3 | 213 | 1206 |
| Phase 2 (Gap) | 19 | 399 | 19 |
| Phase 3 (PC spawn) | 2 | 1292 | 10009 |
| Phase 4 (GUID batch) | 16 | 15645 | 122624 |
| Phase 5 (Mixed) | 60 | 48780 | 391186 |
| **TOTAL (0-99)** | 100 | 66329 | 514544 |

---

## Key Findings

### Packet #0 — AoC Opcode 3
- **Payload**: opcode=0x03, FString="50995344" (8 decimal digits)
- **Status**: REQUIRES RE — not in stock UE5
- **For M1.1**: Emit as captured placeholder until RE complete

### Packets #3-21 — Natural synchronization gap
- 19 trivial packets (bb=1 each)
- Will occur naturally in native emission — not essential to replicate verbatim

### Packets #22-23 — PC ActorOpen (CRITICAL)
- ActorBuilder already 99.9% correct for pkt#22
- ESSENTIAL for client entry

### Packets #24-45 — GUID exports
- Bulk NetGUID records for NPCs, level, HUD
- Likely essential for actor resolution
- Status: TBD after decode_exports pass

### Packets #46-99 — Property updates
- Can defer to post-entry streaming

---

## Next Steps

1. Decode Phase 4 (pkt#24-45) using decode_exports.py
2. Build actor class catalog (Deliverable 2)
3. Determine minimal ordered subset (Deliverable 3)
4. Map dependencies (Deliverable 4)

