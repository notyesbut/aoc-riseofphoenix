# RE: BP_AOCHUD_C (HUD widget / UMG actor)

**Class hierarchy:** AActor → AHUD → UMG Widget Blueprint
**Blueprint path:** `/Game/UI/Widgets/BP_AOCHUD`
**Class name:** `BP_AOCHUD_C`
**Checksum:** 0xac6f1251
**Sources:** native-bootstrap-sequence.md:107, pc-spawn-handle-catalog.md:42

---

## Bootstrap Context

HUD spawns as subobject of PC in pkt#22:
- **Bunch #2** in pkt#22 (PC ActorOpen sequence)
- **Subobject ID**: 506 (PackageMap handle)
- **Fragment 1 of 2**: 873 bits (PART-INIT)
- **Fragment 2 of 2**: 173 bits (PART-FIN)
- **Total**: 1046 bits (reassembled)
- **Export**: `BP_AOCHUD_C` from `/Game/UI/Widgets/BP_AOCHUD` (chk=0xac6f1251)

---

## CRITICAL FINDING: has_rep_layout=0

From pc-spawn-handle-catalog.md:127-136:
```
[199..234] Content-block header for SUBOBJECT guid=506
           (has_rep_layout=0 → fixed-size payload, no SIP length prefix)
[234..4864] SUBOBJECT payload — 4630 bits (95% of PC bunch!)
```

**HUD is NOT a standard RepLayout stream.** Payload is fixed-size, binary-encoded (custom NetSerialize or FastArraySerializer).

## OnRep Catalog Search (277 entries)

All UI-related searches returned zero matches:
- `OnRep_*UI*`: 0 matches
- `OnRep_*Menu*`: 0 matches
- `OnRep_*Widget*`: 0 matches
- `OnRep_*HUD*`: 0 matches

**Implications:**
- HUD may be entirely client-side (no replication)
- May use generic property callbacks (e.g., appearance component state)
- Or uses CustomDelta which doesn't generate `OnRep_*` strings

---

## Speculated Contents

UI widget blueprints typically manage:
- Menu visibility (inventory, character, skills, map)
- Selected filters/tabs
- Cosmetic display state
- Hotbar configuration

But the 4630-bit size suggests much more — possibly:
- Full map fog-of-war / POI data
- Quest log state
- Inventory snapshot
- Party/raid roster

---

## Known Unknowns

### HIGH
1. Exact NetSerialize/NetDeltaSerialize format for the 4630-bit payload
2. Widget class hierarchy — parent UMG widget types
3. Which properties are in the 4630-bit block
4. Reassembly of fragments 1 + 2 (873 + 173 bits)

### MEDIUM
5. Client-side prediction rules
6. HUD vs. PlayerController coupling
7. Why payload split into 2 fragments (may just be MTU)

## IDA-Based Next Steps

1. Find `UBP_AOCHUD_C::NetSerialize()` vtable entry
2. Disassemble to understand binary layout
3. Map 873-bit payload to field offsets
4. Identify any FastArraySerializer subobjects

---

## MVP Assessment

**HUD replication may be deferrable** for Path B M1 if:
- It's purely cosmetic (appearance, hotbar)
- Client can fall back to hardcoded defaults

**But for full multiplayer fidelity**, HUD state decoding is essential.

**Pragmatic recommendation**: Splice the captured HUD bunches until we have time to decode them. This is what the PcEmitter's 848-bit tail effectively does.

---

## References
- `native-bootstrap-sequence.md:93-112` — PC spawn with HUD location
- `pc-spawn-handle-catalog.md:127-136` — HUD content-block analysis
- `re-review-2026-04-22.md:262-308` — Source file structure (UI plugin)
