# Session 2026-04-24 — Deep RE Findings Consolidation

## What the user saw (screenshot)
- Character in world ✓
- HUD frame rendered (HP/MP/Stamina bars visible) ✓
- Values blank/zero (no HP number, no MP, no Name) ✗
- Level indicator "6" visible (but unclear if that's real or placeholder)

## Root cause identified
Hybrid mode was capped at **100 replay packets**. But the first property-value bundle (Name, HP, MP, Stamina) lives in **pkts #100-115**. We were cutting off ONE packet too early.

Fixed in `launch_all_hybrid.bat`: `MAX_PKTS 100 → 150`. Ready to test — no rebuild needed since it's a CLI arg.

---

## Autonomous RE session outputs

### New docs written
| File | Content |
|---|---|
| `BOOTSTRAP-STATIC-VS-DYNAMIC.md` | Per-packet static vs dynamic classification of first 100 packets |
| `LIVE-SERVER-STATE-ARCHITECTURE.md` | WorldState + CharacterState + PropertyUpdateEmitter + 10Hz tick design |
| `replay-packet-index-catalog.md` | Property-update packets found in pkts #100-120 |
| `class-specific-field-diff.md` | (bard pcap analysis — concluded it's HTTPS, useless) |
| `fighter-vs-ranger-byte-diff.md` | Cross-session diff (background agent in progress) |
| `ranger-capture-findings.md` | Ranger pcap IS game traffic; morph-target format discovered |
| `re-apawn-playerpawn-c.md` | Pawn replicated property catalog |
| `re-aocplayerstate.md` | PlayerState replicated property catalog |
| `re-aocgamestate.md` | GameState minimal RE |
| `re-bp-aochud.md` | HUD widget analysis |
| `character-name-location.md` | "RandomChar" byte location at pkt[104] |

### Code scaffolding written
| File | Purpose |
|---|---|
| `src/net/bootstrap/character_profile.h` | Source of truth for dynamic character values |
| `src/net/bootstrap/netguid_allocator.h` | Static + dynamic NetGUID allocation |
| `src/net/bootstrap/packet_recipe.{h,cpp}` | Static / Patched / Native recipe framework |
| `src/protocol/tools/find_character_name_in_replay.py` | Name FString locator (proven working) |
| `src/protocol/tools/find_name_update_channel.py` | Name update + channel identifier |
| `src/protocol/tools/extract_pkt78_bunches_raw.py` | Raw bunch-stream extractor |

---

## Key facts discovered (with evidence citations)

### Fact 1: Captured character is a Mage, not Fighter
Per `dist/Release/logs/emu-20260424-103004.log`:
```
CreateChar 'RandomChar' world='aoc-emu-useast2-local' info_raw=6631B
JSON content includes: "race":"Kaelar", "gender":"Male", "class":"Mage"
```

Updates our `AoCArchetype` understanding — the captured session is class=17751 (Mage), not 17747 (Fighter).

### Fact 2: CharacterName wire format is `[cmd=0x6A][FString]`
Per `find_character_name_in_replay.py` output:
```
pkt[104] orig_seq=14369
byte 202: 6A          ← cmd_index
byte 203-206: 0B 00 00 00 ← FString length (11 = 10 chars + NUL)
byte 207-217: "RandomChar\0"
```

### Fact 3: Name appears ONCE in first 200 packets of replay
Search range: packets #0..#199 of `replay_data.bin`. Exactly 1 hit at pkt[104]. The "pkts 104..113 chain" mentioned in old logs refers to NEIGHBORING property-update packets (not additional Name hits).

### Fact 4: Variable-length names break bit-count invariants
Per old injection attempt log:
```
[BootstrapSequence::apply_synthesis] builder produced 3318 bits, expected 3302
```
Difference = 16 bits = 2 bytes. "MyHero" (6 chars, 11-byte FString) vs "RandomChar" (10 chars, 15-byte FString) = 4-byte diff. The previous synthesizer refused to emit mismatched-size bunches — which is CORRECT behavior (prevents client parse errors).

**Implication**: `PatchedPacketRecipe` for CharacterName must either:
- (a) Constrain custom names to EXACTLY 10 chars (same byte count as captured)
- (b) Emit a separate native Name-update bunch AFTER the replay bootstrap completes (has its own chSeq, can be any length)

Option (b) is correct architecture. Approach (a) is a dead-end hack.

### Fact 5: Ranger pcap IS game traffic but NO login phase
4,157 UDP packets verified. 200 S>C extracted. First 200 packets contain:
- Character customization morph names (`Jaw_Sharpness`, `Nose_Forward`, ...)
- Level references (`Verra_World_Master`)
- NO cmd=0x6A Name updates (character already in-world pre-capture)

This is a respawn capture, not a login. For class-diff we need a different pcap.

### Fact 6: Character customization uses named morph targets
Wire format (discovered from ranger pcap):
```
[float_value 4B][2B separator][FString length 4B][ASCII][NUL]
```
Each face-feature has a named morph (`Jaw_Sharpness`, `Lips_Top_Shape`, etc.). The 16-float array assumption was wrong — it's a sparse list of morph references.

---

## Path forward — two concrete options

### Option A: Test with MAX_PKTS=150 now
- Run `launch_all_hybrid.bat`
- Expected outcome: HUD displays "RandomChar" + initial HP/MP/Stamina values
- Takes 1 minute; confirms our analysis is correct; unblocks all future work

### Option B: Implement native CharacterName update (using Fact 4 Option b)
- Background agent will finish cross-session diff → confirms cmd=0x6A is universal
- Write `emit_character_name_update()` that emits a separate property-update bunch AFTER bootstrap completes
- Custom names of any length work
- Requires knowing the subobject channel (still TBD)

Recommend Option A first (5 minutes, confirms architecture). Then Option B.

---

## What's still unknown

1. **Subobject channel numbers** — CharacterInformationComponent, StatsComponent, HUD subobject channels. Need `decode_pkt78_subobjects.py` to discover.
2. **Universal vs session-specific bit positions** — cross-session Fighter/Ranger diff in progress (background agent).
3. **Class/Race/Gender encoding** — agents confirmed class_id isn't stored as plain LE uint32. Likely VLE-encoded. Needs binary analysis.
4. **HP/MP/Stamina cmd_indices** — known to be in pkts #100-115 as float32 values. Which cmd_index maps to which field? Needs decoder work.

---

## Immediate action for you

```
1. Run launch_all_hybrid.bat (MAX_PKTS now 150)
2. Report what you see:
   - Does HUD show values now? (HP/MP/Stamina numbers)
   - Does the character name display? ("RandomChar" expected)
   - Does Level indicator show real values?
```

If YES to all three: **captured bootstrap is complete, architecture is correct, next milestone is NATIVE emission (one-by-one replacement of spliced packets).**

If NO to any: we learn something specific. Each "no" is a concrete next RE target with known fixtures + known tools.
