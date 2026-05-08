# Session End State — 2026-04-25 ~02:00

**Status**: in-world, stable, Tier-1 framework complete but blocked on common-value false-positives for Level/HP/Gold/stats. Resume tomorrow with RE target `sub_143F2F820`.

---

## What works right now

| Feature | Status | Evidence |
|---|---|---|
| Login flow (Auth → XClient → GameServer) | ✅ | Log line 29+ |
| NATIVE NMT handshake (Hello/Challenge/Login/Welcome/NetSpeed/18) | ✅ | Lines 168-229 |
| `*** MAP LOADED [NATIVE] ***` (client transitioned to Verra_World_Master) | ✅ | Line 250 |
| Replay streaming (first 100 packets of 29,010) | ✅ | 100 `[REPLAY] >> #N` lines |
| CharacterName rewrite (M2.1 NUL-pad 1-10 chars) | ✅ | Line 235: `★ Patched 'RandomChar' → "MyHero" in 1 replay packet(s)` |
| Character in-world (Ruins of Aela, Cleric) | ✅ | Screenshot, input packets ch=19 active 2+ min |
| Static NPCs (Lionguard Tannur, etc.) | ✅ | Visible in screenshot |
| Tier-1 safety cap (aborts patches with > 10 matches) | ✅ | Built in aoc_server.exe |

## Working launcher

**`launch_all_tier1_demo.bat`** (identical to hybrid when all CUSTOM_*=-1). Flags:

```
--native
--custom-name MyHero
--replay replay_data.bin
--replay-max-packets 150
--custom-level -1 --custom-hp -1 --custom-hp-max -1 ...
--verbose-bunches --verbose-bunch-limit 0
```

All `--custom-*` currently `-1` (skip).

## Captured values (verified against HUD)

Updated in `game_server.h::Config::captured_*`:

| Property | Captured value | Source |
|---|---|---|
| `captured_level` | 1 | HUD confirmed 2026-04-25 |
| `captured_hp_current` | **90** | HUD confirmed (not 100) |
| `captured_hp_max` | **90** | HUD confirmed |
| `captured_mp_current` | **90** | HUD confirmed |
| `captured_mp_max` | **90** | HUD confirmed |
| `captured_stamina_max` | 100 | HUD confirmed |
| `captured_class_id` | 17748 | Cleric (from earlier logs) |
| `captured_gold` | 0 (guess) | Unverified |
| `captured_xp_current` | 0 (guess) | Unverified |
| `captured_str/dex/int/vit` | 10 (guess) | Unverified |
| `captured_race_id` | -1 (disabled) | Unknown |

## What does NOT work (and why)

| Property | Blocker |
|---|---|
| `CharacterName` 11-16 chars | Partial-bunch reassembly not RE'd — requires full URepLayout decode |
| `Level` patch | Captured=1 → `01 00 00 00` matches thousands of generic int32=1 values → SAFETY ABORT |
| `HP_max` patch | Captured=90 → `5A 00 00 00` is MODERATELY common; likely SAFETY ABORT |
| `Gold` patch | Captured=0 → `00 00 00 00` is ubiquitous — guaranteed SAFETY ABORT |
| `STR/DEX/INT/VIT` patch | Captured=10 (guess) → common value, likely SAFETY ABORT |
| `Class ID` patch | Captured=17748 → **unique, SHOULD work** (untested; try tomorrow) |
| Mobs / wandering NPCs | Need MAX_PKTS > ~500 — untested |

**The fundamental fix** is replacing naive byte-pattern search with ANCHORED patterns that include cmd_index context. Requires RE of `URepLayout::ReceiveProperties` cmd dispatch.

## Persistent artifacts (saved to disk)

### Code

| File | Purpose |
|---|---|
| `src/protocol/tools/replay_property_patcher.h` | Tier-1 patcher (2-pass count→apply with max_safe_hits=10) |
| `src/protocol/tools/extract_aoc_property_names.py` | Extracts UPROPERTY strings from client binary |
| `src/protocol/tools/ida_dump_bunch_func.idc` | IDC script to dump any function (currently set to `0x143F2F820`) |
| `src/protocol/tools/ida_find_bunch_parser.idc` | Pass 1 IDC hunt |
| `src/protocol/tools/ida_find_bunch_parser_v2.idc` | Pass 3 brute-force xref scan |
| `src/protocol/tools/ida_find_bunch_overflow.idc` | Byte-pattern LEA scan |
| `src/net/game_server.h` | Tier-1 Config fields + captured values (HP/MP=90 confirmed) + patcher invocation in ctor |
| `src/main.cpp` | 14 `--custom-*` CLI flags + 5 `--captured-*` CLI flags |

### Docs

| File | Purpose |
|---|---|
| `docs/AOC-WIRE-FORMAT-RE-KNOWLEDGE.md` | Full wire-format RE: SIP, MBG, content-block layout, FastArray, FInBunch/UActorChannel struct layouts |
| `docs/WHAT-WE-CAN-DO-NOW.md` | 4-tier capability catalog |
| `docs/PATCHABLE-PROPERTIES-CATALOG.md` | 18,483 property names extracted from binary |
| `docs/TIER-1-PROPERTY-PATCHER.md` | Usage guide + safety cap + discovery workflow |
| `docs/SESSION-END-STATE.md` | ← THIS FILE |
| `docs/IDA-BUNCH-PARSER-GUIDE.md` | IDA workflow |

### Launcher

| File | Purpose |
|---|---|
| `dist/Release/launch_all_tier1_demo.bat` | Hybrid + Tier-1 overrides (all -1 by default = safe) |
| `dist/Release/launch_all_hybrid.bat` | Proven-working base (keep as fallback) |

### Extracted intelligence

| File | Purpose |
|---|---|
| `dist/Release/aoc_property_names.txt` | 18,483 character properties |
| `dist/Release/aoc_property_names_all.txt` | 79,953 all UE5 properties |
| `dist/Release/ida_bunch_parser_hunt.txt` | Pass 1 output |
| `dist/Release/ida_bunch_func_141D36DD0.txt` | FFastArraySerializerHelper::BuildChangelist |
| `dist/Release/ida_bunch_func_141D20340.txt` | FastArrayDeltaSerialize_DeltaSerializeStructs |
| `dist/Release/ida_bunch_func_143F30430.txt` | UActorChannel::ReceivedBunch |
| `dist/Release/ida_bunch_func_143F2A2A0.txt` | UActorChannel::ProcessBunch |

---

## RE PLAN FOR TOMORROW

### Goal
**Unlock reliable patching of Level, HP, MP, Gold, STR/DEX/INT/VIT** via anchored-pattern patcher (Tier-1.5).

### Primary RE target: `sub_143F2F820` = `FObjectReplicator::ReceivedBunch`

This function is called by `UActorChannel::ProcessBunch` (sub_143F2A2A0) after the content block header is parsed. It receives an inner FInBunch of `NumPayloadBits` size and dispatches property reads based on a `cmd_index`.

**Why**: once we know the cmd_index for each property, we can build **anchored patterns**:

```
[cmd_index_byte][value_bytes]   ← unique pattern per property
```

Example:
- Level patch needle: `<cmd_LEVEL> 01 00 00 00` (typically 1-3 matches — safe)
- HP max patch needle: `<cmd_MAXHEALTH> 5A 00 00 00` (few matches — safe)

### How to dump (IDA)

```
1. Open IDA with AOCClient-Win64-Shipping.i64
2. G → 143F2F820 → Enter
3. F5 (decompile)
4. Ctrl+A, Ctrl+C in pseudocode pane
5. Paste into <HOME>\Desktop\New Text Document (6).txt (OVERWRITE)
6. Save
7. ALSO: File → Script file → src/protocol/tools/ida_dump_bunch_func.idc (already set to 0x143F2F820)
8. Paste the raw dump into same or different file and tell me where it is
```

### What I'll do with the dump

1. Identify the cmd_index dispatch table (switch/if-else or vtable-like lookup).
2. Map each handle to its property name using known patterns (`CharacterLevel`, `MaxHealth`, `Gold`).
3. Build `add_int32_anchored()` rules in Tier-1.5 patcher:
   ```cpp
   patcher.add_int32_anchored("character_level",
       /*prefix*/{cmd_LEVEL_bytes},
       /*captured*/1, /*new*/25,
       /*suffix*/{},
       /*expected_hits*/1);
   ```
4. Update `launch_all_tier1_demo.bat` with safe-max values (Level=25, HP=9999, etc.).
5. Test in-game → Level 25 should show on HUD.

### Alternative parallel RE (lower priority, easier)

`sub_143F2C340` = `UActorChannel::ReadContentBlockHeader` — we already have its pseudocode but haven't integrated the full content-block header format into our wire-format doc. A quick re-read + update of `AOC-WIRE-FORMAT-RE-KNOWLEDGE.md` closes that loop.

### Experiments to run tomorrow (independent of RE)

1. **Raise MAX_PKTS**: try `500`, then `1000`, then `5000` in `launch_all_tier1_demo.bat`. Document the breaking point (if any). Goal: find the maximum safe packet count that spawns more world content (mobs, vendors).

2. **Test class patch** (distinctive value, SHOULD work):
   ```bat
   set CUSTOM_CLASS=5
   ```
   Expected: `character_class_id: 1-3 patch(es)` in log, visible class change in-game.

3. **Find additional captured values** for Gold/XP/stats: log in with defaults, read the HUD carefully, update `captured_*` defaults.

---

## Known-good working recipe

If anything breaks tomorrow, fallback to this EXACT recipe:

1. Build: `powershell -File build_server.ps1` (from project root)
2. Launch: `dist\Release\launch_all_tier1_demo.bat` with ALL `CUSTOM_*=-1`
3. Login: test222 / test
4. Play char: "Hatemost" (captured character ID `3d3f803c320078d0e5a9377c66a6355f`)
5. Client will show "MyHero" (M2.1 NUL-pad) in HUD, spawn in Ruins of Aela
6. Connection stays active indefinitely (keep-alive Maintain loop)

## Where we left the IDA dump script

`src/protocol/tools/ida_dump_bunch_func.idc` line 145:
```c
target_ea = 0x143F2F820;   // FObjectReplicator::ReceivedBunch — cmd_index dispatch to properties
```

Just run the IDC script and/or copy F5 pseudocode into `New Text Document (6).txt`.

## Open questions

1. ~~Is `sub_143F2F820` actually `FObjectReplicator::ReceivedBunch`~~ ✅ **ANSWERED 2026-04-26**: YES, confirmed. Has 2 receive paths (batch + per-property).
2. Does AoC use standard UE5 cmd_index (varint / SerializeIntPacked) or a custom format? → Answer in `sub_143F2DC60` (next dump).
3. Are stats held in `APlayerState` or a separate `AttributeSet` object (GAS pattern)? → Likely both; need to inspect which class's RepLayout reads HP/Mana/etc.
4. What's the MAX_PKTS threshold before parser drift? → Empirical — test tomorrow.

---

## Update 2026-04-26 — `sub_143F2F820` dumped

See `docs/RE-FINDINGS-FOBJECTREPLICATOR.md` for full analysis.

---

## Update 2026-04-26 (same session, later) — ALL 4 functions dumped

See `docs/RE-FINDINGS-COMPLETE-PROPERTY-DISPATCH.md` for the full analysis.

Functions analyzed in this pass:
1. **`sub_143F2DC60`** = `ReadPropertyChangeHeader` (cmd_index + NumBits decoder)
2. **`sub_143F33E80`** = per-property RepLayout dispatch + RepNotify
3. **`sub_1444E4A40`** = `URepLayout::ReceiveProperties` (batch path)
4. **`sub_1444E4620`** = Custom-delta / FastArray handle reader

### Complete wire format per property

```
[SerializeInt(max=NumProperties)]  cmd_handle    ~8 bits
[SerializeIntPacked]                NumBits       1-5 bytes
[NumBits bits]                      property data
```

### Vtable offsets confirmed

- `+384` (slot 48): `Serialize(buf, n)` — byte-aligned
- `+400` (slot 50): `SerializeInt(val, max)` — `ceil(log2(max))` bits
- `+408` (slot 51): `SerializeIntPacked(val)` — AoC-SIP 1-5 bytes

### ★ CRITICAL EMPIRICAL FINDING ★

Ran `find_stats_block.py` scanner on all 29,010 packets. **Zero matches**
for HP=90 (int32 or float), Stamina=100 (float), ClassId=17748 (int32).

**Root cause**: RepLayout properties are written with `SerializeBits`
at the current bit offset. Most property values land at NON-byte-aligned
bit positions. Byte-level memcmp search can NEVER find them.

**Implication**: `ReplayPropertyPatcher` (Tier-1) cannot patch bit-packed
int32/float properties. Only works for:
- FStrings with byte-aligned bodies (M2.1 `RandomChar` ✅)
- FastArray element bodies (byte-aligned per UActorChannel::ProcessBunch)
- Fixed-position structure headers

**Solution**: Tier-1.5 bit-level patcher. See the REVISED build plan in
`RE-FINDINGS-COMPLETE-PROPERTY-DISPATCH.md`.

---

**End of session. Resume by:**
1. Reading `docs/RE-FINDINGS-COMPLETE-PROPERTY-DISPATCH.md` (most recent — has the critical finding).
2. Reading updated `docs/PATCHABLE-PROPERTIES-CATALOG.md` (reflects bit-packing reality).
3. Writing the bit-walker (`src/protocol/tools/bit_walk_pkt104.py`) per the REVISED plan.
4. Running it on pkt#104 to extract (cmd, nbits, value, bit_offset) tuples.
5. Matching against HUD values to identify property offsets.
6. Extending `ReplayPropertyPatcher` with `add_bit_patch(bit_offset, width, captured, new_val)`.
7. Testing in-game.

Estimated tomorrow's work: 2-3 hours for bit walker + 1 hour patcher ext + 30 min testing.
