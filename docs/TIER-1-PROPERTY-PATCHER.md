# Tier-1 Property Patcher — User Guide

**What it does**: rewrites fixed-width numeric properties (Level, HP, Gold,
Class ID, etc.) in captured replay packets before the server streams them
to the client. The client sees YOUR values instead of the captured ones.

**Why it's safe**: all patches are SAME-SIZE byte overwrites (4 bytes →
4 bytes for int32, etc.). Packet size and bit alignment are preserved —
the client's parser cannot detect the modification. No bunch reassembly,
no bdb recomputation, no partial-bunch drama.

**What it does NOT do** (yet):
- Variable-length FString patches (use `custom_name` 1-10 chars, still limited
  to the original slot size pending further RE).
- Creating new actors.
- Modifying server-authoritative state (the server simulation just streams
  captured packets — there's no backing state).

---

## Configuration

All patcher knobs are in the `GameServer::Config` struct in
`src/net/game_server.h`. Each property has TWO fields:

- `captured_*` — the value that was present when the replay was recorded.
  The patcher searches for THIS byte pattern in the packets.
- `custom_*` — the new value to write. Default is `-1` (skip).

### Complete field list

| Custom field | Captured field | Default captured | Description |
|---|---|---|---|
| `custom_level` | `captured_level` | 1 | Character level (1-60) |
| `custom_hp_current` | `captured_hp_current` | 100 | Current HP |
| `custom_hp_max` | `captured_hp_max` | 100 | Max HP |
| `custom_mp_current` | `captured_mp_current` | 100 | Current MP |
| `custom_mp_max` | `captured_mp_max` | 100 | Max MP |
| `custom_stamina_max` | `captured_stamina_max` | 100 | Max Stamina |
| `custom_gold` | `captured_gold` | 0 | Gold balance |
| `custom_xp_current` | `captured_xp_current` | 0 | Current XP |
| `custom_str` | `captured_str` | 10 | Strength stat |
| `custom_dex` | `captured_dex` | 10 | Dexterity stat |
| `custom_int_stat` | `captured_int_stat` | 10 | Intelligence stat |
| `custom_vit` | `captured_vit` | 10 | Vitality stat |
| `custom_class_id` | `captured_class_id` | 17748 | Class ID (17748 = Cleric) |
| `custom_race_id` | `captured_race_id` | -1 | Race ID (disabled — set captured_race_id first) |

### Example: Level 99 demigod

```cpp
// Set in GameServer::Config before calling start()
cfg.custom_level      = 99;
cfg.custom_hp_max     = 9999;
cfg.custom_hp_current = 9999;
cfg.custom_mp_max     = 5000;
cfg.custom_mp_current = 5000;
cfg.custom_gold       = 999999;
cfg.custom_str        = 50;
cfg.custom_dex        = 50;
cfg.custom_int_stat   = 50;
cfg.custom_vit        = 50;
```

---

## How it works (under the hood)

For each `(captured, custom)` pair that's set and different:

1. Encode both values as 4-byte little-endian.
2. Byte-scan every packet in `replay_data_->packets`:
   - For each position where `memcmp(pkt.raw + i, &captured_bytes, 4) == 0`,
     overwrite those 4 bytes with the new value's bytes.
3. Count hits per rule. Log a warning if a rule finds 0 matches (usually
   means the `captured_*` value doesn't match what's actually in the replay).

### The patcher lives in

`src/protocol/tools/replay_property_patcher.h` — header-only.

Invocation: `game_server.h` ~line 4176, inside the replay-load path. The
invocation runs AFTER the replay is loaded but BEFORE any packet is streamed.
Runs once per replay-load.

### Log output example

```
[Replay][Tier1] applying 3 property patch rule(s)...
[Replay][Tier1] patch report:
  character_level: 2 patch(es)
  character_hp_max: 2 patch(es)
  character_gold: 0 patch(es) [SANITY WARN: hit count mismatch (expected -1, got 0)]
```

`0 patches` for a rule means the captured value doesn't match. See
"discovery workflow" below.

---

## Discovery workflow — finding a new property

Not every property has the correct captured value listed by default.
Some captured values were guesses. To verify a value or find a new one:

### Step 1: know the in-game state of the captured character

The replay in `dist/Release/replay_data.bin` was recorded with a specific
character in a specific state. Figure out its exact:
- Level
- HP max / current
- Gold / currencies
- Stats values

Best bet: open the replay in the legacy debug viewer, or play back once
and observe the in-game HUD values.

### Step 2: search for that value as a byte pattern

Use a hex-dump tool. For a captured value of 100 (= `64 00 00 00` LE int32),
search through replay packets for that 4-byte pattern.

Helper script:

```bash
# Search all replay packets for a 4-byte LE int32 pattern
python src/protocol/tools/find_byte_pattern.py --int32 100
```

(Script to be written — stub for now. For immediate use, a manual
`hexdump | grep` works.)

### Step 3: verify hit count makes sense

A property like "max HP" might appear:
- Once (in the actor's initial state bunch)
- Twice (once for PlayerState, once for PlayerController duplicate)
- Three times (if RepNotify + FastArray echo)

If you see 50+ matches, the value isn't distinctive enough — use an
anchored pattern:

```cpp
// Find pattern that has specific context before the value
patcher.add_int32_anchored("level",
    /*prefix*/ {0x12, 0x34, 0x56},  // bytes that appear before the level
    /*captured*/ 1,
    /*new_val*/ 99,
    /*suffix*/ {0x78, 0x9A});       // bytes that appear after
```

### Step 4: patch and test in-game

Set `custom_*` to a **visually obvious** test value and connect:
- Level: set to 99 → HUD should show "Level 99"
- HP: set to 9999 → HP bar should show different max
- Gold: set to 1234567 → inventory/currency panel should show the amount
- Class ID: set to some other value → portrait/abilities may change

If the patch doesn't appear visually, the value isn't what you thought it
was — try again with different `captured_*`.

---

## Known captured values (verified)

| Property | Captured value | Source |
|---|---|---|
| Class ID | 17748 | Earlier logs showed "Cleric (17748)" in HUD |

Everything else listed in the config defaults is a **guess** — please
update as you verify.

## Known captured values (unverified — guesses)

| Property | Guessed captured | Status |
|---|---|---|
| Level | 1 | UNKNOWN — may be something else |
| HP max/cur | 100 | UNKNOWN |
| MP max/cur | 100 | UNKNOWN |
| Stamina max | 100 | UNKNOWN |
| Gold | 0 | UNKNOWN (if truly 0, patcher won't work for gold) |
| XP current | 0 | UNKNOWN |
| STR/DEX/INT/VIT | 10 | UNKNOWN |
| Race ID | ??? | Disabled by default |

---

## Verifying with byte-level hex dump

For a quick visual scan of pkt#104 (the "character update" packet):

```python
python src/protocol/tools/dump_pkt104_hex.py
```

(Script to be written — stub.) Produces a 16-byte-per-row hex dump with
ASCII on the right, showing pkt#104's bytes with known offsets annotated:

```
byte 200 (bit 1600): ... 6A 0B 00 00 00 52 61 6E 64 6F 6D 43 68 61 72 00 ...
                         ^  ^^^^^^^^^^^ ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                         |  len=11      "RandomChar" + NUL
                         cmd_index=0x6A
```

Cross-reference this with the `captured_*` values in your config to find
where each property lives.

---

## ⚠️ CRITICAL: common small values cause SAFETY ABORT

**`01 00 00 00` (int32=1) appears THOUSANDS of times in replay packets**,
not just in the level property. It's used for:
- Array counts
- Boolean `true`
- RepKey starting values
- NetGUID field indices
- Map entry counts

If you set `custom_level=99` with `captured_level=1`, the naive patcher
would replace EVERY `01 00 00 00` → `63 00 00 00`, corrupting thousands
of unrelated packets and **causing the client to time out** (as observed
2026-04-25).

**Built-in safety**: the patcher now does a TWO-PASS count-then-apply.
If a rule matches > `max_safe_hits` (default 10) times, it's **aborted**
with a warning:

```
[GameServer][Tier1]   character_level: 0 patch(es)
  [SANITY WARN: SAFETY ABORT — 4732 matches exceeds max_safe_hits=10
                (captured value too generic; patch skipped)]
```

This means the rule did **NOT** modify any bytes — your replay is intact.

### Safe vs risky captured values

| Captured value | Risk | Reason |
|---|---|---|
| `17748` (Cleric CharacterClassId) | ✅ SAFE | Unique, appears ~2-3 times max |
| `0x4A6C_1D72` (NetGUID-sized random) | ✅ SAFE | Random = unique |
| `100` (typical HP_max) | ⚠️ MAYBE | Moderate false-positives |
| `10` (typical stat value) | ❌ RISKY | Very common — SAFETY ABORT likely |
| `1` (Level=1, or typical flag) | ❌ FAILS | Thousands of matches — SAFETY ABORT guaranteed |
| `0` (any zero value) | ❌ FAILS | Everywhere — SAFETY ABORT guaranteed |

### What this means for you

- **`class_id` change works** (17748 is distinctive)
- **`level=1` patches CANNOT work** with naive search (requires anchored
  pattern with context bytes — future work)
- **Future: anchored patterns** will let us patch small common values by
  anchoring them to surrounding bytes that uniquely identify the property
  location (e.g., "find the pattern `6A 01 00 00 00` where 6A is the cmd
  marker, then patch the int32 after it"). Requires more RE.

## Limitations and caveats

1. **0 and 1 are UN-patchable** without anchored patterns (see above).
   Workaround: use `add_int32_anchored` with surrounding context bytes.

2. **Max level in AoC = 25**. Even if the patch lands, values > 25 will
   be rejected by the client. Same for class_id / race_id — use known
   valid enum values only.

3. **RepNotify properties**: the client calls a notification delegate when
   the value changes. Usually harmless, but could trigger unexpected UI
   animations (e.g., level-up fanfare).

4. **Client prediction**: some properties are client-predicted and the
   server authoritatively corrects them periodically. In pure-replay mode
   this isn't an issue (no live server), but if you mix with native mode,
   the server value will override your patch.

5. **Invalid enum values may crash**: setting `class_id = 99999` (not a
   real class) may cause the client UI to fail loading that class's icon
   / name. Stick to known valid ranges.

6. **The patcher runs ONCE at replay load**. If you change `custom_*`
   fields mid-session, they won't take effect until next replay reload.
