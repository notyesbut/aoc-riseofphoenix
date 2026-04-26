# CRITICAL Data-Source Insight — 2026-04-26

User's intuition was 100% correct: **"HP had a different value than what's displayed"**.

This doc captures the insight that fundamentally changes our approach.

---

## Facts discovered

### `data/characters.json` contains character metadata

```json
{
  "archetype_id": 17747,
  "character_id": "3d3f803c320078d0e5a9377c66a6355f",
  "character_name": "Hatemost",
  "class_name": "Bard",          ← NOT Cleric!
  "level": 1,
  "race_id": 0,
  "race_name": "Kaelar",
  ...
}
```

### Archetype IDs are CONSECUTIVE INTEGERS

From the JSON:
- `archetype_id = 17747` → **Bard** (Hatemost)
- `archetype_id = 17750` → **Mage** (MyBigNameCharact)

Inferred (gaps between these):
- `17744` → ? (first archetype — maybe Fighter)
- `17745` → ?
- `17746` → ?
- `17747` → **Bard** ✅ confirmed
- `17748` → **Cleric** (very likely — matches earlier "17748" reference in logs)
- `17749` → Ranger?
- `17750` → **Mage** ✅ confirmed
- `17751+` → Rogue, Summoner, Tank...

**User's intuition confirmed**: class_id is a small range of integers
representing classes (Bard=17747, Cleric≈17748, Mage=17750). These aren't
FNames themselves but ARE the archetype IDs that map to FName class names.

### HP / MP / Stamina do NOT exist in characters.json

The JSON has:
- character_id, character_name, class_name, race_name, level, gender,
  create_info_hex (face/body customization data)

It does NOT have:
- Health, MaxHealth, Mana, MaxMana, Stamina, MaxStamina

**So where does `HP=90/90, MP=90/90, Stamina=100` come from on our HUD?**

---

## Two separate characters, two separate data sources

### OUR character (MyHero/Hatemost)

- **Source**: `data/characters.json` + client-side class defaults
- Name: set via `--custom-name MyHero` → M2.1 NUL-pad in replay bytes
- Class: Bard (archetype_id=17747 in JSON, but HUD might show Cleric symbol from replay confusion)
- Level: 1 (from JSON)
- HP/MP/Stamina: **computed client-side from class defaults** (Bard level 1 = 90/90/100)
- **NOT stored in replay packets as raw values**

### REPLAYED character (RandomChar)

- **Source**: replay_data.bin (actual captured bytes)
- HP=90, MP=90 shown in floating nametag above its head
- **These values ARE in the replay** — but bit-packed at non-byte-aligned offsets
- We can't find them via byte-level search

---

## Implications for property patching

### What we CAN patch

| Target | How | Status |
|---|---|---|
| Our character's name | M2.1 NUL-pad in replay pkt#104 | ✅ Working |
| Our character's archetype_id | Modify `characters.json` AND/OR replay bytes | ⚠️ Partial (JSON easy, replay hard) |
| Our character's class_name | `characters.json` (simple JSON edit) | ✅ Easy |
| Our character's level | `characters.json` (simple JSON edit) | ✅ Easy |
| Our character's race_id | `characters.json` | ✅ Easy |
| Our character's HP/MP/Stamina | Class-default or GAS override packet | ❌ HARD — need to find where client-defaults come from |
| RandomChar's HP/MP | Bit-walk replay to find bit offset + bit-patch | ⚠️ Need bit walker |
| RandomChar's nametag (above head) | Already via M2.1 name patch | ✅ Working |

### What we CANNOT patch with byte search (confirmed)

- Any bit-packed RepLayout property (HP, MP, Stamina, Level at runtime)
- Floats written via SerializeBits at non-byte-aligned positions

### Easy wins we should try FIRST

**Edit `characters.json`** directly:

```json
{
  "archetype_id": 17750,      ← change from 17747 (Bard) to 17750 (Mage)
  "class_name": "Mage",
  "level": 25,                ← force level 25
  ...
}
```

Then log in — our character should appear as a Mage at level 25 (if the
client doesn't override with its own data).

**Caveats**:
- Client may cache character data — delete local cache
- Level might not affect ability unlock (client-side validation)
- class_name change might not update HUD unless archetype_id also matches

---

## New function dumps (2026-04-26 afternoon)

### `sub_1444E4D20` — `URepLayout::ReceiveProperty_BackwardsCompatible`

Two modes based on `Connection->Driver[240] & 1`:

**New-driver mode** (line 97-161):
- Reads 1 bit (bHasHandleBits?)
- Calls `sub_1444E55B0` — the handle-stream decoder (not yet dumped)
- 14 args: `(RepLayout, 0, classId, bunch, 0, NumProps-1, 0, data_buf, data_buf, 0, &out1, &out2, ?)`

**Legacy mode** (line 162-334):
- For each property in order (no cmd_index):
  - Reads 1 bit = `bIsPresent`
  - If present: walks Cmd tree, invoking each leaf's `vtable[+200]` (type's Serialize)
  - For structs: recurses via `sub_1444EF330`

**KEY FINDING**: Legacy batch mode has **NO cmd_index**. Each property
has a 1-bit present flag, read in a FIXED ORDER determined by RepLayout.
This means the "Level" property in a class of 200 replicated properties
would be read at bit offset = (sum of widths of properties 0..Level-1 +
their present-bits). Extremely position-dependent.

### `sub_144236550` — `UNetDriver::GetRepLayoutForObject` (cache lookup)

- Takes (NetDriver*, out struct, UObject*)
- Hash-map lookup with SRW lock (shared → upgrade to exclusive if miss)
- If cache miss: calls `sub_1444D2E30` to build new RepLayout from UClass
- `sub_1444D2E30` is the static `URepLayout::Create()` builder — RE'ing
  this would give us the EXACT property-to-handle map statically.

---

## Revised plan

### Step 1 (easy, do first): Character-select metadata patching

Edit `data/characters.json` and see what the HUD shows. Quick experiments:
- `"level": 25` → does HUD show Level 25?
- `"archetype_id": 17750, "class_name": "Mage"` → Mage class?
- `"race_id": 1, "race_name": "Vek"` → different race?

This path doesn't touch the replay at all — pure metadata override.

### Step 2 (medium): Find archetype_id in replay bytes

`17747` = `53 45 00 00` LE. Search the replay for that pattern.

### Step 3 (harder): Bit-walker for RepLayout property stream

Only if we need to patch properties that the JSON route can't affect
(RandomChar's actual replayed HP, etc.). Build the bit-walker per
RE-FINDINGS-COMPLETE-PROPERTY-DISPATCH.md.

### Step 4 (highest value): Dump `sub_1444D2E30`

The RepLayout builder. Statically tells us:
- Property order per class
- Bit widths per property
- Handle → property_name mapping

With that we don't need a bit-walker at all — we can calculate exact
bit offsets for any property.

---

## Why we should pivot to character.json first

- **5 minute test** — edit JSON, relaunch, see what changes
- **Zero risk** — no replay corruption, no binary changes
- **Direct test** of hypothesis: "does our HUD reflect JSON metadata or replay bytes?"

The answer tells us the data flow:
- If HUD updates → our character IS driven by JSON → patch JSON for everything
- If HUD ignores JSON → our character is from replay → need bit-walker

---

## Immediate action item

Test this **right now**:

1. Copy `data/characters.json` to `characters.json.bak`
2. Edit Hatemost's entry:
   ```json
   "level": 25,
   "archetype_id": 17750,
   "class_name": "Mage"
   ```
3. Re-launch `launch_all_tier1_demo.bat`
4. Does the HUD show Level 25 / Mage?
5. Report back

That test result unlocks the correct next path.

---

## CONFIRMED — zero archetype_ids in replay (scan result)

Ran `find_stats_block.py` with archetype_id scan:

| archetype_id | Class | Byte pattern | Hits in replay |
|---|---|---|---|
| 17747 | Bard | `53 45 00 00` | **0** |
| 17748 | Cleric? | `54 45 00 00` | **0** |
| 17749 | Ranger? | `55 45 00 00` | **0** |
| 17750 | Mage | `56 45 00 00` | **0** |

**Conclusion**: Our character's archetype_id is NEVER transmitted in the
replay as byte-aligned int32. It's delivered via:
1. **characters.json** → XClient proto → client uses for local character
2. **Embedded in the UE5 client's class-blueprint system** (hardcoded
   defaults per class)

The replay only contains the **world state** (other characters, NPCs,
terrain, environment). Our character is **created locally** from the
characters.json metadata.

This also means: **HP, MP, Stamina values for OUR character come from
client-side UE5 BP class defaults** (e.g., `BP_PC_Bard` has `Health=90,
Mana=90, Stamina=100` hardcoded). To change those, we need either:
- Edit the BP (requires the Unreal Editor + source)
- Send a GAS AttributeSet replication that overrides the defaults
  (requires MORE RE — GAS replication is FastArray-based)
- Change archetype_id to a different class with different defaults

---

## New path for stat patching (if JSON approach works)

If HUD reflects characters.json metadata, we can add custom stat fields
to the JSON:

```json
{
  "archetype_id": 17747,
  "character_name": "Hatemost",
  "level": 25,                   ← custom
  "hp_current": 9999,            ← custom (if we extend the schema)
  "hp_max": 9999,
  "mp_max": 5000,
  ...
}
```

Then modify the XClient proto handler in `src/net/game_server.h` to
send these custom values to the client. This is a **pure server-side
change** — no replay patching, no bit-walking needed.

But first we need to confirm the JSON metadata flow works.
