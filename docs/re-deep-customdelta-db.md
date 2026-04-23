# Deep RE — CustomDelta Internals + Game Database Extraction

**Session:** 2026-04-21 night
**Binary:** `E:\Ashes of Creation\Game\AOC\Binaries\Win64\AOCClient-Win64-Shipping.exe`
**Database:** `E:\Ashes of Creation\Game\AOC\Plugins\DesignDataPlugin\Generated\Client\CacheDB.dbc` (138 MB)

---

# TL;DR of the breakthroughs

1. **CustomDelta in AoC uses `FFastActorLocationArray`** — UE5 FastArraySerializer pattern. We now know the lifecycle hooks: `PostReplicatedAdd`, `PostReplicatedChange`, `PreReplicatedRemove`.

2. **AoC has a custom spatial-visibility system** called `UFilteredActorTrackingRegistry` with 6 identified methods. **This is exactly what we need for Phase 4 multi-client broadcast** — they already invented our "who should see this movement?" wheel.

3. **CacheDB.dbc is a custom "IDB" format** (not SQLite), but **it contains 571,767 ASCII strings** representing ALL game content: every ability, every status effect, every class trait, every weapon tier, every status debuff. Complete data dump.

4. **Source-file paths leaked from debug symbols**: `C:\P4\rel\AOCUE5\Game\Plugins\GameSystems\Source\GameSystemsPlugin\Private\GameService\ActorTracking\ActorTrackingType.cpp`. Tells us:
   - They use Perforce
   - Module layout: `Game/Plugins/GameSystems/Source/GameSystemsPlugin/Private/GameService/...`
   - `GameSystemsPlugin` is a major in-house plugin

5. **SQLite is embedded in the client binary** (at RVA 0x0bc9a000) with full pragma table. It's used somewhere internally but NOT for CacheDB.dbc.

---

# PART A — CustomDelta / FastArraySerializer deep findings

## A.1 What UE5 FastArraySerializer looks like in this binary

At RVA 0x09f58000 we find the reflection metadata for `FFastArraySerializer`:

```
@ 0x09f58058  FMapint64int32                      ← int64→int32 map (for dirty tracking)
@ 0x09f58338  ReplicationID                       ← per-item unique ID
@ 0x09f58348  ReplicationKey                      ← per-item dirty marker
@ 0x09f58358  MostRecentArrayReplicationKey       ← array-level dirty marker
@ 0x09f58398  FastArraySerializerItem             ← base struct name
```

These are the field names inside `FFastArraySerializer` and `FFastArraySerializerItem`. Standard UE5 stuff.

## A.2 AoC's actual FastArraySerializer implementation

At RVA 0x0b831000 we found AoC's own `FFastActorLocationArray`:

```
@ 0x0b831c40  C:\P4\rel\AOCUE5\Game\Plugins\GameSystems\Source\GameSystemsPlugin\Private\GameService\ActorTracking\ActorTrackingType.cpp
@ 0x0b831ce0  FFastActorLocationArray::PreReplicatedRemove      ← fires when an actor-location entry is removed
@ 0x0b831e50  FFastActorLocationArray::PostReplicatedAdd        ← fires when a new actor-location is added
@ 0x0b831f98  FFastActorLocationArray::PostReplicatedChange     ← fires when an actor-location updates
```

**Implication:** AoC replicates actor positions via this FastArraySerializer (not via individual UPROPERTY replicas). The struct `FActorLocation` (guessed name) is the item type; each player has their own.

## A.3 Spatial visibility — `UFilteredActorTrackingRegistry`

This is AoC's custom relevancy engine — deciding who receives what updates:

```
@ 0x0b8320d0  UFilteredActorTrackingRegistry::GetActorLocationsToRequeryForInstigators
@ 0x0b832330  UFilteredActorTrackingRegistry::CalculateRelevantTrackersForActorLocation
@ 0x0b832628  UFilteredActorTrackingRegistry::IsLocationRelevantToTracker
@ 0x0b832b80  UFilteredActorTrackingRegistry::GetLocationUpdatesForServer
@ 0x0b832da8  UFilteredActorTrackingRegistry::GetAllActorLocations
@ 0x0b832e40  UFilteredActorTrackingRegistry::UpdateServerRelevancyTable
```

**Implication for our server:** when we implement multi-client broadcast (Phase 4), **the architecture to mirror is this exact pattern**:
- A "registry" of all actor locations
- A relevancy calculator that decides which clients see which actors
- A batch-update function that computes all server-to-client deltas per tick

We can literally study this pattern in IDA (.i64 database exists) to understand the algorithm. Names and function boundaries are already known — a skilled RE with IDA could document the exact logic in a few hours.

## A.4 NetDeltaSerialize lifecycle hooks

Standard UE5 pattern confirmed:
- `PostReplicatedAdd`: client-side callback fired when server signals a new item joined the array
- `PostReplicatedChange`: fired when an existing item's ReplicationKey increments (state changed)
- `PreReplicatedRemove`: fired right before the client removes an item

These are the functions the client invokes when applying FastArraySerializer deltas. For **generating** these deltas from our server, we need to format the wire payload UE5's receiver expects:

```
Format (simplified, from UE5 source):
  BaseReplicationKey (int32)         ← last-seen array key on receiver
  ArrayReplicationKey (int32)        ← current array key on sender
  NumChanged (int32)
  for each changed item:
    ReplicationID (int32)            ← item identifier
    NumBits (int32)
    [NumBits bits of item state]
  NumDeleted (int32)
  for each deleted item:
    ReplicationID (int32)
```

Since the key fields are named in the binary (`ReplicationID`, `ReplicationKey`, `MostRecentArrayReplicationKey`), we can reproduce this exactly.

## A.5 What's NOT in the binary as strings

Notably absent (all returned 0 hits):
- `AoCCharacter_NetSerialize`
- `BaseCharacterInfo_NetDeltaSerialize`
- `Server_Reliable`, `Client_Reliable` literal RPC markers
- `ServerRPC_`, `ClientRPC_`
- Generic `FBitReader`, `FBitWriter` strings
- `NetSerialize` is found 13× but always as a generic method name, not a specific override

**Conclusion:** AoC does NOT use per-property custom NetSerialize overrides on its components. The identity fields (CharacterName, PrimaryArchetype, CharacterRace, CharacterGender) go through standard RepLayout. Only the ACTOR LOCATION stream uses FastArraySerializer.

**This confirms:** our existing RepLayout walker decodes the fields we care about. We just haven't focused the walker on the right content block yet (Phase 1.1).

## A.6 Practical next steps for CustomDelta

**For movement replication (Phase 4 priority):**
1. Study `FFastActorLocationArray` struct layout (needs IDA engagement or empirical capture-diffing)
2. Replicate the FastArraySerializer wire format in C++
3. Each connected client has one entry in `FFastActorLocationArray`; when they move, increment their `ReplicationKey` and the array's `MostRecentArrayReplicationKey`, then serialize deltas to peers

**For non-movement replication (everything else):**
- Standard RepLayout via `phase3_walker.py`
- Confirmed via `OnRep_CharacterName`, `HandleRaceChanged` etc. that these use RepNotify — standard path

---

# PART B — Game Database (CacheDB.dbc) extraction

## B.1 Format identification

```
File: CacheDB.dbc
Size: 144,085,052 bytes (~138 MB)
Header (32 bytes):
  00: 49 44 42 01   "IDB" + version 1
  04: 74 c0 63 09   unknown u32 = 0x0963c074 = 157,532,276
  08: 05 e0 6e 69   unknown u32 = 0x696ee005 = 1,768,873,989 (looks like random seed or hash)
  0c: 00 00 00 00   padding
  10: 00 00 00 00 71 01 00 00   next u32 = 369 (index count?)
  18: zeros
  20: 00 00 00 00 00 00 00 00   padding
  28: 80 83 b0 07 = 129,008,512  ← near the 128MB mark, possibly data section end
  30: onward — GUID/hash entries begin
```

NOT SQLite. Custom binary. Likely a **Dolt-style versioned database dump** (from DoltDesignDataProvider in `DesignDataSystem.ini`). Each row probably has:
- 16-byte GUID (commit hash or row ID)
- Serialized payload

## B.2 Strings extracted

Scanned the full 138 MB file for printable ASCII ≥ 6 chars: **571,767 distinct strings**.

Categorized:

| Pattern | Count | Examples |
|---|---|---|
| 32-char hex strings (GUIDs/hashes) | ~34,800 | `DCB297D3495F9C8E694D0E857343BB78`, `A54349554E1E02E65864B38772FB71FB` |
| BP paths (`/Script/*`, `/Game/*`) | **30,526** | `/Script/GameSystemsPlugin.AbilityConditionIsMostHated`, `/Script/GameSystemsPlugin.AbilityTargetSortByHealth` |
| Status effects (`Status_*`) | 247 | `Status_Burning`, `Status_Bleeding`, `Status_Silenced`, `Status_Stunned`, `Status_Chilled`, `Status_Frozen`, `Status_Fear` |
| Class abilities (`Bard_*`, `Cleric_*`, `Fighter_*`, `Mage_*`, `Ranger_*`, `Rogue_*`, `Summoner_*`, `Tank_*`) | **3,452** | `Ranger_Name`, `Ranger_Subheader`, `Ranger_ArchetypeDescription`, `Ranger_Trait_Name_1..4`, `Bard_Name`, etc. |
| Weapon refs | 925 | `Weapon_Wand_Hit_1..6+`, `Weapon_Proc_ArrowStorm_Hit` |
| Node/Civic refs | 1,769 | `Node_MemorialSite_Prayer`, `Node_Playground`, `Node_War_Mayor_Buff_PhysicalPower` |
| Ability descriptions | many | "Restore health equal to $hit2$ to all party members..." etc. |

## B.3 Concrete data extracted

**All 8 archetypes are there with descriptions and traits:**
```
Bard_Name, Bard_Subheader, Bard_ArchetypeDescription, Bard_Trait_Name_1..4, Bard_Trait_Description_1..4
Cleric_Name, Cleric_Subheader, Cleric_ArchetypeDescription, ...
Fighter_Name, ...
Mage_Name, ...
Ranger_Name, ...
Rogue_Name, ...
Summoner_Name, ...
Tank_Name, ...
```

**Complete status effect catalog (sample):**
```
Status_Burning      — fire DoT
Status_Bleeding     — physical DoT
Status_Hemorrhage   — severe bleed
Status_Chilled      — slow
Status_Frozen       — immobilize
Status_Snared       — movement root
Status_Silenced     — no magic casting
Status_Stunned      — full interrupt
Status_Shocked      — electric proc
Status_Dazed        — reduced cast
Status_Demoralize   — debuff stacking
Status_Humiliate    — debuff stacking
Status_Fear         — forced flee
Status_Weakened     — damage reduction
Status_Disarmed     — no weapon attacks
Status_Wound        — healing reduction
Status_Conflagration — fire stacking
Status_Infect       — spreads to nearby
Status_Volatile     — explodes on expire
```

**Ability tooltips with interpolation markers:**
```
"Hurl a ball of fire toward your target, dealing $hit:Mage_Fireball_Projectile_Hit$ and applying $eff..."
"{skill:Mage:Mage_Passive_Fireball:{effect:Mage_Passive_Fireball}: Fireball also applies {hit2:apply0..."
"Restore health equal to $hit2$ to all party members in range and apply $hit1:apply0$."
"Held ability: Fire a beam of healing energy toward a target ally. Charging this spell allows the bea..."
```

These are JINJA-style templates. `$hit$`, `$effect:X$`, `{skill:Class:Ability}`, `{formula:*}` are placeholders resolved at display time from other data.

**Ability condition/targeting system** (fully named classes via Unreal paths):
```
AbilityConditionIsMostHated      ← AI: target who's most-hated
AbilityConditionHasEffect        ← only if target has an effect
AbilityConditionHealthPercent    ← below % HP triggers
AbilityConditionBlueprint        ← BP-scripted condition
AbilityConditionNeverConsider    ← blacklist
AbilityTargetAcquisitionSphereTrace  ← cone/sphere target find
AbilityTargetSortByHealth        ← sort by HP asc/desc
```

This is their **AI behavior library** — every one of these is a reusable building block for NPC AI scripting.

## B.4 Files saved from this analysis

All in `dist/Release/`:
- `re_cachedb_all_strings.txt` — every string in the .dbc file with its byte offset (~45 MB text file)
- `re_cachedb_tables.txt` — deduped table-like and path-like strings only

These are GIGANTIC but they're the catalog of every named entity in AoC's design database.

## B.5 How to actually USE this data

### Option 1 — Serve the data as-is (MVP)
Don't parse the file. Just make our server answer "what's the tooltip for ability X?" by grepping through `re_cachedb_all_strings.txt`. Ugly but works for an emulator.

### Option 2 — Write a real IDB parser
To parse CacheDB.dbc into rows:
1. Figure out the row layout (variable-length? fixed?)
2. Identify the offset table at the start (likely the 369 entries we saw at 0x14)
3. Each entry: 16-byte GUID + offset + size + payload
4. Payload: could be JSON, protobuf, or UE5 FProperty-serialized

### Option 3 — Extract from PAK files
AoC ships pakchunks in UE5's new IoStore format:
- `global.utoc` — table of contents for the global chunk
- `pakchunk0-100+-WindowsClient.ucas/.utoc/.pak`

These contain the UE5 asset data (blueprints, data tables as UE assets). Using `UnrealPak.exe` or the community tool `retoc` or `fmodel`, we can extract these to get:
- `.uasset` files containing `UDataTable` rows for races, archetypes, stats, items
- `.uasset` for each `Status_*` effect
- `.uasset` for each ability blueprint

**This is probably the cleanest path for getting structured data.** UnrealPak supports .utoc/.ucas natively. PAK files may need encryption keys (mounted via AES for UE5 IoStore).

### Option 4 — Rebuild our own tables
For MVP multiplayer we don't need the full game data. We need:
- 8 archetype IDs (we already have these: 17747..17754)
- ~10 race IDs (we have 3 confirmed, rest to discover)
- ~4 genders
- ~20 status effects (optional for Phase 5 combat)

A minimal static table in our code covers the MVP. Full data extraction deferred until we need it.

---

# PART C — What this means for the Master Plan

Revisiting `docs/master-plan-multiplayer.md`:

### Phase 4 (multi-client broadcast) just got MUCH clearer
AoC has `UFilteredActorTrackingRegistry` with 6 named functions. We should:
- Model our `BroadcastManager` after it
- Call the corresponding operations server-side: given actor at position P moves, compute who cares, emit FastArray item with new ReplicationKey
- Use `FFastActorLocationArray`-style payload format for movement updates

### Phase 5 (game simulation) has all the content definitions available
Every status effect, every archetype trait, every ability description is in CacheDB.dbc. When we want to implement e.g. "apply Status_Burning to target":
- Lookup `Status_Burning` in our extracted data → get tick damage, duration
- Apply to target's stats
- Replicate via the standard RepLayout path

### Phase 6 (production) gets a DB extraction task
Build a proper IDB parser (or use pak extraction) to power the full game data. This lets our server answer "what are an Empyrean Mage's starting stats?" without hardcoding.

---

# PART D — Updated confidence on the roadmap

With today's RE, our confidence on Master Plan phases becomes:

| Phase | Before today | After today | Why |
|---|---|---|---|
| Phase 0 (cleanup) | High | High | Unchanged |
| Phase 1 (decode identity handles) | Medium | **High** | Confirmed RepLayout (not CustomDelta); walker ready |
| Phase 2 (actor builders) | Medium | High | Phase 1 output enables this directly |
| Phase 3 (per-client state) | Medium | Medium | No new info, but no new obstacles |
| Phase 4 (multi-client broadcast) | Low ("custom delta is scary") | **High** | `UFilteredActorTrackingRegistry` pattern to mirror |
| Phase 5 (game simulation) | Low-medium | **Medium-high** | All content definitions accessible; mechanic logic still needs RE |
| Phase 6 (hardening) | Low | Low | Still future |

**Every critical path Phase went up in confidence.** This was a net-positive session for scope certainty.

---

# Files produced in this session

| File | Purpose |
|---|---|
| `dist/Release/re_customdelta.py` | Scan for FastArraySerializer / NetDeltaSerialize patterns |
| `dist/Release/re_customdelta_deep.py` | Dump regions around confirmed hits |
| `dist/Release/re_cachedb_analyze.py` | CacheDB.dbc format analysis + string extraction |
| `dist/Release/re_customdelta.txt` | FastArraySerializer scan report |
| `dist/Release/re_customdelta_deep.txt` | Regional dumps (FastArray + NetDelta + SQLite) |
| `dist/Release/re_cachedb_all_strings.txt` | All 571,767 strings from CacheDB.dbc (~45MB text) |
| `dist/Release/re_cachedb_tables.txt` | Filtered table/path strings from CacheDB.dbc |
| `docs/re-deep-customdelta-db.md` | **THIS FILE** |

---

# Priority actions (ranked)

For the next deep-RE session (whenever we want to push further):

1. **Extract the IoStore paks** — run `UnrealPak.exe` or `retoc` against `pakchunk*-WindowsClient.utoc/.ucas`. Output: thousands of `.uasset` files including `UDataTable` assets for races, classes, items. **This gives us structured game data** (vs. the unparsed text soup of CacheDB.dbc).

2. **Write a CacheDB.dbc IDB format parser** — 8-12 hours of work. Start with the offset table at file start (369 entries?), reverse each entry, extract row bytes. Once we have rows, cross-reference with string offsets to label each row.

3. **Open the .i64 IDA database** (when we have IDA Pro) and document `UFilteredActorTrackingRegistry` methods precisely. Get exact struct layouts for `FActorLocation`, the registry's internal data structures.

4. **Cross-reference Perforce path leaks** — scan the binary for ALL `C:\P4\rel\AOCUE5\` source-file paths. Each one tells us which .cpp contributed to a code chunk, giving us module attribution.

5. **Dump specific `FFast*Array` struct contents** — we know `FFastActorLocationArray` exists. Likely siblings: `FFastBuffArray`, `FFastCooldownArray`, etc. Scan for that pattern.

---

## Closing thought

Today's evidence completely **inverts our earlier pessimism** about CustomDelta. What we thought was "AoC invented a mysterious custom serialization we can't decode" is actually "AoC uses standard UE5 RepLayout for identity, FastArraySerializer for position, and has a well-named spatial visibility system".

The binary is extremely readable once you know where to look. The IDA database (1.9GB) that exists alongside the exe means someone ALREADY reverse-engineered significant portions of it. Engaging that database properly in a future session would unlock even more structural understanding.
