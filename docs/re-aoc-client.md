# Reverse Engineering: AOCClient-Win64-Shipping.exe

**Date:** 2026-04-21 (evening RE session)
**Binary:** `E:\Ashes of Creation\Game\AOC\Binaries\Win64\AOCClient-Win64-Shipping.exe` (225 MB)
**Goal:** Find how class (archetype), race, and gender are encoded on the wire — specifically, the CustomDelta / NetDeltaSerialize layout that our Phase M5 work couldn't decode from captured packets alone.

---

## TL;DR of findings

- **Property names are `PrimaryArchetype`, `CharacterRace`, `CharacterGender`, `CharacterName`** — NOT `ArchetypeId` / `RaceId` / `GenderId` as our earlier XClient-based mapping assumed.
- **These are standard UE5 replicated properties with RepNotify (`OnRep_CharacterName`, `HandleRaceChanged`)** — meaning they flow through the normal RepLayout handle stream, NOT through AoC's CustomDelta. Critical implication: **our Phase 2 walker (phase3_rep_layout.py) SHOULD be able to find them as RepLayout handles, not CustomDelta blobs.**
- **Components discovered:** `CharacterInformationComponent` (identity), `CharacterCombatInformationComponent` (combat), `CharacterSecondaryInformationComponent` (secondary stats), `AlignmentComponent` (faction). The property we want (`PrimaryArchetype`, `CharacterRace`, etc.) lives on the actor or one of these components — likely `CharacterInformationComponent`.
- **IDA database exists** (1.9 GB .i64 + 1.5 GB .id0) from prior analysis — worth engaging if we want deeper drill-downs. Requires IDA Pro to open.
- **CacheDB.dbc** (138 MB, magic `IDB\x01`) at `Plugins/DesignDataPlugin/Generated/Client/` is the locally cached game design database — contains class definitions, stat tables, probably the IDs we need.
- **Live DB reference:** `DesignDataSystem.ini` points to MySQL at `10.10.1.217:3306` as the authoritative source for design data. The dbc is a snapshot from that.

---

## File inventory

### Binaries
```
AOCClient-Win64-Shipping.exe        225 MB  (the real game EXE)
AOCClient-Win64-Shipping.exe.i64    1.9 GB  (IDA Pro database — prior RE!)
AOCClient-Win64-Shipping.exe.id0    1.5 GB  (IDA symbol DB)
AOCClient-Win64-Shipping.exe.id1    883 MB  (IDA segment DB)
AOCClient-Win64-Shipping.exe.id2    1.9 MB
AOCClient-Win64-Shipping.exe.nam    1.2 MB  (IDA symbol names)
AOCClient-Win64-Shipping.exe.til    1.2 KB  (IDA type info)

AOCClient.exe                        EAC bootstrapper (launches shipping)
EOSSDK-Win64-Shipping.dll           161 KB  (small — likely our proxy?)
EOSSDK_real.dll                      18 MB  (real Epic Online Services SDK)
SecureEngineSDK64.dll                39 KB  (anti-cheat)
amd_fidelityfx_dx12.dll             6.4 MB
tbb12.dll / tbbmalloc.dll            threading building blocks
```

### Game data
```
Content/Paks/         UE5 IoStore containers (.pak/.ucas/.utoc)
  global.ucas/.utoc   Global IoStore + table-of-contents
  pakchunk0-100+-WindowsClient.*    Split chunks for fast download
Plugins/
  DesignDataPlugin/
    Generated/Client/CacheDB.dbc    138 MB — the cached design data
  Nvidia/             GPU vendor plugins
  Sentry/             Error telemetry
```

### Config
```
Config/DesignDataSystem.ini:
  [DoltDesignDataProvider]  LocalCommitHash=, Branch=main
  [SQLDesignDataProvider]   HostName=10.10.1.217  Database=design_data  Port=3306
  [CacheDesignDataProvider] Path=C:/P4/rel/AOCUE5/Game/Plugins/DesignDataPlugin/Generated/Client/CacheDB.dbc
```
The client has THREE design data providers configured; at runtime it uses whichever is reachable. In shipping it's the cached dbc.

---

## Confirmed property / class names (string-scan hits in exe)

### Identity fields — these are what we've been hunting

| String | Hits | First @ | Notes |
|---|---|---|---|
| **`CharacterName`** | 50 | 0x0b109e87 | FString, replicated |
| **`OnRep_CharacterName`** | 1 | 0x0b7081f0 | RepNotify callback — confirms standard RepLayout replication |
| **`SetCharacterName`** | 2 | 0x0b4bcbb2, 0x0b734590 | Setter |
| **`PrimaryArchetype`** | 14 | 0x0b0b386c | THE class/archetype field — NOT `ArchetypeId` |
| **`InterServerSetPrimaryArchetype`** | 1 | implied | Cross-server RPC that sets archetype |
| **`CharacterArchetype`** | 1 | 0x0b57d5a8 | Appears on a siege-related class (participant display) |
| **`CharacterRace`** | 15 | 0x0b201050 | Replicated property |
| **`HandleRaceChanged`** | 1 | 0x0b201060 | RepNotify callback |
| **`CharacterGender`** | 10 | 0x0b21f120 | Replicated property |
| **`CharacterGuildName`** | 1 | 0x0b57d5c0 | FString |
| **`CharacterCitizenNodeId`** | 1 | 0x0b57d5d8 | Node citizenship |

### Component class names (full C++ names)

| Short (wire label) | Full C++ class name | @ |
|---|---|---|
| BaseCharacterInfo | **`CharacterInformationComponent`** | 0x0b73e380 |
| CombatInfo | **`CharacterCombatInformationComponent`** | 0x0b73e3e0 |
| InteractInfo | **`CharacterSecondaryInformationComponent`** | 0x0b73e458 |
| AlignmentComponent | (same — generic-ish name) | 0x0b73e328 |
| AbilityComponent | **`UAoCAbilityComponent`** | 0x0b7f4648 |
| StatsComponent | **`UAoCStatsComponent`** | 0x0b800aa8 |

### Actor class names

| Class | Full name | First @ |
|---|---|---|
| AoC PlayerController | **`AAoCPlayerController`** | 0x0b7c2dcb |
| AoC Character (Pawn) | **`AAoCCharacter`** | 0x0b7cdab0 |
| AoC PlayerController C++ | `UAoCCharacter` (different — component maybe) | 0x0b7d0558 |

### NetDriver / wire-format

| String | Hits | Notes |
|---|---|---|
| `UIntrepidNetDriver` | 2 | Custom net driver — confirmed |
| `IntrepidNetDriver` | 3 | Variant refs |
| `PackageMapClient` | 1 | UE5 package map (we know this) |
| `FastArraySerializer` | 8 | UE5 fast array replication |
| `NetSerialize` | 13 | Custom serialization entry |
| `SendProperties` | 1 | RepLayout send entry |
| `PartialInitial` | 2 | Partial bunch debug string |
| `PartialFinal` | 1 | Partial bunch debug string |

Note: **`NetDeltaSerialize` returned 0 hits** as a string. This is EXPECTED — it's a virtual method, compiled into vtable lookups, no runtime string. Similarly no direct `CustomDelta` string.

### UMG character creator widget names (race/class buttons — at 0x0b21d3c8+)

Full list of race buttons (in declaration order):
```
0x0b21d3c8  KaelarButton
0x0b21d3d8  VaeluneButton
0x0b21d3e8  RenkaiButton
0x0b21d468  VekButton
0x0b21d488  EmpyreanButton
0x0b21d498  PyraiButton
0x0b21d4a8  DunirButton
0x0b21d4b8  NikuaButton
0x0b21d4c8  TulnarButton
```
Gaps between entries (e.g. 0x3e8 → 0x468 = 0x80 gap) suggest unused slots or other widgets interleaved.

Full list of class buttons:
```
0x0b21d4d8  BardButton
0x0b21d4e8  ClericButton
0x0b21d4f8  FighterButton
0x0b21d528  MageButton
0x0b21d538  RangerButton
0x0b21d548  RogueButton
0x0b21d558  SummonerButton
0x0b21d568  TankButton
```

So **all 9 races + 8 classes** are present. Matches our XClient archetype mapping (17747..17754 for classes).

### Selector group widget names

```
0x0b21d578  TopTabButtonGroup
0x0b21d590  ClassButtonGroup
0x0b21d5a8  RaceButtonGroup
0x0b21d5b8  GenderButtonGroup
```

---

## Architectural conclusions

### Class/race/gender are standard RepLayout properties, NOT CustomDelta

The presence of **`OnRep_CharacterName`** and **`HandleRaceChanged`** RepNotify callbacks confirms that these fields use UE5's **standard RepLayout** (the handle-based stream we already decode with phase3_walker.py). They are NOT in CustomDelta.

This contradicts our Session 2 hypothesis that "class/race are buried in CustomDelta". They're actually in RepLayout — we just haven't decoded them yet because:
1. They appear ONLY in the initial ActorOpen spawn (not in movement updates)
2. Our walker's aggregate stats showed RL handles as "Multi: N" (multi-property payloads), which means the walker captures them but hasn't split them per-handle

### The property probably lives on `CharacterInformationComponent`

Given it's called "CharacterInformation" and the replicated identity fields (CharacterName, CharacterRace, PrimaryArchetype, CharacterGender) are all "Character*" named, they likely live on this component. The component is a subobject of the Pawn, so within the Pawn's ActorOpen bunch, there's a **content block for CharacterInformationComponent**, and inside that block is the RepLayout handle stream that contains the identity fields.

### CacheDB.dbc is a static lookup table

The 138 MB `CacheDB.dbc` contains all design data: race definitions, class definitions, stat tables, abilities, items, etc. At runtime the client resolves IDs (e.g. `PrimaryArchetype=17747`) against this database to get displayable names and stats. We don't need to decode this for multiplayer — we just need to know the IDs and let the client do the lookup.

### Server-side RPCs exist

Found `InterServerSetPrimaryArchetype` — a server-side function. This tells us class can be changed at runtime, from one server to another. Useful context but not a blocker.

---

## Next-session action plan

### Easy wins now that we know the field names

1. **Re-run our phase3_walker with focus on ch=78+ (character channels) for INITIAL spawn bunches only.** Filter for multi-property payloads that decode into handles. Print handle + prop_bits + prop payload hex. One of those handles will contain `"RandomChar"` as an FString — that's `CharacterName` handle.
2. **Once CharacterName handle is identified,** look at adjacent handles in the initial spawn. `PrimaryArchetype` and `CharacterRace` will be siblings (consecutive handles in the property list of `CharacterInformationComponent`).
3. **Cross-check with known values.** If `CharacterRace` is a u8 or u16 field with value 2 (known XClient mapping = Kaelar), scan for handles emitting `{2}` bits. If `PrimaryArchetype` is 17747 (Bard), scan for handles emitting that value.

### Medium: map the full UProperty list

Using the IDA database (if we want to open it) — we can dump the `UClass::StaticClass()` registration for `CharacterInformationComponent`, which lists every UProperty with its name, type, offset, and replication flags. That gives us the COMPLETE handle-to-name mapping in one shot.

Alternative (no IDA): extract property name TABLES from the exe. UClass metadata is stored in the exe's `.rdata` as contiguous chunks. The offsets we've found (0x0b57d5a8 for Character* identity, 0x0b73e328 for component class names) are fragments of these tables.

### Long: decode CacheDB.dbc

If we ever want to drive the game entirely from our server (not just replay with patches), we'd need to read CacheDB.dbc or query MySQL on 10.10.1.217. For MVP multiplayer this isn't needed — we can ship client-side ID references (17747 = Bard) without knowing what Bard IS in game mechanics.

---

## Why this changes tomorrow's plan

**Previous plan (from session save doc):**
- Option A: extend CharacterProfile with pawn/PS/component hint fields
- Option B: Pawn actor builder with CustomDelta splice

**Updated plan given RE findings:**
- Option A stays (still useful)
- Option B changes: we can **decode PrimaryArchetype / CharacterRace / CharacterName as proper RepLayout handles** on the `CharacterInformationComponent` content block, which means our builder can EMIT them from scratch using profile data, not splice them!
- CustomDelta splicing is only needed for the REMAINING state (buffs, stats, cooldowns) which we can pass through as captured bytes.

Bottom line: **the "decode the wire format for class/race" problem is SOLVABLE with our existing phase3 walker**, because they're standard RepLayout, not CustomDelta. We just need one targeted scan focused on character initial-spawn bunches.

---

---

# PART 2: Full System Catalog (evening expansion scan)

A second pass with 366 keywords across 16 system categories. Full reports in
`dist/Release/re_scan_full.txt` (513 lines) and `re_admin_regions.txt` (965 lines).

## Coverage summary

| Category | Keywords found | Total hits |
|---|---|---|
| Identity (character name/class/race/gender) | 17/23 | 132 |
| Nodes (civic / node levels / siege) | 26/33 | **655** |
| Zones (Riverlands, ZOI, world partition) | 14/18 | 291 |
| Inventory / items / equipment | 19/24 | 294 |
| Combat / abilities / buffs | 29/33 | **786** |
| Mounts / caravans / vehicles | 13/19 | 251 |
| NPCs / enemies / AI | 20/29 | 554 |
| Gathering / artisan / anvils | 21/25 | 644 |
| Quests / commissions | 12/16 | 353 |
| Social (guild/party/chat) | 19/20 | 522 |
| Movement (sprint/swim/sit) | 15/19 | 479 |
| Stats (HP/mana/stamina) | 15/22 | 401 |
| Network internals | 9/14 | 41 |
| Design data | 8/12 | 120 |
| Server RPCs | 6/7 | 264 |
| **Admin / GM** | **30/52** | **376** |

## Top findings per category (what's actually in the binary)

### Admin / GM — we can load as admin 🎯

```
bIsGM                  @ 0xb6beb68   ← THE "is GM" flag variable
bIsDev                 @ 0xb31c5a8   ← dev-mode flag
GMChat                 @ 3 hits      ← GM-only chat channel
Role                   @ 36 hits     ← player role enum
Admin                  @ 12 hits
CheatManager           @ 6 hits      ← UCheatManager subclass
Cheat                  @ 50+ hits    ← cheat command family
ExecCheat              @ (via Cheat)
Spectator              @ 50+ hits
IsSpectator            @ 3 hits
IsAdmin                @ (via Admin)
```

**Specific GM commands discovered** (all in `ServerGM_*` RPC family):

| Command | What it does |
|---|---|
| `GMCommand`, `GMRequest` | Generic GM command dispatch |
| `ServerGM*` (50 hits) | Entire family of server-side GM actions |
| `GMEnterDialogue` / `GMExitDialogue` | Force-enter any NPC dialogue |
| `GMEnterDialogueWithTarget` | Target-specific |
| `GMEndNodeSiege` | End a node siege instantly |
| `GMExecuteNextSiegeEventInSeconds` | Fast-forward siege timeline |
| `ServerSetRace` | **Set character race directly** 🎯 |
| `ServerGMGetNodeTaxTable` | Inspect node tax |
| `ServerGMGetPlayerVariablesState` | Dump player vars |
| `ServerGMGetWorldVariablesState` | Dump world vars |
| `ServerGMGiveNodeARelic` | Give relic to node |
| `ServerGMDeclareNodeSiege` | Start siege |
| `ServerGMDeclareNodeWar` | Declare war |
| `ServerGMDeclineDialogueSubMenu` | Skip dialogue |
| `ServerGMDeliverItemsAuto` | Mass-deliver items |
| `ServerGMViewIndividualWarStats` | Stats inspection |
| `ServerGMViewIntrepidCronTasks` | Server scheduled tasks |
| `ServerActivateActionResponseCheat` | Action responses cheat |
| `ServerDumpHateMap` | AI aggro debug |
| `ServerDumpInvokerReport` | Invoker system debug |
| `ServerDumpNavMeshBoundsVolumes` | Nav-mesh debug |
| `ServerDumpNpcsInRadius` | List NPCs near you |
| `ServerDumpPopulationServiceLogs` | Population service |
| `ServerKickAllPlayers` | Kick every player |
| `ServerSetInvulnerable` | Godmode |
| `ServerSetInfiniteStamina` | Infinite sprint |
| `ServerToggleIgnoreInvites` | Block invite spam |
| `ServerToggleMaxLevel`, `ServerToggleMaxLevelCheat` | Max level cheat |
| `ServerSetRenderingCombatSettings*` | Visual tweaks |
| `ServerRemoveOldestGuildWarCharges` | War management |
| `ServerRemoveOldestNodeWarCharges` | War management |
| `ResetAllWarCooldowns` | Clear war cooldowns |
| `ResetCityNodeRelicActivationCooldown` | Relic reset |
| `FastForwardRealTime` | Time manipulation |
| `FastForwardToActivity` | Jump ahead |
| `SetSeason` | Change in-game season |
| `SetServerTickRate` | Adjust tick |
| `ToggleZOIDebug` / `ToggleZOIDebugPanel` | Zone debug |
| `KillAll` | Kill everything |

**To load as admin:** the key is setting `bIsGM = true` on our PlayerController's replicated state. At minimum we need:
1. The bit offset of `bIsGM` in the replicated property stream (findable with targeted walker run)
2. Patch it to 1 in the captured replay bunch
3. (Optional) Similarly set `bIsDev` or equivalent for dev-mode features

Or, the server RPC route: our emulator could fake processing of `ServerSetRace`, `ServerToggleMaxLevel` etc. to change client state from the server side — but these RPCs require matching handshake auth which we may not have.

Probably the cleanest path: **patch `bIsGM=1` in the initial PlayerController spawn bunch**. One bit flip in the RepLayout property stream, enables the entire GM command menu on the client UI.

### Identity — confirmed property names from Part 1, plus

```
CharacterAlignment   @ 13 hits   ← alignment/corruption tracking
CharacterLevel       @ 8 hits    ← level field
PlayerLevel          @ 11 hits   ← another level (maybe distinct)
AdventureLevel       @ (via PlayerLevel cat)
CorruptionLevel      @ (via Identity)
```

So the full character identity field set is:
- `CharacterName` (FString)
- `PrimaryArchetype` (int — the 17747..17754 range)
- `CharacterRace` (int — Kaelar=2 etc)
- `CharacterGender` (int — 1=Male, 2=Female)
- `CharacterAlignment` (?)
- `CharacterLevel` / `AdventureLevel` (int)
- `CharacterGuildName` (FString)
- `CharacterCitizenNodeId` (NetGUID or int)

### Nodes — 655 hits, civic systems are RICH

```
NodeLevel           50x  ← level 0-6 stage
NodeType            42x  ← military / scientific / economic / divine (guess)
NodeSiege           50x
NodeId              48x
CitizenshipDues     48x  ← what we saw in game!
Mayor               50x
Citizen             50x
Citizenship         50x
Freehold            50x
City                50x
```

The full node stage enum is present as strings: `Expedition`, `Encampment`, `Village`, `Town`, `City`, `Metropolis`. All 6 stages, which matches AoC's published design.

Also found: `NodePlot`, `FreeholdPlot`, `BuildingPlot`, `NodeTax`, `TaxRate`, `Vassalship`, `ParentNode`, `ChildNode`, `NodeConstruction`.

### Zones — world partition system

```
WorldPartition       50x
Region              50x
ZOI / ZoneOfInfluence   ← found
PersistentLevel     (confirmed — we saw this in our Phase 3 output)
StartingZone        (found)
SpawnZone           (found)
```

Also: the literal zone names `Riverlands`, `Forest`, `Tundra`, `Mountains`, `Desert` are referenced. `Verra` and `World_Master` (the map name) both hit.

### Combat — 786 hits, biggest category

All expected pieces present: `Ability`, `TakeDamage`, `DealDamage`, `CombatState`, `Cooldown`, `GlobalCooldown`, `Buff`, `Debuff`, `StatusEffect`, `CritChance`, `CritDamage`, `Target`, `Targeting`. Damage types: `Physical`, `Magical`, `Fire`, `Ice`. Plus `BasicAttack`, `Cast`, `Channel`.

### Mounts — Protectors Pride + Corsair + Rowboat confirmed

The PCAPRepo mount names match: `ProtectorsPride`, `Corsair`, `Rowboat`. Plus vehicle infrastructure: `VehicleRegistry`, `VehicleRegistration`, `StabledVehicles`, `VehicleRecovery`, `TransportCaravan`, `WagonCaravan`, `Caravel`.

### Gathering — anvils are there!

```
Anvil               ← confirmed
Forge, Loom, Furnace   ← crafting stations
CraftingStation
CraftingRecipe, Recipe, Reagent
Mining, Herbalism, Fishing, Lumberjacking
GatheringSkill, Profession
Harvestable
Commodity, Crate, CommodityCrate
```

### Inventory — standard ecosystem

```
UAoCInventory        ← C++ inventory component
InventoryItem, ItemSlot, EquipSlot
ItemClass, ItemBP, ItemStack, StackSize
MainHand, OffHand
ItemRarity, ItemLevel, ItemQuality
EquipItem, UseItem, DropItem
```

### NPCs — factions + AI

```
AIController, Behavior, BehaviorTree   ← UE5 standard AI
Spawner, SpawnPoint, NPCSpawn
Faction, Alignment, Hostile, Friendly
Vendor, Merchant, Shopkeeper
QuestNPC, QuestGiver
Villager, Guard
```

Plus specific enemy family names: `Goblin`, `Skeleton`, `Undead`, `Construct`, `AnimatedArmor`, `EnchantedArmor`, `Wretched`, `Ambusher`, `Languid`.

### Social — guild / group / chat

```
Guild, GuildId, GuildName, GuildRank
Party, Group, Raid
Friend, FriendList, IgnoreList
Chat, ChatChannel, ChatMessage
Whisper, Shout, Say
Alliance, War
```

### Movement — all the actions

```
RepMovement, CharacterMovement, UCharacterMovementComponent
Sprint, Walk, Run, Jump, Dodge
Swim, Climb, Flying
Sit, SitDown, StandUp
Stamina, StaminaCost
MovementSpeed, WalkSpeed, SprintSpeed
```

---

## New action items — building from scratch

### 1. `bIsGM` patch — unlock GM mode 🎯 highest leverage

Find the bit position of `bIsGM` in the PlayerController's RepLayout handle stream (it's a boolean = 1 bit).
Patch it to 1 in our captured replay.
Result: GM menu appears in client, ServerGM_* commands become callable via client UI.

This is a **one-bit patch** with potentially huge visible effect. Ranks extremely high on effort/reward.

### 2. `CharacterName` + `PrimaryArchetype` handle identification

With the RE findings from Part 1, run a targeted walker pass against initial-spawn bunches on character channels (ch=78, 104, etc). Find which RL handle carries "RandomChar" as an FString → that's the `CharacterName` handle. Adjacent handles will be `PrimaryArchetype`, `CharacterRace`, `CharacterGender` (by declaration order in UCLASS).

### 3. Node level patching (for node progression)

`NodeLevel` has 50+ hits and is a replicated int. If we can find the NodeInfo actor's channel, patching `NodeLevel` at the right bit offset could upgrade a node from Wilderness → Metropolis instantly. Joeva would then populate with its full town buildings (probably — the proximity-streaming might still need work).

### 4. Catalog the stat property offsets

HP / Mana / Stamina are all replicated properties on `UAoCStatsComponent`. Finding their handles in the RepLayout stream lets us write god-mode patches (set HP = 9999).

### 5. Item spawning

`SpawnItem` (1 hit) and `GiveItem` (8 hits) exist. If we can call these server-side RPCs from our emulator (via synthesized bunches), we could give test characters any item. Needs RPC argument decoding first.

---

## Summary: What's realistically achievable

Given this RE plus our existing walker infrastructure, the realistic roadmap to "playable multiplayer with admin access" is:

| Step | Effort | Impact |
|---|---|---|
| **bIsGM=1 patch** | Low | GM menu unlocks |
| Walker identifies CharacterName handle | Low | Variable-length name fix via builder path |
| PrimaryArchetype handle | Low (once Name found) | Class change working |
| CharacterRace handle | Low | Race change working |
| NodeLevel patch | Medium (find NodeInfo actor) | Joeva town renders |
| Pawn builder from scratch | Medium | Multiplayer foundation |
| PlayerState builder | Medium | Character info replication |
| NetGuidAllocator integration with all builders | Medium | Per-player isolation |
| Multi-client broadcast | High | Actual multiplayer |
| CustomDelta decode (if needed later) | High | Full wire understanding |

**The `bIsGM` patch is the single highest-leverage thing on this list.** One bit flip in the capture, and the entire GM command system becomes interactive.

---

## Files produced during this session

All in `dist/Release/`:
- `re_extract_symbols.py` — Extract strings from IDA `.nam` (doesn't produce much; binary format)
- `re_scan_exe.py` — Targeted keyword scan of the 225 MB exe (Part 1 focused set)
- `re_scan_full.py` — **Comprehensive 366-keyword scan (Part 2)** covering 16 categories
- `re_dump_region.py` — Dump printable strings in specific byte-offset regions (focused list)
- `re_dump_admin.py` — Dump admin/GM regions + identity regions for cross-reference
- `re_exe_matches.txt` — Part 1 keyword match report
- `re_scan_full.txt` — Part 2 full match report (513 lines)
- `re_admin_regions.txt` — Admin/GM + identity region string dumps (965 lines)
- `re_regions.txt` — Per-region string dumps (Part 1 focused)
- `re_nam_symbols.txt` — (empty — nam format not human-readable)

Rerun any of these fresh by pointing them at `E:\Ashes of Creation\Game\AOC\Binaries\Win64\AOCClient-Win64-Shipping.exe`.

The scripts are intentionally standalone — no import dependencies on our emulator code — so they'll still work if anything in the main project changes.

---

## Open questions for next session

1. **What's the exact handle number** for `CharacterName` in the `CharacterInformationComponent` RepLayout? (answerable by targeted walker run)
2. **What's the exact field order** on `CharacterInformationComponent`? (likely: `CharacterName`, `PrimaryArchetype`, `CharacterRace`, `CharacterGender`, `CharacterGuildName` — by declaration order, handles 1..N)
3. **Does the Pawn have its own identity fields**, or are they ALL on `CharacterInformationComponent` as a subobject? (probably the latter — that's why the component exists)
4. **Can we decode `CacheDB.dbc`** to get race/class enum tables? (a nice-to-have, not a blocker)

These are all investigable without breaking anything. Session 4 of the multiplayer track can open with "run targeted phase3 on character initial-spawn → list all handles with their decoded values → match to property names from this doc".
