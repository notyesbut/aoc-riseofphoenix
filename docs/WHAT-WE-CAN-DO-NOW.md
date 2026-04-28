# What We Can Do Now — Capability Catalog

Given our RE knowledge (see `AOC-WIRE-FORMAT-RE-KNOWLEDGE.md`), here's what's
achievable. Ranked by effort vs. value.

**Answer to "are we only limited to change the character name?"**:
**No, not even close.** The character name was the tip of the iceberg — it's the
hardest kind of property to patch (variable-length FString inside a nested
content block inside a partial-initial bunch). Now that we understand the full
structure, everything else is easier.

---

## TIER 1 — Ready to ship today (no new RE needed)

These require ONLY the knowledge we already have and can be done immediately
against the existing replay capture.

### 1.1 Any fixed-width numeric property in any subobject

Anywhere in a bunch you find a numeric property (int32, float, uint8, bool):
just overwrite the bytes. No length fields to update, no shifts needed.

**Examples you can patch right now:**
- **HP / MP / Stamina current & max** (floats inside PlayerState)
- **Level** (int32)
- **XP progress toward next level** (int32)
- **Gold, currencies, any numeric resource** (int32/int64)
- **Stat values** — STR/DEX/INT/VIT (int32 or uint8)
- **Movement speed modifier** (float)
- **Class/Race ID** (uint8, enum) — though be careful, this drives cosmetics
- **Server-authoritative flags** (IsPvPFlagged, IsAFK, IsInCombat)
- **Faction ID / Guild ID** (uint32)
- **Alignment / Karma** (float or int32)

**Effort**: low — needle-search for known replay bytes, overwrite. Same
approach as current M2.1 NUL-pad but without the length issue.

**Caveats**:
- If the property is a **RepNotify**, the client calls a delegate when it
  changes — usually safe, sometimes triggers UI animations.
- If the server later sends an **authoritative update** with the real value,
  your patch gets overwritten. For replay-mode this is fine (replay is
  deterministic). For live-server mode (Path B), the server controls the value
  directly.

### 1.2 Any FString property ≤ 10 characters

The M2.1 NUL-pad approach already works for these. You can freely rewrite:
- **Character name** (already in use, 1-10 chars)
- **Guild tag** (typically 3-6 chars — fits cleanly)
- **Title / honorific** (if ≤ 10 chars)
- **Pet name** (if ≤ 10 chars)

**Any FString up to the slot size** — find the `int32 len` + bytes + NUL
pattern in captures, NUL-pad your replacement. Slot-length depends on capture
but is typically 11 bytes of ASCII for each 10-char field.

### 1.3 Transform data (position, rotation, velocity)

The `SerializeNewActor` block contains bSerializeLocation/Rotation/Scale/Velocity
flags + optional `FVector_NetQuantize`/`FRotator` data.

You can modify:
- **Spawn location** — where your character appears
- **Initial facing** — which direction you look
- **Velocity** — initial motion (useful for teleports)

**Caveats**: physics/movement prediction will correct you toward the server's
authoritative position within ~200ms unless the server is also running in
native mode.

### 1.4 Inject/modify diagnostic log strings

Any `off_149F5XXXX` log format string in the binary can be traced to its call
site via xref. You can modify log verbosity, trigger specific log messages, or
correlate in-game events with binary log output — useful for debugging.

---

## TIER 2 — Ship this week (one more RE round trip per item)

These need specific function RE that we've scoped but not completed.

### 2.1 Variable-length FString ≥ 11 characters (the current stretch goal)

**Blocked on**: `sub_143F2C340` (ReadContentBlockHeader) disasm — ONE MORE dump.

Once done: rewrite FStrings of ANY length, anywhere. Full variable-length:
- Character names 11-24 chars
- Chat messages
- Long guild descriptions
- Item names / descriptions  
- Quest text
- Ability/spell names

**Effort**: 1 hour after the final RE round.

### 2.2 Full FastArray element edits

We've RE'd all 4 FastArray functions. You can now **synthesize or modify
per-element updates** for any FastArray property:
- **Inventory slot contents** (items in bags)
- **Equipped gear slots** (helmet, chest, weapons, etc.)
- **Known abilities / skill array**
- **Active buffs / debuffs** (with durations)
- **Party/raid member list**
- **Quest log entries** (status, progress, objectives)
- **Friends list / ignore list**
- **Hotbar assignments**

**Effort**: build a `FastArrayEmitter` class using the known format
(RepKey + BaseKey + NumChanged + NumDeletes + ElementIDs[] + per-element body).
Similar to `PackageMapExporter` we already have.

### 2.3 NetGUID fabrication (spawn unknown actors)

FIntrepidNetworkGUID is 128-bit. We can issue fresh NetGUIDs for server-
synthesized actors by picking unique `{ObjectId, ServerId, Randomizer}` tuples.
Combined with the PackageMap export section (RE'd in `package_map_exporter.h`):

- **Spawn NPCs** anywhere in the world
- **Inject item drops** from killed mobs
- **Place world objects** (campfires, flags, portals)
- **Create interactive props** (chests, doors)

**Effort**: `src/net/bootstrap/netguid_allocator.h` exists but needs wiring
into the live emit path.

### 2.4 Remove actors from world view

Send a `bClose` control bunch on the actor's channel to despawn it client-side:
- **Kick a mob out of view**
- **Hide deserted players** 
- **Remove completed quest givers**

**Effort**: minimal — `emit_close_bunch()` helper, use existing bunch writer.

### 2.5 Static world content (the "shift the map" capability)

Via PackageMapExports, you can make the client load **ANY class blueprint**
referenced by path. If we can enumerate paths (engine has a known set):

- **Swap actor skins** (make goblin look like elf)
- **Replace items** (your bronze sword looks golden)
- **Retexture environment** (season events themes)

**Effort**: medium — needs a blueprint path catalog; PackageMapExporter
already supports this.

---

## TIER 3 — Multi-week projects (significant RE remaining)

### 3.1 Full URepLayout::ReceiveProperties decode

**Blocked on**: `sub_143F2F820` (FObjectReplicator::ReceivedBunch) RE.

Once done: we know every single property read order, cmd_index mapping,
conditional-replication bits. Lets us:

- **Modify any property of any actor, of any length**, with zero guessing.
- **Strip/filter specific properties** (remove location updates but keep stats).
- **Inject new properties** into the stream (requires matching the CLASS's
  RepLayout structure — complex but possible).

### 3.2 AES-GCM StatelessConnect handshake (pure-native bootstrap)

**Blocked on**: AoC's crypto handshake is different from stock UE5. The
client uses AES-GCM with keys derived from a server-sent challenge.

Once RE'd: no more hybrid mode. Server can synthesize the initial handshake
natively and issue any session keys. Enables a truly server-authoritative
emulator that doesn't depend on replays at all.

**Existing partial progress**: `src/net/` has `UIntrepidNetDriver` RE notes.
Needs completing.

### 3.3 Movement prediction / authoritative server physics

UE5's CharacterMovementComponent does client-side prediction with server
reconciliation. To be fully authoritative (Path B), we need to understand:
- The client's input packet format (WASD/jump/etc. in C>S direction)
- The server's move-acknowledgement format (S>C)
- The reconciliation algorithm (to avoid rubber-banding)

**Partial progress**: some input-channel packet captures already decoded.

### 3.4 Combat / ability system

Abilities use the UE5 GameplayAbilitySystem (GAS). The GAS wire format is
heavily FastArray-based (AttributeSets, ActiveGameplayEffects, etc.).

Since we've RE'd FastArray fully, this is actually **medium effort, not hard**:
mostly mapping attribute/effect IDs to their meaning.

**Unlocks**:
- Custom abilities, custom damage formulas
- Buff/debuff application from the server
- Server-controlled PvP / PvE balance

---

## TIER 4 — Beyond emulator — creative mods

These are what the wire-format mastery enables **beyond a server emulator**.

### 4.1 Client-side overlays without touching the binary

Since we understand every packet, we can build:
- **DPS meters** (parse combat events, compute metrics)
- **Radar / minimap additions** (parse actor positions, render offsets)
- **Quest tracker overlay** (parse journal updates)
- **Inventory spreadsheet exporter**
- **Chat loggers / translators**

Using: MITM proxy that decodes + re-encodes packets, forwarded to local overlay.

### 4.2 Multi-client synchronization

With server knowledge: run multiple bots that coordinate in-world. Apply
patches per-client for independent characters without re-capturing replays.

### 4.3 Test harnesses for client bugs

Inject malformed packets (with specific fuzz patterns matching our RE'd
structure) to probe client robustness. Useful for security research.

### 4.4 Content preservation

As AoC updates, the wire format may change. Document every version's format
over time. Archive pre-release betas that would otherwise become unplayable
as servers shut down.

---

## Immediate next actions (ranked)

| # | Task | Unlocks | Effort |
|---|---|---|---|
| 1 | Dump `sub_143F2C340` (ReadContentBlockHeader) | Tier 2.1 — variable-length names | 1h |
| 2 | Press X on `sub_143F30430` → find UChannel::ReceivedRawBunch | Verify bdb; unlock multi-bunch patching | 30m |
| 3 | Wire `FastArrayEmitter` class in `src/protocol/emit/` | Tier 2.2 — inventory/abilities | 1 day |
| 4 | Build the Tier 1.1 "property patcher" framework (scan, match, rewrite) | All numeric patches | 4h |
| 5 | Dump `sub_143F2F820` (FObjectReplicator::ReceivedBunch) | Tier 3.1 — full URepLayout decode | 2h + analysis |

---

## Short answer for your question

> "Are we only limited to change the character name?"

**Absolutely not.** With current knowledge:

- **We can edit ANY numeric/boolean property** in any bunch (HP, Level, Gold,
  Class, Race, flags) immediately. No further RE needed.
- **We can edit any FString ≤ 10 chars** immediately (guild tags, titles, etc.).
- **We can rewrite ANY FString of any length** after ONE more RE dump.
- **We can synthesize full FastArray updates** (inventory, abilities, buffs) —
  all four helper functions are already RE'd.
- **We can spawn / despawn actors** via NetGUID fabrication + PME exports.
- **We can modify transforms** (position, rotation, velocity).

The character name was just the hardest single item because it exercises
every layer of the stack simultaneously. Everything else is easier.
