# Bootstrap Static vs Dynamic Field Classification

**Purpose:** For every packet in the 100-packet bootstrap, identify which bit ranges are STATIC (same across sessions) vs DYNAMIC (change per-character). This is the foundation for the `PacketRecipe` system.

**Methodology:** A field is DYNAMIC if changing it would change what a new character sees. A field is STATIC if its value is determined by the server class/map/archetype structure (session-invariant).

---

## Classification rules

A field is **STATIC** if ALL of:
- Value derives from class hash / map name / archetype CDO
- Unchanged across captures of different characters
- Not a NetGUID assigned at runtime

A field is **DYNAMIC** if ANY of:
- Per-character identity (name, class, race, gender, appearance)
- Per-character transform (spawn location, rotation)
- Per-character stats (health/mana/stamina, level, level progression)
- Per-session NetGUID (actor NetGUIDs allocated at spawn — PC, Pawn, PlayerState, AuthServerIDReplicated)
- Timestamp (frame time, start time)
- Session state (score, ping)

A field is **DEPENDENT** if:
- Packet seq/ack (rewritten per our session by `build_replay_packet`)
- Per-channel chSeq (tracked by `ClientState`)
- ACK history bits (our session)

---

## Packet-by-packet classification

### Phase 1: NMT echoes (pkts #0, #2)

**pkt#0 — AoC opcode 3 (42B, ch=0 reliable 112 bits, chSeq=954)**
- Content: `03 09 00 00 00 35 30 39 39 35 33 34 34 00`
- Opcode byte `03` — STATIC (fixed value)
- FString len `09 00 00 00` (=9 LE) — STATIC
- ASCII `"50995344\0"` — **PROBABLY STATIC but uncertain** (may be session-specific token)
- chSeq=954 — DEPENDENT (tracked per-channel)
- **Classification**: `StaticPacketRecipe` with bytes-verbatim.

**pkt#2 — NMT_Welcome re-emit (151B, ch=0 reliable 984 bits, chSeq=955)**
- Content: `01` + FString("/Game/Levels/Verra_World_Master/Verra_World_Master") + FString("/Game/GameBlueprints/AoCGameModeBaseBP.AoCGameModeBaseBP_C") + FString("")
- Opcode=01 — STATIC
- Map path — STATIC (per map choice)
- Gamemode path — STATIC
- Redirect — STATIC (empty)
- chSeq — DEPENDENT
- **Classification**: `StaticPacketRecipe` OR skip entirely (we already emit NMT_Welcome natively during NMT handshake).

### Phase 2: Sentinel fillers (pkts #3-#21)

All 19 packets are 21B bb=1 sentinels. SKIP entirely — our Maintain loop produces natural keepalives.
**Classification**: not in plan. 19 packets eliminated from the 100.

### Phase 3: PC spawn & continuation (pkts #22, #23)

**pkt#22 — PC ActorOpen (784B, ch=3 ActorOpen rel=1 part=1-- exp=1 ctrl=1 chSeq=1978)**

Bunch breakdown (from `docs/native-bootstrap-sequence.md` §2.3):
| Bunch | Size | Content | Static/Dynamic |
|---|---|---|---|
| #0 | 3545 bits | PC export section + SerializeNewActor header | MIXED (see below) |
| #1 | 1314 bits | PC body tail (continues into pkt#23) | MIXED |
| #2 | 873 bits | HUD subobject (part 1) | STATIC |
| #3 | 173 bits | HUD subobject (part 2) | STATIC |

Bunch #0 detail — SerializeNewActor:
| Field | Static/Dynamic | Source |
|---|---|---|
| bHasRepLayoutExport=0 | STATIC | Wire format |
| NumGUIDsInBunch=3 | STATIC | 3 exports always |
| Export[0]: AoCPlayerControllerBP_C chk=0x6b62891c | STATIC | Class hash |
| Export[1]: PersistentLevel chk=0 → Verra_World_Master chk=0 → /Game/Levels/... | STATIC | Map hash |
| Export[2]: GlobalGMCommands chk=0xcaaaee3e → /Script/GameSystemsPlugin | STATIC | Class hash |
| actor_netguid (Obj=10341530, Srv=60, Rnd=1860730596) | **DYNAMIC** | Per-session |
| archetype_netguid = 3503756484819958835 | STATIC | Class CDO |
| level_netguid = 16442478405498561049 | STATIC | Map |
| serialize_location=1, quantize_location=1 | STATIC | Format flag |
| location_max_bits=24 | STATIC | Quantization |
| location_scaled=(-5940754, -502674, -7750527) | **DYNAMIC** | Spawn position |
| serialize_rotation=0, serialize_scale=0, serialize_velocity=0 | STATIC | Format flags |

Bunch #1 (1314 bits) — PC RepLayout tail:
- Contains: cmd_index-indexed properties from `decode_property_stream_v5.py` SCHEMA
- `AuthServerIDReplicated` (NetGUID, cmd=0) — **DYNAMIC** (per-server)
- `bReplicateMovement` bool (cmd=1) — STATIC (=1)
- `bHidden` (cmd=2) — STATIC (=0)
- `TargetViewRotation` (cmd=8, FRotator) — **DYNAMIC** (view direction)
- AoC-specific cmd=9..26 — DYNAMIC (per-session state)
- **Key dynamic field buried here**: references to Pawn NetGUID, PlayerState NetGUID

Bunch #2+#3 (1046 bits) — HUD subobject:
- `has_rep_layout=0` → CustomDelta payload
- Content mostly STATIC (UI layout), but may include HotbarSlots (DYNAMIC per character)

**Classification**: pkt#22 = `PatchedPacketRecipe` with patches for actor_netguid (bits ~40-168 in bunch#0 SNA body) + spawn location (bits ~260-332). Bunch #1 tail = `PatchedPacketRecipe` for cmd=0 NetGUID + any Pawn/PS refs. Bunch #2+#3 = Static for now.

### Phase 4: Early GUIDExports (pkts #24, #26, #28 on ch=85)

Each is a ch=85 GUIDExport bunch with bdb=1615 bits (identical structure).
**Content**: PackageMap class CDOs being announced to the client.
**Classification**: `StaticPacketRecipe` — pure class-hash/path content.

### Phase 5: ch=2 GUIDExport + ch=30 ActorClose (pkt#25)

**pkt#25 — 912B, ch=2 GUIDExport PART-INIT 4923 bits + ch=30 ActorClose 1936 bits**
- ch=2 GUIDExport: probably GameState or PlayerState package-map registration.
  - If this opens PlayerState → contains PlayerState actor_netguid (DYNAMIC) + archetype (STATIC)
- ch=30 ActorClose: closes some transient channel from server-load phase. STATIC.
**Classification**: `PatchedPacketRecipe` (if PlayerState is opened here — dynamic netguid) OR `StaticPacketRecipe` (if just class registrations).

### Phase 6: PARSE_FAIL / opaque continuations (pkts #27, #45, #46)

Our scanner can't fully parse these (likely AoC CustomDelta payloads).
**Classification**: `StaticPacketRecipe` — splice as-is. These contain subobject state that's mostly per-class.

### Phase 7: ch=3 big partial stream (pkts #29-#44, ~16 packets of 978B)

**This is the PC's RepLayout tail + subobjects streamed as partial continuation bunches.** ~75K bits total.

Contents (inferred from replay walker + schema):
- More PC AoC-specific properties (cmd=9..26)
- PlayerController subobject references
- Possibly: inventory, quest log, hotbar config
- **Contains CharacterName reference (if on the CharacterInformationComponent which is on the Pawn, not PC, this might NOT be here)** — needs decode to confirm

**Dynamic fields potentially buried here:**
- AoC-specific NetGUIDs (cmd=10 CaravanLaunchNode, cmd=16 ControllersOriginalPawn, cmd=17 ControlledExternalPawn, cmd=22 PuppetComponentReference — ALL DYNAMIC)
- cmd=23 CharacterInGameSettings (DYNAMIC per preferences)
- cmd=24 MarkedTargets (DYNAMIC)
- Various UStruct bodies (DYNAMIC)

**Classification strategy**: `StaticPacketRecipe` for now. These packets are the hardest to decode. Most of the data is dynamic, but our character isn't using most of it on initial spawn (no caravan, no puppet, empty MarkedTargets). Using the captured session's values produces a working-but-generic character; substituting is M4 work.

### Phase 8: ch=4+ other actors (pkts #47-#99)

New partial sets on different channels (NPC spawns, environment actors).
**Static/Dynamic:** These actors are probably NPCs/static meshes in Verra. Their state is mostly session-invariant (same NPCs exist for every character). Some have per-character aggro state but not at spawn time.
**Classification**: `StaticPacketRecipe` — pure splice.

---

## Summary table: 100 packets by recipe mode

| Phase | Packets | Count | Recipe mode | Dynamic field count |
|---|---|---|---|---|
| NMT echoes | #0, #2 | 2 | Static | 0 |
| Sentinel fillers | #1, #3-#21 | 20 | SKIP | — |
| PC ActorOpen + cont | #22, #23 | 2 | **Patched** | 3-5 (actor_netguid, spawn loc, Pawn/PS refs) |
| ch=85 GUIDExports | #24, #26, #28 | 3 | Static | 0 |
| ch=2 + ch=30 | #25 | 1 | Patched | 1-2 (if PS opened) |
| PARSE_FAIL | #27, #45-#46 | 3 | Static | unknown |
| ch=3 PC tail stream | #29-#44 | 16 | Static | ~10 (buried in UStruct bodies) |
| ch=4+ other actors | #47-#99 | 53 | Static | few (NPC AI state) |

**Net**: 80 packets to emit (20 sentinels skipped). Of those, 3-5 are `Patched` (most important dynamic fields), ~75 are `Static`.

**Upgrade priorities (first replacements):**
1. **pkt#22 → Patched**: actor_netguid + spawn location — unlocks multi-client (each player their own PC NetGUID at their own location)
2. **pkt#23 (PC tail bunch #1) → Patched**: AuthServerIDReplicated NetGUID + Pawn NetGUID ref
3. **pkt#78 equivalent → Patched**: CharacterName + class + race + gender + appearance
4. **pkt#22 → Native**: full ActorBuilder emission (gated by byte-identity test, already passing)

---

## CharacterName — the most-asked dynamic field

**Where does CharacterName live in the replay?**

Per `docs/re-apawn-playerpawn-c.md`, CharacterName is on `CharacterInformationComponent` — a subobject of the Pawn, not the PC. So it's emitted as part of the Pawn ActorOpen sequence.

Looking at our captured fixtures:
- `captured_pkt_78.bin` is labeled "Pawn ActorOpen fixture" per `captured_pkt_78_meta.txt`
- The Pawn spawn in the broader replay (pkt#14343 per bunches_bootstrap.log) is a ch=14 ActorOpen with bdb=4326 bits (PART-INIT)

CharacterName appears as an FString inside the CharacterInformationComponent's CustomDelta payload. Exact bit offset requires decode — that's Phase D (field locator script).

**Initial plan**: once we know CharacterName's bit range in pkt#78, we write:
```cpp
FieldPatch character_name_patch = {
    .field_name = "CharacterName",
    .bit_offset = <TBD>,
    .encode = [](const CharacterProfile& p) { return encode_fstring(p.name); },
};
```

And pkt#78 becomes a `PatchedPacketRecipe` that injects our `profile.name` in place of "Hatemost".

---

## Next concrete steps

1. **Scaffold** `CharacterProfile`, `NetGUIDAllocator`, `PacketRecipe` (Phase B)
2. **Initial plan** — `bootstrap_plan.cpp` with all 100 packets as `StaticPacketRecipe` (Phase C)
3. **Field locator** — Python tool to find `"Hatemost"` FString byte range in replay_data.bin; use it as the CharacterName bit offset (Phase D)
4. **First patch** — upgrade the Pawn-bearing packet to `PatchedPacketRecipe{character_name}` (Phase E)
5. **Second patch** — upgrade pkt#22 to `PatchedPacketRecipe{actor_netguid, spawn_location}` (Phase F)

After Phase E: custom name shows in HUD. After Phase F: each player gets a unique PC NetGUID at their own position → multiplayer feasibility.
