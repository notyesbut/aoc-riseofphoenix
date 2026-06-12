# RE: Design-Data / Asset-Registry Pre-Warm Before CharacterAppearance

**Target:** PM151 stretch goal — let the appearance bunch carry **real** cosmetic
asset IDs (race / hair / eye GUIDs) without killing possession, by replicating
whatever the real AoC server does to ensure the referenced assets are loadable
*before* `OnRep_CharacterCustomization` fires.

**Scope of this note:** identify the concrete server→client mechanism that
"pre-warms" the design-data / asset registry, its wire layout, and where a new
emitter should fire in `world_bootstrap_emitter.cpp`. Plus an inventory of pcaps
that could be diffed to observe it live.

**Legend:** **[CONFIRMED]** = read directly from a cited SDK dump / IDA dump /
source file. **[INFERRED]** = derived from UE5 engine rules / architecture, not yet
validated against a live capture.

> **TL;DR.** There is **no per-character "design-data record set" bunch**. AoC
> resolves cosmetic GUIDs **locally** on the client through its DesignDataManager
> and async-loads the assets by ID (`AsyncLoadRecordById` →
> `UASyncAssetLoadingSubsystem`). The possession-death hazard is a **race**: the
> appearance OnRep kicks off an async load that has not finished by the time
> `ClientRestart`/`AcknowledgePossession` is evaluated. The server's pre-warm is
> the stock UE5 **`ClientSetBlockOnAsyncLoading()`** reliable client RPC, which
> forces the client to **block the game thread on pending async loads** so the
> appearance assets are resolved synchronously and possession survives. This is a
> **zero-payload PC-channel reliable RPC** — far simpler to emit than a
> record-shipping bunch, and it does not require deep Ghidra to finalize.

---

## (a) Mechanism identification

### a.1 The three candidate mechanisms from the spec, adjudicated

| Candidate (from `spec-appearance.md` §5.3 / `appearance-repindices.md` §6.2) | Verdict | Evidence |
|---|---|---|
| (a) A `DesignData` / `IntrepidNetUtilitySubsystem` client RPC shipping the record set | **REJECTED** | `IntrepidNetUtilitySubsystem` has **no** design-data RPCs — its entire method surface is server-grid / heatmap / config (`IntrepidNet_classes.hpp:486-517`, methods `:494-501`). The `IntrepidNetDebugComponent` RPCs (`:143-159`) are sharding/promotion only. No "ship records" RPC exists anywhere on the IntrepidNet surface. **[CONFIRMED — by absence.]** |
| (c) A `DesignData` object replicated as an actor/subobject | **REJECTED** | `UDesignDataManager` / `UAoCDesignDataManager` derive from **`UObject`**, not `AActor` (`DesignDataPlugin_classes.hpp:94,124`; `GameSystemsPlugin_classes.hpp:17478,17498`). They are subsystems, not replicated actors — they cannot be opened on a channel. `UDesignDataRecordContainer` is also a bare `UObject` with only local getters (`GameSystemsPlugin_classes.hpp:36216-36241`). **[CONFIRMED.]** |
| (b) Driving `PostAssetsReadyForInitAppearance` | **PARTIAL / INTERNAL** | `PostAssetsReadyForInitAppearance` is a **member function of `UBaseModularAppearanceComponent`** (`GameSystemsPlugin_classes.hpp:17307`), **not** a `Net` UFunction — its flags in the GObjects dump show no `NetClient`/`NetServer` (`docs/aoc-sdk/GObjects-Dump.txt:32063`). It is an **internal callback** the component invokes on *itself* once its own async loads finish, not something the server pushes. So it is the **gate**, but the server does not drive it directly over the wire. **[CONFIRMED — it is the local completion callback, not an RPC.]** |
| **(NEW) `ClientSetBlockOnAsyncLoading()` reliable client RPC** | **IDENTIFIED — primary mechanism** | See a.2. **[CONFIRMED present in client RPC table; INFERRED that it is what pre-warms appearance.]** |

### a.2 How the asset reference actually resolves (the load path)

**[CONFIRMED]** The cosmetic GUIDs do **not** travel as records over the network.
They are 64-bit IDs the client resolves locally:

- `FAppearanceId.RecordGuid` / `.TypeId` (`GameSystemsPlugin_structs.hpp:22911-22919`)
  and `SharedAppearanceInfoId → FAppearanceInfoId → FDesignDataObjectId`
  `Guid`/`TypeId`/`Name` (`GameSystemsPlugin_structs.hpp:37135` →
  `DesignDataPlugin_structs.hpp:183-191`) are **plain int64/FName lookup keys**.
- The client resolves a key → record via the DesignDataManager
  (`AsyncLoadRecordById`, IDA dump `docs/ida-dumps/Logs.txt:88394`;
  `LoadRecordHandle` `:60066`; `GetBaseCharacterFromGuid` `:60895`). These are
  **local** lookups against the client's cooked design-data store
  (`UCachedDesignDataAsset`, `DesignDataPlugin_classes.hpp:69-90`), populated at
  load time — in dev via the Dolt/P4 provider
  (`OnDesignDataProviderConnected`, `DesignDataPlugin_classes.hpp:104`;
  `EDoltDesignDataProviderTask`, `DesignDataPlugin_structs.hpp:18-27`); in
  shipping from the cooked cache.
- Resolving a record then **async-loads the referenced SkeletalMesh / appearance
  asset** through `UASyncAssetLoadingSubsystem* AssetLoader`
  (`GameSystemsPlugin_classes.hpp:17277`), driven by
  `UBaseModularAppearanceComponent::AsyncInitAppearances`
  (IDA dump `docs/ida-dumps/new 4.txt:95961`; source path
  `…/Private/BaseModularAppearanceComponent.cpp`, `:95960`). The pending set is
  tracked in `PendingLoadAppearances` (`docs/ida-dumps/Logs.txt:69450`); when it
  drains, the component fires its own `PostAssetsReadyForInitAppearance`
  (`GameSystemsPlugin_classes.hpp:17307`) and the merge proceeds.

**[CONFIRMED]** The hazard in `appearance_emitter.cpp:280-298` is therefore an
**async-load race**, not a "missing records" problem: `OnRep_CharacterCustomization`
starts `AsyncInitAppearances`; if those loads have not completed (and have not been
forced to block) by the time `ClientRestart` runs `AcknowledgePossession`, the
subobject is in a half-initialized state and possession tears down.

### a.3 The pre-warm primitive: `ClientSetBlockOnAsyncLoading()`

**[CONFIRMED]** `Engine.PlayerController.ClientSetBlockOnAsyncLoading` is a
**reliable client RPC**:

- Flags: `RequiredAPI, Net, NetReliable, Native, Event, Public, NetClient`
  (`docs/aoc-sdk/CppSDK/SDK/Engine_functions.cpp:28388-28404`).
- **Zero parameters** — `UObject::ProcessEvent(Func, nullptr)`
  (`Engine_functions.cpp:28401`); declaration `Engine_classes.hpp:8347`.
- It is present and bound in the **AoC client's PlayerController RPC dispatch
  table** at handle/index **40** (`docs/RE-AOC-CLASSES.md:213`,
  VA `0x1443fa1e0`), immediately **after** `ClientRestart` (#37) and
  `ClientRetryClientRestart` (#38) in the same `FunctionLinks` cluster
  (`RE-AOC-CLASSES.md:170-214`).
- It physically sits **adjacent to `ClientRestart`** in two independent UFunction
  pointer tables in the binary
  (`docs/ida-dumps/client_restart_param.txt:24-31` and `:43-50`;
  `docs/ida-dumps/find_cr_in_table.txt:57`;
  `docs/ida-dumps/rpc_table_42318.txt:114`). The standalone dispatch thunk that
  pushes the name onto the wire is `sub_140FA4D40`
  (`docs/ida-dumps/Other Client Finding.txt:371-376`).

Semantically (stock UE5): `APlayerController::ClientSetBlockOnAsyncLoading()` sets
`bShouldFlushAsyncLoadingOnBunch` on the client's net connection, so the **next**
bunch(es) that trigger async loads (here: the appearance OnRep) **flush async
loading to completion before the packet is fully processed**. That is exactly the
"lobby-side asset-registry pre-warm" the spec describes empirically: it converts
the racy async appearance load into a synchronous, completed one, so
`PostAssetsReadyForInitAppearance` has fired and the subobject is valid before
`AcknowledgePossession` is evaluated.

**[INFERRED]** that this specific RPC (vs. some other flush/streaming RPC) is what
the real server uses to guard the appearance path. The inference is strong because
(1) it is the **only** engine primitive whose sole job is "block the client on
async loads," (2) it is **co-located with `ClientRestart`** — the very RPC whose
`AcknowledgePossession` the race kills — and (3) related streaming/flush RPCs
(`ClientFlushLevelStreaming` #21, `ClientForceGarbageCollection` #22,
`ClientPrestreamTextures` #33) exist in the same table and could be secondary
participants. Validation requires a live capture (see §pcaps).

> Note on the codebase's existing `ClientInitializeCharacter()` (mechanism 1 in
> the spec): it remains complementary, not a substitute. It drives the client's
> local `SetRace`/`SetGender` → `RaceGenderAppearanceId`
> (`world_bootstrap_emitter.cpp:257-285`) so the **race/gender base mesh** record
> can be looked up. `ClientSetBlockOnAsyncLoading` is the orthogonal guard that
> makes the **cosmetic-GUID** loads safe. Both belong in the chain.

---

## (b) Wire layout

### b.1 `ClientSetBlockOnAsyncLoading` — the pre-warm RPC

**[CONFIRMED] (param-less)** / **[INFERRED] (handle/index on this connection).**

It is an ordinary UE5 **reliable RPC bunch on the PlayerController channel** — the
same framing the codebase already uses for `ClientInitializeCharacter()`
(`world_bootstrap_emitter.cpp:277-281`, via `host_.emit_client_initialize_character`)
and for the `ClientRestart`/PC.Pawn property updates. The function carries **no
parameters**, so the payload after the function selector is empty:

```
[ PC channel bunch header (reliable) ]
[ function reference / RPC selector ]      ← FieldExport or cached field handle
                                             for "ClientSetBlockOnAsyncLoading"
[ 0 payload bits ]                          ← ProcessEvent(Func, nullptr)
```

- The **RPC selector** is the only variable. On AoC's `AAoCPlayerController` it is
  index **40** in the BP/RPC FunctionLinks dispatch table
  (`RE-AOC-CLASSES.md:213`). Whether the wire writes that index directly, a
  RepLayout command handle, or a FieldExport-by-name is the same open question the
  codebase already faces for `ClientInitializeCharacter` (handle `142±10`,
  `game_server.h:2308-2310`) — i.e. it should be a **probe-overridable handle**,
  not a hard-coded constant. **[INFERRED]**
- Because the payload is empty, there is **no struct/FName/FGuid encoding to get
  wrong** — this is the key reason the mechanism is low-risk relative to shipping
  records. **[CONFIRMED — function takes no params.]**

### b.2 What is explicitly NOT on the wire

**[CONFIRMED]** No `FDesignDataObjectId` records, no `FAppearanceId` arrays, no
design-data table is serialized as a preload. The `Guid`/`TypeId`/`Name` triples
(`DesignDataPlugin_structs.hpp:183-191`) live **client-side**; the server only ever
sends the **lookup keys** inside the existing appearance struct
(`FCharacterCustomizationSaveData` int64 fields + `AppearanceIDs` +
`SharedAppearanceInfoId`). The pre-warm adds **no new data payload** — only the
blocking-control RPC.

### b.3 Corroboration of the appearance struct field order (bonus)

While confirming the above, the IDA field-name table for
`FCharacterCustomizationSaveData` was located at `docs/ida-dumps/dd.txt:1-39`. It
independently lists the wire field order ending in `… RacialHorns,
RacialHornsLength, NailColor, NailOpacity, DecalData, DecalBlendGroups,
bIsHelmetVisible, bIsCapeVisible` — **directly corroborating** the §5.1 struct
layout in `appearance-repindices.md` (and the serializer-bug finding that the four
trailing fields are real). **[CONFIRMED]** This is useful for the safe-tier
serializer fix even independent of the preload work.

### b.4 Confidence on the wire format

- **CONFIRMED:** the RPC exists, is reliable/client/parameterless, and is bound in
  the AoC client's PC dispatch table next to `ClientRestart`.
- **INFERRED / needs a capture:** (1) the exact selector encoding/handle for this
  RPC on this connection, and (2) that this RPC (and not, or in addition to,
  `ClientFlushLevelStreaming` / `ClientForceGarbageCollection` /
  `ClientPrestreamTextures`) is what the real server emits in the appearance
  pre-warm window.

---

## (c) Emitter integration point

### c.1 Where it fires

A new **`AppearanceAssetPreloadEmitter`** (or, given the payload-less shape, a host
helper `host_.emit_client_set_block_on_async_loading(...)` mirroring
`emit_client_initialize_character`) must fire **before** the appearance bunch so the
client is in "block on async loading" mode when `OnRep_CharacterCustomization`
arrives.

**Integration point:** `src/net/world_bootstrap_emitter.cpp`, **immediately before
line 212** (the `AppearanceEmitter app(...)` construction / `emit_default_seed`
call). This is exactly the "before the appearance call (~line 212)" slot the task
specifies, and matches `spec-appearance.md` T7 ("new `DesignDataPreloadEmitter`
before `appearance_emitter.cpp` call at `world_bootstrap_emitter.cpp:212`").

```
   world_bootstrap_emitter.cpp:201-216  (current)
     ...
208    // ... infrastructure to send real appearance data ...
211    // Failure here is non-fatal — possession is already complete.
   >>> NEW: emit ClientSetBlockOnAsyncLoading() here (probe-gated, default off) <<<
212    AppearanceEmitter app(host_, client_key_);
213    if (!app.emit_default_seed(addr)) { ... }
```

Ordering rationale (stock UE5 semantics): `ClientSetBlockOnAsyncLoading` arms the
connection's async-load-flush flag; the **subsequent** appearance bunch's OnRep then
runs its async loads to completion synchronously before the packet finishes
processing — so the flag must be set **first**. **[INFERRED]**

### c.2 What it must contain

- A single reliable PC-channel RPC bunch invoking
  `ClientSetBlockOnAsyncLoading` with **empty payload**
  (`Engine_functions.cpp:28391-28404`).
- A **probe-overridable RPC handle** (default = derived index 40 /
  `RE-AOC-CLASSES.md:213`), e.g. `probe_appearance_preload_handle.txt`, following
  the existing `probe_cic_handle.txt` pattern
  (`world_bootstrap_emitter.cpp:266-267`).
- A **probe gate** `probe_appearance_preload.txt` (default **0 / off**) so it ships
  only when intentionally testing the real-ID path. **[INFERRED]**

### c.3 Coupling to `strip_assets`

This emitter is the **precondition** for flipping
`probe_appearance_strip_assets.txt → 0` (`appearance_emitter.cpp:309`). Recommended
enablement order for the stretch test:
1. Land the safe-tier serializer fix (`spec-appearance.md` §4) — independent.
2. Add this emitter, gated **off**.
3. Enable it (`probe_appearance_preload.txt=1`) **and** keep `strip_assets=1`
   first — confirm it is a clean no-op for possession (regression guard).
4. Only then flip `strip_assets=0` and confirm V9 (real cosmetics render **and**
   possession survives, `spec-appearance.md` §10.4). Do **not** flip
   `strip_assets=0` while this emitter is off — that is the **[CONFIRMED]**
   possession-killing path.

### c.4 Fallback if blocking alone is insufficient

If a live test shows `ClientSetBlockOnAsyncLoading` is necessary but not sufficient,
the same emitter slot (`:211`) is where to add a secondary flush —
`ClientFlushLevelStreaming` (#21, VA `0x1443f9410`, `RE-AOC-CLASSES.md:194`) and/or
`ClientPrestreamTextures` (#33) — using the same param-less / handle-probe pattern.
Both are reliable client RPCs in the same dispatch table. **[INFERRED]**

---

## Useful pcaps for diffing the preload (live validation)

**Status: no pcaps are present in this checkout.** The `archive/misc/PCAPRepo-main/`
path named in the task **does not exist**; `archive/` is empty; `dist/Release/`
contains only the 32 build artifacts (binaries/DLLs/tests), **no `PCAPRepo-main/`
and no `.pcap`/`.pcapng` files**. The repo's pcap library is referenced by docs but
not committed here.

Captures that the docs reference and that **would** be the right diff candidates if
re-obtained (paths are as documented, relative to `dist/Release/`):

| Documented path / name | Why useful for the preload | Source doc |
|---|---|---|
| `dist/Release/PCAPRepo-main/character/aoc_ranger_respawn_home_point_j_20260205_230233.pcap` (3.4 MB, 4,170 pkts, 1,950 S→C) | **Best candidate.** A character **respawn** carries a full possession + appearance sequence on an already-created character → would contain the `ClientRestart` / appearance-OnRep / async-load window where any pre-warm RPC must appear. Diff the S→C bunches just before the `CharacterAppearanceComponent` property update for a parameter-less PC-channel reliable RPC (the `ClientSetBlockOnAsyncLoading` selector). | `docs/pcap-ranger-analysis.md:5`, `docs/path-to-multiplayer.md:19` |
| `dist/Release/ranger_respawn_game_packets.bin` (200 S→C pkts, ~26 KB, extracted from the above) | Pre-extracted S→C subset of the same respawn — smaller search space for the RPC. | `docs/pcap-ranger-analysis.md:29`, `docs/LIVE-SERVER-STATE-ARCHITECTURE.md:278` |
| `PCAPRepo-main/.../aoc_tank_east_20260203_190549.pcap`, `aoc_tank_west_*.pcap` | Same char, different zone — login/travel into world also crosses the possession+appearance+async-load boundary; useful as a second sample of the pre-warm window. | `docs/path-to-multiplayer.md:20,107-108` |
| `PCAPRepo-main/.../aoc_*_walking_running.pcap` (bard/rogue/tank) | Same action, different class/appearance — good for isolating which bunches are appearance/asset-driven vs. movement. | `docs/path-to-multiplayer.md:22-23` |
| `dist/Release/replay_data.bin` (bootstrap, ~400 pkts) | The project's own known-good bootstrap. Does **not** contain a real appearance sequence (our path strips assets), so it is a **negative** control, not a source of the preload RPC. | `docs/path-to-multiplayer.md:14` |

**Tooling already present** to process a re-obtained pcap:
`src/protocol/tools/pcap_to_jsonl.py` (decodes UDP bunches to JSONL, the same
format as `docs/bootstrap-2000-catalog.jsonl`). To observe the preload: convert the
ranger-respawn pcap, then scan S→C bunches on the PlayerController channel in the
window between the `ClientRestart` bunch and the `CharacterAppearanceComponent`
(`sub_guid = pawn + 8`) property update for a **reliable, zero-payload** RPC — that
is the `ClientSetBlockOnAsyncLoading` signature.

---

## CONFIRMED vs INFERRED rollup

**CONFIRMED:**
- No design-data record-shipping RPC on `IntrepidNetUtilitySubsystem`
  (`IntrepidNet_classes.hpp:486-517`); DesignData managers are `UObject`
  subsystems, not replicated actors (`DesignDataPlugin_classes.hpp:94,124`;
  `GameSystemsPlugin_classes.hpp:17478,17498`).
- Cosmetic GUIDs resolve **locally** (`AsyncLoadRecordById`,
  `Logs.txt:88394`; `AssetLoader`, `classes.hpp:17277`;
  `AsyncInitAppearances`/`PendingLoadAppearances`, `new 4.txt:95961`,
  `Logs.txt:69450`) → the hazard is an async-load **race**.
- `PostAssetsReadyForInitAppearance` is an internal component callback (the gate),
  not a `Net` RPC (`classes.hpp:17307`; `GObjects-Dump.txt:32063`).
- `ClientSetBlockOnAsyncLoading` is a reliable, param-less `NetClient` RPC
  (`Engine_functions.cpp:28388-28404`; `Engine_classes.hpp:8347`), bound in the
  AoC PC dispatch table at index 40 next to `ClientRestart`
  (`RE-AOC-CLASSES.md:210-213`; `client_restart_param.txt:24-31,43-50`).
- The appearance struct trailing-field order is corroborated by `dd.txt:1-39`.
- No pcaps exist in this checkout; documented candidate paths recorded above.

**INFERRED (needs a live capture to finalize):**
- That `ClientSetBlockOnAsyncLoading` (vs. / in addition to
  `ClientFlushLevelStreaming` etc.) is the specific RPC the real server emits in
  the appearance pre-warm window.
- The exact selector/handle encoding for this RPC on the live connection
  (probe-overridable like `ClientInitializeCharacter`).
- That setting the block flag *before* the appearance bunch is sufficient to keep
  `AcknowledgePossession` alive with real asset IDs.

**Does this require deep Ghidra on the client binary to finalize?**
**No** for the wire format itself: the RPC is parameter-less, so there is no struct
to reverse — the only unknown is the dispatch handle, which is already probe-driven
in this codebase and best pinned from a **live pcap diff**, not from static
disassembly. A single ranger-respawn pcap (above) resolves both open INFERRED
points. Deeper IDA/Ghidra would only be needed if blocking proves insufficient and
the true mechanism turns out to be a custom AoC flush path rather than the stock
engine RPC.
