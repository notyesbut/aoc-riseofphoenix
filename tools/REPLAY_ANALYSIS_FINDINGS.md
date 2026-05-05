# Replay Mining — Findings (2026-05-05)

## TL;DR

The replay mining session produced four critical insights that **fundamentally change** our understanding of the visible-mesh problem:

1. **The replay has ZERO data-table preload bunches.** Across 29010 packets, there are no `DT_Hair`, `DT_Race`, `DT_Skin`, `AppearanceData` or any character-data-table asset paths. The client loads these tables from **its own cooked content** — not from the server.

2. **The captured CharacterAppearance content block is only 126 bits / 16 bytes.** This is *way* too small to be a full `FCharacterCustomizationSaveData` struct (~1672 bits). The captured server is sending a **minimal property update** — most likely just `RaceGenderAppearanceId` (Int64 packed FName) + `bForceHideHeldItems`.

3. **The captured appearance subobject uses sub_guid = 58.** This is a tiny number (vs. our minted 16777226). It's almost certainly a **stably-named subobject reference** that the client resolves by name on the actor's CDO — not a globally-allocated PackageMap NetGUID.

4. **PlayerPawnSplicer (built but never tested) has a mode 2 "surgical" splice** that rewrites the captured Pawn NetGUID 54 → 16777218 so the captured 8 subobjects bind to OUR possessed pawn. This was set up in PM109 and is sitting in the codebase ready to test.

## What we mined from the replay

| Tool | Output | What it shows |
|---|---|---|
| `replay_decoder.py` | `replay_decoded.txt` (13.9 MB) | bunch-by-bunch hex dump of every packet |
| `replay_full_analyze.py` | `replay_full_analysis.txt`, `replay_asset_paths.txt` | bunch kind histogram, channel openings, all asset paths grouped by category |
| `replay_netguid_map.py` | `replay_netguid_map.txt` | best-effort NetGUID → asset-path map |

### Bunch kind histogram (29010 packets)

```
  ActorUpdate        50346
  GUIDExport         29943
  ActorClose         17714
  PartialCont         8069
  ActorOpen           3443
  Control             1100
  ActorReliable        917
```

### Asset paths found (74 unique)

- **CharacterAppearance/Customization: 0** ← critical
- **Hair/Eye/Skin/Race assets: 9** (NPC paths only — no DataTables)
- **DataTable assets: 0** ← critical (confirms client-cooked DTs)
- **PlayerPawn / Character classes: 1** (`/Game/ThirdPersonCPP/Blueprints/PlayerPawn` at pkt#78 ch=85)
- **Level / World streaming: 12** (Verra_World_Master + `_Generated_/...` runtime cells)
- **Other: 52** (NPC archetypes, montages, FX, BP classes)

## Why our previous attempts failed

| Attempt | Result | Why |
|---|---|---|
| Mode 0 (empty V3 wrap) | possession ok, no mesh | `serialize_int(handle=0, max=4)` writes `0b00` = end-marker → client reads "no properties to update" → defaults stay → no mesh |
| Mode 1 (single bForceHide bit) | possession ok, no mesh | same handle-0 issue + bForceHide is bool not asset trigger |
| Mode 2 (full 209-byte struct) | regressions / black screen | sending a struct with handle=2 or 3 makes client try to apply it → `OnRep_CharacterCustomization` fires → FindRow on **0-valued asset IDs** returns null → mesh assembly null-derefs |
| Mode 3 (captured 16 bytes) | black screen | bytes contain references to **captured-session-only NetGUIDs** (e.g. value `0x1E` = 30) → those NetGUIDs aren't in our session's PackageMap → client null-derefs |
| Strip assets (mode 2 with zeros) | possession lost | Even sending `RaceEnum=0` triggers a racial mesh load that fails the same way |

The common thread: **any non-trivial CharacterCustomization update fails because either (a) its asset IDs reference NetGUIDs we haven't registered, or (b) its zero values aren't valid keys in the client's data tables.**

## The path that should work — mode 2 SURGICAL splice (untested)

`PlayerPawnSplicer::emit_captured_stream` mode 2:

1. Takes the captured pkt#78 (5160 bits) verbatim
2. Bit-surgically rewrites the captured Pawn NetGUID `54` → our minted `16777218`
3. Adjusts `BunchDataBits` from 2963 → 2987 to compensate the +24-bit shift
4. Sends 5184 bits as a single splice

**What this gives us:**
- Captured stream's 8 subobjects (BaseCharacterInfo through CharacterAppearance) bind to **our** pawn
- The captured 126-bit appearance content block (with sub_guid=58) is included
- **The captured server's own working appearance bytes ride to our session**
- If the client's cooked DataTables contain the captured ranger's IDs (which they should, since the captured ranger is from the same client install), the mesh assembles

**What's untested:**
- Whether the client tolerates the captured-session's NetGUID references in subobject content blocks when the actor itself is at our minted NetGUID
- Whether having BOTH our `PlayerPawnEmitter` AND the splicer fire creates a "double pawn" issue
- Whether PM117's subobject_exports interferes with the splice

## How to run the experiment

The infrastructure is all built. Probes:

```
probe_pkt78_splice.txt          = 2    (NEW — surgical splice)
probe_subobject_exports.txt     = 0    (DISABLE — splice provides its own subobjects)
probe_pd2_appearance.txt        = 0    (DISABLE — splice provides appearance)
probe_appearance_emit.txt       = 0    (DISABLE — splice provides everything)
```

Then launch and check:
- Does possession still land (`🎉 ServerAcknowledgePossession` in log)?
- Does the visible mesh appear?
- Does the connection hold?

If yes → we have visible mesh, project advances dramatically.
If no → we have a clear next experiment (which probe combination causes failure).

## Why this is different from previous tests

Every previous test used **our PlayerPawnEmitter** producing **our synthetic content blocks**. The splicer instead ships the **captured server's actual bytes** — bytes we KNOW make a mesh appear (RandomChar renders fully when the launcher replays this exact stream).

The only modification is the Pawn NetGUID, which is a **single 24-bit shift** offline-applied to the byte stream. Everything else is byte-identical to the working captured stream.

## Architecture-level conclusion

We've been trying to **synthesize** appearance updates because we assumed that's how the server pushes character data to the client. The replay reveals that **AOC's server pushes very little appearance data** — most of the rendering happens client-side from cooked DataTables, triggered by tiny RPC-like nudges (the 126-bit content block). The path of least resistance to a visible mesh is to **forward those tiny working nudges** rather than synthesize our own — at least until we understand the AOC client's lookup pipeline well enough to substitute.

Once mode 2 surgical works (or doesn't), we have either:
- A **working visible-mesh path** — even if it only shows the captured ranger's appearance for every player
- A **clear failure mode** that tells us exactly which layer is incompatible (NetGUID-cross-session, subobject-tree-binding, etc.)
