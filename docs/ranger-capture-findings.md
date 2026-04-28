# Ranger Respawn PCAP — Key Findings

**Source:** `dist/Release/PCAPRepo-main/character/aoc_ranger_respawn_home_point_j_20260205_230233.pcap`
**Extracted to:** `dist/Release/ranger_respawn_game_packets.bin` (200 S>C packets, 107KB)
**Analysis date:** 2026-04-24

## Is it game traffic?

**YES.** 4,157 packets with UE5 magic bytes `96 76 0c 50`. Source port 7372 (Ranger's server instance).

## Why it's less useful than hoped

This is a **RESPAWN** capture, not a login. The character was already in-world. Meaning:
- **No `cmd=0x6A` Name-update bunches** in the first 200 S>C packets — the client already has the name cached from its original login
- **No initial-stats bundle** — HP/MP/Stamina were already established pre-capture
- No class/race/gender announcements — those were sent at initial login, not respawn

## What it DOES give us

### 1. Character customization wire format (★ useful)

Bytes around offset 52622-55000 contain a sequence of **named morph target** FStrings:

```
offset  length  FString                preamble
52622   14      'Temples_Sharp'        00 80 61 c4 68 1f
52846   14      'Jaw_Sharpness'        00 00 f2 2d 89 1f
53030   11      'Snear_Left'           00 80 70 3d 8a 1f
53266   15      'Lips_Top_Shape'       00 00 a8 ac 8c 1f
53786   13      'Nose_Forward'         00 80 38 08 36 1f
54009   15      'Nose_Tip_Bulge'       00 80 c6 36 a4 1f
54208   16      'Ears_Tip_Pointy'      00 00 00 00 c0 1f
54738    9      'Philtrum'             00 00 b8 1e 85 1f
54927   18      'Nose_Broken_Right'    00 00 00 00 00 00
```

**Implication:** The `CharacterCustomization` ByteArray on the Pawn's `CharacterInformationComponent` is NOT the 16-float array we assumed earlier — it's a sparse list of `[float_value][FString morph_name]` entries. Each face feature has a NAMED target.

**Each entry's shape** (inferred from preamble pattern `XX YY ZZ WW AA 1f`):
- 4 bytes: float value (IEEE 754 LE)
- 2 bytes: ??? (separator / count?)
- 4 bytes: FString length (LE)
- N bytes: ASCII name
- 1 byte: NUL

So `CharacterCustomization` is self-describing; a custom character's appearance can be sent by constructing this exact sequence with different morph values.

### 2. Static markers shared across sessions

Both captures (Fighter + Ranger) contain these byte-identical static strings:
- `Verra_World_Master` — confirms the map is universal
- `PersistentLevel` — UE5 standard

These can be hardcoded in `NetGUIDAllocator` knowing they map to the same NetGUIDs in every session.

### 3. Packet rate & pacing

Ranger respawn: ~200 S>C packets in the first ~second, then steady state at ~10Hz. Matches UE5's default NetUpdateFrequency.

## What the ranger DOES NOT give us

- **Different character name** — can't confirm `cmd=0x6A` is universal since name wasn't broadcast
- **Different class_id** — for the same reason
- **Initial spawn flow** — would need a login pcap for that

## Next-capture wishlist

To complete the cross-session diff, we need **a login-phase pcap from a DIFFERENT character/class**. Ideally:
- Bard, Ranger, or Tank (any non-Fighter)
- Captured from the login click onwards (not mid-session)
- Full 30-second clean capture after "Enter World"

Without one: we're limited to the Fighter replay for all spawn-phase property layouts.

## Actionable takeaways

1. **The HUD-empty problem isn't solved by adding a ranger diff** — there's no Name update in the ranger's first 200 packets to compare against. The Fighter pkt[104] remains our only reference.

2. **Increase `--replay-max-packets` 100→150** in `launch_all_hybrid.bat` — this captures the Fighter's pkt[104] Name update + the nearby stat updates. Single biggest lever right now.

3. **Morph-target wire format** discovered here informs future `emit_character_customization()` work — not needed for HUD-values-appear, but critical for "custom character appearance" later.

4. **The ranger respawn itself** might be a useful fixture for building a native `emit_respawn()` down the road — study the SEQUENCE of packets when a character respawns, since that's the "re-hydrate after death" code path.
