# CharacterName wire location — discovered

**Source:** `find_character_name_in_replay.py` run on `replay_data.bin`
**Date:** 2026-04-24

## Finding

The captured character name is **"RandomChar"** (10 chars), NOT "Hatemost" as originally assumed in earlier docs.

## Location

| Parameter | Value |
|---|---|
| Replay packet index | **104** (zero-based) |
| orig_seq | 14369 |
| Packet raw size | 978 B |
| bunch_start_bit | 152 |
| bunch_bits | 7665 |
| Byte offset of 'R' in raw packet | **207** |
| Bit offset of 'R' in raw packet | 1656 |
| Bit offset of 'R' within bunch stream | **1504** (= 1656 − 152) |
| Bit offset of FString length prefix within bunch stream | **1472** (= 1504 − 32) |

## Wire format

Bytes surrounding the name:

```
offset  203  204  205  206  207  208  209  210  211  212  213  214  215  216  217
value   [6a] [0b] [00] [00] [00] [52] [61] [6e] [64] [6f] [6d] [43] [68] [61] [72] [00]
                                  R    a    n    d    o    m    C    h    a    r   \0
         ^    ^─────────────────^  ^──────────────────────────────────────────────^  ^
         │    │                    │                                                 │
     cmd_index  FString.Length     ASCII bytes                                      NUL
     (var int,  (int32 LE = 11 =                                                   (part of
      1 byte)   10 chars + NUL)                                                    FString body)
```

**Format**: `[var_int cmd_index=0x6A][int32 LE length (incl. NUL)][ASCII][NUL]`

## Channel

Running `decode_pkt78_v2.py` equivalent on pkt[104] returned:
- Bunch #0: ch=8833 bdb=818 partial=1 — parser drift (ch=8833 is nonsense; partial continuation bunches confuse the parser)
- 22 more bunches with bdb=0 (parser consuming trailing padding)

**Likely actual channel**: the bunch is a CONTINUATION of an earlier actor's partial stream. Based on the byte offset (1504 bits into the bunch, well past any channel-0 NMT content), and the cmd_index=0x6A matching the `add_name_update_v2` pattern in `pc_emitter.cpp`, this is probably a property update on either:
- The Pawn actor's CharacterInformationComponent subobject (per `docs/re-apawn-playerpawn-c.md`), channel ≈ 14 or 114
- Or a dedicated subobject channel derived from the Pawn

To definitively determine the channel, decode the FULL partial-continuation stream from pkt#78 onwards until the Name update bunch is found.

## Implication for our emission

**The initial 100-packet bootstrap does NOT contain CharacterName.** The captured character spawns without a name; the client renders a default or empty string until pkt#104 arrives ~7 seconds later and sets "RandomChar".

This means:
- **For hybrid mode (current)**: the client sees "RandomChar" (captured name).
- **For custom name injection**: we need to EITHER replay pkt[104] with our name substituted OR emit our own Name update after the bootstrap completes.

## Why our prior native Name injection didn't work

`pc_emitter::emit_properties()` was emitting on ch=3 (PC's channel) with cmd=0x6A. But CharacterName lives on the Pawn's CharacterInformationComponent, NOT on the PC. Sending a cmd=0x6A update on ch=3 either silently fails (no such property on PC) or targets a different property that happens to have that cmd_index on the PC.

**To get custom name working:**
1. Identify the exact channel pkt[104]'s bunch is on (requires better partial-bunch decoder OR reading pkt[104] surrounding packets to find the OPEN bunch that declared the channel).
2. Build a property update on that channel with cmd=0x6A + our custom name's FString.
3. Use chSeq = (previous reliable chSeq on that channel) + 1.

## Variable-length name constraint

Captured FString is 15 bytes on wire (4 len + 10 ASCII + 1 NUL). For a PatchedPacketRecipe to work without re-fragmenting the packet, the replacement name must produce the **same byte count**:

| Custom name | Length | On-wire bytes | Works as patch? |
|---|---|---|---|
| "RandomCha" | 9 | 14 | ❌ 1 byte short |
| "RandomChar" | 10 | 15 | ✓ same as captured |
| "MyHero" | 6 | 11 | ❌ 4 bytes short |
| "MyHeroooooo" | 11 | 16 | ❌ 1 byte over |
| "MyHeroooo!" | 10 | 15 | ✓ padded to captured length |

For M2 (PatchedRecipe): enforce `name.size() == captured_name_size` at login time. For longer names, emit a separate Name-update bunch AFTER the bootstrap completes (NativeRecipe route).

## Next steps

1. Write `decode_pkt104.py` — fully parse pkt[104] including partial-bunch reassembly to identify channel + exact cmd_index encoding.
2. Build `CharacterNamePatchRecipe` that targets pkt[104] with `bit_offset=1472, bit_width=120` (= 15 bytes × 8).
3. Or, more robust: add a POST-bootstrap `emit_character_name_update()` that natively constructs a Name update bunch on the correct channel + chSeq.
