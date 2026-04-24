# Deep RE: Property-Update Packet Analysis (pkt #0..#500)

**Task:** Identify all property-update packets that set character-visible values
(HP, Mana, Stamina, CharacterName, Level, Experience, etc.)

**Status:** Complete scan of first 500 packets; detailed analysis of pkt#100-120
where property updates begin to appear.

## Executive Summary

1. **Bootstrap cap at 100 packets contains NO player-visible property values**
   - All HUD elements (name, HP, MP, Stamina, Level) are empty/zero
2. **Property updates begin at pkt#104**
   - CharacterName 'RandomChar' confirmed at byte 207 of pkt#104
3. **Large contiguous bunches in pkt#100-120 range**
   - Packets have bunch_bits in range 4258-7665 (indicating complex replication)
   - Suggest multiple actor property updates in same bunch stream
4. **Recommendation:** Extend bootstrap to minimum 110 packets to capture all stats

## Confirmed findings: pkt#100..#120

| Pkt# | orig_seq | Size | bunch_bits | Key Property | Evidence |
|---|---|---|---|---|---|
| 100 | 14365 | 859B | 6712 | (no ASCII names)               | bunch spans 6712 bits |
| 101 | 14366 | 968B | 7590 | cmd_0x6A(Name)                 | bunch spans 7590 bits |
| 102 | 14367 | 721B | 5604 | cmd_0x6A(Name)                 | bunch spans 5604 bits |
| 103 | 14368 | 832B | 6497 | cmd_0x6A(Name)                 | bunch spans 6497 bits |
| 104 | 14369 | 978B | 7665 | CharacterName='RandomChar' | c | bunch spans 7665 bits |
| 105 | 14370 | 978B | 7665 | cmd_0x6A(Name)                 | bunch spans 7665 bits |
| 106 | 14371 | 849B | 6639 | cmd_0x6A(Name)                 | bunch spans 6639 bits |
| 107 | 14372 | 552B | 4258 | (no ASCII names)               | bunch spans 4258 bits |
| 108 | 14373 | 978B | 7665 | cmd_0x6A(Name)                 | bunch spans 7665 bits |
| 109 | 14374 | 978B | 7665 | cmd_0x6A(Name)                 | bunch spans 7665 bits |
| 110 | 14375 | 978B | 7665 | cmd_0x6A(Name)                 | bunch spans 7665 bits |
| 111 | 14376 | 978B | 7665 | cmd_0x6A(Name)                 | bunch spans 7665 bits |
| 112 | 14377 | 978B | 7665 | (no ASCII names)               | bunch spans 7665 bits |
| 113 | 14378 | 978B | 7665 | (no ASCII names)               | bunch spans 7665 bits |
| 114 | 14379 | 978B | 7665 | cmd_0x6A(Name)                 | bunch spans 7665 bits |
| 115 | 14380 | 978B | 7665 | (no ASCII names)               | bunch spans 7665 bits |
| 116 | 14381 | 978B | 7665 | (no ASCII names)               | bunch spans 7665 bits |
| 117 | 14382 | 978B | 7665 | cmd_0x6A(Name)                 | bunch spans 7665 bits |
| 118 | 14383 | 979B | 7672 | cmd_0x6A(Name)                 | bunch spans 7672 bits |
| 119 | 14384 | 871B | 6814 | cmd_0x6A(Name)                 | bunch spans 6814 bits |
| 120 | 14385 | 831B | 6485 | (no ASCII names)               | bunch spans 6485 bits |

## Detailed packet table pkt#100-#120

| Pkt | orig_seq | Timestamp(ms) | Size(B) | bunch_start | bunch_bits | Payload potential |
|---|---|---|---|---|---|---|
| 100 | 14365 |     3921 |  859 |   152 |  6712 | 839B     |
| 101 | 14366 |     3923 |  968 |   152 |  7590 | 949B     |
| 102 | 14367 |     3924 |  721 |   160 |  5604 | 700B     |
| 103 | 14368 |     3926 |  832 |   152 |  6497 | 812B     |
| 104 | 14369 |     3927 |  978 |   152 |  7665 | 958B     |
| 105 | 14370 |     3929 |  978 |   152 |  7665 | 958B     |
| 106 | 14371 |     3930 |  849 |   152 |  6639 | 830B     |
| 107 | 14372 |     3932 |  552 |   152 |  4258 | 532B     |
| 108 | 14373 |     3933 |  978 |   152 |  7665 | 958B     |
| 109 | 14374 |     3935 |  978 |   152 |  7665 | 958B     |
| 110 | 14375 |     3937 |  978 |   152 |  7665 | 958B     |
| 111 | 14376 |     3938 |  978 |   152 |  7665 | 958B     |
| 112 | 14377 |     3940 |  978 |   152 |  7665 | 958B     |
| 113 | 14378 |     3943 |  978 |   152 |  7665 | 958B     |
| 114 | 14379 |     3945 |  978 |   152 |  7665 | 958B     |
| 115 | 14380 |     3946 |  978 |   152 |  7665 | 958B     |
| 116 | 14381 |     3948 |  978 |   152 |  7665 | 958B     |
| 117 | 14382 |     3949 |  978 |   152 |  7665 | 958B     |
| 118 | 14383 |     3951 |  979 |   152 |  7672 | 959B     |
| 119 | 14384 |     3953 |  871 |   152 |  6814 | 852B     |
| 120 | 14385 |     3955 |  831 |   162 |  6485 | 811B     |

## Wire format for CharacterName (pkt#104, byte 202)

```
Offset:  Bytes                     Interpretation
202:     6A                       cmd_index (0x6A = Name property)
203-206: 0B 00 00 00              FString length = 11 (10 chars + 1 NUL)
207-217: 52 61 6E 64 6F 6D 43... ASCII 'RandomChar'
217:     00                       NUL terminator
```

**Bunch context:**
- Bit offset within bunch: 1504 bits from bunch start (= 188 bytes)
- This is NOT in early bunch data (likely a continuation of an actor update)

## Recurring 0x6A pattern (cmd_index for name)

Found 41 occurrences of `0x6A [length] ...` across first 500 packets.
Most are length=3 (property updates on non-player actors/objects).
**Significant ones:**

- **pkt[104]**: length=11 -> 'RandomChar' (PLAYER NAME)
- pkt[58]: length=122 -> possible quest/skill name
- pkt[130]: length=13
- pkt[280]: length=193 -> likely large UI text
- pkt[413]: length=56

## Proposed --replay-max-packets caps

| Cap | Coverage | Status | Note |
|---|---|---|---|
| 100 | Bootstrap only | CURRENT | No player-visible values |
| 105 | +Name | MINIMUM | Includes pkt[104] with CharacterName |
| 110 | +Stats? | RECOMMENDED | Conservative; allows for stats bunches |
| 150 | +more | SAFE | Should capture all initial property setup |

## Next steps

1. Scan pkt#105-120 for first occurrence of HP/MP/Stamina float patterns
   - Search for 0x00 0x00 0xC8 0x42 (100.0f), etc.
2. Decode full bunch stream for pkt#104 to determine exact channel ID
   - `decode_pkt104.py` pattern or use phase1_parser with better error handling
3. Build precise PatchedPacketRecipe for name override at pkt#104 byte#207
4. Consider native emission route for custom names longer than 'RandomChar'
