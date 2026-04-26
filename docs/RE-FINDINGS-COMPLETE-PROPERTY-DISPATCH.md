# Complete Property-Dispatch RE — 4-function analysis (2026-04-26)

All four critical functions dumped and analyzed. This completes the
cmd_index decode chain and unlocks anchored-pattern patching.

Analyzed:
1. `sub_143F2DC60` = `ReadPropertyChangeHeader`
2. `sub_143F33E80` = per-property RepLayout dispatch
3. `sub_1444E4A40` = batch RepLayout receive (URepLayout::ReceiveProperties entry)
4. `sub_1444E4620` = custom-delta (FastArray) handle reader

---

## THE WIRE FORMAT — fully decoded

### One property change entry (inside a content block's inner bunch)

```
═══════════════════════════════════════════════════════════════
Path B: Legacy RepLayout handle (most common)
═══════════════════════════════════════════════════════════════
  [SerializeInt(max = NumProperties)]    cmd_handle
    ← variable bit width = ceil(log2(NumProperties))
    ← for a class with 64 properties = 6 bits
    ← for a class with 256 properties = 8 bits
    ← for a class with 1024 properties = 10 bits

  [SerializeIntPacked]                    NumBits
    ← AoC-SIP variable 1-5 bytes
    ← typically 1 byte for < 128 bits

  [NumBits bits]                          property data
    ← the actual value bytes

═══════════════════════════════════════════════════════════════
Path A: New/delta mode (flag Driver[240] & 1)
═══════════════════════════════════════════════════════════════
  [SerializeInt(max = NumProperties)]    cmd_handle   ← same as above
  [SerializeIntPacked]                    NumBits
  [NumBits bits]                          property data

═══════════════════════════════════════════════════════════════
Custom delta (FastArray) via sub_1444E4620
═══════════════════════════════════════════════════════════════
  [1 bit]                                 has_guid_ref
  [SerializeIntPacked]                    handle (if MaxHandle > 1)
  ... then property's NetSerialize invokes (FastArray format)

═══════════════════════════════════════════════════════════════
Batch RepLayout (bHasRepLayout=true) via sub_1444E4A40
═══════════════════════════════════════════════════════════════
  [1 bit]                                 bHasUnmappedGuids
  [SerializeIntPacked]                    initial_cmd
  if bHasUnmappedGuids:
    [4 bytes]                             unmapped_guid_counter
  ... sub_1444E6570 loops remaining handles
```

---

## Critical vtable offsets (FArchive / FInBunch)

| Offset | Slot | Method | Reads |
|---|---|---|---|
| `+384` | 48 | `Serialize(void* buf, int64 n)` | N bytes byte-aligned |
| `+400` | 50 | `SerializeInt(uint32& value, uint32 max)` | `ceil(log2(max))` bits |
| `+408` | 51 | `SerializeIntPacked(uint32& value)` | 1-5 bytes AoC-SIP |

Confirmed empirically across all 4 functions.

---

## PropertyInfo struct layouts (reconstructed)

### ClassInfo (a4 in sub_143F2DC60)

| Offset | Type | Field |
|---|---|---|
| +24 | `PropertyInfo*` | PropertyArray (40-byte entries, indexed by handle) |
| +32 | `int32` | NumProperties |

### PropertyInfo (per-property entry, 40 bytes at ClassInfo[+24] + 40*handle)

Path A version (from sub_143F2DC60 line 99-166):

| Offset | Type | Field |
|---|---|---|
| +20 | `uint32` | property_key / name_hash (used for hash-map lookup at +50) |
| +24 | `FString` | property_name (displayed in logs) |
| +35 | `uint8` | bLoggedError (flagged after first error) |

### FastArray PropertyInfo (48 bytes — sub_1444E4620 line 81)

| Offset | Type | Field |
|---|---|---|
| +0..7 | `FString*` | property_name |
| +40 | `int32` | property_index (use for post-process, -1 = none) |
| +44 | `uint32` | flags (bit 3 = bIsDeltaProperty) |

### ClassInfo for FastArrays (a4 in sub_1444E4620)

| Offset | Type | Field |
|---|---|---|
| +48 | `uint32` | MaxHandle (if 1, skip handle read) |
| +64 | `uint16` | base_handle_offset |
| +112 | `TypeInfo*` | NetSerialize dispatch (vtable+88) |

---

## FRepPropertyChangeHeader — return struct layout

From `sub_143F2DC60` output (`*a6`), confirmed:

| Offset | Type | Field |
|---|---|---|
| +0 | `void*` | property_ptr \| (bit 0 = RepLayout marker) |
| +8 | `uint32` | property_index (cmd_handle) — ★ THE ANCHOR |
| +16 | `uint8` | error_flag (set on unknown handle) |

---

## How property values SHOW UP in the bit stream

For a class with ~200 replicated properties (e.g. `APlayerState`):
- `ceil(log2(200))` = **8 bits** per cmd_handle
- For Level (say handle 42): `00101010` LSB-first
- For Health (say handle 45): `00101101` LSB-first

Then NumBits = SIP (typically `80` = 1 byte for Level/Health since int32=32 bits, SIP-encoded as `20 00` = value 32).

Wait — 32 bits: SIP-encode 32 as:
- byte = ((32 & 0x7F) << 1) | 0 = 0x40 (no continuation)
- So 1 byte = 0x40

Then 32 bits of int32 data.

**Total per property:**
```
8 bits cmd_handle + 8 bits NumBits_SIP + 32 bits value = 48 bits = 6 bytes
```

Five properties in a row (Level, HP, HP_max, MP, MP_max) ≈ 30 bytes of byte-aligned content.

---

## What this means for anchored patching

### Approach 1: Empirical byte-pattern anchor (PRAGMATIC)

Since we know captured values are distinctive when seen TOGETHER (Level=1, HP=90, HP_max=90), we can search for the combined byte pattern WITHOUT knowing the cmd_handle.

Expected bytes near the stats block (pkt#104-ish):
```
... [cmd_byte] 20 00 01 00 00 00 [cmd_byte] 20 00 5A 00 00 00
    [cmd_byte] 20 00 5A 00 00 00 [cmd_byte] 20 00 5A 00 00 00 ...
```

Where `20 00` = SIP value 32 (NumBits for int32). The combined pattern
`01 00 00 00 ?? 40 5A 00 00 00 ?? 40 5A 00 00 00` is ~18 bytes and
should match ONE location only.

### Approach 2: Full RE of URepLayout::InitFromClass

More work, but gives definitive handle → property_name map:
- Dump `sub_144236550` (class RepLayout fetcher) and trace backward
- Eventually reach the RepLayout init code that builds the cmd table
- Extract the property ordering at class-register time

### Approach 3: Empirical byte-diff

Capture a second replay with different character stats (Level=2, HP=100).
Byte-diff the two. Bytes that differ = stat locations. Done.

---

## Additional sub-functions discovered (for future RE)

| EA | Likely role | Priority |
|---|---|---|
| `sub_1444E5420` | New-driver RepLayout receive (called when Driver flag set) | ★★ |
| `sub_1444E6570` | RepLayout handle iteration loop | ★★★ |
| `sub_1444E4D20` | `ReceiveProperty_BackwardsCompatible` (actual property read) | ★★★ |
| `sub_1444E29B0` | Post-receive FastArray hook | ★ |
| `sub_141741E70` | Handle → property lookup in RepLayout | ★★ |
| `sub_144236550` | `UNetDriver::GetObjectClassRep` (RepLayout by class) | ★ |
| `sub_144265650` | Something called only on new-driver path + reliability | ★ |
| `sub_143F24AD0` | `UActorChannel::GetCustomDeltaProperties` | — |
| `sub_143F435B0` | Post-property-received callback on channel | — |

---

## Log-string mapping (NEW strings found)

| Address | Function | Meaning (inferred) |
|---|---|---|
| `off_14A8A8A60` | sub_143F2DC60 | "ReadPropertyChangeHeader: null class for %s" |
| `off_14A8A8B08` | sub_143F2DC60 | "cmd read error (bunch IsError) for %s" |
| `off_14A8A8BC8` | sub_143F2DC60 | "cmd %d out of range for class %s" |
| `off_14A8A8CB0` | sub_143F2DC60 | "property at handle %d has no key for %s" |
| `off_14A8A8DC0` | sub_143F2DC60 | "property %s: handle not found in receive map" |
| `off_14A8A8EB0` | sub_143F2DC60 | "read error during legacy handle decode for %s" |
| `off_14A8A8F50` | sub_143F2DC60 | "handle %d exceeds range for %s" |
| `off_14A8A8FE8` | sub_143F2DC60 | "handle not in any range for %s" |
| `off_14A8A9088` | sub_143F2DC60 | "NumBits read error for property %s" |
| `off_14A8A9148` | sub_143F2DC60 | "property data init error for %s" |
| `off_14A8AA818` | sub_143F33E80 | "property not found in class rep for %s" |
| `off_14A8AA8B8` | sub_143F33E80 | "property missing replicate flag" |
| `off_14A8AA948` | sub_143F33E80 | "property read role mismatch" |
| `off_14A8AA00`* | sub_143F33E80 | "rewinding bunch due to ..." (reliability-related) |
| `off_14A8AAA50` | sub_143F33E80 | "invoking receive for property %s" (verbose) |
| `off_14A8AAAA0` | sub_143F33E80 | "failed to get class rep" |
| `off_14A8AAB40` | sub_143F33E80 | "bunch error after ReceiveProperty call" |
| `off_14A8AAC18` | sub_143F33E80 | "bunch not fully consumed after property read" |
| `off_14A8AAD58` | sub_143F33E80 | "netdriver rejected property (CanClientReceive=false)" |
| `off_14A8AACE0` | sub_143F33E80 | "NetMemory integrity violation after property" |
| `off_14AA7BFE0` | sub_1444E4A40 | "RepLayout receive had unmapped guids: %d" |
| `off_14AA7D4E0` | sub_1444E4620 | "custom delta handle %s out of range" |
| `off_14AA7D548` | sub_1444E4620 | "property %s missing delta flag" |
| `off_14AA7D5E8` | sub_1444E4620 | "bunch error after custom delta NetSerialize" |
| `off_14AA7D6F0` | sub_1444E4620 | "custom delta read did not consume all bits" |

These log strings can be cross-referenced to find sibling functions.

---

## CRITICAL FINDING (2026-04-26 scan) — stats are BIT-PACKED

Empirical scan (`find_stats_block.py`) across all 29,010 replay packets:

| Value searched | Encoding | Hits |
|---|---|---|
| HP=90 | int32 LE (`5A 00 00 00`) | **0** |
| HP=90 | float (`00 00 B4 42`) | **0** |
| Stamina=100 | int32 LE (`64 00 00 00`) | 1122 (too common) |
| Stamina=100 | float (`00 00 C8 42`) | **0** |
| ClassId=17748 | int32 LE (`54 45 00 00`) | **0** |
| HP=90 + HP_max=90 | consecutive pairs | **0** |

**Conclusion**: None of our captured stat values appear at **any byte-aligned
position** in the replay. The only matches are trivial (int32=0, int32=1).

### Why this is expected (given the wire format)

Each property inside a content block is written at a **non-byte-aligned bit
offset**. The format per property is:

```
[cmd_handle : SerializeInt(max=NumProps) ≈ 8 bits]   ← at bit offset B
[NumBits    : SerializeIntPacked ≈ 8-16 bits]         ← at bit offset B+8
[data       : NumBits bits]                            ← at bit offset B+16..24
```

If cmd_handle takes 8 bits and NumBits_SIP takes 8 bits, the data is at
bit offset `B + 16` — which is byte-aligned ONLY when `B % 8 == 0`. For
subsequent properties, `B` rotates by the accumulated bits of prior
properties, so **most property values are NOT at byte boundaries**.

Example: if HP=90 is written at bit offset 1431 as a 32-bit value:
- byte 178: contains top 1 bit of HP + 7 bits of prior property
- byte 179: contains bits 1..8 of HP (shifted)
- byte 180: bits 9..16
- ...

Raw byte sequence looks nothing like `5A 00 00 00` because of the shift.

### This means: byte-level patching CANNOT work for bit-packed properties

The Tier-1 `ReplayPropertyPatcher` is **fundamentally incompatible** with
bit-packed RepLayout properties. It only works for:

- **Byte-aligned content blocks** (e.g. FastArray element bodies, which are
  written at byte boundaries — see `sub_141D48FD0` analysis)
- **FString payloads** where the 4-byte length prefix lands on a byte
  boundary (our M2.1 NUL-pad works because `RandomChar\0` is byte-aligned
  at byte 207)
- **Fixed structure headers** at known byte positions

For arbitrary bit-packed int32/float properties, we need a **bit-level
patcher** that:

1. Walks the bit stream of pkt#104 at known starting offsets
2. Parses the property sequence (cmd_handle + NumBits + value) per the
   RE'd format
3. Matches property values by bit-exact comparison (not byte)
4. Rewrites the bits in place (preserving bit alignment)

---

## REVISED build plan — Tier-1.5 bit-level patcher

### Step 1: Build a bit-walker for pkt#104

Walk from the start of the outer bunch header, using our RE'd format:

```python
# Pseudocode
br = BitReader(pkt.raw, pkt.bunch_start_bit)

# Walk outer bunch header (~38 bits)
ctrl, paused, reliable, ch_idx, has_pme, has_mbg, partial, bdb = parse_bunch_header(br)

# Advance past PME / MBG sections (if flags set)
if has_pme: skip_pme_section(br)
if has_mbg:
    br.align_to_byte()
    num_mbg = br.read_uint16_le()
    br.skip_bits(num_mbg * 128)

# Parse content block loop
while br.pos < bunch_end:
    bOutermostEnd = br.read_bit()
    if bOutermostEnd: break
    bIsChannelActor = br.read_bit()
    if not bIsChannelActor:
        net_guid = parse_netguid_via_packagemap(br)
    num_payload_bits = br.read_sip_aoc()

    inner_end = br.pos + num_payload_bits
    # Inside inner bunch: per-property loop
    while br.pos < inner_end:
        cmd = br.read_serialize_int(NumProperties)   # NumProperties unknown — try 256
        nbits = br.read_sip_aoc()
        start = br.pos
        # Read nbits as raw integer
        value = br.read_bits(nbits)
        print(f"cmd={cmd}  nbits={nbits}  value={value}  bitpos={start}")
        br.pos = start + nbits
```

### Step 2: Run this walker on pkt#104

Output will be a list of `(cmd, nbits, value, bit_offset)` tuples. Match:

- `cmd=?, nbits=32, value=1` → candidate for Level
- `cmd=?, nbits=32, value=90` → candidate for HP / MP
- `cmd=?, nbits=32, value=100` → candidate for Stamina
- `cmd=?, nbits=?, value=17748` → candidate for ClassId

### Step 3: Verify by checking hit count and bit offset

Each captured value should appear ONCE (not 0, not 100+). If we find
Level=1 at bit offset X, we have our anchor.

### Step 4: Extend patcher with bit-level API

```cpp
struct BitPatchRule {
    std::string  name;
    size_t       bit_offset;    // absolute bit offset in packet
    size_t       bit_width;     // how many bits (32 for int32)
    uint32_t     captured;
    uint32_t     new_val;
};

patcher.add_bit_patch("character_level",
    /*bit_offset*/1431,
    /*bit_width*/32,
    /*captured*/1,
    /*new_val*/25);
```

Applies `write_bits_at(raw, 1431, 25, 32)` — rewrites exactly those 32 bits,
no side effects.

### Step 5: Test in-game

Level=25 should show on HUD. If it doesn't, the cmd maps to a different
property (Level could be at a different handle); try the next candidate
bit offset.

---

## For tomorrow's work

1. Write the bit-walker (`src/protocol/tools/bit_walk_pkt104.py`)
2. Run on pkt#104, produce property list with bit offsets
3. Match against HUD values to identify properties
4. Extend `ReplayPropertyPatcher` with `add_bit_patch()`
5. Rebuild + test in-game

Estimated effort: 2-3 hours for the bit walker + 1 hour for patcher
extension + 30 min for in-game verification.

---

## Bonus: why M2.1 CharacterName patch works despite bit-packing

The `"RandomChar\0"` FString has a **32-bit length prefix = 11**. At the
position where the FString starts, the previous data has already
consumed some bits. The FString's `int32 length` field gets **byte-aligned
automatically** because FString `SerializeBits()` does:

```cpp
Ar.SerializeBits(&length, 32);   // bit-level
Ar.Serialize(bytes, length);     // BYTE-ALIGNED — serializes byte-by-byte
```

The `Serialize(void*, int64)` call (vtable+384) **aligns to the next byte
boundary** before copying. So the actual string bytes land on a byte
boundary. That's why `memcmp` for `RandomChar\0` finds a match at byte 207,
even though preceding property bits are fragmented.

int32/float RepLayout properties don't get this byte-alignment — they're
written purely with `SerializeBits` — hence our bit-walking problem.
