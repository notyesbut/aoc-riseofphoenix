#!/usr/bin/env python3
"""
H.4a: locate CharacterName bytes in captured PC spawn bunch.

Search the 4859-bit captured payload for:
  1. ASCII "Hatemost"
  2. UTF-16 LE "Hatemost" (H\0 a\0 t\0 e\0 m\0 o\0 s\0 t\0)
  3. Other known values: captured archetype/level NetGUIDs (sanity checks)
  4. Any other printable ASCII runs of 3+ chars that might be guild name etc.

For every hit, report:
  - The byte offset
  - The bit offset (bit = byte * 8 + bit_in_byte)
  - Whether it falls in the property-stream region (bit >= 4011)
  - Surrounding 32 bytes of context
"""
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.stdout.reconfigure(encoding='utf-8')

FIXTURE = HERE / 'captured_pc_spawn_reassembled.bin'
data = FIXTURE.read_bytes()
total_bits = len(data) * 8

PROP_STREAM_START = 4011   # from H.3d — property stream begins here
TOTAL_BDB = 4859           # actual bdb (byte-rounding gives 4864 but 5 are padding)


def search(needle, label):
    print(f"\n{'='*75}")
    print(f"Searching for {label} — {len(needle)} bytes: {needle.hex()}")
    print(f"{'='*75}")
    pos = 0
    hits = []
    while pos < len(data):
        found = data.find(needle, pos)
        if found == -1:
            break
        hits.append(found)
        pos = found + 1

    if not hits:
        print(f"  NO HITS")
        return []
    for hit in hits:
        bit_offset = hit * 8
        in_stream = bit_offset >= PROP_STREAM_START
        stream_mark = " ★ IN PROPERTY STREAM" if in_stream else ""
        print(f"  found @ byte {hit} (bit {bit_offset}){stream_mark}")
        # Dump 32 bytes of context around hit
        context_start = max(0, hit - 8)
        context_end = min(len(data), hit + len(needle) + 8)
        ctx = data[context_start:context_end]
        hex_str = ' '.join(f'{b:02x}' for b in ctx)
        # Highlight the match within context
        highlight_start = (hit - context_start)
        marker = ' ' * (highlight_start * 3) + '^' * (len(needle) * 3 - 1)
        print(f"    context: {hex_str}")
        print(f"    marker:  {marker}")
    return hits


# ── Search ASCII strings ──
search(b"Hatemost",        "ASCII 'Hatemost'")
search(b"H\x00a\x00t\x00e\x00m\x00o\x00s\x00t\x00",  "UTF-16 LE 'Hatemost'")

# Try common variations
search(b"hatemost",  "ASCII 'hatemost' (lowercase)")
search(b"HATEMOST",  "ASCII 'HATEMOST' (uppercase)")

# Also search for known NetGUID struct bytes (archetype)
# Actor NetGUID: ObjectId=10341530 ServerId=60 Randomizer=1860730596
# Archetype: ObjectId=3503756484819958835
# Level: ObjectId=16442478405498561049

import struct
def find_qword(val, label):
    needle = struct.pack('<Q', val)
    search(needle, f"{label} (qword 0x{val:016X})")

find_qword(10341530, "Actor ObjectId")
find_qword(3503756484819958835, "Archetype ObjectId")
find_qword(16442478405498561049, "Level ObjectId")

# Known Kaelar race, Bard class? Let's search common character-archetype values
# Bard = 17747 per test_actor_builder.cpp (placeholder guess)
def find_dword(val, label):
    needle = struct.pack('<I', val)
    hits = search(needle, f"{label} (dword 0x{val:08X})")
    return hits

find_dword(17747, "Bard archetype hint")


# ── Also: scan for ANY printable ASCII runs of 3+ chars in the bunch ──
print(f"\n\n{'='*75}")
print(f"Printable ASCII runs (3+ chars) in captured bunch")
print(f"{'='*75}")

runs = []
run_start = None
run_chars = []
for i, b in enumerate(data):
    if 0x20 <= b < 0x7F:
        if run_start is None:
            run_start = i
        run_chars.append(chr(b))
    else:
        if run_start is not None and len(run_chars) >= 3:
            runs.append((run_start, ''.join(run_chars)))
        run_start = None
        run_chars = []
if run_start is not None and len(run_chars) >= 3:
    runs.append((run_start, ''.join(run_chars)))

for (byte_pos, s) in runs[:40]:
    bit_pos = byte_pos * 8
    in_stream = bit_pos >= PROP_STREAM_START
    mark = " ★" if in_stream else ""
    print(f"  byte {byte_pos:3d} (bit {bit_pos:4d}): {s!r}{mark}")
