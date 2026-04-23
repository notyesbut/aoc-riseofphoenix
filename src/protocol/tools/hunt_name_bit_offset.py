#!/usr/bin/env python3
"""
hunt_name_bit_offset.py — find the character-name FString in the captured
pkt#22 PlayerController ActorOpen bunch.

Goals:
  1. Locate the character name bytes (both ASCII and UCS-2 paths).
  2. Do a BIT-level scan — FString bytes in a bunch are NOT necessarily
     byte-aligned.  The payload starts after a variable-length header
     plus a rep-field-mask, both of which are bit-packed.
  3. For any hit, show the surrounding context AND look for an FString
     length prefix (int32 `save_num`) immediately preceding.
  4. Enumerate every 3+ char printable ASCII run in the file — this tells
     us what strings are present without needing to know them in advance.

Usage:
    python hunt_name_bit_offset.py

Fixture: captured_pc_spawn_reassembled.bin (608B / 4864 bits)

What we're trying to confirm:
  * Our catalog has AAoCPlayerController[RepIndex 11] = "Name" = String.
  * If the character's name appears at bit offset X in the payload, then
    bits preceding X encode the rep-field-mask + any earlier properties
    (RepIndex 0..10).
  * The save_num preceding the name tells us ASCII (+value) or UCS-2 (-value).
"""
import sys
import struct
from pathlib import Path

HERE = Path(__file__).parent
sys.stdout.reconfigure(encoding='utf-8')

FIXTURE = HERE / 'captured_pc_spawn_reassembled.bin'
data = FIXTURE.read_bytes()
total_bits = len(data) * 8

# From H.3d analysis (test_pc_spawn_diff): payload begins after the header
# + exports + NewActor stuff at ~bit 3933 (property stream).  Real effective
# bit length is 4859 (last 5 bits are byte-rounding padding).
PROP_STREAM_START = 3933
EFFECTIVE_BITS    = 4859

print(f"{'='*75}")
print(f"  hunt_name_bit_offset.py")
print(f"  fixture={FIXTURE.name}  {len(data)}B  {total_bits}b")
print(f"  property stream starts at bit {PROP_STREAM_START}")
print(f"  effective payload bits: {EFFECTIVE_BITS}")
print(f"{'='*75}")


# ─── Bit-level reader helpers ────────────────────────────────────────────

def read_bit(buf, bit_offset):
    """UE5 LSB-first per-byte bit read."""
    return (buf[bit_offset >> 3] >> (bit_offset & 7)) & 1

def read_bits(buf, bit_offset, n):
    """Read n bits as an integer, LSB-first per-byte."""
    v = 0
    for i in range(n):
        v |= read_bit(buf, bit_offset + i) << i
    return v

def read_uint32_at_bit(buf, bit_offset):
    return read_bits(buf, bit_offset, 32)

def read_int32_at_bit(buf, bit_offset):
    v = read_bits(buf, bit_offset, 32)
    # Sign-extend
    return v - 0x100000000 if v >= 0x80000000 else v

def read_byte_at_bit(buf, bit_offset):
    return read_bits(buf, bit_offset, 8)


# ─── Bit-level needle scan ───────────────────────────────────────────────

def bit_scan_ascii(needle_str):
    """Find every bit offset where the ASCII bytes of `needle_str` match
    when read LSB-first.  Returns a list of bit offsets."""
    needle = needle_str.encode('ascii')
    needle_bits = len(needle) * 8
    hits = []
    for bo in range(total_bits - needle_bits + 1):
        ok = True
        for i, b in enumerate(needle):
            if read_byte_at_bit(data, bo + i * 8) != b:
                ok = False
                break
        if ok:
            hits.append(bo)
    return hits


def bit_scan_ucs2(needle_str):
    """Find every bit offset where the UCS-2 LE bytes of `needle_str` match."""
    ucs2 = needle_str.encode('utf-16-le')
    bits_len = len(ucs2) * 8
    hits = []
    for bo in range(total_bits - bits_len + 1):
        ok = True
        for i, b in enumerate(ucs2):
            if read_byte_at_bit(data, bo + i * 8) != b:
                ok = False
                break
        if ok:
            hits.append(bo)
    return hits


def report_hits(label, needle_str, hits):
    print()
    print(f"  {label}: \"{needle_str}\" — {len(hits)} hit(s)")
    for bo in hits:
        byte_off = bo // 8
        bit_in_byte = bo & 7
        in_stream = bo >= PROP_STREAM_START
        stream_mark = "  ★ IN PROPERTY STREAM" if in_stream else ""
        print(f"    bit {bo} (byte {byte_off}, bit_in_byte {bit_in_byte}){stream_mark}")

        # Check for int32 save_num immediately before
        if bo >= 32:
            sn_bit = bo - 32
            sn = read_int32_at_bit(data, sn_bit)
            is_plausible_ascii  = sn == len(needle_str) + 1      # +1 for NUL
            is_plausible_ucs2   = sn == -(len(needle_str) + 1)
            tag = ""
            if is_plausible_ascii:
                tag = "  ← PRECEDED BY int32 save_num = +len+1 (ASCII FString start!)"
            elif is_plausible_ucs2:
                tag = "  ← PRECEDED BY int32 save_num = -(len+1) (UCS-2 FString start!)"
            else:
                tag = f"  (preceding int32 at bit {sn_bit} = {sn}, not a plausible save_num)"
            print(f"      save_num scan: {tag}")


# ─── ASCII-run extractor (bit-level, tolerant of bit-alignment) ──────────

def extract_ascii_runs(min_len=4):
    """Walk every bit offset; at each, try to extract consecutive printable
    ASCII bytes (0x20..0x7E).  Report runs of length >= min_len."""
    runs = []
    bo = 0
    while bo < total_bits - 8:
        run = []
        cur = bo
        while cur < total_bits - 8:
            byte = read_byte_at_bit(data, cur)
            if 0x20 <= byte <= 0x7E:
                run.append(byte)
                cur += 8
            else:
                break
        if len(run) >= min_len:
            runs.append((bo, bytes(run).decode('ascii', errors='replace')))
            bo = cur   # skip past the run
        else:
            bo += 1
    return runs


# ─── Run the hunt ────────────────────────────────────────────────────────

print(f"\n## ASCII hunt for candidate character names (bit-aligned) ##")

for name in ["RandomChar", "Hatemost", "YourName", "Test", "Player", "Admin"]:
    hits = bit_scan_ascii(name)
    report_hits(f"ASCII", name, hits)

print(f"\n## UCS-2 LE hunt for candidate character names (bit-aligned) ##")
for name in ["RandomChar", "Hatemost", "YourName"]:
    hits = bit_scan_ucs2(name)
    report_hits(f"UCS-2", name, hits)


print(f"\n## Printable ASCII runs >= 4 chars (byte-aligned preview) ##")
# Byte-aligned only for readability — we already did the bit-level hunt above
runs = []
i = 0
while i < len(data):
    run = []
    while i < len(data) and 0x20 <= data[i] <= 0x7E:
        run.append(data[i])
        i += 1
    if len(run) >= 4:
        start = i - len(run)
        s = bytes(run).decode('ascii', errors='replace')
        runs.append((start, s))
    i += 1
for byte_off, s in runs:
    bit_off = byte_off * 8
    in_stream = bit_off >= PROP_STREAM_START
    mark = "  ★" if in_stream else ""
    print(f"  byte {byte_off:4d} (bit {bit_off:4d}):  '{s}'{mark}")


print(f"\n## Printable ASCII runs >= 4 chars at SHIFTED bit alignments ##")
# Now also check bit-shifted alignments in case the string isn't byte-aligned
for shift in range(1, 8):
    shifted_runs = []
    bo = shift
    while bo < total_bits - 8:
        run = []
        cur = bo
        while cur < total_bits - 8:
            byte = read_byte_at_bit(data, cur)
            if 0x20 <= byte <= 0x7E:
                run.append(byte)
                cur += 8
            else:
                break
        if len(run) >= 4:
            shifted_runs.append((bo, bytes(run).decode('ascii', errors='replace')))
            bo = cur
        else:
            bo += 8
    if shifted_runs:
        print(f"\n  shift={shift} bit:")
        for bo, s in shifted_runs:
            byte_off = bo // 8
            bit_in_byte = bo & 7
            in_stream = bo >= PROP_STREAM_START
            mark = "  ★" if in_stream else ""
            print(f"    bit {bo} (byte {byte_off}+{bit_in_byte}b):  '{s}'{mark}")


print(f"\n{'='*75}")
print(f"  DONE.")
print(f"{'='*75}")
