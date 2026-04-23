#!/usr/bin/env python3
"""
Dump the 4,630-bit subobject block from the captured PC spawn bunch.
Look for FString content, fixed patterns, and recognisable ASCII.
"""
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8')

from phase1_parser import read_bits_le

FIXTURE = HERE / 'captured_pc_spawn_reassembled.bin'
payload = FIXTURE.read_bytes()

# Subobject starts at bit 234, spans 4630 bits (from decode_pc_spawn.py)
SUB_START = 234
SUB_BITS  = 4630

# Extract to a fresh byte stream (bit-aligned to 0)
sub_bytes = []
bit = SUB_START
while bit + 8 <= SUB_START + SUB_BITS:
    v, _ = read_bits_le(payload, bit, 8)
    sub_bytes.append(int(v) & 0xFF)
    bit += 8
remaining = (SUB_START + SUB_BITS) - bit
if remaining > 0:
    v, _ = read_bits_le(payload, bit, remaining)
    sub_bytes.append(int(v) & 0xFF)

sub = bytes(sub_bytes)
print(f"Subobject payload: {len(sub)} bytes ({SUB_BITS} bits)\n")

# Save for offline inspection.
out = HERE / 'captured_subobject_506.bin'
out.write_bytes(sub)
print(f"Wrote {out}\n")

# Hex dump first 128 bytes
print("First 128 bytes:")
for row_off in range(0, min(128, len(sub)), 16):
    row = sub[row_off:row_off+16]
    hex_part = ' '.join(f'{b:02x}' for b in row)
    ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in row)
    print(f"  {row_off:04x}: {hex_part:<48}  {ascii_part}")

# Search for ASCII runs of length >=6
print("\nASCII runs (>=6 chars):")
i = 0
found_any = False
while i < len(sub):
    if 32 <= sub[i] < 127:
        j = i
        while j < len(sub) and 32 <= sub[j] < 127:
            j += 1
        run_len = j - i
        if run_len >= 6:
            run = sub[i:j].decode('ascii', errors='replace')
            print(f"  @ offset 0x{i:04x} ({run_len} chars): \"{run}\"")
            found_any = True
        i = j
    else:
        i += 1
if not found_any:
    print("  (none found; payload is opaque / likely custom-delta)")

# Look for FString header patterns: int32 length followed by ASCII bytes.
print("\nPossible FString headers (int32 len 1-200 followed by ASCII):")
for i in range(len(sub) - 4):
    lo = int.from_bytes(sub[i:i+4], 'little', signed=True)
    if 1 < lo < 200 and i + 4 + lo <= len(sub):
        # Check if the next `lo-1` bytes look like ASCII + NUL terminator
        candidate = sub[i+4:i+4+lo]
        if len(candidate) == lo and candidate[-1] == 0:
            ascii_part = candidate[:-1]
            if all(32 <= b < 127 for b in ascii_part) and len(ascii_part) >= 3:
                print(f"  @ offset 0x{i:04x}: len={lo}  \"{ascii_part.decode('ascii')}\"")

# SerializeIntPacked checks — look for likely NetGUID embeds (small SIP values)
print("\nPossible SIP-encoded values in first 64 bytes:")
from phase1_parser import serialize_int_packed
bit_pos = 0
byte_pos = 0
# Read bit-level since SIP is bit-aligned
while byte_pos < min(64, len(sub)):
    val, new_pos = serialize_int_packed(sub, byte_pos * 8)
    bits_consumed = new_pos - byte_pos * 8
    bytes_consumed = (bits_consumed + 7) // 8
    if val is not None and val < 2**24:
        print(f"  @ byte 0x{byte_pos:04x}: SIP={val} "
              f"({bits_consumed}b, first-byte 0x{sub[byte_pos]:02x})")
    byte_pos += max(1, bytes_consumed)
    if byte_pos > 64:
        break
