#!/usr/bin/env python3
"""
Decode the export bunch header + 3 exports from the reassembled PC spawn.
Uses phase1_parser's SIP reader to properly parse each export.
"""
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.stdout.reconfigure(encoding='utf-8')

from phase1_parser import (
    read_bit, read_bits_le, serialize_int_packed, serialize_int_packed64,
)

p = (HERE / 'captured_pc_spawn_reassembled.bin').read_bytes()
total_bits = len(p) * 8

print(f"Loaded {len(p)}B ({total_bits} bits)")
print()

pos = 0

# Step 1: bHasRepLayoutExport
b_rep_layout = read_bit(p, pos); pos += 1
print(f"[bit 0]  bHasRepLayoutExport = {b_rep_layout}")

# Step 2: int32 NumGUIDsInBunch (32 bits LSB-first)
num_guids, new_pos = read_bits_le(p, pos, 32)
pos = new_pos
print(f"[bits 1..32] NumGUIDsInBunch = {num_guids}")
print()

# Parse each export via recursive InternalLoadObject format
def read_fstring(data, bit_pos):
    """UE5 FString: int32 save_num (LSB) + save_num bytes (LSB-first within byte).
       If save_num > 0: ANSI with NUL.  If save_num < 0: UCS-2.  If 0: empty."""
    save_num_raw, bit_pos = read_bits_le(data, bit_pos, 32)
    save_num = save_num_raw if save_num_raw < 0x8000_0000 else save_num_raw - 0x1_0000_0000
    if save_num == 0:
        return "", bit_pos, 0
    if save_num > 0:
        chars = []
        for i in range(save_num):
            b, bit_pos = read_bits_le(data, bit_pos, 8)
            chars.append(int(b) & 0xFF)
        # Drop trailing NUL if present
        if chars and chars[-1] == 0:
            chars = chars[:-1]
        return bytes(chars).decode('ascii', errors='replace'), bit_pos, save_num
    # UCS-2 path (negative save_num)
    count = -save_num
    chars = []
    for i in range(count):
        c, bit_pos = read_bits_le(data, bit_pos, 16)
        chars.append(int(c) & 0xFFFF)
    if chars and chars[-1] == 0:
        chars = chars[:-1]
    return ''.join(chr(c) if c < 128 else '?' for c in chars), bit_pos, save_num


def read_internal_object(data, bit_pos, depth=0):
    """Read one InternalWriteObject output (NetGUID + optional flags + path)."""
    indent = "  " * depth
    guid, bit_pos = serialize_int_packed64(data, bit_pos)
    if guid is None:
        return None, bit_pos
    guid_value = guid >> 1 if guid else 0
    is_static = bool(guid & 1)
    kind = "static" if is_static else "dynamic" if guid else "null"
    print(f"{indent}  NetGUID = {guid} (value={guid_value}, {kind})")
    if guid == 0:
        return {'guid': 0}, bit_pos

    # ExportFlags (8 bits)
    flags, bit_pos = read_bits_le(data, bit_pos, 8)
    flags = int(flags) & 0xFF
    b_has_path = (flags & 1)
    b_no_load = (flags >> 1) & 1
    b_has_checksum = (flags >> 2) & 1
    print(f"{indent}  ExportFlags = 0x{flags:02x}  "
          f"(bHasPath={b_has_path} bNoLoad={b_no_load} bHasChecksum={b_has_checksum})")

    if not b_has_path:
        return {'guid': guid, 'value': guid_value}, bit_pos

    # Recurse for outer
    print(f"{indent}  outer:")
    outer, bit_pos = read_internal_object(data, bit_pos, depth + 1)

    # Read FString path
    path, bit_pos, save_num = read_fstring(data, bit_pos)
    print(f"{indent}  path = \"{path}\" (save_num={save_num})")

    # Optional checksum
    checksum = None
    if b_has_checksum:
        checksum, bit_pos = read_bits_le(data, bit_pos, 32)
        print(f"{indent}  checksum = 0x{int(checksum):08x}")

    return {
        'guid': guid, 'value': guid_value,
        'outer': outer, 'path': path, 'checksum': checksum,
    }, bit_pos


for i in range(num_guids):
    print(f"=== Export [{i}] ===")
    obj, pos = read_internal_object(p, pos, 0)
    print()

print(f"\nExport section ends at bit {pos} ({pos/8:.2f} bytes)")
print(f"Remaining actor-content bits: {total_bits - pos}")
print()
print("Context around end of export section:")
print(f"  bit {pos-8} .. {pos+8}:")
bits_around = []
for i in range(max(0, pos-8), min(total_bits, pos+16)):
    bit = (p[i >> 3] >> (i & 7)) & 1
    bits_around.append(str(bit))
print(f"  {' '.join(bits_around[:8])} [END] {' '.join(bits_around[8:])}")
